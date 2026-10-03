# SPDX-License-Identifier: Apache-2.0
"""Check fixed provider URLs, conditional updates and hostile response limits."""

import copy
import json
import os
import ssl
from pathlib import Path

import pytest
from ficc_node import container_kubeconfig as config
from ficc_node import container_spec as spec
from ficc_node.container_engine import Engine
from ficc_node.container_kubernetes import Kubernetes

from ficc.providers.containers import validate


def resource(index=0, kind="container"):
    return {"kind": kind, "id": f"{index:064x}" if kind == "container" else f"{index:032x}",
            "name": f"fixture-{index}", "namespace": "" if kind == "container" else "fixture"}


def engine_row(index=0):
    return {"Id": f"{index:064x}", "Name": f"/fixture-{index}", "Created": "fixed", "Image": "sha256:fixture",
            "Config": {"Image": "fixture", "Tty": False}, "HostConfig": {}, "State": {"Status": "running"}}


def request(action, params):
    return {"version": 1, "profile": "a" * 32, "provider": "docker", "connection": "rootless", "context": "",
            "namespace": "", "binding": "b" * 64, "action": action, "parameters": params}


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("provider", ["docker", "podman"])
def test_engine_inventory_fixed_ids_multiplexed_logs_and_stop(count, provider):
    engine = Engine.__new__(Engine)
    engine.provider, engine.prefix = provider, "/fixed"
    calls = []

    class HTTP:
        def json(self, method, path, query=None):
            calls.append((method, path, query))
            if path.endswith("/containers/json"):
                return [{"Id": f"{i:064x}"} for i in reversed(range(count))]
            return engine_row(int(path.split("/")[-2], 16))

        def request(self, method, path, query=None, **kwargs):
            calls.append((method, path, query))
            message = b"log\n\x1bsecret"
            data = b"\x01\0\0\0" + len(message).to_bytes(4, "big") + message
            return 204 if method == "POST" else 200, data, False

    engine.http = HTTP()
    rows = engine.inventory("all", 0, 256)["results"]
    assert [row["data"]["resource"]["id"] for row in rows] == [f"{i:064x}" for i in range(count)]
    for index in range(count):
        pointer = resource(index)
        logs = engine.logs(pointer, 20, 6, "")
        assert "\x1b" not in logs["text"] and logs["truncated"]
        expected = {key: engine.status(pointer)[key] for key in ("resource", "state", "definition", "revision", "replicas")}
        assert engine.apply("stop", expected, None) == {"state": "accepted"}
    posts = [call for call in calls if call[0] == "POST"]
    assert len(posts) == count and all(call[1].endswith("/stop") for call in posts)
    assert {tuple(call[2].items()) for call in posts} == {(('t' if provider == 'docker' else 'timeout', 10),)}


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_transport_rejects_reordered_extra_and_replaced_results(count):
    engine = Engine.__new__(Engine)
    pointers = [resource(i) for i in range(count)]
    rows = [{"resource": pointer, "data": engine.describe(engine_row(i))} for i, pointer in enumerate(pointers)]
    payload = request("status", {"resources": pointers})
    validate({"results": copy.deepcopy(rows)}, payload)
    bad = copy.deepcopy(rows)
    bad[-1]["resource"]["id"] = "f" * 64
    with pytest.raises(ValueError):
        validate({"results": bad}, payload)
    with pytest.raises(ValueError):
        validate({"results": rows + rows[:1]}, payload)
    if count > 1:
        with pytest.raises(ValueError):
            validate({"results": list(reversed(rows))}, payload)
    with pytest.raises(ValueError):
        spec.request(request("exec", {"command": "id"}))
    with pytest.raises(ValueError):
        spec.request(request("status", {"resources": pointers + pointers[:1]}))


def kube_row(index=0):
    return {"metadata": {"uid": f"{index:032x}", "name": f"fixture-{index}", "namespace": "fixture", "resourceVersion": "102"},
            "spec": {"replicas": 1, "template": {"spec": {"containers": [{"name": "app", "image": "fixture"}]}}},
            "status": {"readyReplicas": 1}}


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("replicas", [0, 1])
def test_kubernetes_scale_has_atomic_identity_revision_replica_tests(count, replicas):
    kube = Kubernetes.__new__(Kubernetes)
    kube.namespace = "fixture"
    calls = []

    class HTTP:
        def json(self, method, path, query=None, **kwargs):
            calls.append((method, path, kwargs))
            index = int(path.split("fixture-")[-1].split("/")[0])
            row = kube_row(index)
            row["spec"]["replicas"] = replicas
            return {"metadata": row["metadata"], "spec": {"replicas": replicas} if replicas else {}} if path.endswith("/scale") else row
    kube.http = HTTP()
    for index in range(count):
        pointer = resource(index, "deployment")
        status = kube.status(pointer)
        expected = {key: status[key] for key in ("resource", "state", "definition", "revision", "replicas")}
        assert kube.apply("scale", expected, 2) == {"state": "accepted"}
    patches = [call for call in calls if call[0] == "PATCH"]
    assert len(patches) == count
    for _, path, kwargs in patches:
        assert path.endswith("/scale") and kwargs["content_type"] == "application/json-patch+json"
        assert [(op["op"], op["path"]) for op in kwargs["body"]] == [
            ("test", "/metadata/uid"), ("test", "/metadata/resourceVersion"), ("test", "/spec"), ("add", "/spec/replicas")]
    with pytest.raises(spec.ProviderError):
        kube.status({**resource(0, "deployment"), "id": "f" * 32})
    with pytest.raises(spec.ProviderError):
        kube.status({**resource(0, "deployment"), "namespace": "another"})


def kubeconfig(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".kube").mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    data = {"apiVersion": "v1", "kind": "Config", "contexts": [{"name": "fixture", "context": {"cluster": "fixture", "user": "fixture"}}],
            "clusters": [{"name": "fixture", "cluster": {"server": "https://127.0.0.1:6443", "certificate-authority-data": "Y2E="}}],
            "users": [{"name": "fixture", "user": {"token": "synthetic-test-token"}}]}
    path = home / ".kube/config"
    path.touch(mode=0o600)
    return path, data, {"context": "fixture", "namespace": "fixture", "binding": None}


@pytest.mark.parametrize("field,value", [("exec", {"command": "/must-not-run"}), ("auth-provider", {}), ("tokenFile", "/must-not-read"),
    ("username", "forbidden"), ("password", "forbidden"), ("as", "other"), ("external-unknown", "forbidden")])
def test_kubeconfig_refuses_executable_external_and_unknown_auth(tmp_path, monkeypatch, field, value):
    path, data, profile = kubeconfig(tmp_path, monkeypatch)
    data["users"][0]["user"][field] = value
    path.write_text(json.dumps(data))
    monkeypatch.setattr(config.subprocess, "Popen", lambda *a, **k: pytest.fail("JSON credentials must not execute a subprocess"))
    with pytest.raises(ValueError):
        config.load(profile)


@pytest.mark.parametrize("field,value", [("insecure-skip-tls-verify", True), ("proxy-url", "http://proxy.invalid"),
    ("certificate-authority", "/must-not-read"), ("tls-server-name", "other.invalid")])
def test_kubeconfig_refuses_tls_overrides_and_external_paths(tmp_path, monkeypatch, field, value):
    path, data, profile = kubeconfig(tmp_path, monkeypatch)
    data["clusters"][0]["cluster"][field] = value
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        config.load(profile)


def test_kubeconfig_private_file_bounds_json_depth_and_tls_verification(tmp_path, monkeypatch):
    path, data, profile = kubeconfig(tmp_path, monkeypatch)
    path.write_text(json.dumps(data))
    contexts = []
    class TLS:
        def __init__(self, protocol):
            assert protocol == ssl.PROTOCOL_TLS_CLIENT
            contexts.append(self)
        def load_verify_locations(self, *, cadata):
            assert cadata == "ca"
    monkeypatch.setattr(config.ssl, "SSLContext", TLS)
    _, binding = config.load(profile)
    assert contexts[0].minimum_version == ssl.TLSVersion.TLSv1_2
    with pytest.raises(spec.ProviderError):
        config.load({**profile, "binding": "a" * 64})
    assert len(binding) == 64
    path.chmod(0o644)
    with pytest.raises(ValueError):
        config.load(profile)
    path.chmod(0o600)
    path.write_bytes(b" " * 262145)
    with pytest.raises(ValueError):
        config.load(profile)
    for raw in (b'{"a":1,"a":2}', b"[" * 34 + b"0" + b"]" * 34):
        with pytest.raises(ValueError):
            config.convert(raw)
    fd = config.memory(b"secret fixture")
    try:
        with pytest.raises(OSError):
            os.write(fd, b"changed")
    finally:
        os.close(fd)
