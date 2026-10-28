# SPDX-License-Identifier: Apache-2.0
"""Exercise installed-provider arguments and immutable CDI decisions without privileged execution."""

import copy
import errno
import importlib
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROVIDER = Path(__file__).resolve().parents[2] / "executor-providers/podman/src"
sys.path.insert(0, str(PROVIDER))
runner = importlib.import_module("ficc_executor_podman.runner")
devices = importlib.import_module("ficc_executor_podman.devices")
prepare = importlib.import_module("ficc_executor_podman.prepare")


def approved_archive(path, kind="oci", *, damaged=False, duplicate=False):
    import hashlib
    import io
    import json
    import tarfile

    def encoded(value):
        return json.dumps(value, separators=(",", ":")).encode()
    config = encoded({"architecture": "amd64", "os": "linux", "config": {"Entrypoint": ["/runtime"]}, "rootfs": {"type": "layers", "diff_ids": []}})
    digest = "sha256:" + hashlib.sha256(config).hexdigest()
    def descriptor(data):
        return {"digest": "sha256:" + hashlib.sha256(data).hexdigest(), "size": len(data)}
    if kind == "oci":
        manifest = encoded({"schemaVersion": 2, "config": descriptor(config), "layers": []})
        index = encoded({"schemaVersion": 2, "manifests": [{**descriptor(manifest), "annotations": {"org.opencontainers.image.ref.name": "sha256:" + "a" * 64}}]})
        files = [("index.json", index), ("blobs/sha256/" + descriptor(manifest)["digest"][7:], manifest),
                 ("blobs/sha256/" + digest[7:], config.replace(b"runtime", b"changed") if damaged else config)]
    else:
        files = [("manifest.json", encoded([{"Config": digest[7:] + ".json", "RepoTags": ["example:latest"], "Layers": []}])), (digest[7:] + ".json", config)]
    if duplicate:
        files.append(files[0])
    with tarfile.open(path, "w") as archive:
        for name, data in files:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    path.chmod(0o444)
    return digest


@pytest.mark.parametrize("kind", ["oci", "docker"])
def test_provider_refuses_source_image_id_before_advertising_exported_image(tmp_path, monkeypatch, kind):
    import ficc_executor_podman as provider

    from ficc.execution.files import fingerprint

    path = tmp_path / "runtime.tar"
    exported = approved_archive(path, kind)
    saved = fingerprint(path, owner=os.getuid())
    monkeypatch.setattr(provider, "fingerprint", lambda _: saved)
    configuration = {"version": 1, "images": [{"digest": "sha256:" + "a" * 64, "archive": str(path), "archive_digest": saved["digest"]}], "inputs": [], "gpu": None}
    with pytest.raises(ValueError, match="Use its config ID: " + exported):
        provider.Driver(configuration)
    configuration["images"][0]["digest"] = exported
    assert list(provider.Driver(configuration).images) == [exported]


@pytest.mark.parametrize("damage,duplicate,reason", [(True, False, "differs from its descriptor"), (False, True, "ambiguous")])
def test_provider_archive_metadata_is_unambiguous_and_digest_bound(tmp_path, damage, duplicate, reason):
    from ficc_executor_podman.archive import verify

    from ficc.execution.files import fingerprint

    path = tmp_path / "runtime.tar"
    expected = approved_archive(path, damaged=damage, duplicate=duplicate)
    with pytest.raises(ValueError, match=reason):
        verify(path, expected, fingerprint(path, owner=os.getuid()))


def test_distribution_digest_is_portable_but_binds_runtime_bytes(tmp_path, monkeypatch):
    import base64
    import csv
    import hashlib
    import importlib.metadata

    from ficc.execution import providers

    current = []
    monkeypatch.setattr(importlib.metadata, "entry_points", lambda **kwargs: current)
    def installed(name, code=b"API_VERSION = 1\n"):
        root = tmp_path / name
        root.mkdir(mode=0o700)
        metadata = root / "example-1.dist-info"
        metadata.mkdir(mode=0o700)
        files = {"example.py": code, "example-1.dist-info/METADATA": b"Name: example\nVersion: 1\n",
                 "example-1.dist-info/direct_url.json": ('{"url":"file:///different/' + name + '.whl"}').encode()}
        rows = []
        for path, data in files.items():
            target = root / path
            target.write_bytes(data)
            target.chmod(0o600)
            encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
            rows.append([path, "sha256=" + encoded, str(len(data))])
        with (metadata / "RECORD").open("w") as stream:
            csv.writer(stream).writerows([*rows, ["example-1.dist-info/RECORD", "", ""]])
        current[:] = [SimpleNamespace(dist=importlib.metadata.PathDistribution(metadata), value="example:configure")]
        return providers.distribution("example", owner=os.getuid())[1]
    first = installed("first")
    assert installed("second") == first
    assert installed("changed", b"API_VERSION = 2\n") != first
    (tmp_path / "changed/example.py").write_bytes(b"unrecorded replacement")
    with pytest.raises(ValueError, match="package record"):
        providers.distribution("example", owner=os.getuid())


def test_shared_archive_requires_public_immutable_owned_path(monkeypatch):
    values = {"/library/model.oci": SimpleNamespace(st_mode=stat.S_IFREG | 0o444, st_uid=0, st_nlink=1,
        st_dev=1, st_ino=2, st_size=100, st_mtime_ns=3, st_ctime_ns=4),
        "/library": SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
        "/": SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)}
    monkeypatch.setattr(Path, "lstat", lambda path: values[str(path)])
    assert prepare.shared_archive("/library/model.oci")["inode"] == 2
    values["/library"].st_mode = stat.S_IFDIR | 0o700
    assert prepare.shared_archive("/library/model.oci") is None
    values["/library"].st_mode = stat.S_IFDIR | 0o755
    values["/library/model.oci"].st_mode = stat.S_IFREG | 0o644
    assert prepare.shared_archive("/library/model.oci") is None
    values["/library/model.oci"].st_mode = stat.S_IFREG | 0o444
    values["/library/model.oci"].st_uid = 1000
    assert prepare.shared_archive("/library/model.oci") is None


def test_engine_timeout_reports_the_operation_in_workload_logs(tmp_path, monkeypatch):
    import subprocess
    engine = object.__new__(runner.Engine)
    engine.root, engine.prefix, engine.environment = tmp_path, ["/usr/bin/podman"], {}
    def timeout(argv, **kwargs):
        assert kwargs["timeout"] == 30
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(ValueError, match="image operation exceeded"):
        engine.call(["image", "inspect", "sha256:" + "a" * 64])
    assert (tmp_path / "stderr").read_text() == "The rootless engine image operation exceeded its 30 second bound.\n"


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_payload_arguments_cannot_change_engine_flags_or_host_environment(tmp_path, count):
    for index in range(count):
        root = tmp_path / f"attempt-{index}"
        request = {"context": {"directory": str(root), "cgroup": "/system.slice/fixed",
            "plan": {"attempt_id": f"{index:032x}", "job": {"payload": {
                "argv": ["/payload", "--privileged", "--volume=/etc:/host"],
                "environment": {"LD_PRELOAD": "/work/value", "CONTAINERS_CONF": "/work/false"}}}}},
            "barrier": "/root-approved/barrier", "image_digest": "sha256:" + "a" * 64,
            "containers_config": str(root / "containers.conf"), "gpu": {"cdi_name": None}}
        args = runner.arguments(request)
        boundary = args.index(request["image_digest"])
        assert args[boundary:] == [request["image_digest"], "--", "/payload", "--privileged", "--volume=/etc:/host"]
        assert "--network=none" in args[:boundary] and "--read-only-tmpfs=false" in args[:boundary]
        assert not any(item == "--dns" or item.startswith("--dns=") for item in args[:boundary])
        assert "--no-hosts" in args[:boundary]
        assert "--volume=" + str(root / "resolv.conf") + ":/etc/resolv.conf:ro,nosuid,nodev" in args[:boundary]
        assert "--privileged" not in args[:boundary]
        assert "--security-opt=no-new-privileges" in args[:boundary]
        assert "--http-proxy=false" in args[:boundary] and "--log-driver=none" in args[:boundary]
        assert "--cap-drop=ALL" in args[:boundary] and "--pull=never" in args[:boundary]
        ordinary = runner.Engine(request)
        assert not any(item.startswith("--storage-opt=") for item in ordinary.prefix)
        request["context"]["plan"]["job"]["endpoint"] = {"port": 8080}
        managed = runner.Engine(request)
        assert "--storage-driver=overlay" in managed.prefix
        assert "--storage-opt=overlay.mount_program=/usr/bin/fuse-overlayfs" in managed.prefix
        values = runner.environment(root, request)
        assert "LD_PRELOAD" not in values and values["CONTAINERS_CONF"] == str(root / "containers.conf")
        assert set(values) == {"PATH", "LANG", "LC_ALL", "HOME", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME",
                               "XDG_DATA_HOME", "TMPDIR", "CONTAINERS_STORAGE_CONF", "CONTAINERS_CONF"}


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_no_network_resolver_is_empty_read_only_and_bound_to_the_attempt(tmp_path, count):
    mask = os.umask(0o077)
    try:
        for index in range(count):
            root = tmp_path / f"attempt-{index}"
            root.mkdir()
            mounted = prepare.resolver(root)
            source = root / "resolv.conf"
            assert source.read_bytes() == b""
            assert stat.S_IMODE(source.stat().st_mode) == 0o444
            assert source.stat().st_uid == root.stat().st_uid
            assert mounted["source"] == str(source) and mounted["target"] == "/etc/resolv.conf"
            assert mounted["read_only"] and mounted["identity"]["inode"] == source.stat().st_ino
            assert mounted["identity"]["bytes"] == 0
    finally:
        os.umask(mask)


def mapped(monkeypatch):
    uuid = ["GPU-" + f"{index:08x}-0000-0000-0000-000000000000" for index in (1, 2)]
    obj = devices.Devices(None)
    obj.mapping = {value: {"path": "/dev/nvidia" + str(index), "major": 195, "minor": index}
                   for index, value in enumerate(uuid)}
    obj.shared = {name: {"major": 195 if name.endswith("ctl") else 511, "minor": 255 if name.endswith("ctl") else index}
                  for index, name in enumerate(devices.SHARED)}
    obj.libraries = []
    monkeypatch.setattr(devices, "inventory", lambda: {value: index for index, value in enumerate(uuid)})
    monkeypatch.setattr(Path, "exists", lambda _path: True)
    def node(path, expected=None):
        return {"source": path, "identity": {"device": 1, "inode": 4, "mode": stat.S_IFCHR | 0o666,
                                             "rdev": expected or os.makedev(10, 229)}}
    monkeypatch.setattr(devices, "character", node)
    return obj, uuid


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_uuid_selection_emits_only_selected_character_devices_and_no_hooks(monkeypatch, count):
    obj, uuids = mapped(monkeypatch)
    for index in range(count):
        selected, denied = index % 2, 1 - index % 2
        result = obj.select([uuids[selected]])
        assert result["negative"] == ["/dev/nvidia" + str(denied)]
        assert result["positive"] == ["/dev/nvidia" + str(selected), *devices.SHARED]
        assert [row["source"] for row in result["devices"]] == ["/dev/fuse", *result["positive"]]
        edits = result["cdi"]["devices"][0]["containerEdits"]
        assert set(edits) == {"deviceNodes", "mounts"}
        assert all(row["permissions"] == "rw" and row["type"] == "c" for row in edits["deviceNodes"])
        assert "NVIDIA_VISIBLE_DEVICES" not in str(result)
    empty = obj.select([])
    assert empty["positive"] == [] and empty["cdi"] is None
    assert empty["negative"] == ["/dev/nvidia0", "/dev/nvidia1"]
    with pytest.raises(ValueError, match="physical GPU"):
        obj.select(["GPU-00000003-0000-0000-0000-000000000000"])
    monkeypatch.setattr(devices, "inventory", lambda: {uuids[0]: 1, uuids[1]: 0})
    with pytest.raises(ValueError, match="mapping changed"):
        obj.select([uuids[0]])


def test_actual_character_guard_rejects_regular_file_and_wrong_device(tmp_path):
    path = tmp_path / "node"
    path.write_bytes(b"foreign")
    with pytest.raises(ValueError):
        devices.character(str(path))
    with pytest.raises(ValueError):
        devices.character("/dev/null", os.makedev(195, 0))
    accepted = devices.character("/dev/null", os.makedev(1, 3))
    assert accepted["identity"]["rdev"] == os.makedev(1, 3)


@pytest.mark.parametrize("operation", ["start", "prepare"])
def test_changed_input_and_stronger_isolation_never_reach_launch(tmp_path, operation):
    from ficc_executor_podman import Driver

    from ficc.execution.files import identity
    image = tmp_path / "approved.oci"
    image.write_bytes(b"original")
    driver = object.__new__(Driver)
    driver.images = {"sha256:" + "a" * 64: object()}
    driver.identities = {str(image): identity(image.lstat())}
    driver.devices = SimpleNamespace(select=lambda _rows: None)
    ctx = {"plan": {"job": {"runtime": {"image_digest": next(iter(driver.images)), "network": "none",
                                       "isolation": "hardware-vm"}, "limits": {"gpu_devices": []}}}}
    with pytest.raises(ValueError, match="only shared-kernel"):
        getattr(driver, operation)([ctx])
    ctx["plan"]["job"]["runtime"]["isolation"] = "shared-kernel"
    image.write_bytes(b"substituted")
    with pytest.raises(ValueError, match="changed after"):
        getattr(driver, operation)([ctx])


def test_device_probe_records_real_errors_without_substituting_environment(monkeypatch):
    calls = []
    def opened(path, _flags):
        calls.append(path)
        raise OSError(errno.EPERM, "denied")
    monkeypatch.setattr(runner.os, "open", opened)
    request = {"gpu": {"positive": [], "negative": ["/dev/nvidia0", "/dev/nvidia1"]}}
    assert runner.device_probe(copy.deepcopy(request)) == [
        {"path": path, "errno": errno.EPERM, "expected": errno.EPERM} for path in calls]
    assert calls == request["gpu"]["negative"]
