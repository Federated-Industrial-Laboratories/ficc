# SPDX-License-Identifier: Apache-2.0
"""Exercise durable job admission, grants, partial results, and recovery."""

import asyncio
import copy
import time

import pytest
from conftest import node

from ficc.errors import Failure
from ficc.job_schema import JobRequest
from ficc.jobs import Jobs


def request(count=1):
    return {"action": "job.submit", "node_ids": [f"node-{index}" for index in range(count)],
            "job": {"label": "Bounded test", "argv": ["/usr/bin/printf", "%s", "hello"],
                    "cwd": "", "env": {}, "limits": {"cpu_percent": 100,
                    "memory_high_bytes": 201326592, "memory_max_bytes": 268435456,
                    "memory_swap_max_bytes": 0, "tasks_max": 32, "runtime_seconds": 300},
                    "allow_session_lifetime": True, "gpu_reservations": {}}}


@pytest.fixture(autouse=True)
def manual_poll(monkeypatch):
    async def stopped(self):
        await asyncio.Event().wait()
    monkeypatch.setattr(Jobs, "poll", stopped)


class Remote:
    def __init__(self):
        self.calls = []
        self.states = {}
        self.lose_ack = False

    async def job(self, node, body, check=None):
        if check:
            check()
        self.calls.append((node["id"], copy.deepcopy(body)))
        action = body["action"]
        if action == "job.capabilities":
            return {"jobs": True, "logout_persistent": False}
        job_id = body["job_id"]
        if action == "job.submit":
            self.states[job_id] = {"job_id": job_id, "state": "running", "result": None,
                                   "effective_limits": body["job"]["limits"], "session_lifetime": True,
                                   "reservations": [], "error": None}
            if self.lose_ack:
                raise Failure("unreachable", "Launch acknowledgement lost.", 502)
        if action == "job.cancel":
            self.states[job_id]["state"] = "cancelled"
        if action == "job.logs":
            return {"data_base64": "aGVsbG8=", "next_offset": 5, "total_bytes": 5,
                    "dropped_bytes": 0, "complete": False}
        return self.states.get(job_id, {"job_id": job_id, "state": "unknown", "result": None})


def prepare(console, monkeypatch, count=1):
    client, service = console
    remote = Remote()
    monkeypatch.setattr(service.ssh, "job", remote.job)
    for index in range(count):
        service.store.save_node(node(index))
    actor = client.get("/api/v1/session").json()["principal"]["id"]
    return client, service, remote, actor


def submit(client, body=None, key="first-submission-key"):
    preview = client.post("/api/v1/operation-previews", json=body or request())
    assert preview.status_code == 200, preview.text
    result = client.post("/api/v1/operations", json={"preview_id": preview.json()["preview_id"]},
                         headers={"Idempotency-Key": key})
    assert result.status_code == 202, result.text
    return result.json(), preview.json()


@pytest.mark.parametrize("count", [1, 64])
def test_durable_batch_partial_results_and_scoped_reads(console, monkeypatch, count):
    client, service, remote, actor = prepare(console, monkeypatch, count)
    operation, _ = submit(client, request(count))
    assert len(operation["targets"]) == count
    assert all(item["state"] == "queued" for item in operation["targets"])
    for target in operation["targets"]:
        asyncio.run(service.jobs.reconcile(operation["id"], target["node_id"]))
    assert sum(body["action"] == "job.submit" for _, body in remote.calls) == count
    target = operation["targets"][0]
    remote.states[target["job_id"]].update(state="succeeded", result={"exit_code": 0})
    asyncio.run(service.jobs.reconcile(operation["id"], target["node_id"]))
    operation = client.get("/api/v1/operations/" + operation["id"]).json()
    assert operation["targets"][0]["state"] == "succeeded"
    if count == 64:
        assert operation["targets"][1]["state"] == "running"
    token, _ = service.auth.issue("token", scopes=["jobs:read"], node_ids=["node-0"])
    view = client.get("/api/v1/operations", headers={"Authorization": "Bearer " + token}).json()
    assert len(view["operations"][0]["targets"]) == 1
    assert view["operations"][0]["request"]["node_ids"] == ["node-0"]
    assert "node" not in view["operations"][0]["targets"][0]


def test_idempotency_survives_preview_expiry_and_conflicts(console, monkeypatch):
    client, service, remote, actor = prepare(console, monkeypatch)
    operation, preview = submit(client)
    service.jobs.previews.clear()
    retry = client.post("/api/v1/operations", json={"preview_id": preview["preview_id"]},
                        headers={"Idempotency-Key": "first-submission-key"})
    assert retry.status_code == 202 and retry.json()["id"] == operation["id"]
    conflict = client.post("/api/v1/operations", json={"preview_id": "f" * 32},
                           headers={"Idempotency-Key": "first-submission-key"})
    assert conflict.status_code == 409
    assert len(service.jobs.store.all()) == 1


def test_revoked_queued_authority_blocks_dispatch(console, monkeypatch):
    client, service, remote, actor = prepare(console, monkeypatch)
    operation, _ = submit(client)
    service.auth.revoke(actor)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    assert service.jobs.store.get(operation["id"])["targets"][0]["state"] == "failed"
    assert not any(body["action"] == "job.submit" for _, body in remote.calls)


def test_revoke_during_ssh_preparation_blocks_dispatch(console, monkeypatch):
    client, service, remote, actor = prepare(console, monkeypatch)
    operation, _ = submit(client)
    called = False

    async def revoke_before_dispatch(node, body, check=None):
        nonlocal called
        service.auth.revoke(actor)
        check()
        called = True
    monkeypatch.setattr(service.ssh, "job", revoke_before_dispatch)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    assert not called
    assert service.jobs.store.get(operation["id"])["targets"][0]["state"] == "failed"


def test_lost_ack_restart_queries_without_resubmission(console, monkeypatch):
    client, service, remote, actor = prepare(console, monkeypatch)
    operation, _ = submit(client)
    remote.lose_ack = True
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    assert service.jobs.store.get(operation["id"])["targets"][0]["state"] == "unknown"
    controller = service.jobs.controller
    service.jobs = Jobs(service)
    assert service.jobs.controller == controller
    service.auth.revoke(actor)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    assert service.jobs.store.get(operation["id"])["targets"][0]["state"] == "running"
    assert sum(body["action"] == "job.submit" for _, body in remote.calls) == 1


def test_cancel_and_logs_require_separate_grants(console, monkeypatch):
    client, service, remote, actor = prepare(console, monkeypatch)
    operation, _ = submit(client)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    url = "/api/v1/operations/" + operation["id"]
    token, _ = service.auth.issue("token", scopes=["jobs:read"], node_ids=["node-0"])
    headers = {"Authorization": "Bearer " + token}
    assert client.get(url + "/logs/node-0", headers=headers).status_code == 403
    assert client.post(url + "/cancel", json={"node_ids": ["node-0"], "force": False}, headers=headers).status_code == 403
    assert client.get(url + "/logs/node-0?limit=65537").status_code == 422
    assert client.get(url + "/logs/node-0").json()["data_base64"] == "aGVsbG8="
    assert client.post(url + "/cancel", json={"node_ids": ["node-0"], "force": False}).status_code == 202
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    assert service.jobs.store.get(operation["id"])["targets"][0]["state"] == "cancelled"


def test_queued_cancel_never_launches_and_unknown_blocks_forget(console, monkeypatch):
    client, service, remote, actor = prepare(console, monkeypatch)
    operation, _ = submit(client)
    assert client.delete("/api/v1/nodes/node-0").status_code == 409
    asyncio.run(service.jobs.cancel(operation["id"], ["node-0"], False, actor))
    assert service.jobs.store.get(operation["id"])["targets"][0]["state"] == "cancelled"
    assert not any(body["action"] == "job.submit" for _, body in remote.calls)


def test_session_lifetime_and_preview_binding(console, monkeypatch):
    client, service, remote, actor = prepare(console, monkeypatch)
    body = request()
    body["job"]["allow_session_lifetime"] = False
    preview = client.post("/api/v1/operation-previews", json=body).json()
    assert not preview["targets"][0]["ready"]
    result = client.post("/api/v1/operations", json={"preview_id": preview["preview_id"]},
                         headers={"Idempotency-Key": "rejected-request-key"})
    assert result.status_code == 409
    preview = client.post("/api/v1/operation-previews", json=request()).json()
    token, _ = service.auth.issue("token")
    result = client.post("/api/v1/operations", json={"preview_id": preview["preview_id"]},
                         headers={"Idempotency-Key": "another-actor-key", "Authorization": "Bearer " + token})
    assert result.status_code == 409
    service.jobs.previews[preview["preview_id"]]["expires_at"] = time.time() - 1
    assert client.post("/api/v1/operations", json={"preview_id": preview["preview_id"]},
                       headers={"Idempotency-Key": "expired-request-key"}).status_code == 409


@pytest.mark.parametrize("change", [
    lambda body: body["node_ids"].append("node-0"),
    lambda body: body["job"]["argv"].append("\0"),
    lambda body: body["job"]["env"].update(CUDA_VISIBLE_DEVICES="0"),
    lambda body: body["job"]["limits"].update(cpu_percent=0),
    lambda body: body["job"]["limits"].update(tasks_max=True),
    lambda body: body["job"].update(cwd="relative"),
    lambda body: body["job"].update(argv=["x" * 4096] * 128),
])
def test_job_bounds(change):
    body = request()
    change(body)
    with pytest.raises(ValueError):
        JobRequest.model_validate(body)


def test_revoked_cancel_grant_prevents_remote_signal(console, monkeypatch):
    client, service, remote, actor = prepare(console, monkeypatch)
    operation, _ = submit(client)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    token, grant = service.auth.issue("token", scopes=["jobs:cancel"], node_ids=["node-0"])
    asyncio.run(service.jobs.cancel(operation["id"], ["node-0"], False, grant.id))
    service.auth.revoke(grant.id)
    asyncio.run(service.jobs.reconcile(operation["id"], "node-0"))
    assert not any(body["action"] == "job.cancel" for _, body in remote.calls)
    assert service.jobs.store.get(operation["id"])["targets"][0]["state"] == "unknown"


def test_helper_upgrade_keeps_node_id_and_checks_consent(console, monkeypatch):
    from conftest import sample

    client, service, remote, actor = prepare(console, monkeypatch)
    installed = []

    async def install(node, check=None):
        check()
        installed.append(node["id"])

    async def probe(node, check=None):
        if check:
            check()
        value = sample()
        value.update(helper_version="2", capabilities={"resources": True, "jobs": True, "logout_persistent": False})
        return value
    monkeypatch.setattr(service.ssh, "install", install)
    monkeypatch.setattr(service.ssh, "probe", probe)
    path = "/api/v1/nodes/node-0/helper-upgrade"
    assert client.post(path, json={"expected_fingerprint": "SHA256:incorrect-fingerprint"}).status_code == 409
    result = client.post(path, json={"expected_fingerprint": "SHA256:synthetic-key"})
    assert result.status_code == 200
    assert result.json()["id"] == "node-0" and result.json()["capabilities"]["jobs"]
    assert installed == ["node-0"]
    assert any(event["action"] == "helper.upgrade" and event["outcome"] == "requested" for event in service.store.events())


def test_separate_job_credential_has_bounded_lifetime_and_audit(tmp_path):
    from fastapi.testclient import TestClient

    from ficc.api import create_app
    from ficc.cli import local_request
    from ficc.settings import Settings

    app = create_app(Settings(state_dir=tmp_path / "state", demo=True))
    with TestClient(app, base_url="http://127.0.0.1:8170"):
        value = local_request(tmp_path / "state", {"action": "job-credential"})
        assert 3590 <= value["expires_at"] - time.time() <= 3600
        assert "jobs:execute" in app.state.service.auth.current(value["id"]).scopes
        assert any(item["action"] == "credential.create" and item["target"] == value["id"] for item in app.state.service.store.events())


def test_upgrade_serializes_old_observation_and_returns_fresh_capabilities(console, monkeypatch):
    from conftest import sample

    client, service, remote, actor = prepare(console, monkeypatch)

    async def scenario():
        started, release = asyncio.Event(), asyncio.Event()
        probes, installed = [], []

        async def probe(node, check=None):
            check() if check else None
            probes.append(node["id"])
            value = sample()
            if len(probes) == 1:
                started.set()
                await release.wait()
            else:
                value.update(helper_version="2", capabilities={"jobs": True, "logout_persistent": False})
            return value

        async def install(node, check=None):
            check()
            installed.append(node["id"])

        monkeypatch.setattr(service.ssh, "probe", probe)
        monkeypatch.setattr(service.ssh, "install", install)
        old = asyncio.create_task(service.refresh(["node-0"]))
        await started.wait()
        upgrade = asyncio.create_task(service.upgrade("node-0", "SHA256:synthetic-key", actor))
        await asyncio.sleep(0)
        assert installed == []
        release.set()
        await old
        result = await upgrade
        assert result["capabilities"]["jobs"]
        assert service.store.node("node-0")["helper_version"] == "2"
        assert installed == ["node-0"] and len(probes) == 2
    asyncio.run(scenario())


def test_schema_one_migrates_without_losing_settings(tmp_path):
    import sqlite3

    from ficc.store import Store

    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    path = directory / "state.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
                        "INSERT INTO settings VALUES ('preserved', 'true'); PRAGMA user_version=1;")
    path.chmod(0o600)
    store = Store(path)
    assert store.get_setting("preserved", False) is True
    version = store.db.execute("PRAGMA user_version").fetchone()[0]
    assert version == 2
    store.close()
    reopened = Store(path)
    assert reopened.get_setting("preserved", False) is True
    reopened.close()


def test_serialized_unicode_and_batch_envelopes_are_refused_before_intent(console, monkeypatch):
    client, service, remote, actor = prepare(console, monkeypatch)
    body = request()
    body["job"]["argv"] = ["/usr/bin/printf"] + ["\U0001f600" * 1000] * 8
    response = client.post("/api/v1/operation-previews", json=body)
    assert response.status_code == 422
    assert remote.calls == [] and service.jobs.store.all() == []
    body = request(64)
    body["job"]["gpu_reservations"] = {
        node: [{"uuid": "GPU-" + str(index), "memory_bytes": 1} for index in range(64)]
        for node in body["node_ids"]}
    with pytest.raises(ValueError, match="64 KiB"):
        JobRequest.model_validate(body)


def test_queued_output_uses_packaged_helper_and_controller_response_validation(console, monkeypatch, tmp_path):
    import base64
    import json
    import sys

    from ficc.process import run
    from ficc.ssh import SSH, archive

    client, service, remote, actor = prepare(console, monkeypatch)
    operation, _ = submit(client)
    assert operation["targets"][0]["state"] == "queued"
    home = tmp_path / "remote-home"
    home.mkdir(mode=0o700)
    helper = tmp_path / "node.pyz"
    helper.write_bytes(archive())
    wrapper = "import os,runpy,sys;os.environ['HOME']=sys.argv[1];sys.argv=sys.argv[2:];runpy.run_path(sys.argv[0],run_name='__main__')"

    async def command(node, fixed_command, payload, check=None):
        if check:
            check()
        return await run([sys.executable, "-c", wrapper, str(home), str(helper)], payload)

    monkeypatch.setattr(service.ssh, "command", command)
    monkeypatch.setattr(service.ssh, "job", SSH.job.__get__(service.ssh, SSH))
    path = f'/api/v1/operations/{operation["id"]}/logs/node-0'
    first = client.get(path + "?stream=stdout&offset=0&limit=32")
    assert first.status_code == 200, first.text
    assert first.json() == {"data_base64": "", "next_offset": 0, "total_bytes": 0,
                            "dropped_bytes": None, "complete": False}
    stderr = client.get(path + "?stream=stderr&offset=7&limit=32")
    assert stderr.status_code == 200 and stderr.json()["next_offset"] == 7
    job = home / ".local/state/ficc/jobs" / operation["targets"][0]["job_id"]
    assert not job.exists()
    job.mkdir(mode=0o700)
    for name, value in (("request.json", {"controller_id": service.jobs.controller}),
                        ("result.json", {"state": "succeeded", "result": {"dropped_bytes": 0}})):
        file = job / name
        file.write_text(json.dumps(value))
        file.chmod(0o600)
    output = job / "stdout"
    output.write_bytes(b"ready after dispatch\n")
    output.chmod(0o600)
    later = client.get(path + "?stream=stdout&offset=0&limit=32")
    assert later.status_code == 200, later.text
    assert base64.b64decode(later.json()["data_base64"]) == output.read_bytes()
    assert later.json()["complete"] and later.json()["dropped_bytes"] == 0
