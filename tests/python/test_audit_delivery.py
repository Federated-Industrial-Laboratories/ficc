# SPDX-License-Identifier: Apache-2.0
"""Exercise real TLS audit custody, uncertain acknowledgements and asynchronous admission."""

import asyncio
import hashlib
import json
import secrets
import subprocess
import threading
from types import SimpleNamespace

import pytest
from ficc_audit_https.collector import Journal, server

from ficc import audit_state
from ficc.audit_cli import configure
from ficc.audit_delivery import Delivery
from ficc.audit_sdk import AuditError, encoded
from ficc.errors import Failure
from ficc.secret_cli import initialize
from ficc.secrets import Secrets
from ficc.store import Store


@pytest.fixture
def destination(tmp_path):
    private = tmp_path / "custody"
    private.mkdir(mode=0o700)
    cert, key = private / "cert.pem", private / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", str(key), "-out", str(cert)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    key.chmod(0o600)
    token = secrets.token_urlsafe(32).encode()
    journal = Journal(private / "records")
    collector = server(("127.0.0.1", 0), journal, token, cert, key)
    thread = threading.Thread(target=collector.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"url": f"https://localhost:{collector.server_port}/v1/audit/append", "ca_pem": cert.read_text()}, token, journal
    finally:
        collector.shutdown()
        collector.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
        journal.close()


@pytest.fixture
def delivery(tmp_path, destination):
    config, token, journal = destination
    state = tmp_path / "controller"
    initialize(state, tmp_path / "controller.key")
    Secrets(state).put("audit-append", token)
    store = Store(state / "state.sqlite3")
    service = SimpleNamespace(store=store, settings=SimpleNamespace(state_dir=state))
    configure(state, encoded({"provider": "https", "configuration": config, "secret_reference": "audit-append",
                              "required": True, "max_lag_events": 2}), store)
    host = Delivery(service)
    actor = SimpleNamespace(id="credential-id", subject_id="subject-id", project_id="project-id")
    try:
        yield host, service, actor, journal
    finally:
        assert host.task is None, "Close the owned audit worker before the shared state database."
        store.close()


async def test_tls_append_ack_loss_restart_exact_replay_and_metadata_redaction(delivery, destination, monkeypatch):
    host, service, _actor, journal = delivery
    marker = "private-query-and-password"
    service.store.audit("source.write", marker, outcome=marker, actor=marker)
    original = journal.append

    def lost(raw):
        result = original(raw)
        result["durable"] = False
        return result

    monkeypatch.setattr(journal, "append", lost)
    with pytest.raises(AuditError, match="exact batch"):
        await host.step()
    pending = (service.settings.state_dir / audit_state.PRIVATE / audit_state.CHECKPOINT).read_bytes()
    assert marker.encode() not in pending and destination[1] not in pending
    assert host.state.value["cursor"] == 0
    assert journal.db.execute("SELECT count(*) FROM batches").fetchone()[0] == 1
    restarted = Delivery(service)
    monkeypatch.setattr(journal, "append", original)
    await restarted.step()
    assert restarted.status()["delivered_through"] == 1
    assert journal.db.execute("SELECT count(*) FROM batches").fetchone()[0] == 1
    raw = bytes(journal.db.execute("SELECT body FROM batches").fetchone()[0])
    assert marker.encode() not in raw and destination[1] not in raw
    changed = json.loads(raw)
    changed["events"][0]["action"] = "conflict"
    with pytest.raises(AuditError):
        await restarted.driver.append(encoded(changed), destination[1])
    assert journal.db.execute("SELECT count(*) FROM batches").fetchone()[0] == 1
    assert hashlib.sha256(raw).hexdigest() == journal.db.execute("SELECT digest FROM batches").fetchone()[0]


async def test_gap_backpressure_missing_secret_and_restore_enforcement(delivery):
    host, service, actor, _journal = delivery
    for index in range(4):
        service.store.audit("fixture.audit", str(index))
    with service.store.lock, service.store.db:
        service.store.db.execute("DELETE FROM audit WHERE id<4")
    await host.step()
    assert host.status()["retention_gap_events"] == 3
    assert host.status()["delivered_through"] == 4
    host.lag = 3
    with pytest.raises(Failure) as refused:
        await host.require("workload.submit", "request-id", actor)
    assert refused.value.code == "audit_backpressure"
    host.lag = 0
    vault = Secrets(service.settings.state_dir)
    vault.delete("audit-append", vault.status("audit-append")["revision"])
    try:
        with pytest.raises(Failure) as refused:
            await host.require("source.write", "run-id", actor)
        assert refused.value.code == "audit_unavailable"
        assert host.status()["pending_batch"]
    finally:
        await host.close()
    # The backup-retained policy marker prevents missing destination custody
    # from silently disabling required audit enforcement on isolated restore.
    private = service.settings.state_dir / audit_state.PRIVATE
    private.rename(service.settings.state_dir / "separate-audit-custody")
    restored = Delivery(service)
    assert restored.required and restored.status()["state"] == "unavailable"
    with pytest.raises(Failure):
        await restored.require("workload.submit", "request-id", actor)


async def test_delayed_checkpoint_does_not_block_loop_and_cancel_owns_io(delivery, monkeypatch):
    host, _service, actor, journal = delivery
    entered, release = threading.Event(), threading.Event()
    original = host.state.save

    def delayed(value):
        entered.set()
        assert release.wait(5)
        original(value)

    monkeypatch.setattr(host.state, "save", delayed)
    waiting = asyncio.create_task(host.require("workload.submit", "request-id", actor))
    closing = None
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        assert not waiting.done()
        # Independent maintenance keeps making progress while fsync is blocked.
        ticks = 0
        for _ in range(10):
            await asyncio.sleep(0)
            ticks += 1
        assert ticks == 10
        waiting.cancel()
        await asyncio.gather(waiting, return_exceptions=True)
        closing = asyncio.create_task(host.close())
        await asyncio.sleep(0)
        assert not closing.done()
        assert journal.db.execute("SELECT count(*) FROM batches").fetchone()[0] == 0
    finally:
        release.set()
        if closing is not None:
            await closing
        else:
            await host.close()
    assert host.task is None


async def test_required_intent_ack_precedes_return_and_pending_queue_is_bounded(delivery, monkeypatch):
    host, _service, actor, journal = delivery
    entered, release = asyncio.Event(), asyncio.Event()
    original = host.driver.append

    async def delayed(raw, credential):
        entered.set()
        await release.wait()
        return await original(raw, credential)

    monkeypatch.setattr(host.driver, "append", delayed)
    waiting = asyncio.create_task(host.require("workload.submit", "request-id", actor))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        assert not waiting.done()
        others = [asyncio.create_task(host.require("source.write", str(index), actor)) for index in range(15)]
        await asyncio.sleep(0)
        with pytest.raises(Failure) as refused:
            await host.require("source.write", "overflow", actor)
        assert refused.value.code == "audit_backpressure"
        for task in others:
            task.cancel()
        await asyncio.gather(*others, return_exceptions=True)
        release.set()
        await waiting
        rows = [json.loads(row[0]) for row in journal.db.execute("SELECT body FROM batches")]
        assert any(event["kind"] == "intent" and event["action"] == "workload.submit" for row in rows for event in row["events"])
        assert not host.state.value["pending"]
    finally:
        release.set()
        await host.close()


@pytest.mark.parametrize("provider", ["postgresql", "s3"])
async def test_source_write_rechecks_secret_after_delayed_audit_ack(delivery, destination, monkeypatch, provider):
    from urllib.parse import urlsplit

    from ficc import source_runtime
    from ficc.auth import Auth
    from ficc.sources import Sources

    host, service, _actor, _journal = delivery
    service.auth = Auth(service.store)
    service.live = lambda: None
    service.audit_delivery = host
    _, actor = service.auth.issue("token")
    vault = Secrets(service.settings.state_dir)
    credential = ({"username": "fixture", "password": "before"} if provider == "postgresql" else
                  {"access_key_id": "fixture", "secret_access_key": "before"})
    vault.put("reader", encoded(credential))
    approved = vault.put("writer", encoded(credential))["revision"]
    sources = Sources(service)
    connection = await sources.create({"name": "Audit credential fixture", "provider": provider,
        "configuration": {"database": "fixture"} if provider == "postgresql" else {"bucket": "audit-fixture", "prefix": "fixture/"},
        "endpoint": {"host": "localhost", "port": urlsplit(destination[0]["url"]).port, "addresses": ["127.0.0.1"],
                     "fixed_address": "127.0.0.1", "private_network": True, "ca_pem": destination[0]["ca_pem"]},
        "read_secret": "reader", "write_secret": "writer", "permissions": ["read", "write"]},
        "source-create-audit", actor.id)
    entered, release = asyncio.Event(), asyncio.Event()
    original = host.driver.append
    dispatched = []

    async def delayed(raw, credential):
        if any(event["kind"] == "intent" for event in json.loads(raw)["events"]):
            entered.set()
            await release.wait()
        return await original(raw, credential)

    async def execute(packet, _limits, _check, _receive):
        dispatched.append(packet["action"])
        raise AssertionError("A changed credential must be refused before worker dispatch.")

    monkeypatch.setattr(host.driver, "append", delayed)
    monkeypatch.setattr(source_runtime, "execute", execute)
    try:
        if provider == "postgresql":
            query = sources.register(connection["id"], {"name": "Bound write", "mode": "write", "specification": {
                "statement": "UPDATE readings SET value = %(value)s"}, "parameters": [{"name": "value", "type": "integer"}]},
                "source-query-audit", actor.id)
            run = await sources.submit(query["id"], {"action": "write", "parameters": {"value": 1}}, "source-run-audit", actor.id)
        else:
            # The dataset has already been admitted; retain its immutable upload
            # identity while exercising the real connection/packet/secret path.
            upload = {**sources.owner(actor), "connection_id": connection["id"], "dataset_id": "d" * 32,
                "manifest_digest": "a" * 64, "file_index": 0, "key": "fixture/output", "size": 1, "sha256": "b" * 64,
                "state": "creating", "provider_upload_id": None, "part_bytes": None, "parts": None, "last_run_id": None}
            sources.store.insert("source_uploads", upload, "source-upload-audit", "c" * 64)
            monkeypatch.setattr(sources.uploads, "source", lambda _upload, _actor: {})
            run = await sources.uploads.admit(upload, {"operation": "begin"}, "source-run-audit", actor.id)
        task = sources.tasks[run["id"]]
        await asyncio.wait_for(entered.wait(), 5)
        assert sources.status(run["id"], actor.id)["state"] == "queued" and not dispatched
        changed = {key: "after" if key in {"password", "secret_access_key"} else value for key, value in credential.items()}
        vault.put("writer", encoded(changed), approved)
        current = sources.connection(connection["id"], actor.id, "write")
        assert current["revision"] == connection["revision"] and current["write_secret_revision"] == approved
        release.set()
        await asyncio.wait_for(task, 5)
        result = sources.status(run["id"], actor.id)
        assert result["state"] == "failed" and result["error"]["code"] == "secret_changed", result
        assert not dispatched
        if provider == "s3":
            assert sources.uploads.get(upload["id"], actor.id)["state"] == "aborted"
    finally:
        release.set()
        await sources.close()
        await host.close()


async def test_workload_admission_waits_without_blocking_cancel_and_rechecks_authority(policy_console, destination, tmp_path, monkeypatch):
    from policy_fixtures import activate, install_pack
    from test_execution_ledger import plan
    from workload_fixtures import contributor
    from workload_queue_fixtures import scheduler

    from ficc.workloads.schema import Submission

    client, service, material = policy_console
    activate(client, install_pack(client, material))
    actor = service.auth.resolve(client.cookies.get("ficc_session"))
    queue = service.workloads
    node = contributor(service, actor.project_id)
    scheduler(queue)
    request = Submission(job=plan(0).job, node_ids=[node["id"]])
    existing = await queue.submit(request, secrets.token_hex(16), actor)
    initialize(service.settings.state_dir, tmp_path / "audit.key")
    Secrets(service.settings.state_dir).put("audit-append", destination[1])
    configure(service.settings.state_dir, encoded({"provider": "https", "configuration": destination[0],
        "secret_reference": "audit-append", "required": True, "max_lag_events": 10000}), service.store)
    service.audit_delivery = host = Delivery(service)
    entered, release = asyncio.Event(), asyncio.Event()
    original = host.driver.append

    async def wait_for_ack(raw, credential):
        entered.set()
        await release.wait()
        return await original(raw, credential)

    monkeypatch.setattr(host.driver, "append", wait_for_ack)
    waiting = asyncio.create_task(queue.submit(request, secrets.token_hex(16), actor))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        assert len(queue.records.jobs()) == 1 and not waiting.done()
        # Audit waiting holds no Store lock, and cleanup needs no destination ack.
        stopped = queue.cancel(existing["id"], existing["revision"], actor)
        assert stopped["state"] == "cancelled"
        service.auth.revoke(actor.id)
        release.set()
        with pytest.raises(Failure):
            await waiting
        assert len(queue.records.jobs()) == 1
        _, resumed = service.auth.issue("token")
        retried = await queue.retry(stopped["id"], stopped["revision"], resumed)
        assert retried["state"] == "queued"
        events = [event for row, in destination[2].db.execute("SELECT body FROM batches")
                  for event in json.loads(row)["events"]]
        assert any(event.get("action") == "workload.retry" and event["kind"] == "intent" for event in events)
    finally:
        release.set()
        await host.close()


def test_metadata_backup_excludes_checkpoint_and_preserves_required_mode(delivery, tmp_path):
    from ficc.backup import export, restore

    _host, service, _actor, _journal = delivery
    service.store.set_setting("controller_id", "c" * 32)
    service.store.close()
    bundle, restored = tmp_path / "backup", tmp_path / "restored"
    export(service.settings.state_dir, bundle)
    assert not (bundle / audit_state.PRIVATE).exists()
    restore(bundle, restored, True)
    recovered = Store(restored / "state.sqlite3")
    try:
        assert recovered.get_setting(audit_state.REQUIRED, False) is True
        host = Delivery(SimpleNamespace(store=recovered, settings=SimpleNamespace(state_dir=restored)))
        assert host.status()["required"] and host.status()["state"] == "unavailable"
    finally:
        recovered.close()


async def test_explicit_best_effort_stays_optional_when_provider_is_missing(delivery, monkeypatch):
    from ficc import audit_delivery
    from ficc.audit_cli import mode

    _host, service, actor, _journal = delivery
    mode(service.settings.state_dir, False, service.store)

    def missing(_name):
        raise AuditError("audit_provider")

    monkeypatch.setattr(audit_delivery, "load", missing)
    optional = Delivery(service)
    assert optional.status()["state"] == "unavailable" and not optional.required
    await optional.require("workload.submit", "request-id", actor)
    mode(service.settings.state_dir, True, service.store)
    required = Delivery(service)
    with pytest.raises(Failure):
        await required.require("workload.submit", "request-id", actor)
