# SPDX-License-Identifier: Apache-2.0
"""Exercise FICC pairing, exact grants, replay and verified model ranges on duplex sockets."""
import asyncio
import hashlib
import secrets
import socket
import threading
from types import SimpleNamespace

import pytest

from ficc.errors import Failure
from ficc.federation import artifacts, pairing
from ficc.federation.schema import Approval, GrantSpec
from ficc.federation.transport import Channel, HyperNet
from ficc.models.cache import WRITE_CHUNK
from ficc.models.schema import Manifest
from ficc.service import Service
from ficc.settings import Settings


class Streams:
    """Only substitute HyperNet's separately qualified verified-peer handoff."""
    def __init__(self, source, destination):
        self.source, self.destination = source, destination
        self.principal = source.cluster()["principal"]

    async def connect(self, target):
        assert target == self.destination.cluster()["service"]
        left, right = socket.socketpair()
        cluster = self.destination.cluster()
        common = {"network": cluster["network"], "incarnation": cluster["incarnation"],
                  "service": target, "protocol": "ficc.federation/1",
                  "session": secrets.token_hex(32), "generation": 1}
        outgoing = await Channel.wrap(SimpleNamespace(socket=left, peer=common, close=left.close))
        incoming = await Channel.wrap(SimpleNamespace(socket=right, peer={**common, "principal": self.principal}, close=right.close))
        task = asyncio.create_task(self.destination.serve(incoming))
        self.destination.connections.add(task)
        task.add_done_callback(self.destination.connections.discard)
        return outgoing


async def test_hypernet_connection_failure_preserves_bounded_sdk_diagnostic():
    message = "Authority session closed\nwhile preparing stream " + "x" * 1000
    def refused(*args, **kwargs):
        raise RuntimeError(message)
    transport = object.__new__(HyperNet)
    transport.agent = SimpleNamespace(connect=refused)
    with pytest.raises(Failure, match="Authority session closed while preparing stream") as caught:
        await transport.connect("33" * 32)
    assert caught.value.code == "hypernet_connect"
    assert str(caught.value).endswith(" ".join(message.split())[:512])
    assert "\n" not in str(caught.value)


@pytest.fixture
async def pair(tmp_path):
    services = [Service(Settings(state_dir=tmp_path/name, control=False)) for name in ("a", "b")]
    managers = [s.federation for s in services]
    actors = [s.auth.issue("token")[1] for s in services]
    for index, manager in enumerate(managers):
        manager.service.store.set_setting("federation.configuration", {
            "agent_directory": str(tmp_path / "unused"), "cluster": {
                "key": manager.key.public_key().public_bytes_raw().hex(), "label": str(index),
                "network": "11"*32, "incarnation": "22"*32,
                "service": ("33" if index == 0 else "44")*32,
                "principal": ("55" if index == 0 else "66")*32}})
    managers[0]._transport = Streams(managers[0], managers[1])
    managers[1]._transport = Streams(managers[1], managers[0])
    try:
        yield managers, actors
    finally:
        for manager in managers:
            await manager.close()
        for service in services:
            service.close()


def manifest(data):
    return Manifest(name="Range model", revision="immutable-1", format="gguf", licence="Apache-2.0",
        entrypoint="model.gguf", files=[{"name": "model.gguf", "digest": "sha256:"+hashlib.sha256(data).hexdigest(), "bytes": len(data)}])


async def approved(managers, actors, spec):
    a, b = managers
    offer = await pairing.start(a, b.cluster()["service"], spec.scopes, actors[0])
    accepted = pairing.approve(b, offer["id"], Approval(revision=1, grant=spec), actors[1])
    peer = await pairing.finish(a, offer["id"], actors[0])
    return peer, b.grants.get(accepted["receipt"]["payload"]["grant"]), offer


async def test_pairing_proves_keys_and_denies_wrong_hypernet_principal(pair):
    managers, actors = pair
    a, b = managers
    peer, grant, offer = await approved(managers, actors, GrantSpec())
    assert peer["state"] == "paired"
    value, _ = await a.client.request(peer["id"], "discover", {}, actors[0])
    assert value["services"] == []
    a._transport.principal = "77"*32
    with pytest.raises(Failure, match="do not match"):
        await a.client.request(peer["id"], "discover", {}, actors[0])
    a._transport.principal = a.cluster()["principal"]
    await b.authority.revoke(grant["id"], actors[1])
    with pytest.raises(Failure, match="inactive"):
        await a.client.request(peer["id"], "discover", {}, actors[0])
    await b.remove(grant["peer"], actors[1])
    with pytest.raises(Failure, match="removed"):
        await pairing.finish(a, offer["id"], actors[0])


async def test_model_transfer_resumes_and_publishes_only_digest_verified_bytes(pair):
    managers, actors = pair
    a, b = managers
    data = b"one immutable model range\n" * 50000
    model = manifest(data)
    remote = b.service.models.create(model.model_dump(), actors[1])
    cache = b.service.models.cache_for(remote)
    for offset in range(0, len(data), 1024*1024):
        cache.write(model.files[0], offset, data[offset:offset+1024*1024])
    peer, grant, _ = await approved(managers, actors, GrantSpec(scopes=["models:read", "models:transfer"],
        models=[remote["id"]], transfer_bytes=len(data)*2))
    with pytest.raises(Failure, match="not published"):
        await a.client.request(peer["id"], "models.manifest", {"model": "99"*16}, actors[0])
    local = a.service.models.create(model.model_dump(), actors[0])
    a.service.models.cache_for(local).write(model.files[0], 0, data[:12345])
    state = {}
    await artifacts.acquire(a, peer["id"], remote["id"], actors[0], state)
    assert state["state"] == "complete", state
    assert a.service.models.view(a.service.models.get(local["id"], actors[0]))["ready"]
    assert b.grants.get(grant["id"])["used_bytes"] == len(data)-12345
    assert hashlib.sha256(a.service.models.cache_for(local).path(model.files[0]).read_bytes()).hexdigest() == hashlib.sha256(data).hexdigest()


async def test_federated_acquisition_finalizes_full_partial_without_empty_range(pair):
    managers, actors = pair
    a, b = managers
    data = b"durable federated bytes"
    model = manifest(data)
    remote = b.service.models.create(model.model_dump(), actors[1])
    b.service.models.cache_for(remote).write(model.files[0], 0, data)
    peer, grant, _ = await approved(managers, actors, GrantSpec(scopes=["models:read", "models:transfer"],
        models=[remote["id"]], transfer_bytes=len(data)))
    local = a.service.models.create(model.model_dump(), actors[0])
    a.service.models.cache_for(local).path(model.files[0], True).write_bytes(data)
    state = {}
    await artifacts.acquire(a, peer["id"], remote["id"], actors[0], state)
    assert state["state"] == "complete", state
    assert a.service.models.view(local)["ready"]
    assert b.grants.get(grant["id"])["used_bytes"] == 0


async def test_model_transfer_pause_waits_for_durable_write_before_resume(pair, monkeypatch):
    managers, actors = pair
    a, b = managers
    data = b"x" * (WRITE_CHUNK + 65536)
    model = manifest(data)
    remote = b.service.models.create(model.model_dump(), actors[1])
    source = b.service.models.cache_for(remote)
    for offset in range(0, len(data), WRITE_CHUNK):
        source.write(model.files[0], offset, data[offset:offset + WRITE_CHUNK])
    peer, _, _ = await approved(managers, actors, GrantSpec(scopes=["models:read", "models:transfer"],
        models=[remote["id"]], transfer_bytes=len(data) * 2))
    local = a.service.models.create(model.model_dump(), actors[0])
    cache = a.service.models.cache_for(local)
    started, release = threading.Event(), threading.Event()
    write = cache.write

    def blocked(*arguments):
        started.set()
        assert release.wait(5), "The test must release the admitted write."
        return write(*arguments)

    monkeypatch.setattr(cache, "write", blocked)
    state = {}
    pending = asyncio.create_task(artifacts.acquire(a, peer["id"], remote["id"], actors[0], state))
    try:
        assert await asyncio.to_thread(started.wait, 5)
        pending.cancel()
        await asyncio.sleep(0.01)
        assert not pending.done(), "Pause must retain ownership until the admitted write finishes."
    finally:
        release.set()
        await asyncio.gather(pending, return_exceptions=True)
    assert pending.cancelled() and state["state"] == "paused"
    assert state["offset"] == WRITE_CHUNK
    assert not cache.status(model.files[0])["complete"]
    monkeypatch.setattr(cache, "write", write)
    await artifacts.acquire(a, peer["id"], remote["id"], actors[0], state)
    assert state["state"] == "complete"
    assert cache.path(model.files[0]).read_bytes() == data


@pytest.mark.parametrize("recovery", ["resume", "revoke", "pause", "changed_manifest"])
async def test_transfer_connection_loss_rechecks_authority_and_resumes_durable_bytes(pair, monkeypatch, recovery):
    from ficc.federation.identity import digest
    from ficc.inference.stream import Stream
    managers, actors = pair
    a, b = managers
    data = b"x" * (WRITE_CHUNK + 65536)
    model = manifest(data)
    remote = b.service.models.create(model.model_dump(), actors[1])
    source = b.service.models.cache_for(remote)
    for offset in range(0, len(data), WRITE_CHUNK):
        source.write(model.files[0], offset, data[offset:offset + WRITE_CHUNK])
    peer, grant, _ = await approved(managers, actors, GrantSpec(scopes=["models:read", "models:transfer"],
        models=[remote["id"]], transfer_bytes=len(data) * 3))
    local = a.service.models.create(model.model_dump(), actors[0])
    cache = a.service.models.cache_for(local)
    request = a.client.request
    offsets = []
    async def interrupted(peer_id, operation, body, actor, request_id=None):
        result, stream = await request(peer_id, operation, body, actor, request_id)
        if operation == "models.manifest" and offsets and recovery == "changed_manifest":
            changed = {**result["manifest"], "revision": "changed-during-reconnect"}
            return {"manifest": changed, "manifest_digest": digest(changed)}, stream
        if operation != "models.range":
            return result, stream
        offsets.append(body["offset"])
        if len(offsets) > 1:
            return result, stream
        async def chunks():
            received = 0
            async for chunk in stream:
                received += len(chunk)
                yield chunk
                if received >= WRITE_CHUNK:
                    raise ConnectionResetError("The admitted transport closed.")
        return result, Stream(chunks(), stream.aclose)
    monkeypatch.setattr(a.client, "request", interrupted)
    state = {}
    pending = asyncio.create_task(artifacts.acquire(a, peer["id"], remote["id"], actors[0], state))
    async def reconnecting():
        while state.get("state") != "reconnecting":
            assert not pending.done(), state
            await asyncio.sleep(0)
    try:
        await asyncio.wait_for(reconnecting(), 5)
        assert cache.status(model.files[0]) == {"offset": WRITE_CHUNK, "complete": False, "bytes": len(data)}
        if recovery == "revoke":
            await b.authority.revoke(grant["id"], actors[1])
        elif recovery == "pause":
            pending.cancel()
        await asyncio.wait_for(asyncio.gather(pending, return_exceptions=True), 5)
        if recovery == "resume":
            assert state["state"] == "complete" and offsets == [0, WRITE_CHUNK]
            assert cache.path(model.files[0]).read_bytes() == data
        else:
            assert state["state"] == ("paused" if recovery == "pause" else "interrupted")
            assert offsets == [0] and not cache.status(model.files[0])["complete"]
            if recovery == "changed_manifest":
                assert state["error"]["code"] == "federation_manifest_changed"
                assert len(a.service.models.records.all()) == 1
    finally:
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)


async def test_model_transfer_reconnect_allowance_is_finite(pair, monkeypatch):
    managers, actors = pair
    calls = []
    async def unavailable(*args, **kwargs):
        calls.append(args[1])
        raise Failure("hypernet_connect", "The companion is unavailable.", 503)
    monkeypatch.setattr(managers[0].client, "request", unavailable)
    state = {}
    await asyncio.wait_for(artifacts.acquire(managers[0], "11" * 16, "22" * 16, actors[0], state), 10)
    assert state["state"] == "interrupted" and state["retry"] == 3
    assert calls == ["models.manifest"] * 4


async def test_mutation_retry_returns_same_record_and_rejects_changed_arguments(pair):
    managers, actors = pair
    a, b = managers
    peer, _, _ = await approved(managers, actors, GrantSpec(scopes=["models:manage"]))
    request_id = secrets.token_hex(16)
    body = {"manifest": manifest(b"model").model_dump()}
    first, _ = await a.client.request(peer["id"], "models.create", body, actors[0], request_id)
    again, _ = await a.client.request(peer["id"], "models.create", body, actors[0], request_id)
    assert first["id"] == again["id"]
    assert len(b.service.models.records.all()) == 1
    changed = {"manifest": {**body["manifest"], "name": "Changed"}}
    with pytest.raises(Failure, match="different arguments"):
        await a.client.request(peer["id"], "models.create", changed, actors[0], request_id)
    removed, _ = await a.client.request(peer["id"], "models.remove", {"model": first["id"]}, actors[0], secrets.token_hex(16))
    assert removed["removed"]


async def test_model_registration_cannot_reveal_an_unpublished_revision(pair):
    managers, actors = pair
    a, b = managers
    body = {"manifest": manifest(b"private model").model_dump()}
    private = b.service.models.create(body["manifest"], actors[1])
    peer, _, _ = await approved(managers, actors, GrantSpec(scopes=["models:manage"]))
    with pytest.raises(Failure, match="not published"):
        await a.client.request(peer["id"], "models.create", body, actors[0], secrets.token_hex(16))
    assert b.service.models.get(private["id"], actors[1])["id"] == private["id"]


async def test_remote_recovery_requires_explicit_acknowledgement_and_new_operation(pair):
    import time

    from test_execution_ledger import offer
    from workload_fixtures import INSTALLATION, contributor, placement, result, submitted

    from ficc.inference.schema import Record, Specification

    managers, actors = pair
    a, b = managers
    owner = actors[1]
    model = b.service.models.create(manifest(b"model").model_dump(), owner)
    node = contributor(b.service, owner.project_id)
    queue = b.service.workloads
    job = submitted(b.service, owner, node)
    plan, lease = placement(job, node["id"])
    queue.records.reserve(plan, lease, INSTALLATION, offer(1).limits)
    queue.records.observation(result(plan, "unknown"), node["id"], INSTALLATION)
    queue.records.observation(result(plan, "released"), node["id"], INSTALLATION)
    spec = Specification(alias="recovery", model_id=model["id"], engine="llama_cpp", runtime=plan.job.runtime,
                         executable="/server", placements=[{"node_id": node["id"], "limits": plan.job.limits}])
    record = Record(id=secrets.token_hex(16), project_id=owner.project_id, subject_id=owner.subject_id, actor=owner.id,
                    spec=spec, generation=1, desired="stopped", state="stopped", reason=None, workloads=[job.id],
                    created_at=time.time(), revision=1).model_dump()
    b.service.inference.records.save(record)
    peer, _, _ = await approved(managers, actors, GrantSpec(scopes=["inference:manage"], services=[record["id"]]))
    body = {"service": record["id"], "revision": 1, "operation": "start"}
    operation = secrets.token_hex(16)
    with pytest.raises(Failure) as refused:
        await a.client.request(peer["id"], "inference.control", body, actors[0], operation)
    assert refused.value.code == "inference_unknown_outcome"
    for invalid in ("true", 1, None):
        with pytest.raises(Failure) as rejected:
            await a.client.request(peer["id"], "inference.control", {**body, "acknowledge_unknown": invalid},
                                   actors[0], secrets.token_hex(16))
        assert rejected.value.code == "federation_request"
    body["acknowledge_unknown"] = True
    with pytest.raises(Failure) as conflict:
        await a.client.request(peer["id"], "inference.control", body, actors[0], operation)
    assert conflict.value.code == "operation_conflict"
    operation = secrets.token_hex(16)
    started, _ = await a.client.request(peer["id"], "inference.control", body, actors[0], operation)
    repeated, _ = await a.client.request(peer["id"], "inference.control", body, actors[0], operation)
    assert repeated == started and started["generation"] == 2 and started["state"] == "pending"
    assert queue.records.get(job.id).state == "queued"
    assert queue.records.attempt(plan.attempt_id).state == "released"


async def test_pairing_removal_requires_fresh_receipt_and_grants_can_retire(pair):
    managers, actors = pair
    a, b = managers
    peer, grant, offer = await approved(managers, actors, GrantSpec())
    old_receipt = b.offers.get(offer["id"])["receipt"]
    await a.remove(peer["id"], actors[0])
    await b.remove(grant["peer"], actors[1])
    await b.retire(grant["id"], actors[1])
    fresh = await pairing.start(a, b.cluster()["service"], ["discover"], actors[0])
    accepted = pairing.approve(b, fresh["id"], Approval(revision=1, grant=GrantSpec(scopes=["discover"])), actors[1])
    from ficc.federation.identity import digest
    with pytest.raises(Failure, match="removed"):
        pairing.confirm(b, offer["id"], digest(old_receipt), a.cluster()["key"], {"principal": a.cluster()["principal"]})
    current = await pairing.finish(a, fresh["id"], actors[0])
    assert current["remote_grant"]["id"] == accepted["receipt"]["payload"]["grant"]
    value, _ = await a.client.request(current["id"], "discover", {}, actors[0])
    assert value["services"] == []
    refreshed = await a.refresh_grants(current["id"], actors[0])
    assert len(refreshed["grants"]) == 1
    await a.refresh_grants(current["id"], actors[0], refreshed["grants"][0]["id"])
    with pytest.raises(Failure, match="Revoke"):
        await b.retire(refreshed["grants"][0]["id"], actors[1])


@pytest.mark.parametrize("end", ["revoke", "remove"])
async def test_revocation_and_peer_removal_cancel_active_streams(pair, monkeypatch, end):
    from ficc.federation import operations
    managers, actors = pair
    a, b = managers
    peer, grant, _ = await approved(managers, actors, GrantSpec())
    closed = asyncio.Event()
    async def stream():
        try:
            yield b"started"
            await asyncio.Event().wait()
        finally:
            closed.set()
    async def dispatch(*_args):
        return {"stream": True, "status": 200}, stream()
    monkeypatch.setattr(operations, "dispatch", dispatch)
    _, chunks = await a.client.request(peer["id"], "inference.invoke", {}, actors[0])
    assert await asyncio.wait_for(anext(chunks), 2) == b"started"
    if end == "revoke":
        await b.authority.revoke(grant["id"], actors[1])
    else:
        await a.remove(peer["id"], actors[0])
    await asyncio.wait_for(closed.wait(), 2)
    await chunks.aclose()
    assert not a.outgoing[peer["id"]]


async def test_stop_on_revoke_covers_creation_before_receipt_and_needs_no_live_grant(pair):
    from ficc.inference.attached import Attached, Attachment, Profile
    managers, actors = pair
    _, b = managers
    _, grant, _ = await approved(managers, actors, GrantSpec(scopes=["inference:manage"], stop_on_revoke=True))
    profile = Profile(name="existing", projects=[actors[1].project_id], url="http://127.0.0.1:1/v1",
                      model="external-model", capabilities=["chat"])
    b.service.store.set_setting("inference.endpoint_profiles", [profile.model_dump()])
    b.service.inference.attached = Attached(b.service.inference)
    selected = b.service.inference.attached.available(actors[1])[0]
    spec = Attachment(alias="owned", engine="attached", profile=selected["name"], profile_digest=selected["digest"])
    delegated = b.service.auth.current(grant["credential"])
    owned = await b.service.inference.create(spec, delegated)
    other = await b.service.inference.create(spec.model_copy(update={"alias": "unrelated"}), actors[1])
    # Simulate a crash after durable service creation, before the federation
    # operation and created-service receipt can record the returned identity.
    assert grant["created_services"] == []
    b.service.auth.revoke(delegated.id)
    revoker = b.service.auth.issue("token", scopes=["federation:manage"])[1]
    await b.authority.revoke(grant["id"], revoker)
    assert b.service.inference.records.get(owned["id"])["desired"] == "stopped"
    assert b.service.inference.records.get(other["id"])["desired"] == "running"


async def test_owner_approves_an_incoming_offer_into_selected_project(pair):
    from ficc.federation.records import validate_records
    managers, actors = pair
    a, b = managers
    project = b.service.auth.identities.create("project", "Receiving project")
    owner = b.service.auth.issue("token", project_id=project["id"])[1]
    offer = await pairing.start(a, b.cluster()["service"], ["discover"], actors[0])
    accepted = pairing.approve(b, offer["id"], Approval(revision=1, grant=GrantSpec(scopes=["discover"])), owner)
    await pairing.finish(a, offer["id"], actors[0])
    assert not b.offers.all(actors[1].project_id)
    assert b.offers.all(project["id"])[0]["id"] == accepted["id"]
    validate_records(b.service.store.db)


async def test_close_before_first_response_byte_releases_channel(pair, monkeypatch):
    from ficc.federation import operations
    managers, actors = pair
    a, b = managers
    peer, _, _ = await approved(managers, actors, GrantSpec())
    closed = asyncio.Event()
    async def stream():
        try:
            await asyncio.Event().wait()
            yield b"unreachable"
        finally:
            closed.set()
    async def dispatch(*_args):
        return {"stream": True, "status": 200}, stream()
    monkeypatch.setattr(operations, "dispatch", dispatch)
    _, chunks = await a.client.request(peer["id"], "inference.invoke", {}, actors[0])
    await chunks.aclose()
    await asyncio.wait_for(closed.wait(), 2)
    assert not a.outgoing[peer["id"]]


async def test_http_disconnect_cancels_initial_remote_response():
    from ficc.federation.routes import connected
    closed = asyncio.Event()
    async def response():
        try:
            await asyncio.Event().wait()
        finally:
            closed.set()
    async def disconnected():
        return True
    with pytest.raises(Failure, match="disconnected"):
        await connected(SimpleNamespace(is_disconnected=disconnected), response())
    assert closed.is_set()


async def test_completed_http_response_stops_a_receive_that_suppresses_cancellation():
    from ficc.federation.routes import connected
    entered = asyncio.Event()
    cancelled = False
    polls = 0
    async def disconnected():
        nonlocal cancelled, polls
        polls += 1
        entered.set()
        if cancelled:
            await asyncio.sleep(1)
            return True
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled = True
        return False
    async def response():
        await entered.wait()
        return {"replicas": 1}, None
    assert await connected(SimpleNamespace(is_disconnected=disconnected), response()) == ({"replicas": 1}, None)
    assert cancelled
    assert polls == 1


@pytest.mark.parametrize("operation", ["refresh", "finish", "request"])
async def test_peer_removal_cannot_be_undone_by_an_inflight_reply(pair, monkeypatch, operation):
    managers, actors = pair
    a, _ = managers
    peer, _, offer = await approved(managers, actors, GrantSpec())
    received, release = asyncio.Event(), asyncio.Event()
    if operation == "request":
        original = a.client.submit
        async def delayed(*args, **kwargs):
            result = await original(*args, **kwargs)
            received.set()
            await release.wait()
            return result
        monkeypatch.setattr(a.client, "submit", delayed)
        pending = asyncio.create_task(a.client.request(peer["id"], "discover", {}, actors[0]))
    else:
        original = a.client.call_cluster
        async def delayed(cluster, name, body):
            result = await original(cluster, name, body)
            if name == ("peer.grants" if operation == "refresh" else "pair.confirm"):
                received.set()
                await release.wait()
            return result
        monkeypatch.setattr(a.client, "call_cluster", delayed)
        pending = asyncio.create_task(a.refresh_grants(peer["id"], actors[0], peer["remote_grant"]["id"]) if operation == "refresh"
                                      else pairing.finish(a, offer["id"], actors[0]))
    await asyncio.wait_for(received.wait(), 2)
    await a.remove(peer["id"], actors[0])
    release.set()
    with pytest.raises(Failure):
        await asyncio.wait_for(pending, 2)
    assert a.peers.get(peer["id"])["state"] == "removed"


def test_backup_suspends_binding_and_omits_cluster_private_key(tmp_path):
    from ficc.backup import export, restore
    from ficc.store import Store
    state = tmp_path / "original"
    service = Service(Settings(state_dir=state, control=False))
    private_key = (state / "federation/Identity.key").read_bytes()
    service.store.set_setting("federation.configuration", {"agent_directory": "/private/companion"})
    service.close()
    bundle = tmp_path / "backup"
    export(state, bundle)
    assert not (bundle / "federation").exists()
    restored = tmp_path / "restored"
    restore(bundle, restored, True)
    store = Store(restored / "state.sqlite3")
    try:
        assert store.db.execute("PRAGMA user_version").fetchone()[0] == 17
        assert store.get_setting("federation.configuration", None) is None
    finally:
        store.close()
    recovered = Service(Settings(state_dir=restored, control=False))
    try:
        assert (restored / "federation/Identity.key").read_bytes() != private_key
    finally:
        recovered.close()
