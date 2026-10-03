# SPDX-License-Identifier: Apache-2.0
"""Use real Unix peer credentials to reject local authority and protocol substitution."""

import asyncio
import os
import socket
import struct

import pytest
from test_execution_ledger import identity
from test_execution_local import setup

from ficc.execution import client as executor_client
from ficc.execution.client import Client, credentials, receive, send
from ficc.execution.protocol import MAX_MESSAGE, Snapshot, decode
from ficc.execution.service import Service
from ficc.execution.spec import encoded
from ficc.execution.wire import MAX_REPLY, REPLY


@pytest.mark.asyncio
async def test_unix_peer_credentials_are_kernel_supplied():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        pid, uid, gid = credentials(left)
        assert (pid, uid, gid) == (os.getpid(), os.getuid(), os.getgid())
        right.sendall(b'{"uid":0}')
        assert credentials(left) == (pid, uid, gid)
    finally:
        left.close()
        right.close()


@pytest.mark.asyncio
async def test_real_unprivileged_socket_requires_root_server_for_the_production_client(tmp_path):
    path = tmp_path / "untrusted.sock"
    async def close(_reader, writer):
        await asyncio.sleep(0.01)
        writer.close()
        await writer.wait_closed()
    server = await asyncio.start_unix_server(close, path=path)
    try:
        assert os.getuid() != 0
        with pytest.raises(ValueError, match="machine administrator"):
            await Client(path).request(Snapshot(version=1, id=identity(999), action="snapshot", after=None))
    finally:
        server.close()
        await server.wait_closed()
        await asyncio.sleep(0.02)


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_actual_transport_peer_gets_bound_snapshots_but_cannot_change_local_offer(tmp_path, count):
    s, _values, _provider, _envelope, _clock = setup(tmp_path, count)
    # OS execution is simulated; the socket, framing, and peer credentials are real.
    s.settings.transport_uid = os.getuid()
    s.settings.local_owner_uids = []
    service = Service(s)
    path = tmp_path / "control.sock"
    server = await asyncio.start_unix_server(service.accept, path=path)
    async def exchange(message):
        reader, writer = await asyncio.open_unix_connection(path)
        try:
            await send(writer, encoded(message), MAX_MESSAGE)
            return REPLY.validate_json(await receive(reader, MAX_REPLY)).model_dump()
        finally:
            writer.close()
            await writer.wait_closed()
    try:
        for index in range(count):
            request = {"version": 1, "id": identity(40000 + index), "action": "snapshot", "after": None}
            reply = await exchange(request)
            assert reply["id"] == request["id"] and reply["node_id"] == s.settings.node_id
            assert reply["snapshot"]["maximum_lease_seconds"] == 30
            assert len(reply["snapshot"]["capacity"]["slots"]) == count
        before = s.ledger.offer()
        change = {"version": 1, "id": identity(80000), "action": "set_offer", "expected_revision": before.revision,
                  "settings": before.model_dump(exclude={"revision", "mode", "control"}), "control": "stopped"}
        denied = await exchange(change)
        assert denied["ok"] is False and s.ledger.offer() == before
        forged = {**change, "peer_uid": 0}
        with pytest.raises(ValueError):
            decode(encoded(forged))
    finally:
        server.close()
        await server.wait_closed()
        await asyncio.sleep(0.02)
        s.close()


@pytest.mark.asyncio
async def test_framing_refuses_large_or_incomplete_control_messages_before_json():
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack("!I", MAX_MESSAGE + 1))
    with pytest.raises(ValueError):
        await receive(reader, MAX_MESSAGE)
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack("!I", 10) + b"abc")
    reader.feed_eof()
    with pytest.raises(asyncio.IncompleteReadError):
        await receive(reader, MAX_MESSAGE)


async def test_executor_disconnect_is_a_recoverable_io_error(tmp_path, monkeypatch):
    path = tmp_path / "restarting.sock"
    monkeypatch.setattr(executor_client, "credentials", lambda _socket: (1, 0, 0))

    async def interrupted(reader, writer):
        await receive(reader, MAX_MESSAGE)
        writer.write(struct.pack("!I", 10) + b"abc")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_unix_server(interrupted, path=path)
    try:
        with pytest.raises(OSError, match="disconnected"):
            await Client(path).request(Snapshot(version=1, id=identity(999), action="snapshot", after=None))
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_actual_transport_peer_can_fence_new_absence_but_cannot_acknowledge_legacy(tmp_path, count):
    s, plans, provider, _envelope, _clock = setup(tmp_path, count)
    s.settings.transport_uid = os.getuid()
    s.settings.local_owner_uids = []
    assert os.getuid() != 0
    service = Service(s)
    path = tmp_path / "admission.sock"
    server = await asyncio.start_unix_server(service.accept, path=path)

    async def exchange(action, **extra):
        reader, writer = await asyncio.open_unix_connection(path)
        try:
            request = {"version": 1, "id": identity(99000), "action": action, "installation_id": s.settings.installation_id,
                "ledger_id": s.ledger.identity, "admission_version": 1, "plans": [plan.model_dump() for plan in plans], **extra}
            await send(writer, encoded(request), MAX_MESSAGE)
            return REPLY.validate_json(await receive(reader, MAX_REPLY)).model_dump()
        finally:
            writer.close()
            await writer.wait_closed()

    try:
        refused = await exchange("reconcile_absent", acknowledge_unknown=True)
        assert not refused["ok"] and s.ledger.all() == []
        observed = await exchange("reject_absent")
        assert observed["ok"] and len(observed["results"]) == count
        assert all(row["ok"] and row["attempt"]["state"] == "failed" for row in observed["results"])
        assert s.ledger.retained() == [] and not provider.starts
    finally:
        server.close()
        await server.wait_closed()
        await asyncio.sleep(0.02)
        s.close()
