# SPDX-License-Identifier: Apache-2.0
"""Close quiet revoked channels and retain unaffected distinct node identities."""

import time
from contextlib import ExitStack

import pytest
from contributor_fixtures import enrollment, heartbeat


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_quiet_channels_observe_batched_certificate_revocation(contributor_console, count):
    f = contributor_console
    # The network backend uses the separate continuously heartbeating workflow.
    if hasattr(f.service.store.db, "snapshot"):
        pytest.skip("The network database is qualified with continuous heartbeat clients.")
    nodes = [enrollment(f, index) for index in range(count)]
    with ExitStack() as stack:
        sockets, leases = [], []
        for index, node in enumerate(nodes):
            socket = stack.enter_context(f.client.websocket_connect("/api/v1/node-channel/stream", headers=f.peer(node["fingerprint"], index)))
            socket.send_json(heartbeat(index))
            sockets.append(socket)
            leases.append(socket.receive_json())
        with f.service.store.lock, f.service.store.db:
            for node in nodes[::2]:
                certificate = f.service.contributors.records.get("contributor_certificates", node["fingerprint"])
                certificate["status"] = "revoked"
                f.service.contributors.records.update("contributor_certificates", certificate)
        before = time.monotonic()
        for socket in sockets[::2]:
            assert socket.receive()["type"] == "websocket.close"
        assert time.monotonic() - before < 3
        for index in range(1, count, 2):
            sockets[index].send_json(heartbeat(index, leases[index]["session_id"], 2))
            assert sockets[index].receive_json()["node_id"] == nodes[index]["node_id"]


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_quiet_channels_close_when_authority_storage_fails(contributor_console, monkeypatch, count):
    f = contributor_console
    if hasattr(f.service.store.db, "snapshot"):
        pytest.skip("The network database is qualified with continuous heartbeat clients.")
    nodes = [enrollment(f, index) for index in range(count)]
    with ExitStack() as stack:
        sockets = []
        for index, node in enumerate(nodes):
            socket = stack.enter_context(f.client.websocket_connect("/api/v1/node-channel/stream", headers=f.peer(node["fingerprint"], index)))
            socket.send_json(heartbeat(index))
            assert socket.receive_json()["node_id"] == node["node_id"]
            sockets.append(socket)
        def unavailable(fingerprints):
            raise OSError("Synthetic authority storage outage")
        monkeypatch.setattr(f.service.contributors.records, "active_certificates", unavailable)
        before = time.monotonic()
        for socket in sockets:
            assert socket.receive()["type"] == "websocket.close"
        assert time.monotonic() - before < 3
        assert f.service.contributors.sessions == {}
