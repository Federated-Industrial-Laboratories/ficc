# SPDX-License-Identifier: Apache-2.0
"""Exercise distinct project contributors from invitation through live revocation."""

import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from contributor_fixtures import csr, enrollment, heartbeat
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from starlette.websockets import WebSocketDisconnect


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_enroll_connect_rotate_and_revoke(contributor_console, count):
    f = contributor_console
    nodes = [enrollment(f, index) for index in range(count)]
    assert len({row["public_key"] for row in nodes}) == count
    assert len({row["fingerprint"] for row in nodes}) == count
    leases = []
    for index, node in enumerate(nodes):
        response = f.client.post("/api/v1/node-channel/poll", headers=f.peer(node["fingerprint"], index), json=heartbeat(index))
        assert response.status_code == 200, response.text
        leases.append(response.json())
    listing = f.client.get("/api/v1/contributors", headers=f.admin).json()
    assert len(listing["contributors"]) == count
    assert all(row["connected"] for row in listing["contributors"])
    final = nodes[-1]
    pem, key = csr(f.settings, final["node_id"])
    identity = secrets.token_hex(16)
    response = f.client.post("/api/v1/node-channel/rotate", headers=f.peer(final["fingerprint"], count - 1),
                             json={"request_id": identity, "csr_pem": pem})
    assert response.status_code == 200, response.text
    rotated = x509.load_pem_x509_certificates(response.json()["certificate_chain"].encode())[0].fingerprint(hashes.SHA256()).hex()
    assert key != final["public_key"]
    refused = f.client.post("/api/v1/node-channel/poll", headers=f.peer(rotated, count - 1), json=heartbeat(count - 1))
    assert refused.status_code == 403
    assert f.client.post("/api/v1/node-channel/activate", headers=f.peer(rotated, count - 1), json={}).status_code == 200
    assert f.client.post("/api/v1/node-channel/activate", headers=f.peer(rotated, count - 1), json={}).status_code == 200
    assert f.client.post("/api/v1/node-channel/poll", headers=f.peer(final["fingerprint"], count - 1), json=heartbeat(count - 1)).status_code == 403
    final["fingerprint"] = rotated
    for index, node in enumerate(nodes):
        response = f.client.post("/api/v1/node-channel/poll", headers=f.peer(node["fingerprint"], index), json=heartbeat(index))
        assert response.status_code == 200, response.text
    current = f.service.contributors.records.get("contributors", final["node_id"])
    response = f.client.post(f"/api/v1/contributors/{final['node_id']}/disable", headers=f.admin, json={"revision": current["revision"]})
    assert response.status_code == 200, response.text
    for index, node in enumerate(nodes):
        response = f.client.post("/api/v1/node-channel/poll", headers=f.peer(node["fingerprint"], index), json=heartbeat(index))
        assert response.status_code == (403 if index == count - 1 else 200), response.text
    assert len(f.authority.revoked) == 2


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_replayed_invites_and_forged_gateway_leave_peers_usable(contributor_console, count):
    f = contributor_console
    nodes = [enrollment(f, index) for index in range(count)]
    for index, node in enumerate(nodes):
        public = {**f.public, "X-FICC-Client-IP": f"198.51.100.{index + 1}"}
        replay = f.client.post("/api/v1/node-enrollment/claim", headers=public,
                              json={"secret": node["invitation"]["secret"], "node_id": node["node_id"], "csr_pem": node["csr"]})
        assert replay.status_code == 403
        forged = {**public, "X-FICC-Node-Fingerprint": node["fingerprint"]}
        assert f.client.post("/api/v1/node-channel/poll", headers=forged, json=heartbeat(index)).status_code == 403
        wrong = {**f.peer(node["fingerprint"], index), "X-FICC-Node-Gateway": secrets.token_urlsafe(32)}
        assert f.client.post("/api/v1/node-channel/poll", headers=wrong, json=heartbeat(index)).status_code == 403
        assert f.client.get("/api/v1/contributors", headers=f.peer(node["fingerprint"], index)).status_code == 403
        good = f.client.post("/api/v1/node-channel/poll", headers=f.peer(node["fingerprint"], index), json=heartbeat(index))
        assert good.status_code == 200, good.text


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_live_socket_revocation_and_restart_lease(contributor_console, count):
    f = contributor_console
    nodes = [enrollment(f, index) for index in range(count)]
    stop, revoked = threading.Event(), threading.Event()
    opened = [threading.Event() for _ in nodes]
    observations = [None for _ in nodes]

    def run(index):
        try:
            with f.client.websocket_connect("/api/v1/node-channel/stream", headers=f.peer(nodes[index]["fingerprint"], index)) as socket:
                session, sequence = None, 1
                while not stop.is_set():
                    socket.send_json(heartbeat(index, session, sequence))
                    result = socket.receive_json()
                    assert result["node_id"] == nodes[index]["node_id"] and 0 < result["lease_seconds"] <= 30
                    observations[index] = {**result, "received_at": time.monotonic()}
                    session, sequence = result["session_id"], sequence + 1
                    opened[index].set()
                    if index == count - 1 and revoked.is_set():
                        assert socket.receive()["type"] == "websocket.close"
                        return
                    if stop.wait(f.settings.heartbeat_seconds):
                        return
        except WebSocketDisconnect as exc:
            assert index == count - 1 and revoked.is_set() and exc.code == 4403
        finally:
            opened[index].set()

    with ThreadPoolExecutor(max_workers=count) as workers:
        tasks = [workers.submit(run, index) for index in range(count)]
        try:
            for index, event in enumerate(opened):
                assert event.wait(30), "A distinct contributor did not start its heartbeat stream"
                if tasks[index].done():
                    tasks[index].result()
                assert observations[index] is not None
            node = nodes[-1]
            current = f.service.contributors.records.get("contributors", node["node_id"])
            revoked.set()
            response = f.client.post(f"/api/v1/contributors/{node['node_id']}/disable", headers=f.admin,
                                     json={"revision": current["revision"]})
            assert response.status_code == 200
            tasks[-1].result(timeout=f.settings.lease_seconds)
            before = time.monotonic()
            end = before + f.settings.lease_seconds
            while any(value["received_at"] <= before for value in observations[:-1]):
                assert time.monotonic() < end, "An unaffected contributor lost its heartbeat stream"
                for task in tasks[:-1]:
                    if task.done():
                        task.result()
                        pytest.fail("An unaffected contributor connection closed")
                time.sleep(0.05)
        finally:
            stop.set()
        for task in tasks:
            task.result(timeout=f.settings.lease_seconds)
    assert nodes[-1]["node_id"] not in f.service.contributors.sessions
