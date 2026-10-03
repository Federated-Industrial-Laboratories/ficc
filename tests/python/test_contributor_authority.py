# SPDX-License-Identifier: Apache-2.0
"""Reject identity substitution, lost project rights and stale contributor leases."""

import asyncio
import secrets
import threading
import time

import pytest
from contributor_fixtures import csr, enrollment, heartbeat

from ficc.contributor_client import acknowledgement
from ficc.errors import Failure


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_wrong_keys_do_not_consume_invites_or_approve(contributor_console, count):
    f = contributor_console
    nodes = []
    for index in range(count):
        headers = {**f.admin, "X-FICC-Client-IP": f"198.51.100.{index + 1}"}
        invitation = f.client.post("/api/v1/contributor-invitations", headers=headers,
            json={"name": f"Key check {index}", "mode": "managed"}).json()
        wrong, _ = csr(f.settings, invitation["node_id"], uri=f.settings.uri(secrets.token_hex(16)))
        body = {"secret": invitation["secret"], "node_id": invitation["node_id"], "csr_pem": wrong}
        assert f.client.post("/api/v1/node-enrollment/claim", headers=headers, json=body).status_code == 400
        pem, key = csr(f.settings, invitation["node_id"])
        response = f.client.post("/api/v1/node-enrollment/claim", headers=headers, json={**body, "csr_pem": pem})
        assert response.status_code == 201, response.text
        pending = response.json()
        before = len(f.authority.calls)
        assert f.client.post(f"/api/v1/contributor-requests/{pending['request_id']}/approve", headers=headers,
                             json={"public_key": secrets.token_hex(32), "revision": 1}).status_code == 409
        assert len(f.authority.calls) == before
        nodes.append((pending, key, headers))
    for pending, key, headers in nodes:
        response = f.client.post(f"/api/v1/contributor-requests/{pending['request_id']}/approve", headers=headers,
                                 json={"public_key": key, "revision": 1})
        assert response.status_code == 200, response.text
    assert len(f.authority.calls) == count


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_project_isolation_and_revoked_membership(contributor_console, count):
    f = contributor_console
    identities = f.service.auth.identities
    owners, peers = [], []
    for index in range(count):
        user = identities.create("user", f"Node admin {index}")
        project = identities.create("project", f"Node project {index}")
        identities.membership(project["id"], user["id"], ["contributors:read", "contributors:manage"], 0)
        secret, actor = f.service.auth.issue("token", subject_id=user["id"], project_id=project["id"])
        header = {**f.public, "Authorization": "Bearer " + secret, "X-FICC-Client-IP": f"198.51.100.{index + 1}"}
        invitation = f.client.post("/api/v1/contributor-invitations", headers=header,
            json={"name": f"Private node {index}", "mode": "managed"})
        assert invitation.status_code == 201, invitation.text
        value = invitation.json()
        pem, key = csr(f.settings, value["node_id"])
        claim = f.client.post("/api/v1/node-enrollment/claim", headers=header,
                              json={"secret": value["secret"], "node_id": value["node_id"], "csr_pem": pem}).json()
        owners.append((actor, header, project, user))
        peers.append((value["node_id"], claim, key))
    for index, (actor, header, project, user) in enumerate(owners):
        listed = f.client.get("/api/v1/contributors", headers=header).json()["contributors"]
        assert [row["id"] for row in listed] == [peers[index][0]]
        other = peers[(index + 1) % count] if count > 1 else ("f" * 32, {"request_id": "f" * 32}, "f" * 64)
        denied = f.client.post(f"/api/v1/contributor-requests/{other[1]['request_id']}/approve", headers=header,
                              json={"public_key": other[2], "revision": 1})
        assert denied.status_code == 404
    actor, header, project, user = owners[-1]
    identities.membership(project["id"], user["id"], ["contributors:read"], 1)
    final = peers[-1]
    assert f.client.post(f"/api/v1/contributor-requests/{final[1]['request_id']}/approve", headers=header,
                         json={"public_key": final[2], "revision": 1}).status_code == 403
    for index, (_, header, _, _) in enumerate(owners[:-1]):
        pending = peers[index]
        assert f.client.post(f"/api/v1/contributor-requests/{pending[1]['request_id']}/approve", headers=header,
                             json={"public_key": pending[2], "revision": 1}).status_code == 200


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_expired_leases_and_replay_do_not_extend_authority(contributor_console, count):
    f = contributor_console
    nodes = [enrollment(f, index) for index in range(count)]
    for index, node in enumerate(nodes):
        headers = f.peer(node["fingerprint"], index)
        result = f.client.post("/api/v1/node-channel/poll", headers=headers, json=heartbeat(index)).json()
        current = f.service.contributors.sessions[node["node_id"]]
        deadline = current["deadline"]
        replay = heartbeat(index, result["session_id"], 1)
        assert f.client.post("/api/v1/node-channel/poll", headers=headers, json=replay).status_code == 200
        assert current["deadline"] == deadline
        current["deadline"] = time.monotonic() - 1
        assert f.client.post("/api/v1/node-channel/poll", headers=headers, json=heartbeat(index, result["session_id"], 2)).status_code == 403
        good = f.client.post("/api/v1/node-channel/poll", headers=headers, json=heartbeat(index))
        assert good.status_code == 200
        result = good.json()
        assert result["session_id"] != replay["session_id"]
        with pytest.raises(ValueError, match="expired"):
            acknowledgement({"node_id": node["node_id"], "current": {"expires_at": time.time() + 100}},
                            heartbeat(index), result, time.monotonic() - 31)
    f.service.contributors.sessions.clear()
    for node in nodes:
        with pytest.raises(Failure):
            f.service.contributors.guard(node["node_id"], secrets.token_hex(16), node["fingerprint"])


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_concurrent_issuance_is_bounded_and_releases_slots(contributor_console, monkeypatch, count):
    f = contributor_console
    pending = []
    for index in range(count):
        invite = f.service.contributors.invite(f"Queued node {index}", "managed", f.actor)
        pem, key = csr(f.settings, invite["node_id"])
        claimed = f.service.contributors.claim(invite["secret"], pem, invite["node_id"])
        pending.append((claimed["request_id"], key))
    started, release = threading.Event(), threading.Event()
    calls = []
    def issue(value):
        calls.append(value["node_id"])
        started.set()
        if not release.wait(20):
            raise ValueError("Qualification release was not signaled")
        raise ValueError("Synthetic issuer refusal")
    monkeypatch.setattr(f.authority, "issue", issue)
    tasks = [asyncio.create_task(f.service.contributors.issue(identity, key, 1, f.actor)) for identity, key in pending]
    try:
        assert await asyncio.to_thread(started.wait, 10)
        await asyncio.sleep(0.05)
        assert len(calls) == min(count, 4)
    finally:
        release.set()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert all(isinstance(result, Failure) for result in results)
    assert len([result for result in results if result.status == 429]) == max(0, count - 4)
    assert f.service.contributors.issuing == set()
    assert not f.service.contributors.slots.locked()
    assert f.service.contributors.records.rows("contributor_certificates") == []
    for identity, _ in pending:
        row = f.service.contributors.records.get("contributor_requests", identity)
        assert row["status"] in {"failed", "awaiting_approval"}
