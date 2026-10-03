# SPDX-License-Identifier: Apache-2.0
"""Refuse substituted certificates and reclaim revoked enrollment capacity."""

import asyncio
import secrets
import threading

import pytest
from contributor_fixtures import Authority, csr, enrollment, heartbeat
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from ficc.errors import Failure


def pending(f, index):
    invitation = f.service.contributors.invite(f"Boundary node {index}", "managed", f.actor)
    pem, key = csr(f.settings, invitation["node_id"])
    result = f.service.contributors.claim(invitation["secret"], pem, invitation["node_id"])
    return result, pem, key


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_issuer_substitution_never_registers_a_certificate(contributor_console, monkeypatch, count):
    f = contributor_console
    original = f.authority.issue
    other = Authority()
    requests = [pending(f, index) for index in range(count)]
    for index, (claim, pem, key) in enumerate(requests):
        node_id = claim["node_id"]
        request = {"node_id": node_id, "csr_pem": pem, "validity_seconds": 3600}
        if index % 4 == 0:
            wrong, _ = csr(f.settings, node_id)
            result = original({**request, "csr_pem": wrong})
        elif index % 4 == 1:
            result = other.issue(request)
        elif index % 4 == 2:
            result = {"certificate_chain": "invalid certificate"}
        else:
            wrong, _ = csr(f.settings, secrets.token_hex(16))
            result = original({**request, "csr_pem": wrong})
        monkeypatch.setattr(f.authority, "issue", lambda value, result=result: result)
        headers = {**f.admin, "X-FICC-Client-IP": f"198.51.100.{index + 1}"}
        response = f.client.post(f"/api/v1/contributor-requests/{claim['request_id']}/approve", headers=headers,
                                 json={"public_key": key, "revision": 1})
        assert response.status_code == 503
    assert f.service.contributors.records.rows("contributor_certificates") == []
    monkeypatch.setattr(f.authority, "issue", original)
    for claim, _, key in requests:
        current = f.service.contributors.records.get("contributor_requests", claim["request_id"])
        response = f.client.post(f"/api/v1/contributor-requests/{claim['request_id']}/approve", headers=f.admin,
                                 json={"public_key": key, "revision": current["revision"]})
        assert response.status_code == 200, response.text


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_unsupported_signed_extensions_preserve_the_invitation(contributor_console, count):
    f = contributor_console
    for index in range(count):
        invite = f.service.contributors.invite(f"Invalid request {index}", "managed", f.actor)
        signing_key = ed25519.Ed25519PrivateKey.generate()
        invalid = (x509.CertificateSigningRequestBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, invite["node_id"])]))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), True).sign(signing_key, None))
        header = {**f.public, "X-FICC-Client-IP": f"198.51.100.{index + 1}"}
        body = {"secret": invite["secret"], "node_id": invite["node_id"],
                "csr_pem": invalid.public_bytes(serialization.Encoding.PEM).decode()}
        response = f.client.post("/api/v1/node-enrollment/claim", headers=header, json=body)
        assert response.status_code == 400
        pem, _ = csr(f.settings, invite["node_id"])
        assert f.client.post("/api/v1/node-enrollment/claim", headers=header, json={**body, "csr_pem": pem}).status_code == 201


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_remove_revoked_nodes_frees_capacity_without_restoring_authority(contributor_console, count):
    f = contributor_console
    nodes = [enrollment(f, index) for index in range(count)]
    for index, node in enumerate(nodes):
        header = {**f.admin, "X-FICC-Client-IP": f"198.51.100.{index + 1}"}
        identity = node["node_id"]
        revision = f.service.contributors.records.get("contributors", identity)["revision"]
        endpoint = f"/api/v1/contributors/{identity}"
        assert f.client.post(endpoint + "/remove", headers=header, json={"revision": revision}).status_code == 409
        revoked = f.client.post(endpoint + "/disable", headers=header, json={"revision": revision})
        assert revoked.status_code == 200
        assert f.client.post(endpoint + "/remove", headers=header, json={"revision": revision}).status_code == 409
        response = f.client.post(endpoint + "/remove", headers=header, json={"revision": revoked.json()["revision"]})
        assert response.status_code == 200
        assert f.client.post("/api/v1/node-channel/poll", headers=f.peer(node["fingerprint"], index), json=heartbeat(index)).status_code == 404
    assert f.service.contributors.records.rows("contributors") == []
    assert f.service.contributors.records.rows("contributor_requests") == []
    assert f.service.contributors.records.rows("contributor_certificates") == []
    for index in range(count):
        fresh = enrollment(f, index)
        assert fresh["node_id"] not in {node["node_id"] for node in nodes}


@pytest.mark.parametrize("cancel", [False, True])
async def test_late_issuance_cannot_survive_revoke_or_cancellation(contributor_console, monkeypatch, cancel):
    f = contributor_console
    claim, _, key = pending(f, 0)
    started, release = threading.Event(), threading.Event()
    original = f.authority.issue
    def issue(value):
        started.set()
        if not release.wait(5):
            raise TimeoutError("Fixture issuer release was not delivered")
        return original(value)
    monkeypatch.setattr(f.authority, "issue", issue)
    task = asyncio.create_task(f.service.contributors.issue(claim["request_id"], key, 1, f.actor))
    try:
        assert await asyncio.to_thread(started.wait, 3)
        if cancel:
            task.cancel("Request disconnected")
            await asyncio.sleep(0)
            assert not task.done()
        else:
            f.service.contributors.records.disable(claim["node_id"], 1, f.actor)
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError if cancel else Failure):
        await task
    assert not f.service.contributors.issuing
    assert not f.service.contributors.slots.locked()
    assert f.service.contributors.records.rows("contributor_certificates") == []
    assert f.service.contributors.records.get("contributor_requests", claim["request_id"])["status"] == "failed"
