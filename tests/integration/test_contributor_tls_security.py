# SPDX-License-Identifier: Apache-2.0
"""Reject forged node identity and unverified TLS across actual gateways."""

import asyncio
import json
import ssl
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from contributor_tls.authority import private
from contributor_tls.lab import laboratory, poll, retain_material, running, unregistered_material
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_forged_headers_and_invitation_replay_cannot_replace_peer(count):
    from ficc import contributor_client
    from ficc.contributor_client_state import NodeState

    with laboratory() as lab:
        states = await lab.cohort(count)
        protected = states[0]
        target = states[-1]
        identity = protected.load()["node_id"]
        fingerprint = protected.load()["current"]["fingerprint"]
        headers = {"X-FICC-Node-Fingerprint": fingerprint, "X-FICC-Node-Gateway": "forged",
                   "X-FICC-Gateway": "forged", "X-FICC-Client-IP": "203.0.113.99",
                   "Forwarded": "for=203.0.113.99;proto=https"}
        response = await poll(target, headers=headers)
        assert response.status_code == 200
        assert response.json()["node_id"] == target.load()["node_id"]
        if count > 1:
            assert response.json()["node_id"] != identity
        async with httpx.AsyncClient(verify=lab.gateway.tls, trust_env=False, timeout=5) as client:
            response = await client.post(lab.browser_origin + "/api/v1/node-channel/activate",
                                          json={}, headers=headers)
        assert response.status_code == 403
        replay = NodeState(lab.directory / "replayed-node")
        with pytest.raises(ValueError):
            await contributor_client.join(replay, target.path / "invitation.json", lab.gateway.root)
        assert replay.load()["stage"] == "claiming"
        assert replay.load()["pending"]["public_key"] != target.load()["current"]["public_key"]
        unregistered = await unregistered_material(lab, target)
        response = await poll(target, material=unregistered)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"
        for state in states:
            assert (await poll(state)).status_code == 200


def wrong_client(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unapproved client")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        .sign(key, hashes.SHA256()))
    files = directory / "wrong-client.pem", directory / "wrong-client.key"
    private(files[0], cert.public_bytes(serialization.Encoding.PEM))
    private(files[1], key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return files


@pytest.mark.asyncio
async def test_listener_rejects_wrong_missing_and_legacy_tls_certificates():
    from ficc import contributor_client
    from ficc.contributor_client_state import NodeState

    with laboratory() as lab:
        state = await lab.enroll()
        for mode in ("missing", "wrong", "legacy"):
            tls = ssl.create_default_context(cafile=str(lab.gateway.root))
            if mode == "wrong":
                tls.load_cert_chain(*wrong_client(lab.directory))
            if mode == "legacy":
                value = state.load()
                tls.load_cert_chain(state.file(value["current"]["certificate_file"]),
                                    state.file(value["current"]["key_file"]))
                tls.minimum_version = ssl.TLSVersion.TLSv1_2
                tls.maximum_version = ssl.TLSVersion.TLSv1_2
            async with httpx.AsyncClient(verify=tls, trust_env=False, timeout=3) as client:
                with pytest.raises(httpx.TransportError):
                    await client.post(lab.node_origin + "/api/v1/node-channel/activate", json={})
            assert (await poll(state)).status_code == 200
        invitation = lab.api("POST", "/api/v1/contributor-invitations",
                              json={"name": "Untrusted server", "mode": "voluntary"})
        untrusted = NodeState(lab.directory / "untrusted-server")
        private(untrusted.path / "invitation.json", json.dumps(invitation))
        with pytest.raises(httpx.TransportError):
            await contributor_client.join(untrusted, untrusted.path / "invitation.json")
        assert untrusted.load()["stage"] == "claiming"
        assert (await poll(state)).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_registered_revocation_denies_an_existing_tls_connection(count):
    from ficc_node.collect import collect

    with laboratory() as lab:
        states = await lab.cohort(count)
        target = states[-1]
        material = retain_material(target)
        value = target.load()
        async with running(states[:-1], "persistent"):
            if count > 1:
                await lab.connected(states[:-1])
            async with httpx.AsyncClient(verify=target.tls(value, material), trust_env=False,
                                         timeout=5, http2=False) as client:
                message = {"version": 1, "session_id": None, "sequence": 1,
                           "sample": await asyncio.to_thread(collect)}
                first = await client.post(lab.node_origin + "/api/v1/node-channel/poll", json=message)
                assert first.status_code == 200
                connection = first.extensions["network_stream"]
                lab.disable(target)
                second = await client.post(lab.node_origin + "/api/v1/node-channel/poll", json=message)
                assert second.extensions["network_stream"] is connection
                assert second.status_code == 403
            if count > 1:
                assert lab.report(states[0])["status"] == "connected"
                assert lab.listing()[states[0].load()["node_id"]]["connected"]


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_old_sequences_and_other_sessions_cannot_extend_authority(count):
    from ficc_node.collect import collect

    with laboratory() as lab:
        states = await lab.cohort(count)
        target = states[-1]
        async with running(states[:-1], "persistent"):
            if count > 1:
                await lab.connected(states[:-1])
            sample = await asyncio.to_thread(collect)
            first = (await poll(target)).json()
            message = {"version": 1, "session_id": first["session_id"], "sequence": 1,
                       "sample": sample}
            await asyncio.sleep(0.2)
            duplicate = await poll(target, body=message)
            assert duplicate.status_code == 200
            assert duplicate.json()["lease_seconds"] < first["lease_seconds"] - 0.1
            message["sequence"] = 2
            assert (await poll(target, body=message)).status_code == 200
            message["sequence"] = 1
            assert (await poll(target, body=message)).status_code == 409
            if count > 1:
                assert (await poll(states[0], body={**message, "sequence": 3})).status_code == 403
                assert lab.report(states[0])["status"] == "connected"
            replacement = await poll(target)
            assert replacement.status_code == 200
            assert replacement.json()["session_id"] != first["session_id"]
            assert (await poll(target, body={**message, "sequence": 3})).status_code == 403
            assert (await poll(target)).status_code == 200
