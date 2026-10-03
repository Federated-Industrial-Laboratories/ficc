# SPDX-License-Identifier: Apache-2.0
"""Provide distinct signed node identities on isolated controller state."""

import json
import secrets
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from ficc import contributor_certificates
from ficc.api import create_app
from ficc.settings import Settings

ORIGIN = "https://controller.example"


class Authority:
    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.issuer_key = ec.generate_private_key(ec.SECP256R1())
        self.root = self.ca(self.root_key, "Node root", self.root_key, None)
        self.issuer = self.ca(self.issuer_key, "Node issuer", self.root_key, self.root)
        self.roots = self.root.public_bytes(serialization.Encoding.PEM)
        self.calls, self.revoked = [], []
        self.fail = False

    def ca(self, key, name, signer, parent):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(parent.subject if parent else subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
                .not_valid_after(datetime.now(UTC) + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0 if parent else 1), True)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False)
                .sign(signer, hashes.SHA256()))

    def issue(self, request):
        self.calls.append(dict(request))
        if self.fail:
            raise ValueError("Synthetic authority failure")
        csr = x509.load_pem_x509_csr(request["csr_pem"].encode())
        cert = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(self.issuer.subject)
                .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(UTC) - timedelta(seconds=1))
                .not_valid_after(datetime.now(UTC) + timedelta(seconds=request["validity_seconds"]))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.issuer_key.public_key()), False)
                .add_extension(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, False)
                .sign(self.issuer_key, hashes.SHA256()))
        return {"certificate_chain": (cert.public_bytes(serialization.Encoding.PEM)
                                      + self.issuer.public_bytes(serialization.Encoding.PEM)).decode()}

    def revoke(self, chain, reason):
        self.revoked.append((chain, reason))

    def close(self):
        pass


def csr(settings, node_id, *, uri=None):
    key = ed25519.Ed25519PrivateKey.generate()
    value = (x509.CertificateSigningRequestBuilder()
             .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)]))
             .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri or settings.uri(node_id))]), False)
             .sign(key, None))
    return value.public_bytes(serialization.Encoding.PEM).decode(), contributor_certificates.key_fingerprint(key.public_key())


@pytest.fixture
def contributor_console(storage_state, monkeypatch):
    state = storage_state
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    authority = Authority()
    browser_secret, node_secret = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    values = {"gateway.secret": browser_secret, "node-gateway.secret": node_secret,
              "node-ca.pem": authority.roots.decode(),
              "remote.json": json.dumps({"origin": ORIGIN, "socket": str(state.parent / "gateway.sock"), "gateway_secret_file": str(state / "gateway.secret")}),
              "contributors.json": json.dumps({"deployment_id": secrets.token_hex(16), "origin": ORIGIN + ":8443",
                  "ca_file": str(state / "node-ca.pem"), "gateway_secret_file": str(state / "node-gateway.secret"),
                  "issuer": {"provider": "test-ca", "configuration": {}},
                  "limits": {"certificate_seconds": 3600, "invitation_seconds": 900, "lease_seconds": 30,
                             "heartbeat_seconds": 5, "max_nodes": 64}})}
    for name, value in values.items():
        path = state / name
        path.write_text(value)
        path.chmod(0o600)
    monkeypatch.setattr(contributor_certificates, "create", lambda config: authority)
    app = create_app(Settings(state_dir=state, control=False, poll_interval=3600, stale_after=7200))
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        service = app.state.service
        secret, principal = service.auth.issue("token", lifetime=3600)
        public = {"X-FICC-Gateway": browser_secret, "X-FICC-Client-IP": "198.51.100.1"}
        admin = {**public, "Authorization": "Bearer " + secret}
        def peer(fingerprint, index=0):
            return {"X-FICC-Node-Gateway": node_secret, "X-FICC-Node-Fingerprint": fingerprint,
                    "X-FICC-Client-IP": f"203.0.113.{index + 1}"}
        yield SimpleNamespace(client=client, service=service, authority=authority, admin=admin, public=public, peer=peer,
                              actor=principal, settings=service.settings.contributors)


def enrollment(fixture, index=0, *, activate=True):
    client = fixture.client
    headers = {**fixture.admin, "X-FICC-Client-IP": f"198.51.100.{index + 1}"}
    response = client.post("/api/v1/contributor-invitations", headers=headers,
                           json={"name": f"Contributor {index}", "mode": "voluntary"})
    assert response.status_code == 201, response.text
    invitation = response.json()
    pem, key = csr(fixture.settings, invitation["node_id"])
    response = client.post("/api/v1/node-enrollment/claim", headers={**fixture.public, "X-FICC-Client-IP": f"198.51.100.{index + 1}"},
                           json={"secret": invitation["secret"], "node_id": invitation["node_id"], "csr_pem": pem})
    assert response.status_code == 201, response.text
    claimed = response.json()
    assert claimed["public_key"] == key
    response = client.post(f"/api/v1/contributor-requests/{claimed['request_id']}/approve", headers=headers,
                           json={"public_key": key, "revision": 1})
    assert response.status_code == 200, response.text
    response = client.post("/api/v1/node-enrollment/status", headers=fixture.public,
                           json={"request_id": claimed["request_id"], "receipt": claimed["receipt"]})
    assert response.status_code == 200, response.text
    chain = response.json()["certificate_chain"]
    fingerprint = x509.load_pem_x509_certificates(chain.encode())[0].fingerprint(hashes.SHA256()).hex()
    if activate:
        response = client.post("/api/v1/node-channel/activate", headers=fixture.peer(fingerprint, index), json={})
        assert response.status_code == 200, response.text
    return {"node_id": invitation["node_id"], "invitation": invitation, "claimed": claimed,
            "csr": pem, "public_key": key, "fingerprint": fingerprint}


def heartbeat(index=0, session_id=None, sequence=1):
    from conftest import sample
    value = sample(index)
    value["boot_id"] = f"{index:08x}-0000-0000-0000-000000000001"
    value["observed_at"] = time.time()
    return {"version": 1, "session_id": session_id, "sequence": sequence, "sample": value}
