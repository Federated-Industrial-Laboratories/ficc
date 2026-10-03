# SPDX-License-Identifier: Apache-2.0
"""Exercise distinct approved nodes against the real certificate authority."""

import base64
import hashlib
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import cohort, crl, leaf, node, write_private
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from joserfc import jwt

from ficc_certificates_smallstep.validation import public_bytes


@pytest.mark.parametrize("count", [1, 64])
def test_issue_revoke_and_repeat_with_distinct_nodes(authority, provider, count):
    rows = cohort(authority, count)
    results = [provider.issue(value) for value, _ in rows]
    certificates = [leaf(result) for result in results]
    assert len({cert.serial_number for cert in certificates}) == count
    for (value, key), certificate in zip(rows, certificates, strict=True):
        assert public_bytes(certificate.public_key()) == public_bytes(key.public_key())
        assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value \
            == value["node_id"]
        assert list(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value) \
            == [x509.UniformResourceIdentifier(value["identity_uri"])]
        assert list(certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) \
            == [ExtendedKeyUsageOID.CLIENT_AUTH]
        assert (certificate.not_valid_after_utc - certificate.not_valid_before_utc).total_seconds() \
            == value["validity_seconds"]
    unaffected = leaf(provider.issue(node(authority.installation)[0])).serial_number
    before = crl(authority)
    for index, result in enumerate(results):
        provider.revoke(result["certificate_chain"], ["superseded", "disabled", "recovery"][index % 3])
        provider.revoke(result["certificate_chain"], "disabled")
        current = crl(authority)
        assert current - before == {cert.serial_number for cert in certificates[:index + 1]}
        assert unaffected not in current
    provider.close()
    provider.close()
    assert provider._key is None and not provider._transport._thread.is_alive()
    with pytest.raises(ValueError):
        provider.issue(node(authority.installation)[0])


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("fault", ["uri", "dns", "subject", "rsa", "curve", "extension",
                                  "signature", "duration"])
def test_late_invalid_request_does_not_contact_authority(authority, provider, count, fault):
    rows = cohort(authority, count)
    results = [provider.issue(value) for value, _ in rows[:-1]]
    value, _ = rows[-1]
    if fault == "uri":
        value["identity_uri"] = f"urn:ficc:node:{'0' * 32}:{value['node_id']}"
    elif fault == "dns":
        value, _ = node(authority.installation, sans=[x509.DNSName("localhost")])
    elif fault == "subject":
        value, _ = node(authority.installation, subject=x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "0" * 32),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Extra")]))
    elif fault == "rsa":
        value, _ = node(authority.installation, key=rsa.generate_private_key(65537, 2048))
    elif fault == "curve":
        value, _ = node(authority.installation, key=ec.generate_private_key(ec.SECP384R1()))
    elif fault == "extension":
        value, _ = node(authority.installation, extra=x509.BasicConstraints(True, 0))
    elif fault == "signature":
        csr = x509.load_pem_x509_csr(value["csr_pem"].encode())
        der = bytearray(csr.public_bytes(serialization.Encoding.DER))
        der[-1] ^= 1
        body = base64.encodebytes(der).decode()
        value["csr_pem"] = "-----BEGIN CERTIFICATE REQUEST-----\n" + body \
            + "-----END CERTIFICATE REQUEST-----\n"
    else:
        value["validity_seconds"] = 86401
    original = provider._transport.request
    calls = []

    def tracked(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    provider._transport.request = tracked
    with pytest.raises(ValueError, match="Certificate issuance failed"):
        provider.issue(value)
    assert not calls
    provider._transport.request = original
    untouched = {leaf(result).serial_number for result in results}
    assert not untouched.intersection(crl(authority))
    assert leaf(provider.issue(node(authority.installation)[0]))


def sign_body(provider, value):
    csr = x509.load_pem_x509_csr(value["csr_pem"].encode())
    fingerprint = base64.urlsafe_b64encode(hashlib.sha256(
        csr.public_bytes(serialization.Encoding.DER)).digest()).rstrip(b"=").decode()
    token = provider._token(value["node_id"], "/sign", {
        "sans": [value["identity_uri"]], "cnf": {"x5rt#S256": fingerprint}})
    before = datetime.now(UTC).replace(microsecond=0)
    return {"csr": value["csr_pem"], "ott": token, "notBefore": before.isoformat(),
            "notAfter": (before + timedelta(hours=1)).isoformat()}


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("fault", ["binding", "installation", "unbound", "expired", "replay",
                                  "key", "usage"])
def test_authority_rejects_late_token_or_template_abuse(authority, provider, count, fault):
    rows = cohort(authority, count)
    accepted = [provider.issue(value) for value, _ in rows[:-1]]
    value, _ = rows[-1]
    body = sign_body(provider, value)
    claims = jwt.decode(body["ott"], authority.key, algorithms=["ES256"]).claims
    if fault == "binding":
        body["csr"] = node(authority.installation)[0]["csr_pem"]
    elif fault == "installation":
        claims["sans"] = [value["identity_uri"].replace(authority.installation, "0" * 32)]
    elif fault == "unbound":
        claims.pop("cnf")
    elif fault == "expired":
        claims.update({"iat": int(time.time()) - 300, "nbf": int(time.time()) - 300,
                       "exp": int(time.time()) - 120})
    elif fault == "key":
        value, _ = node(authority.installation, key=ec.generate_private_key(ec.SECP384R1()))
        body = sign_body(provider, value)
        claims = jwt.decode(body["ott"], authority.key, algorithms=["ES256"]).claims
    elif fault == "usage":
        value, _ = node(authority.installation, extra=x509.BasicConstraints(True, 0))
        body = sign_body(provider, value)
        claims = jwt.decode(body["ott"], authority.key, algorithms=["ES256"]).claims
    body["ott"] = jwt.encode({"alg": "ES256", "kid": provider.config.kid}, claims,
                              authority.key, algorithms=["ES256"])
    if fault == "replay":
        first = authority.client.post(provider.config.url + "/sign", json=body)
        assert first.status_code == 201
    response = authority.client.post(provider.config.url + "/sign", json=body)
    if fault == "usage":
        # The CA template discards a caller's CA request and emits client use only.
        assert response.status_code == 201
        certificate = x509.load_pem_x509_certificate(response.json()["crt"].encode())
        assert not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        assert list(certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) \
            == [ExtendedKeyUsageOID.CLIENT_AUTH]
    else:
        assert response.status_code in (400, 401, 403)
    assert not {leaf(result).serial_number for result in accepted}.intersection(crl(authority))
    assert leaf(provider.issue(node(authority.installation)[0]))


@pytest.mark.parametrize("seconds", [60, 86400])
def test_requested_validity_bounds(authority, provider, seconds):
    value, _ = node(authority.installation, seconds=seconds)
    certificate = leaf(provider.issue(value))
    assert (certificate.not_valid_after_utc - certificate.not_valid_before_utc).total_seconds() == seconds


@pytest.mark.parametrize("count", [1, 64])
def test_direct_ca_renewal_cannot_bypass_node_approval(authority, provider, tmp_path, count):
    import ssl

    rows = cohort(authority, count)
    results = [provider.issue(value) for value, _ in rows]
    for index, ((_, private_key), result) in enumerate(zip(rows, results, strict=True)):
        cert, key = tmp_path / f"node-{index}.pem", tmp_path / f"node-{index}.key"
        write_private(cert, result["certificate_chain"].encode())
        write_private(key, private_key.private_bytes(serialization.Encoding.PEM,
                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        tls = ssl.create_default_context(cafile=authority.config["root_file"])
        tls.load_cert_chain(cert, key)
        with httpx.Client(verify=tls, trust_env=False, timeout=2) as client:
            response = client.post(provider.config.url + "/renew")
        assert response.status_code in (401, 403)
    assert not {leaf(result).serial_number for result in results}.intersection(crl(authority))
