# SPDX-License-Identifier: Apache-2.0
"""Validate signed node requests and authority certificate results."""

import re
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store

from .config import Config, identifier

PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----")
PEM_CSR = re.compile(rb"-----BEGIN CERTIFICATE REQUEST-----\s+[A-Za-z0-9+/=\s]+"
                     rb"-----END CERTIFICATE REQUEST-----")


def public_bytes(key) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def accepted_key(key) -> None:
    if not (isinstance(key, ed25519.Ed25519PublicKey) or
            isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)):
        raise ValueError("The node key type is unsupported.")


def identity(subject: x509.Name, extensions: x509.Extensions, installation: str,
             node: str | None = None) -> tuple[str, str]:
    if len(subject) != 1:
        raise ValueError("The node subject is invalid.")
    attributes = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(attributes) != 1:
        raise ValueError("The node subject is invalid.")
    actual = identifier(attributes[0].value)
    uri = f"urn:ficc:node:{installation}:{actual}"
    sans = extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if list(sans) != [x509.UniformResourceIdentifier(uri)] or node not in (None, actual):
        raise ValueError("The node identity is invalid.")
    return actual, uri


def request(value: object, config: Config) -> tuple[dict, x509.CertificateSigningRequest]:
    if not isinstance(value, dict) or set(value) != {
            "request_id", "node_id", "identity_uri", "csr_pem", "validity_seconds"}:
        raise ValueError("The certificate request fields are invalid.")
    identifier(value["request_id"])
    node = identifier(value["node_id"])
    duration = value["validity_seconds"]
    if type(duration) is not int or not 60 <= duration <= 86400:
        raise ValueError("The certificate duration is invalid.")
    pem = value["csr_pem"]
    if not isinstance(pem, str) or not 1 <= len(pem) <= 8192 or not pem.isascii():
        raise ValueError("The certificate request exceeds its limit.")
    if not PEM_CSR.fullmatch(pem.encode().strip()):
        raise ValueError("The certificate request encoding is invalid.")
    csr = x509.load_pem_x509_csr(pem.encode())
    accepted_key(csr.public_key())
    if not csr.is_signature_valid or len(csr.extensions) != 1:
        raise ValueError("The certificate request signature or extensions are invalid.")
    if isinstance(csr.public_key(), ec.EllipticCurvePublicKey):
        if not isinstance(csr.signature_hash_algorithm, hashes.SHA256):
            raise ValueError("The certificate request signature algorithm is invalid.")
    _, uri = identity(csr.subject, csr.extensions, config.installation, node)
    if value["identity_uri"] != uri:
        raise ValueError("The certificate request identity is invalid.")
    return value.copy(), csr


def chain(pem: object, config: Config, *, expired: bool = False) -> list[x509.Certificate]:
    if not isinstance(pem, str) or not 1 <= len(pem) <= 16384 or not pem.isascii():
        raise ValueError("The certificate chain exceeds its limit.")
    raw = pem.encode().strip()
    blocks = PEM_CERT.findall(raw)
    if not 2 <= len(blocks) <= 4 or PEM_CERT.sub(b"", raw).strip():
        raise ValueError("The certificate chain encoding is invalid.")
    certificates = [x509.load_pem_x509_certificate(block) for block in blocks]
    leaf = certificates[0]
    accepted_key(leaf.public_key())
    identity(leaf.subject, leaf.extensions, config.installation)
    basic = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    extended = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if (basic.ca or basic.path_length is not None or not usage.digital_signature
            or usage.key_cert_sign or usage.crl_sign or usage.key_agreement or usage.key_encipherment
            or usage.data_encipherment or usage.content_commitment
            or list(extended) != [ExtendedKeyUsageOID.CLIENT_AUTH]):
        raise ValueError("The node certificate usage is invalid.")
    now = datetime.now(UTC)
    at = leaf.not_valid_before_utc + timedelta(seconds=1) if expired else now
    verified = (PolicyBuilder().store(Store(list(config.roots))).time(at).max_chain_depth(3)
                .build_client_verifier().verify(leaf, certificates[1:]))
    if verified.chain[:-1] != certificates:
        raise ValueError("The certificate chain order is invalid.")
    return certificates


def issued(response: dict, value: dict, csr: x509.CertificateSigningRequest,
           config: Config, before: datetime, after: datetime) -> str:
    rows = response.get("certChain")
    if not isinstance(rows, list) or not 2 <= len(rows) <= 4:
        raise ValueError("The authority did not return a certificate chain.")
    if any(not isinstance(row, str) or len(row) > 8192 for row in rows):
        raise ValueError("The authority certificate exceeds its limit.")
    pem = "\n".join(rows)
    certificates = chain(pem, config)
    leaf = certificates[0]
    identity(leaf.subject, leaf.extensions, config.installation, value["node_id"])
    if (public_bytes(leaf.public_key()) != public_bytes(csr.public_key())
            or leaf.not_valid_before_utc != before or leaf.not_valid_after_utc != after):
        raise ValueError("The authority certificate does not match the request.")
    return pem
