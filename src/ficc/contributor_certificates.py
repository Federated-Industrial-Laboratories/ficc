# SPDX-License-Identifier: Apache-2.0
"""Validate node proof of possession and exact registered client certificates."""

import hashlib
import importlib.metadata
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store


def key_fingerprint(key):
    if not (isinstance(key, ed25519.Ed25519PublicKey)
            or isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)):
        raise ValueError("Use an Ed25519 or ECDSA P-256 node key.")
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def request(pem, uri, node_id):
    try:
        return validate_request(pem, uri, node_id)
    except (UnsupportedAlgorithm, x509.DuplicateExtension, x509.ExtensionNotFound,
            x509.UnsupportedGeneralNameType) as exc:
        raise ValueError("The certificate request contains unsupported signing data.") from exc


def validate_request(pem, uri, node_id):
    if not isinstance(pem, str) or not pem.isascii() or len(pem) > 8192:
        raise ValueError("The certificate request is too large or invalid.")
    value = x509.load_pem_x509_csr(pem.encode("ascii"))
    if (not value.is_signature_valid
            or any(attr.oid.dotted_string != "1.2.840.113549.1.9.14" for attr in value.attributes)
            or value.public_bytes(serialization.Encoding.PEM).decode("ascii") != pem):
        raise ValueError("The certificate request does not prove possession of its key.")
    if value.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)]):
        raise ValueError("The certificate request names another node.")
    if len(value.extensions) != 1:
        raise ValueError("The certificate request has unsupported extensions.")
    san = value.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    if list(san.value) != [x509.UniformResourceIdentifier(uri)]:
        raise ValueError("The certificate request names another authority or node.")
    return key_fingerprint(value.public_key())


def certificate(pem, csr, uri, node_id, roots, duration, *, now=None):
    if not isinstance(pem, str) or not pem.isascii() or len(pem) > 16384:
        raise ValueError("The certificate chain is too large or invalid.")
    chain = x509.load_pem_x509_certificates(pem.encode("ascii"))
    if not 1 <= len(chain) <= 5:
        raise ValueError("The certificate chain length is invalid.")
    now = now or datetime.now(UTC)
    PolicyBuilder().store(Store(x509.load_pem_x509_certificates(roots))).time(now).max_chain_depth(4).build_client_verifier().verify(chain[0], chain[1:])
    leaf = chain[0]
    fingerprint = request(csr, uri, node_id)
    if key_fingerprint(leaf.public_key()) != fingerprint:
        raise ValueError("The certificate contains another key.")
    if leaf.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)]):
        raise ValueError("The certificate names another node.")
    if list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value) != [x509.UniformResourceIdentifier(uri)]:
        raise ValueError("The certificate has another identity or additional names.")
    if list(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) != [ExtendedKeyUsageOID.CLIENT_AUTH]:
        raise ValueError("The certificate must be limited to client authentication.")
    if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("A node certificate cannot be an authority.")
    usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    if not usage.digital_signature or usage.key_cert_sign or usage.crl_sign:
        raise ValueError("The certificate key usage is invalid.")
    start, end = leaf.not_valid_before_utc.timestamp(), leaf.not_valid_after_utc.timestamp()
    if not start <= now.timestamp() < end <= now.timestamp() + duration + 5:
        raise ValueError("The node certificate lifetime is invalid.")
    return {"fingerprint": leaf.fingerprint(hashes.SHA256()).hex(), "public_key": fingerprint,
            "not_before": start, "expires_at": end, "certificate_chain": pem}


def create(issuer):
    matches = list(importlib.metadata.entry_points(group="ficc.certificates", name=issuer["provider"]))
    if len(matches) != 1:
        raise ValueError("Install exactly one selected trusted certificate provider.")
    module = matches[0].load()
    if module.API_VERSION != 1:
        raise ValueError("The certificate provider interface is unsupported.")
    driver = module.create(issuer["configuration"])
    if not all(callable(getattr(driver, name, None)) for name in ("issue", "revoke", "close")):
        if callable(getattr(driver, "close", None)):
            driver.close()
        raise ValueError("The certificate provider interface is incomplete.")
    return driver
