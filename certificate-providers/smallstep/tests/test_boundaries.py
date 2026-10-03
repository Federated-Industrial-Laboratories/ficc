# SPDX-License-Identifier: Apache-2.0
"""Check network, certificate and private-file failure boundaries."""

import copy
import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from conftest import cohort, crl, leaf, node, write_private
from proxy import faulty_authority

from ficc_certificates_smallstep import create


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("mode", ["oversize", "duplicate", "number", "compressed", "redirect",
                                 "html", "private-error", "disconnect", "slow", "drip",
                                 "key", "identity", "expired", "lifetime", "usage", "ca", "signature"])
def test_late_response_failure_is_not_replayed(authority, tmp_path, count, mode):
    with faulty_authority(authority, tmp_path) as (config, state):
        provider = create(config)
        try:
            rows = cohort(authority, count)
            certificates = [leaf(provider.issue(value)) for value, _ in rows[:-1]]
            state["mode"] = mode
            started = time.monotonic()
            with pytest.raises(ValueError, match="Certificate issuance failed") as error:
                provider.issue(rows[-1][0])
            assert time.monotonic() - started < 2.0
            assert "PRIVATE_AUTHORITY_RESPONSE" not in str(error.value)
            assert len(state["requests"]) == count
            assert len(set(state["requests"])) == count
            assert not {cert.serial_number for cert in certificates}.intersection(crl(authority))
            state["mode"] = "good"
            assert leaf(provider.issue(node(authority.installation)[0]))
            assert len(state["requests"]) == count + 1
        finally:
            provider.close()


@pytest.mark.parametrize("count", [1, 64])
def test_uncertain_revocation_and_wrong_duplicate_fail_closed(authority, tmp_path, count):
    with faulty_authority(authority, tmp_path) as (config, state):
        provider = create(config)
        try:
            rows = cohort(authority, count)
            results = [provider.issue(value) for value, _ in rows]
            earlier = {leaf(result).serial_number for result in results[:-1]}
            serial = leaf(results[-1]).serial_number
            state["mode"] = "disconnect"
            with pytest.raises(ValueError, match="Certificate revocation failed"):
                provider.revoke(results[-1]["certificate_chain"], "disabled")
            assert len(state["requests"]) == count + 1
            revoked = crl(authority)
            assert serial in revoked and not earlier.intersection(revoked)
            state["mode"] = "wrong-duplicate"
            with pytest.raises(ValueError):
                provider.revoke(results[-1]["certificate_chain"], "disabled")
            assert len(state["requests"]) == count + 2
            state["mode"] = "good"
            provider.revoke(results[-1]["certificate_chain"], "disabled")
            assert len(state["requests"]) == count + 3
        finally:
            provider.close()


@pytest.mark.parametrize("count", [1, 64])
def test_close_cancels_late_request_and_releases_signing_key(authority, tmp_path, count):
    with faulty_authority(authority, tmp_path) as (config, state):
        provider = create(config)
        rows = cohort(authority, count)
        try:
            earlier = [leaf(provider.issue(value)).serial_number for value, _ in rows[:-1]]
            state["mode"] = "slow"
            state["observed"].clear()
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(provider.issue, rows[-1][0])
                assert state["observed"].wait(2)
                started = time.monotonic()
                provider.close()
                assert time.monotonic() - started < 2
                with pytest.raises(ValueError):
                    pending.result(timeout=2)
            assert provider._key is None
            assert not provider._transport._thread.is_alive()
            assert len(state["requests"]) == count
            assert len(set(state["requests"])) == count
            assert not set(earlier).intersection(crl(authority))
            with pytest.raises(ValueError):
                provider.issue(node(authority.installation)[0])
            assert len(state["requests"]) == count
        finally:
            provider.close()


@pytest.mark.parametrize("fault", ["http", "path", "query", "userinfo", "seconds", "inline", "key-url",
                                  "symmetric", "world-readable", "symlink", "hardlink", "directory"])
def test_invalid_configuration_and_private_files(authority, tmp_path, fault):
    config = copy.deepcopy(authority.config)
    if fault == "http":
        config["ca_url"] = config["ca_url"].replace("https:", "http:")
    elif fault == "path":
        config["ca_url"] += "/sign"
    elif fault == "query":
        config["ca_url"] += "?credential=bad"
    elif fault == "userinfo":
        config["ca_url"] = config["ca_url"].replace("https:", "https://name@", 1)
    elif fault == "seconds":
        config["request_seconds"] = 20
    elif fault == "inline":
        config["signing_key"] = "not-a-file"
    else:
        key = tmp_path / "key.json"
        material = authority.key.as_dict(private=True)
        if fault == "key-url":
            material["jku"] = "https://localhost/keys"
        if fault == "symmetric":
            material = {"kty": "oct", "k": "a" * 43}
        write_private(key, json.dumps(material).encode())
        if fault == "world-readable":
            key.chmod(0o644)
        if fault == "symlink":
            link = tmp_path / "link.json"
            link.symlink_to(key)
            key = link
        if fault == "hardlink":
            link = tmp_path / "link.json"
            link.hardlink_to(key)
        if fault == "directory":
            tmp_path.chmod(0o777)
        config["signing_key_file"] = str(key)
    with pytest.raises(ValueError, match="configuration is invalid"):
        create(config)


def test_environment_proxy_is_ignored_and_wrong_tls_fails(authority, monkeypatch, tmp_path):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    provider = create(authority.config)
    try:
        assert leaf(provider.issue(node(authority.installation)[0]))
    finally:
        provider.close()
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from proxy import intermediate_key

    # A non-root trust anchor cannot authorize a different endpoint certificate.
    config = dict(authority.config)
    original = x509.load_pem_x509_certificate((authority.home / "certs/root_ca.crt").read_bytes())
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    wrong = (x509.CertificateBuilder().subject_name(original.subject).issuer_name(original.issuer)
             .public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
             .serial_number(x509.random_serial_number()).not_valid_before(original.not_valid_before_utc)
             .not_valid_after(original.not_valid_after_utc)
             .add_extension(x509.BasicConstraints(True, 1), True)
             .sign(intermediate_key(authority), hashes.SHA256()))
    root = tmp_path / "wrong-root.pem"
    write_private(root, wrong.public_bytes(serialization.Encoding.PEM))
    config["root_file"] = str(root)
    provider = create(config)
    try:
        with pytest.raises(ValueError):
            provider.issue(node(authority.installation)[0])
    finally:
        provider.close()
