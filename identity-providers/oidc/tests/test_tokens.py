# SPDX-License-Identifier: Apache-2.0
"""Reject signed identity assertions with invalid bindings, lifetime or assurance."""

import time

import pytest
from joserfc import jwk
from support import admit, assert_active, assert_last_denied

from ficc_identity_oidc import create


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("claims", [
    {"iss": "https://other.example"}, {"sub": ""}, {"aud": "different"},
    {"aud": ["ficc", "other"], "azp": "other"}, {"aud": ["ficc", "ficc"]},
    {"azp": "other"}, {"nonce": "different"}, {"exp": 1}, {"exp": True},
    {"iat": 9999999999}, {"auth_time": 1}, {"auth_time": 9999999999},
    {"acr": "1"}, {"acr": None}, {"at_hash": "wrong"}, {"nbf": 9999999999},
    {"amr": "otp"},
])
def test_invalid_signed_claims_never_admit(issuer, provider, claims, count):
    rows = admit(issuer, provider, count)
    before = dict(provider._sessions)
    with pytest.raises(ValueError, match="External authentication failed"):
        provider.complete(*issuer.code(count - 1, claims=claims))
    assert provider._sessions == before
    assert_active(provider, rows)
    assert provider.complete(*issuer.code(count))["subject"] == f"person-{count}"


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("header", [{"jku": "https://other.example/keys"},
                                   {"x5u": "https://other.example/cert"},
                                   {"jwk": {"kty": "oct", "k": "AAAA"}},
                                   {"typ": "at+jwt"}, {"kid": "unknown"}])
def test_token_cannot_select_remote_or_embedded_keys(issuer, provider, header, count):
    rows = admit(issuer, provider, count)
    sessions = dict(provider._sessions)
    before = issuer.counts["/keys"]
    with pytest.raises(ValueError):
        provider.complete(*issuer.code(count - 1, header=header))
    assert provider._sessions == sessions
    assert issuer.counts["/keys"] <= before + int("kid" in header)
    fetched = issuer.counts["/keys"]
    with pytest.raises(ValueError):
        provider.complete(*issuer.code(count - 1, header=header))
    assert issuer.counts["/keys"] == fetched
    assert_active(provider, rows)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_wrong_signing_key_and_algorithm(issuer, provider, count):
    rows = admit(issuer, provider, count)
    before = dict(provider._sessions)
    wrong = jwk.RSAKey.generate_key(2048)
    with pytest.raises(ValueError):
        provider.complete(*issuer.code(count - 1, key=wrong))
    symmetric = jwk.OctKey.generate_key(256)
    with pytest.raises(ValueError):
        provider.complete(*issuer.code(count - 1, header={"alg": "HS256"}, key=symmetric))
    assert provider._sessions == before
    assert_active(provider, rows)


def test_ec_signature_and_key_rotation(issuer):
    issuer.key = jwk.ECKey.generate_key("P-256", {"kid": "ec-1", "alg": "ES256", "use": "sig"})
    issuer.keys = [issuer.key.as_dict(private=False)]
    config = {**issuer.configuration(), "algorithms": ["ES256"]}
    provider = create(config, "https://controller.example/auth/callback")
    try:
        first = provider.complete(*issuer.code(0, header={"alg": "ES256", "kid": "ec-1"}))
        issuer.key = jwk.ECKey.generate_key("P-256", {"kid": "ec-2", "alg": "ES256", "use": "sig"})
        issuer.keys = [issuer.key.as_dict(private=False)]
        provider.verifier._updated -= 6
        provider.verifier._attempted -= 6
        second = provider.complete(*issuer.code(1, header={"alg": "ES256", "kid": "ec-2"}))
        assert first["subject"] == "person-0" and second["subject"] == "person-1"
        assert issuer.counts["/keys"] == 2
    finally:
        provider.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("changed", ["sub", "auth_time", "acr", "nonce"])
def test_refresh_preserves_identity_and_original_authentication(issuer, provider, count, changed):
    rows = [provider.complete(*issuer.code(index)) for index in range(count)]
    last = provider._sessions[rows[-1]["handle"]]
    last.token_expiry = time.time() + 1
    changes = {"sub": "different", "auth_time": last.auth_time - 1, "acr": "1", "nonce": "different"}
    issuer.refresh_updates[last.subject] = {changed: changes[changed]}
    results = provider.renew([row["handle"] for row in rows])
    assert all(row["valid"] is True for row in results[:-1])
    assert results[-1] == {"handle": last.handle, "valid": False}
    assert last.handle not in provider._sessions


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("failure", ["consume-drop", "reuse"])
def test_refresh_uncertainty_is_never_replayed(issuer, provider, count, failure):
    rows = [provider.complete(*issuer.code(index)) for index in range(count)]
    last = provider._sessions[rows[-1]["handle"]]
    last.token_expiry = time.time() + 1
    issuer.modes["refresh"] = failure
    results = provider.renew([row["handle"] for row in rows])
    assert all(row["valid"] is True for row in results[:-1])
    assert results[-1] == {"handle": last.handle, "valid": False}
    assert issuer.counts["refresh_token"] == 1
    assert provider.renew([last.handle]) == [{"handle": last.handle, "valid": False}]
    assert issuer.counts["refresh_token"] == 1


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_expired_session_cannot_be_extended(issuer, provider, count):
    rows = admit(issuer, provider, count)
    row = rows[-1]
    session = provider._sessions[row["handle"]]
    session.expires_at = time.time() - 1
    before = dict(issuer.counts)
    results = provider.renew([value["handle"] for value in rows])
    assert issuer.counts["/introspect"] - before["/introspect"] == count - 1
    assert_last_denied(provider, rows, results, session)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_refresh_cannot_change_assurance_within_allowed_set(issuer, count):
    config = {**issuer.configuration(), "required_acr": ["2", "3"]}
    provider = create(config, "https://controller.example/auth/callback")
    try:
        rows = [provider.complete(*issuer.code(index, claims={"acr": "3"})) for index in range(count)]
        last = provider._sessions[rows[-1]["handle"]]
        last.token_expiry = time.time() + 1
        issuer.refresh_updates[last.subject] = {"acr": "2"}
        results = provider.renew([row["handle"] for row in rows])
        assert all(row["valid"] is True for row in results[:-1])
        assert results[-1] == {"handle": last.handle, "valid": False}
    finally:
        provider.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_pkce_verifier_is_required_by_actual_token_endpoint(issuer, provider, count):
    contexts = [issuer.code(index) for index in range(count)]
    assert len({value[1] for value in contexts}) == count
    assert len({value[2] for value in contexts}) == count
    rows = [provider.complete(*context) for context in contexts[:-1]]
    code, _verifier, nonce = contexts[-1]
    wrong = contexts[0][1] if count > 1 else "x" * 64
    before = dict(provider._sessions)
    with pytest.raises(ValueError):
        provider.complete(code, wrong, nonce)
    assert provider._sessions == before
    with pytest.raises(ValueError):
        provider.complete(*contexts[-1])
    assert_active(provider, rows)
    assert provider.complete(*issuer.code(count - 1))["subject"] == f"person-{count - 1}"
