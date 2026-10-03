# SPDX-License-Identifier: Apache-2.0
"""Exercise private-file, discovery, TLS and bounded response requirements."""

import time

import pytest
from issuer import Issuer
from support import admit, assert_active, assert_last_denied

from ficc_identity_oidc import create

CALLBACK = "https://controller.example/auth/callback"


@pytest.mark.parametrize("change", [
    {"issuer": "http://identity.example/realm"}, {"issuer": "https://user@identity.example"},
    {"allowed_origins": ["https://identity.example/path"]}, {"algorithms": ["HS256"]},
    {"algorithms": ["none"]}, {"required_acr": []}, {"max_auth_age": True},
    {"session_seconds": 86401}, {"extra": True}, {"client_id": "ficc\n"},
])
def test_configuration_rejects_unsafe_values(issuer, change):
    before = dict(issuer.counts)
    with pytest.raises(ValueError):
        create({**issuer.configuration(), **change}, CALLBACK)
    assert issuer.counts == before


@pytest.mark.parametrize("callback", ["http://controller.example/auth/callback",
                                     "https://controller.example/auth/callback?next=x",
                                     "https://controller.example/#fragment"])
def test_callback_is_exact_https(issuer, callback):
    with pytest.raises(ValueError):
        create(issuer.configuration(), callback)


@pytest.mark.parametrize("change", [
    {"issuer": "https://different.example"}, {"code_challenge_methods_supported": ["plain"]},
    {"grant_types_supported": ["authorization_code"]}, {"response_types_supported": ["token"]},
    {"token_endpoint_auth_methods_supported": ["none"]},
    {"introspection_endpoint_auth_methods_supported": ["none"]},
    {"introspection_endpoint": "https://unlisted.example/introspect"},
    {"jwks_uri": "http://127.0.0.1/keys"}, {"authorization_endpoint": "https://other.example/login"},
    {"id_token_signing_alg_values_supported": ["HS256"]},
])
def test_discovery_rejects_weaker_or_redirected_protocol(issuer, change):
    issuer.discovery_updates = change
    with pytest.raises(ValueError):
        create(issuer.configuration(), CALLBACK)
    assert issuer.counts.get("/keys", 0) == 0


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("mode", ["unavailable", "redirect", "oversized", "duplicate",
                                 "nonfinite", "compressed", "html", "private-error", "disconnect"])
def test_failed_renewal_drops_handle_and_never_leaks_response(issuer, provider, mode, caplog, count):
    rows = admit(issuer, provider, count)
    last = provider._sessions[rows[-1]["handle"]]
    issuer.subject_modes[("/introspect", last.subject)] = mode
    results = provider.renew([row["handle"] for row in rows])
    assert_last_denied(provider, rows, results, last)
    before = dict(issuer.counts)
    assert provider.renew([last.handle]) == [{"handle": last.handle, "valid": False}]
    assert issuer.counts == before
    assert issuer.counts.get("/never", 0) == 0
    assert "PRIVATE_RESPONSE" not in caplog.text


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_renewal_deadline_denies_slow_response(issuer, provider, count):
    rows = admit(issuer, provider, count)
    last = provider._sessions[rows[-1]["handle"]]
    issuer.subject_modes[("/introspect", last.subject)] = "slow"
    start = time.monotonic()
    results = provider.renew([row["handle"] for row in rows])
    assert time.monotonic() - start < 4 + count / 64
    assert_last_denied(provider, rows, results, last)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_drip_response_cannot_extend_elapsed_request_budget(issuer, provider, monkeypatch, count):
    import ficc_identity_oidc.transport as transport
    rows = admit(issuer, provider, count)
    last = provider._sessions[rows[-1]["handle"]]
    monkeypatch.setattr(transport, "REQUEST_SECONDS", 0.18)
    issuer.subject_modes[("/introspect", last.subject)] = "drip"
    start = time.monotonic()
    results = provider.renew([row["handle"] for row in rows])
    assert time.monotonic() - start < 2 + count / 64
    assert_last_denied(provider, rows, results, last)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_valid_signed_token_cannot_exceed_token_bound(issuer, provider, count):
    rows = admit(issuer, provider, count)
    before = dict(provider._sessions)
    with pytest.raises(ValueError):
        provider.complete(*issuer.code(count - 1, claims={"padding": "a" * (16 * 1024)}))
    assert provider._sessions == before
    assert_active(provider, rows)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_failed_complete_has_fixed_error_without_server_body(issuer, provider, caplog, count):
    rows = admit(issuer, provider, count)
    before = dict(provider._sessions)
    issuer.subject_modes[("/token", rows[-1]["subject"])] = "private-error"
    with pytest.raises(ValueError) as failure:
        provider.complete(*issuer.code(count - 1))
    assert str(failure.value) == "External authentication failed."
    assert failure.value.__suppress_context__ is True
    assert "PRIVATE_RESPONSE" not in caplog.text
    assert provider._sessions == before
    assert_active(provider, rows)


def test_tls_verification_cannot_be_disabled(issuer):
    config = issuer.configuration()
    del config["ca_file"]
    with pytest.raises(ValueError):
        create(config, CALLBACK)
    assert not issuer.counts


def test_trusted_ca_does_not_disable_hostname_verification(tmp_path):
    issuer = Issuer(tmp_path, wrong_hostname=True)
    try:
        with pytest.raises(ValueError):
            create(issuer.configuration(), CALLBACK)
        assert not issuer.counts
    finally:
        issuer.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_batch_deadline_bounds_queued_network_work(issuer, provider, monkeypatch, count):
    import ficc_identity_oidc.provider as implementation
    rows = [provider.complete(*issuer.code(index)) for index in range(count)]
    monkeypatch.setattr(implementation, "BATCH_SECONDS", 0.15)
    issuer.modes["/introspect"] = "slow"
    before = issuer.counts["/introspect"]
    start = time.monotonic()
    handles = [row["handle"] for row in rows]
    assert provider.renew(handles) == [{"handle": handle, "valid": False} for handle in handles]
    assert issuer.counts["/introspect"] - before <= 4
    assert time.monotonic() - start < 1.5
    assert not provider._sessions


def test_environment_proxy_is_not_used(issuer, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    provider = create(issuer.configuration(), CALLBACK)
    try:
        assert provider.complete(*issuer.code(0))["subject"] == "person-0"
    finally:
        provider.close()


@pytest.mark.parametrize("mode", ["public", "symlink", "parent-link", "hardlink", "fifo"])
def test_private_secret_file_cannot_be_replaced_or_shared(issuer, tmp_path, mode):
    path = issuer.secret
    if mode == "public":
        path.chmod(0o644)
    elif mode == "symlink":
        path = tmp_path / "link"
        path.symlink_to(issuer.secret)
    elif mode == "parent-link":
        directory = tmp_path / "linked-parent"
        directory.symlink_to(tmp_path, target_is_directory=True)
        path = directory / issuer.secret.name
    elif mode == "hardlink":
        path = tmp_path / "hardlink"
        path.hardlink_to(issuer.secret)
    else:
        import os
        path = tmp_path / "fifo"
        os.mkfifo(path, mode=0o600)
    try:
        with pytest.raises(ValueError):
            create({**issuer.configuration(), "client_secret_file": str(path)}, CALLBACK)
    finally:
        if mode == "hardlink":
            path.unlink()
    assert not issuer.counts


@pytest.mark.parametrize("field,value", [("expires_in", 0), ("expires_in", True),
                                        ("refresh_token", ""), ("id_token", "bad"),
                                        ("token_type", "MAC")])
def test_invalid_token_response_cannot_admit(issuer, provider, field, value):
    with pytest.raises(ValueError):
        provider.complete(*issuer.code(0, fields={field: value}))
    assert not provider._sessions
