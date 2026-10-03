# SPDX-License-Identifier: Apache-2.0
"""Verify identity admission, distinct batch renewal and memory-only cleanup."""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from support import admit, assert_active, assert_last_denied

from ficc_identity_oidc import API_VERSION

FIELDS = {"handle", "issuer", "subject", "auth_time", "expires_at", "valid_until"}


@pytest.mark.parametrize("count", [1, 64])
def test_complete_renew_rotate_and_forget(issuer, provider, count):
    admitted = [provider.complete(*issuer.code(index)) for index in range(count)]
    assert API_VERSION == 1
    assert all(set(row) == FIELDS for row in admitted)
    assert [row["subject"] for row in admitted] == [f"person-{index}" for index in range(count)]
    assert len({row["handle"] for row in admitted}) == count
    assert all(time.time() < row["valid_until"] <= row["expires_at"] for row in admitted)
    assert all(row["valid_until"] <= time.time() + 30 for row in admitted)
    handles = [row["handle"] for row in admitted]
    refreshed = provider.renew(handles)
    assert [row["handle"] for row in refreshed] == handles
    assert all(row["valid"] is True and set(row) == FIELDS | {"valid"} for row in refreshed)
    originals = {handle: provider._sessions[handle].refresh for handle in handles}
    for handle in handles:
        provider._sessions[handle].token_expiry = time.time() + 1
    rotated = provider.renew(handles)
    assert all(row["valid"] is True for row in rotated)
    assert [row["expires_at"] for row in rotated] == [row["expires_at"] for row in admitted]
    assert [row["auth_time"] for row in rotated] == [row["auth_time"] for row in admitted]
    assert all(provider._sessions[handle].refresh != originals[handle] for handle in handles)
    assert issuer.counts["refresh_token"] == count
    assert issuer.counts["/introspect"] == count * 3
    assert issuer.max_requests <= 4
    sessions = [provider._sessions[handle] for handle in handles]
    provider.forget(handles)
    assert issuer.counts["/revoke"] == count
    assert all(not session.access and not session.refresh and not session.nonce for session in sessions)
    assert provider.renew(handles) == [{"handle": handle, "valid": False} for handle in handles]
    provider.forget(handles)
    assert issuer.counts["/revoke"] == count


def test_authorization_binds_code_flow_nonce_pkce_and_assurance(provider):
    state, nonce, challenge = "s" * 43, "n" * 43, "c" * 43
    value = provider.authorization(state, nonce, challenge)
    parts = urlsplit(value)
    query = parse_qs(parts.query)
    assert parts.path == "/authorize"
    assert query["state"] == [state] and query["nonce"] == [nonce]
    assert query["code_challenge"] == [challenge] and query["code_challenge_method"] == ["S256"]
    assert query["response_type"] == ["code"] and query["response_mode"] == ["query"]
    assert query["scope"] == ["openid"] and query["max_age"] == ["28800"]
    assert query["redirect_uri"] == ["https://controller.example/auth/callback"]
    assert json.loads(query["claims"][0]) == {"id_token": {"acr": {"essential": True, "values": ["2"]}}}
    assert "secret" not in query and "access_token" not in query


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("change", [{"active": False}, {"sub": "different"},
                                    {"client_id": "different"}, {"exp": 1}, {"active": 1}])
def test_final_identity_denied_without_affecting_other_members(issuer, provider, count, change):
    rows = [provider.complete(*issuer.code(index)) for index in range(count)]
    handles = [row["handle"] for row in rows]
    issuer.introspection_updates[f"person-{count - 1}"] = change
    results = provider.renew(handles)
    assert [row["handle"] for row in results] == handles
    assert all(row["valid"] is True for row in results[:-1])
    assert results[-1] == {"handle": handles[-1], "valid": False}
    assert handles[-1] not in provider._sessions
    before = issuer.counts["/introspect"]
    assert provider.renew([handles[-1]]) == [{"handle": handles[-1], "valid": False}]
    assert issuer.counts["/introspect"] == before


@pytest.mark.parametrize("count", [1, 64])
def test_close_clears_every_identity_and_refuses_late_admission(issuer, provider, count):
    rows = [provider.complete(*issuer.code(index)) for index in range(count)]
    sessions = list(provider._sessions.values())
    handles = [row["handle"] for row in rows]
    provider.close()
    provider.close()
    assert provider.config.secret == "" and provider.transport._basic == ""
    assert not provider._sessions
    assert all(not session.access and not session.refresh and not session.nonce for session in sessions)
    assert provider.renew(handles) == [{"handle": handle, "valid": False} for handle in handles]
    with pytest.raises(ValueError):
        provider.complete(*issuer.code(99))
    with pytest.raises(ValueError):
        provider.authorization("s" * 43, "n" * 43, "c" * 43)


@pytest.mark.parametrize("count", [1, 64])
def test_local_forget_precedes_slow_external_revocation(issuer, provider, count):
    rows = admit(issuer, provider, count)
    row = rows[-1]
    session = provider._sessions[row["handle"]]
    issuer.subject_modes[("/revoke", row["subject"])] = "pause"
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(provider.forget, [row["handle"]])
        assert issuer.paused.wait(2)
        assert provider.renew([row["handle"]]) == [{"handle": row["handle"], "valid": False}]
        assert_active(provider, rows[:-1])
        issuer.release.set()
        pending.result(timeout=3)
    assert not session.access and not session.refresh and not session.nonce
    assert issuer.counts["/revoke"] == 1


@pytest.mark.parametrize("count", [1, 64])
def test_forget_racing_renewal_cannot_restore_identity(issuer, provider, count):
    rows = admit(issuer, provider, count)
    row = rows[-1]
    session = provider._sessions[row["handle"]]
    issuer.subject_modes[("/introspect", row["subject"])] = "pause"
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = pool.submit(provider.renew, [value["handle"] for value in rows])
        assert issuer.paused.wait(5)
        removed = pool.submit(provider.forget, [row["handle"]])
        deadline = time.monotonic() + 1
        while row["handle"] in provider._sessions and time.monotonic() < deadline:
            time.sleep(0.01)
        assert row["handle"] not in provider._sessions
        issuer.release.set()
        results = pending.result(timeout=3)
        removed.result(timeout=3)
    assert_last_denied(provider, rows, results, session)
    assert issuer.counts["/revoke"] == 1


@pytest.mark.parametrize("count", [1, 64])
def test_delayed_assertion_cannot_extend_external_verification(issuer, provider, monkeypatch, count):
    import ficc_identity_oidc.provider as implementation
    rows = [provider.complete(*issuer.code(index)) for index in range(count)]
    clock = threading.local()
    replacement = SimpleNamespace(time=lambda: time.time() + getattr(clock, "offset", 0),
                                  monotonic=time.monotonic)
    monkeypatch.setattr(implementation, "time", replacement)
    original = provider._assertion

    def delayed(session):
        if session.subject in {f"person-{count - 1}", f"person-{count}"}:
            clock.offset = 31
        try:
            return original(session)
        finally:
            clock.offset = 0

    monkeypatch.setattr(provider, "_assertion", delayed)
    handles = [row["handle"] for row in rows]
    results = provider.renew(handles)
    assert all(row["valid"] is True for row in results[:-1])
    assert results[-1] == {"handle": handles[-1], "valid": False}
    with pytest.raises(ValueError):
        provider.complete(*issuer.code(count))
    assert len(provider._sessions) == count - 1


@pytest.mark.parametrize("values", [[], ["a" * 32] * 2, ["a" * 31], [None],
                                     [f"{index:032d}" for index in range(65)],
                                     ("a" * 32,), ["bad\n" * 10]])
def test_batch_shape_rejected_before_network(issuer, provider, values):
    before = dict(issuer.counts)
    for method in (provider.renew, provider.forget):
        with pytest.raises(ValueError):
            method(values)
    assert issuer.counts == before
