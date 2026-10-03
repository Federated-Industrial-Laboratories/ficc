# SPDX-License-Identifier: Apache-2.0
"""Verify exact identity approval, current project rights and external lease revocation."""

import asyncio
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from remote_fixtures import ISSUER, external_session, login, session_headers
from test_identity_projects import member


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_distinct_remote_identities_keep_current_mapping_and_project(remote_console, count):
    client, service, provider, gateway = remote_console
    records = []
    for index in range(count):
        user, project, _, _ = member(service, f"Remote member {index}", scopes=["workspaces:read", "workspaces:write"])
        subject = f"external-{index}"
        service.remote_auth.records.save(ISSUER, subject, user["id"], False, 0)
        response = login(client, provider, subject, index)
        assert response.status_code == 303 and response.headers["location"] == "/", response.text
        cookie = response.headers.get_list("set-cookie")[0]
        assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie
        session = client.get("/api/v1/session").json()
        assert session["principal"]["subject_id"] == user["id"]
        assert session["principal"]["project_id"] == project["id"]
        assert session["principal"]["local_owner"] is False
        assert session["remote"] is True
        headers = {**gateway, "Cookie": client.headers.get("cookie", "") or
                   "; ".join(f"{name}={value}" for name, value in client.cookies.items()),
                   "X-CSRF-Token": session["csrf"], "X-FICC-Client-IP": f"198.51.100.{index + 1}"}
        response = client.post("/api/v1/workspaces", headers=headers, json={"name": f"Remote space {index}"})
        assert response.status_code == 201, response.text
        records.append((user, project, session, headers, response.json()))
    assert len(service.remote_auth.bindings) == count
    selected = list(service.remote_auth.bindings.values())
    asyncio.run(service.remote_auth.renew(selected))
    assert len(provider.batches[-1]) == count
    for index, (user, project, session, headers, space) in enumerate(records):
        response = client.get("/api/v1/workspaces", headers=headers)
        assert response.status_code == 200 and response.json()["workspaces"] == [space]
        assert client.get("/api/v1/external-identities", headers=headers).status_code == 403
        service.remote_auth.records.save(ISSUER, f"external-{index}", user["id"], True, 1)
        assert client.get("/api/v1/session", headers=headers).status_code == 401
        service.remote_auth.records.save(ISSUER, f"external-{index}", user["id"], False, 2)
        assert client.get("/api/v1/session", headers=headers).status_code == 401


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_provider_revocation_and_late_invalid_renewal_deny_sessions(remote_console, count):
    client, service, provider, _ = remote_console
    records = []
    for index in range(count):
        user, _, _, _ = member(service, f"Lease member {index}", scopes=["workspaces:read"])
        service.remote_auth.records.save(ISSUER, f"lease-{index}", user["id"], False, 0)
        assert login(client, provider, f"lease-{index}", index).headers["location"] == "/"
        records.append(client.get("/api/v1/session").json()["principal"]["id"])
    selected = list(service.remote_auth.bindings.values())
    provider.denied.add(selected[-1]["assertion"]["handle"])
    asyncio.run(service.remote_auth.renew(selected))
    from ficc.errors import Failure
    with pytest.raises(Failure):
        service.auth.current(records[-1])
    for identity in records[:-1]:
        assert service.auth.current(identity).id == identity
    if count > 1:
        selected = list(service.remote_auth.bindings.values())
        provider.handles[selected[-1]["assertion"]["handle"]]["subject"] = "different-subject"
        asyncio.run(service.remote_auth.renew(selected))
        for identity in records:
            with pytest.raises(Failure):
                service.auth.current(identity)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_unapproved_subject_and_browser_state_cannot_create_owner(remote_console, count):
    client, service, provider, _ = remote_console
    from ficc.errors import Failure
    from ficc.identity_store import LOCAL_OWNER
    requests, controls = [], []
    for index in range(count):
        with pytest.raises(Failure) as caught:
            asyncio.run(external_session(service, provider, f"unapproved-{index}"))
        assert caught.value.code == "identity_unapproved"
        with pytest.raises(Failure):
            service.remote_auth.records.save(ISSUER, f"owner-{index}", LOCAL_OWNER, False, 0)
        user, _, _, _ = member(service, f"Approved {index}")
        subject = f"approved-{index}"
        service.remote_auth.records.save(ISSUER, subject, user["id"], False, 0)
        secret, principal = asyncio.run(external_session(service, provider, subject))
        controls.append((principal, session_headers(secret, principal, index)))
        url, browser = asyncio.run(service.remote_auth.begin())
        state = parse_qs(urlsplit(url).query)["state"][0]
        requests.append((state, provider.grant(state, subject), browser))
    for index, (state, code, browser) in enumerate(requests):
        wrong = requests[(index + 1) % count][2] if count > 1 else "wrong-browser"
        headers = {"Cookie": "__Host-ficc_login=" + wrong, "X-FICC-Client-IP": f"198.51.100.{index + 1}"}
        response = client.get("/auth/callback", params={"state": state, "code": code}, headers=headers)
        assert response.headers["location"] == "/?login=failed"
        assert state not in service.remote_auth.pending
        headers["Cookie"] = "__Host-ficc_login=" + browser
        assert client.get("/auth/callback", params={"state": state, "code": code},
                          headers=headers).headers["location"] == "/?login=failed"
        assert client.get("/api/v1/session", headers=headers).status_code == 401
    assert set(service.remote_auth.bindings) == {principal.id for principal, _ in controls}
    for principal, headers in controls:
        assert client.get("/api/v1/session", headers=headers).json()["principal"] == principal.public()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_remote_cookie_csrf_project_rotation_and_logout(remote_console, count):
    client, service, provider, _ = remote_console
    records = []
    for index in range(count):
        user, first, _, _ = member(service, f"Remote operator {index}", scopes=["workspaces:read", "workspaces:write"])
        second = service.auth.identities.create("project", f"Other project {index}")
        service.auth.identities.membership(second["id"], user["id"], ["workspaces:read", "workspaces:write"], 0)
        subject = f"operator-{index}"
        service.remote_auth.records.save(ISSUER, subject, user["id"], False, 0)
        secret, principal = asyncio.run(external_session(service, provider, subject))
        selected = second if principal.project_id == first["id"] else first
        records.append((principal, session_headers(secret, principal, index), selected))
    for index, (principal, headers, selected) in enumerate(records):
        response = client.post("/api/v1/workspaces", json={"name": "No CSRF"},
                               headers={**headers, "X-CSRF-Token": ""})
        assert response.status_code == 403
        other_csrf = records[(index + 1) % count][0].csrf if count > 1 else "invalid-csrf"
        assert client.post("/api/v1/workspaces", json={"name": "Wrong CSRF"},
                           headers={**headers, "X-CSRF-Token": other_csrf}).status_code == 403
        response = client.post("/api/v1/session/project", json={"project_id": selected["id"]}, headers=headers)
        assert response.status_code == 200, response.text
        assert "Secure" in response.headers["set-cookie"]
        changed = response.json()
        assert changed["principal"]["id"] != principal.id
        assert service.auth.current(changed["principal"]["id"]).kind == "remote"
        assert principal.id not in service.remote_auth.bindings
        assert client.get("/api/v1/session", headers=headers).status_code == 401
        current = {**headers, "Cookie": "__Host-ficc_session=" + response.cookies.get("__Host-ficc_session"),
                   "X-CSRF-Token": changed["csrf"]}
        assert client.get("/api/v1/session", headers={**current, "Sec-Fetch-Site": "cross-site"}).status_code == 403
        assert client.get("/api/v1/session", headers={**current, "Origin": "https://other.example"}).status_code == 403
        assert client.delete("/api/v1/session", headers=current).status_code == 200
        assert client.get("/api/v1/session", headers=current).status_code == 401
        for other, _, _ in records[index + 1:]:
            assert service.auth.current(other.id).subject_id == other.subject_id
    assert not service.remote_auth.bindings


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_expired_leases_and_missing_bindings_preserve_other_sessions(remote_console, count):
    client, service, provider, _ = remote_console
    records = []
    for index in range(count * 2):
        user, _, _, _ = member(service, f"Lease member {index}", scopes=["workspaces:read"])
        subject = f"expiring-{index}"
        service.remote_auth.records.save(ISSUER, subject, user["id"], False, 0)
        secret, principal = asyncio.run(external_session(service, provider, subject))
        records.append((principal, session_headers(secret, principal, index)))
    for principal, headers in reversed(records[:count]):
        service.remote_auth.bindings[principal.id]["assertion"]["valid_until"] = time.time() - 1
        assert client.get("/api/v1/session", headers=headers).status_code == 401
        service.remote_auth.bindings.pop(principal.id, None)
        assert client.get("/api/v1/session", headers=headers).status_code == 401
    for principal, headers in records[count:]:
        assert client.get("/api/v1/session", headers=headers).json()["principal"] == principal.public()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_remote_project_switch_uses_each_approved_projects_current_grants(remote_console, count):
    client, service, provider, _ = remote_console
    for index in range(count):
        user, first, _, _ = member(service, f"Project operator {index}", scopes=["workspaces:read"])
        second = service.auth.identities.create("project", f"Write project {index}")
        service.auth.identities.membership(second["id"], user["id"], ["workspaces:read", "workspaces:write"], 0)
        service.remote_auth.records.save(ISSUER, f"project-{index}", user["id"], False, 0)
        assert login(client, provider, f"project-{index}", index).headers["location"] == "/"
        session = client.get("/api/v1/session").json()
        for selected in (first, second, first):
            changed = client.post("/api/v1/session/project", json={"project_id": selected["id"]},
                                  headers={"X-CSRF-Token": session["csrf"]})
            assert changed.status_code == 200, changed.text
            current = changed.json()
            assert current["expires_at"] == session["expires_at"]
            assert ("workspaces:write" in current["principal"]["scopes"]) == (selected == second)
            session = current
        assert client.delete("/api/v1/session", headers={"X-CSRF-Token": session["csrf"]}).status_code == 200


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_failed_admission_audit_leaves_no_remote_authority(remote_console, monkeypatch, count):
    client, service, provider, _ = remote_console
    records = []
    for index in range(count):
        user, _, _, _ = member(service, f"Audited operator {index}", scopes=["workspaces:read"])
        subject = f"audited-{index}"
        service.remote_auth.records.save(ISSUER, subject, user["id"], False, 0)
        secret, principal = asyncio.run(external_session(service, provider, subject))
        records.append((subject, principal, session_headers(secret, principal, index)))
    before = set(service.remote_auth.bindings)
    original = service.store.audit

    def audit(action, *args, **kwargs):
        if action == "session.external" and kwargs.get("actor"):
            raise OSError("injected admission audit failure")
        return original(action, *args, **kwargs)

    monkeypatch.setattr(service.store, "audit", audit)
    from ficc.errors import Failure
    for subject, _, _ in reversed(records):
        with pytest.raises(Failure) as caught:
            asyncio.run(external_session(service, provider, subject))
        assert caught.value.code == "login_invalid"
        assert set(service.remote_auth.bindings) == before
        assert service.store.db.execute("SELECT count(*) FROM credentials WHERE kind='remote'").fetchone()[0] == count
    for _, principal, headers in records:
        assert client.get("/api/v1/session", headers=headers).json()["principal"] == principal.public()
