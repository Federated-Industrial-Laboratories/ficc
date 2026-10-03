# SPDX-License-Identifier: Apache-2.0
"""Reject forged gateway traffic and restrict external login navigation to public routes."""

from types import SimpleNamespace

import pytest
from remote_fixtures import ORIGIN
from starlette.websockets import WebSocketDisconnect

from ficc import remote_ingress


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_private_gateway_is_required_for_http_and_websockets(remote_console, count):
    client, _, _, _ = remote_console
    for index in range(count):
        headers = {"X-FICC-Gateway": f"forged-{index}", "X-Forwarded-Proto": "https",
                   "X-Forwarded-For": "127.0.0.1", "X-FICC-Client-IP": f"198.51.100.{index + 1}"}
        assert client.get("/api/v1/login", headers=headers).status_code == 403
        with pytest.raises(WebSocketDisconnect) as caught:
            with client.websocket_connect(ORIGIN.replace("https", "wss") + "/api/v1/terminals/unknown/stream", headers=headers):
                pass
        assert caught.value.code == 4403
    response = client.get("/api/v1/login")
    assert response.status_code == 200 and response.json()["ready"]
    assert "wss://controller.example" in response.headers["content-security-policy"]
    assert "ws://127.0.0.1" not in response.headers["content-security-policy"]


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_origin_headers_reject_distinct_untrusted_clients(remote_console, count):
    client, _, _, _ = remote_console
    for index in range(count):
        headers = {"X-FICC-Client-IP": f"198.51.100.{index + 1}"}
        assert client.post("/auth/start", headers={**headers, "Origin": f"https://attacker-{index}.example"}).status_code == 403
        assert client.post("/auth/start", headers={**headers, "Sec-Fetch-Site": "cross-site"}).status_code == 403
        assert client.get("/api/v1/login", headers={**headers, "Host": f"attacker-{index}.example"}).status_code == 403
        assert client.get("/api/v1/login", headers={"X-FICC-Client-IP": f"arbitrary-{index}, 127.0.0.1"}).status_code == 403
        assert client.get("/auth/callback?state=" + "x" * (9000 + index), headers=headers).status_code == 414
        assert client.get("/api/v1/login", headers={**headers, "X-FICC-Gateway": ""}).status_code == 403


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_external_login_landing_does_not_open_cross_site_api_access(remote_console, count):
    client, _, _, _ = remote_console
    client.headers.pop("origin")
    normal = client.get("/")
    assert normal.status_code in {200, 503}
    if normal.status_code == 503:
        assert normal.json()["error"]["code"] == "assets_missing"
    for index in range(count):
        headers = {"X-FICC-Client-IP": f"198.51.100.{index + 1}", "Sec-Fetch-Site": "cross-site",
                   "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
        landing = client.get("/", headers=headers)
        assert landing.status_code == normal.status_code and landing.content == normal.content
        assert "set-cookie" not in landing.headers
        assert landing.headers["x-frame-options"] == "DENY"
        for path in ("/api/v1/session", "/api/v1/nodes", "/static/index.html"):
            denied = client.get(path, headers=headers)
            assert denied.status_code == 403 and denied.json()["error"]["code"] == "invalid_origin"
        for change in ({"Sec-Fetch-Mode": "cors"}, {"Sec-Fetch-Dest": "iframe"},
                       {"Sec-Fetch-Mode": "", "Sec-Fetch-Dest": ""},
                       {"Origin": f"https://attacker-{index}.example"},
                       {"Host": f"attacker-{index}.example"}):
            assert client.get("/", headers={**headers, **change}).status_code == 403
        assert client.post("/", headers=headers).status_code == 403


def test_bounded_login_admission_through_http(remote_console):
    client, service, _, _ = remote_console
    responses = [client.post("/auth/start").status_code for _ in range(40)]
    assert 200 in responses and 429 in responses
    assert len(service.remote_auth.pending) <= 16


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_rate_limits_keep_distinct_client_buckets_separate(remote_console, monkeypatch, count):
    _, service, _, gateway = remote_console
    clock = [0.0]
    monkeypatch.setattr(remote_ingress, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    ingress = remote_ingress.RemoteIngress(None, service.settings)

    def scope(address):
        return {"type": "http", "path": "/auth/start", "raw_path": b"/auth/start", "query_string": b"",
                "headers": [(b"x-ficc-gateway", gateway["X-FICC-Gateway"].encode()),
                            (b"x-ficc-client-ip", address.encode())]}

    for index in range(count):
        address = f"198.51.100.{index + 1}"
        results = [ingress.check(scope(address)) for _ in range(40)]
        assert results[:16] == [None] * 16
        assert results[16:] == [("capacity", 429)] * 24
        assert ingress.check(scope(f"203.0.113.{index + 1}")) is None
        clock[0] += 30
        assert ingress.check(scope(address)) is None
