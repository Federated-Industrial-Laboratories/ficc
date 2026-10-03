# SPDX-License-Identifier: Apache-2.0
"""Exercise generic remote identity binding with a separate deterministic protocol double."""

import asyncio
import base64
import hashlib
import json
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from fastapi.testclient import TestClient

from ficc import identity_provider
from ficc.api import create_app
from ficc.jobs import Jobs
from ficc.settings import Settings

ORIGIN = "https://controller.example"
ISSUER = "https://identity.example/realms/operations"


class Provider:
    issuer = ISSUER

    def __init__(self):
        self.requests, self.codes, self.handles = {}, {}, {}
        self.denied, self.forgotten, self.batches = set(), [], []
        self.closed = False

    def authorization(self, state, nonce, challenge):
        self.requests[state] = (nonce, challenge)
        return ISSUER + "/auth?" + urlencode({"state": state})

    def grant(self, state, subject):
        code = secrets.token_urlsafe(32)
        self.codes[code] = (*self.requests.pop(state), subject)
        return code

    def complete(self, code, verifier, nonce):
        expected, challenge, subject = self.codes.pop(code)
        assert nonce == expected
        assert base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode() == challenge
        handle = secrets.token_urlsafe(32)
        result = {"handle": handle, "issuer": ISSUER, "subject": subject, "auth_time": time.time() - 5,
                  "expires_at": time.time() + 3600, "valid_until": time.time() + 30}
        self.handles[handle] = result
        return dict(result)

    def renew(self, handles):
        self.batches.append(list(handles))
        return [{"handle": handle, "valid": False} if handle in self.denied else
                {**self.handles[handle], "valid": True, "valid_until": time.time() + 30} for handle in handles]

    def forget(self, handles):
        self.forgotten.extend(handles)
        for handle in handles:
            self.handles.pop(handle, None)

    def close(self):
        self.closed = True
        self.handles.clear()


def configure(state):
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret = secrets.token_urlsafe(32)
    values = {
        "gateway-secret": secret,
        "remote.json": json.dumps({"origin": ORIGIN, "socket": str(state.parent / "gateway.sock"),
                                   "gateway_secret_file": str(state / "gateway-secret")}),
        "identity-provider.json": json.dumps({"provider": "test-identity", "configuration": {}}),
    }
    for name, value in values.items():
        path = state / name
        path.write_text(value)
        path.chmod(0o600)
    return {"X-FICC-Gateway": secret, "X-FICC-Client-IP": "198.51.100.1", "Origin": ORIGIN}


@pytest.fixture
def remote_console(tmp_path, monkeypatch):
    state = tmp_path / "state"
    headers = configure(state)
    provider = Provider()
    monkeypatch.setattr(identity_provider, "create", lambda *args: provider)
    async def idle(self):
        await asyncio.Event().wait()
    monkeypatch.setattr(Jobs, "poll", idle)
    app = create_app(Settings(state_dir=state, control=False, poll_interval=3600, stale_after=7200))
    with TestClient(app, base_url=ORIGIN, headers=headers, follow_redirects=False) as client:
        yield client, app.state.service, provider, headers
    assert provider.closed


def login(client, provider, subject, index=0):
    address = {"X-FICC-Client-IP": f"198.51.100.{index + 1}"}
    response = client.post("/auth/start", headers=address)
    assert response.status_code == 200, response.text
    state = parse_qs(urlsplit(response.json()["url"]).query)["state"][0]
    code = provider.grant(state, subject)
    response = client.get("/auth/callback", params={"state": state, "code": code, "iss": ISSUER},
                          headers={**address, "Origin": ISSUER, "Sec-Fetch-Site": "cross-site"})
    return response


async def external_session(service, provider, subject):
    url, browser = await service.remote_auth.begin()
    state = parse_qs(urlsplit(url).query)["state"][0]
    return await service.remote_auth.complete(state, provider.grant(state, subject), browser, ISSUER)


def session_headers(secret, principal, index=0):
    return {"Cookie": "__Host-ficc_session=" + secret, "X-CSRF-Token": principal.csrf,
            "X-FICC-Client-IP": f"198.51.100.{index + 1}"}
