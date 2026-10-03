# SPDX-License-Identifier: Apache-2.0
"""Qualify an explicitly selected live HTTPS gateway and its private identity boundary."""

import os

import httpx
import pytest


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_real_gateway_keeps_identity_administration_private(count):
    origin = os.environ.get("FICC_TEST_HTTPS_GATEWAY")
    if not origin:
        pytest.skip("Select an isolated live HTTPS gateway with the supplied identity profile.")
    issuer = origin + "/auth/realms/ficc"
    with httpx.Client(base_url=origin, timeout=15, follow_redirects=False, trust_env=False) as client:
        for index in range(count):
            response = client.get("/auth/realms/ficc/.well-known/openid-configuration",
                                  headers={"X-Forwarded-Host": "attacker.example", "X-Forwarded-Proto": "http",
                                           "Forwarded": "host=attacker.example;proto=http"})
            assert response.status_code == 200
            value = response.json()
            assert value["issuer"] == issuer and "S256" in value["code_challenge_methods_supported"]
            for name in ("authorization_endpoint", "token_endpoint", "introspection_endpoint", "jwks_uri"):
                assert value[name].startswith(issuer + "/")
            paths = ["/auth/admin/", "/auth/realms/master/.well-known/openid-configuration", "/auth/health",
                     "/auth/metrics", "/auth/realms/ficc/account/", "/health", "/metrics", "/config/",
                     "/auth/realms/ficc/login-actions/%252e%252e/%252e%252e/master/",
                     "/auth/resources/%2f..%2fadmin/", "/auth/resources/%5c..%5cadmin/",
                     "/auth/resources/..%2f..%2fadmin/", "/auth/realms/ficc%2f..%2fmaster/",
                     "/auth/realms/ficc/login-actions/%252fadmin/", "/auth//realms/master/",
                     "/auth/realms/ficc/protocol/openid-connect/../../../../admin/"]
            blocked = client.get(paths[index % len(paths)])
            assert blocked.status_code in {400, 403, 404, 503}, (blocked.status_code, paths[index % len(paths)])
            assert "access_token" not in blocked.text
        assert client.post("/auth/realms/ficc/protocol/openid-connect/token", content=b"x" * 65537).status_code == 413
