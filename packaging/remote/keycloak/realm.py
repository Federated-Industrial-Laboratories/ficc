#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Write a private Keycloak realm import with exact redirects and enforced two-factor login.
# Inputs: public HTTPS origin and private client secret. Output: realm JSON. Exit: 0 success, 1 failure.
"""Generate a replaceable organization identity profile without storing secrets in source."""

import argparse
import json
import os
import re
import stat
from pathlib import Path
from urllib.parse import urlsplit


def profile(origin, client_secret, realm="ficc"):
    url = urlsplit(origin)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.path or url.query or url.fragment or not origin.isascii()
            or any(ord(char) <= 32 for char in origin) or "\\" in origin
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", realm)):
        raise ValueError("Select an exact HTTPS origin and a simple realm name.")
    if not isinstance(client_secret, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", client_secret):
        raise ValueError("Select a random confidential client secret with at least 256 bits of entropy.")

    def flow(alias, executions, top=False):
        return {"alias": alias, "providerId": "basic-flow", "topLevel": top, "builtIn": False,
                "authenticationExecutions": [{"priority": index * 10, **value} for index, value in enumerate(executions, 1)]}

    def nested(alias, requirement):
        return {"flowAlias": alias, "authenticatorFlow": True, "requirement": requirement, "userSetupAllowed": False}

    def step(authenticator, configuration=None, requirement="REQUIRED"):
        result = {"authenticator": authenticator, "authenticatorFlow": False, "requirement": requirement,
                  "userSetupAllowed": False}
        if configuration:
            result["authenticatorConfig"] = configuration
        return result

    return {
        "realm": realm, "enabled": True, "displayName": "FICC organisation access", "sslRequired": "all",
        "registrationAllowed": False, "resetPasswordAllowed": False, "rememberMe": False,
        "loginWithEmailAllowed": False, "duplicateEmailsAllowed": False, "editUsernameAllowed": False,
        "bruteForceProtected": True, "permanentLockout": False, "failureFactor": 5,
        "waitIncrementSeconds": 60, "maxFailureWaitSeconds": 900, "maxDeltaTimeSeconds": 43200,
        "accessTokenLifespan": 300, "ssoSessionIdleTimeout": 1800, "ssoSessionMaxLifespan": 28800,
        "revokeRefreshToken": True, "refreshTokenMaxReuse": 0,
        "passwordPolicy": "length(14) and notUsername(undefined) and notEmail(undefined)",
        "otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1", "otpPolicyDigits": 6, "otpPolicyPeriod": 30,
        "browserFlow": "FICC browser",
        "authenticationFlows": [
            flow("FICC browser", [step("auth-cookie", requirement="ALTERNATIVE"), nested("FICC forms", "ALTERNATIVE")], True),
            flow("FICC forms", [nested("FICC password", "CONDITIONAL"), nested("FICC second factor", "CONDITIONAL")]),
            flow("FICC password", [step("conditional-level-of-authentication", "FICC level one"), step("auth-username-password-form")]),
            flow("FICC second factor", [step("conditional-level-of-authentication", "FICC level two"), step("auth-otp-form")]),
        ],
        "authenticatorConfig": [
            {"alias": "FICC level one", "config": {"loa-condition-level": "1", "loa-max-age": "28800"}},
            {"alias": "FICC level two", "config": {"loa-condition-level": "2", "loa-max-age": "0"}},
        ],
        "clients": [{
            "clientId": "ficc", "name": "FICC", "enabled": True, "protocol": "openid-connect",
            "publicClient": False, "clientAuthenticatorType": "client-secret", "secret": client_secret,
            "standardFlowEnabled": True, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False, "fullScopeAllowed": False,
            "redirectUris": [origin + "/auth/callback"], "webOrigins": [origin],
            "defaultClientScopes": ["basic", "acr"], "optionalClientScopes": [],
            "protocolMappers": [{
                "name": "FICC audience", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
                "config": {"included.client.audience": "ficc", "access.token.claim": "true",
                           "id.token.claim": "false", "introspection.token.claim": "true",
                           "lightweight.claim": "true"},
            }],
            "attributes": {"pkce.code.challenge.method": "S256", "minimum.acr.value": "2",
                           "default.acr.values": "2", "acr.loa.map": '{"2":2}',
                           "id.token.signed.response.alg": "RS256", "use.refresh.tokens": "true"},
        }],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--client-secret-file", type=Path, required=True)
    parser.add_argument("--realm", default="ficc")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    descriptor = os.open(args.client_secret_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError("The client secret must be a private regular file owned by this account.")
        secret = os.read(descriptor, 257).decode("ascii").strip()
    finally:
        os.close(descriptor)
    value = profile(args.origin, secret, args.realm)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


if __name__ == "__main__":
    main()
