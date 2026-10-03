# SPDX-License-Identifier: Apache-2.0
"""Verify signed identity tokens and current token introspection results."""

import base64
import threading
import time

from authlib.oidc.core import CodeIDToken
from joserfc import jwk, jwt

from .config import Config, Decoder, document, text, timestamp
from .transport import Transport

MAX_TOKEN = 16 * 1024
KEY_SECONDS = 300
KEY_RETRY_SECONDS = 5
CLOCK_SKEW = 30


class Verifier:
    def __init__(self, config: Config, transport: Transport, endpoint: str):
        self.config, self.transport, self.endpoint = config, transport, endpoint
        self._lock = threading.Lock()
        self._updated = 0.0
        self._attempted = 0.0
        self._keys: dict[str, dict] = {}
        self._load()

    def _load(self, deadline: float | None = None) -> None:
        self._attempted = time.monotonic()
        result = self.transport.request(self.endpoint, deadline=deadline).get("keys")
        if not isinstance(result, list) or not 1 <= len(result) <= 32:
            raise ValueError("The identity key set is invalid.")
        keys: dict[str, dict] = {}
        for item in result:
            if not isinstance(item, dict):
                raise ValueError("The identity key is invalid.")
            if item.get("use", "sig") != "sig":
                continue
            if item.get("kty") not in ("RSA", "EC"):
                continue
            kid = text(item.get("kid"), 128)
            if (kid in keys or {"d", "p", "q", "dp", "dq", "qi", "oth", "k"} & item.keys()
                    or item.get("key_ops", ["verify"]) != ["verify"]):
                raise ValueError("The identity verification key is invalid.")
            if item["kty"] == "RSA":
                text(item.get("n"), 1366)
                text(item.get("e"), 12)
            key = jwk.import_key(item)
            if isinstance(key, jwk.RSAKey) and not 2048 <= key.public_key.key_size <= 8192:
                raise ValueError("The identity verification key size is unsupported.")
            keys[kid] = item
        if not keys:
            raise ValueError("The identity service has no supported signing keys.")
        self._keys = keys
        self._updated = time.monotonic()

    def _key(self, kid: str, alg: str, *, retry: bool = False, deadline: float | None = None):
        with self._lock:
            age = time.monotonic() - self._updated
            attempted = time.monotonic() - self._attempted
            if age >= KEY_SECONDS or ((kid not in self._keys or retry) and attempted >= KEY_RETRY_SECONDS):
                if attempted < KEY_RETRY_SECONDS:
                    raise ValueError("The identity key refresh is unavailable.")
                self._load(deadline)
            item = self._keys.get(kid)
            expected = "EC" if alg.startswith("ES") else "RSA"
            if not item or item["kty"] != expected or item.get("alg", alg) != alg:
                raise ValueError("The identity signing key is unavailable.")
            return jwk.import_key(item)

    def claims(self, encoded: object, access: str, nonce: str, *, initial: bool = True,
               deadline: float | None = None) -> dict:
        try:
            encoded = text(encoded, MAX_TOKEN)
            parts = encoded.split(".")
            if len(parts) != 3 or len(parts[0]) > 4096:
                raise ValueError("The identity token is invalid.")
            header = document(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
            if (set(header) - {"alg", "kid", "typ"} or header.get("alg") not in self.config.algorithms
                    or header.get("typ", "JWT") != "JWT"):
                raise ValueError("The identity token header is invalid.")
            kid, alg = text(header.get("kid"), 128), header["alg"]
            key = self._key(kid, alg, deadline=deadline)
            try:
                token = jwt.decode(encoded, key, algorithms=self.config.algorithms, decoder_cls=Decoder)
            except Exception:
                key = self._key(kid, alg, retry=True, deadline=deadline)
                token = jwt.decode(encoded, key, algorithms=self.config.algorithms, decoder_cls=Decoder)
            claims = token.claims
            if not isinstance(claims, dict):
                raise ValueError("The identity claims are invalid.")
            now = time.time()
            issued, expires, authenticated = (timestamp(claims.get(name))
                                              for name in ("iat", "exp", "auth_time"))
            if (expires <= now or issued > now + CLOCK_SKEW or expires <= issued
                    or authenticated > now + CLOCK_SKEW or authenticated > issued + CLOCK_SKEW
                    or now - authenticated >= self.config.max_age):
                raise ValueError("The identity token lifetime is invalid.")
            if "nbf" in claims and timestamp(claims["nbf"]) > now + CLOCK_SKEW:
                raise ValueError("The identity token is not yet valid.")
            text(claims.get("sub"), 255)
            audience = claims.get("aud")
            audiences = [audience] if isinstance(audience, str) else audience
            if (not isinstance(audiences, list) or not 1 <= len(audiences) <= 32
                    or any(not isinstance(item, str) for item in audiences)
                    or self.config.client_id not in audiences
                    or len(set(audiences)) != len(audiences)
                    or (len(audiences) > 1 and claims.get("azp") != self.config.client_id)
                    or ("azp" in claims and claims["azp"] != self.config.client_id)):
                raise ValueError("The identity token audience is invalid.")
            if claims.get("iss") != self.config.issuer or claims.get("acr") not in self.config.acr:
                raise ValueError("The identity token issuer or assurance is invalid.")
            if initial or "nonce" in claims:
                if claims.get("nonce") != nonce:
                    raise ValueError("The identity token nonce is invalid.")
            for name in ("nonce", "at_hash"):
                if name in claims:
                    text(claims[name], 256)
            if "amr" in claims and (not isinstance(claims["amr"], list)
                    or len(claims["amr"]) > 32
                    or any(not isinstance(item, str) for item in claims["amr"])):
                raise ValueError("The identity authentication methods are invalid.")
            CodeIDToken(claims, header, params={
                "client_id": self.config.client_id, "access_token": access,
                "nonce": nonce if initial or "nonce" in claims else None,
                "max_age": self.config.max_age,
            }).validate(now=now, leeway=CLOCK_SKEW)
            return claims
        except Exception:
            raise ValueError("The identity token could not be verified.") from None


def introspection(result: dict, config: Config, subject: str) -> float:
    if (result.get("active") is not True or result.get("sub") != subject
            or result.get("client_id") != config.client_id
            or result.get("iss", config.issuer) != config.issuer):
        raise ValueError("The external session is not active.")
    expires = timestamp(result.get("exp"))
    if expires <= time.time():
        raise ValueError("The external session has expired.")
    return expires
