# SPDX-License-Identifier: Apache-2.0
"""Adapt approved node requests to the private Smallstep authority."""

import base64
import hashlib
import secrets
import threading
import time
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from joserfc import jwt
from joserfc.jwk import ECKey

from .config import configuration
from .transport import Transport
from .validation import chain, issued, request


class Provider:
    def __init__(self, value: dict):
        self.config, key = configuration(value)
        self._key: ECKey | None = key
        self._transport = Transport(self.config)
        self._lock = threading.Lock()
        self._closed = False

    def _token(self, subject: str, path: str, extra: dict) -> str:
        with self._lock:
            if self._closed or self._key is None:
                raise ValueError("The certificate provider is closed.")
            now = int(time.time())
            claims = {"iss": self.config.provisioner, "sub": subject,
                      "aud": [self.config.url + path], "iat": now, "nbf": now,
                      "exp": now + 60, "jti": secrets.token_hex(32), **extra}
            return jwt.encode({"alg": "ES256", "kid": self.config.kid, "typ": "JWT"},
                              claims, self._key, algorithms=["ES256"])

    def issue(self, value: dict) -> dict[str, str]:
        deadline = time.monotonic() + self.config.seconds
        try:
            value, csr = request(value, self.config)
            before = datetime.now(UTC).replace(microsecond=0)
            after = before + timedelta(seconds=value["validity_seconds"])
            fingerprint = base64.urlsafe_b64encode(hashlib.sha256(
                csr.public_bytes(serialization.Encoding.DER)).digest()).rstrip(b"=").decode("ascii")
            token = self._token(value["node_id"], "/sign", {
                "sans": [value["identity_uri"]], "cnf": {"x5rt#S256": fingerprint},
                "ficc_request": value["request_id"],
            })
            body = {"csr": value["csr_pem"], "ott": token,
                    "notBefore": before.isoformat(), "notAfter": after.isoformat()}
            status, response = self._transport.request("/sign", body, deadline)
            if status != 201:
                raise ValueError
            pem = issued(response, value, csr, self.config, before, after)
            if time.monotonic() > deadline:
                raise ValueError
            return {"certificate_chain": pem}
        except Exception:
            raise ValueError("Certificate issuance failed; its authority result may be uncertain.") \
                from None

    def revoke(self, certificate_chain: str, reason: str) -> None:
        deadline = time.monotonic() + self.config.seconds
        try:
            codes = {"superseded": 4, "disabled": 5, "recovery": 1}
            if reason not in codes:
                raise ValueError
            leaf = chain(certificate_chain, self.config, expired=True)[0]
            serial = str(leaf.serial_number)
            token = self._token(serial, "/revoke", {})
            status, response = self._transport.request("/revoke", {
                "serial": serial, "ott": token, "reasonCode": codes[reason],
                "reason": reason, "passive": True,
            }, deadline)
            duplicate = {"status": 400, "message": "The request could not be completed: "
                         f"certificate with serial number '{serial}' is already revoked."}
            if not (status == 200 and response == {"status": "ok"}
                    or status == 400 and response == duplicate):
                raise ValueError
        except Exception:
            raise ValueError("Certificate revocation failed; its authority result may be uncertain.") \
                from None

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._key = None
        self._transport.close()
