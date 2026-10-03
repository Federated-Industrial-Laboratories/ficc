# SPDX-License-Identifier: Apache-2.0
"""Make bounded HTTPS requests to explicitly permitted identity endpoints."""

import base64
import threading
import time
from urllib.parse import quote_plus

import httpx

from .config import Config, document

MAX_RESPONSE = 256 * 1024
REQUEST_SECONDS = 5.0
IO_SECONDS = 2.0
CONNECTIONS = 4


class Transport:
    def __init__(self, config: Config):
        self.config = config
        self._slots = threading.BoundedSemaphore(CONNECTIONS)
        self._lock = threading.Lock()
        self._closed = False
        credentials = quote_plus(config.client_id) + ":" + quote_plus(config.secret)
        self._basic = "Basic " + base64.b64encode(credentials.encode()).decode("ascii")
        self._client = httpx.Client(
            verify=config.tls, trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(IO_SECONDS),
            limits=httpx.Limits(max_connections=CONNECTIONS, max_keepalive_connections=CONNECTIONS),
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
        )

    def request(self, endpoint: str, data: dict | None = None, *, empty: bool = False,
                deadline: float | None = None) -> dict:
        endpoint = self.config.endpoint(endpoint)
        started = time.monotonic()
        deadline = min(started + REQUEST_SECONDS, deadline or started + REQUEST_SECONDS)
        if deadline <= started or not self._slots.acquire(timeout=min(IO_SECONDS, deadline - started)):
            raise ValueError("The identity service is busy.")
        try:
            with self._lock:
                if self._closed:
                    raise ValueError("The identity provider is closed.")
            headers = {"Authorization": self._basic} if data is not None else {}
            method = "POST" if data is not None else "GET"
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("The identity request exceeded its deadline.")
            timeout = httpx.Timeout(min(IO_SECONDS, remaining))
            with self._client.stream(method, endpoint, data=data, headers=headers,
                                     timeout=timeout) as response:
                if response.status_code != 200:
                    raise ValueError("The identity service refused the request.")
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise ValueError("Compressed identity responses are not supported.")
                declared = response.headers.get("content-length")
                if declared is not None and (not declared.isdecimal() or int(declared) > MAX_RESPONSE):
                    raise ValueError("The identity response exceeds its limit.")
                raw = bytearray()
                for chunk in response.iter_raw():
                    raw.extend(chunk)
                    if len(raw) > MAX_RESPONSE or time.monotonic() > deadline:
                        raise ValueError("The identity response exceeds its limit.")
                if time.monotonic() > deadline:
                    raise ValueError("The identity request exceeded its deadline.")
                if empty and not raw:
                    return {}
                if response.headers.get("content-type", "").split(";", 1)[0] != "application/json":
                    raise ValueError("The identity response is not JSON.")
                return document(bytes(raw))
        except Exception:
            # HTTP errors can retain request credentials or an untrusted response body.
            raise ValueError("The identity request failed.") from None
        finally:
            self._slots.release()

    def close(self) -> None:
        with self._lock:
            self._closed = True
        # At most four admitted requests can still own the client.
        for _ in range(CONNECTIONS):
            self._slots.acquire()
        try:
            self._client.close()
            self._basic = ""
        finally:
            for _ in range(CONNECTIONS):
                self._slots.release()


def discovery(config: Config, transport: Transport) -> dict[str, str]:
    response = transport.request(config.issuer.rstrip("/") + "/.well-known/openid-configuration")
    if response.get("issuer") != config.issuer:
        raise ValueError("The discovered identity issuer does not match.")
    requirements = {
        "response_types_supported": "code",
        "grant_types_supported": "authorization_code",
        "code_challenge_methods_supported": "S256",
        "token_endpoint_auth_methods_supported": "client_secret_basic",
        "introspection_endpoint_auth_methods_supported": "client_secret_basic",
    }
    for name, required in requirements.items():
        values = response.get(name)
        if (not isinstance(values, list) or not 1 <= len(values) <= 64
                or required not in values or any(not isinstance(item, str) for item in values)):
            raise ValueError("The identity service lacks a required protocol method.")
    if "refresh_token" not in response["grant_types_supported"]:
        raise ValueError("The identity service does not support refresh tokens.")
    if "query" not in response.get("response_modes_supported", ["query"]):
        raise ValueError("The identity service does not support query responses.")
    algorithms = response.get("id_token_signing_alg_values_supported")
    if not isinstance(algorithms, list) or not set(config.algorithms) <= set(algorithms):
        raise ValueError("The identity service lacks the configured signing algorithms.")
    names = ("authorization_endpoint", "token_endpoint", "jwks_uri", "introspection_endpoint")
    result = {name: config.endpoint(response.get(name)) for name in names}
    if "revocation_endpoint" in response:
        methods = response.get("revocation_endpoint_auth_methods_supported",
                               response["token_endpoint_auth_methods_supported"])
        if "client_secret_basic" not in methods:
            raise ValueError("The identity revocation endpoint lacks client authentication.")
        result["revocation_endpoint"] = config.endpoint(response["revocation_endpoint"])
    return result
