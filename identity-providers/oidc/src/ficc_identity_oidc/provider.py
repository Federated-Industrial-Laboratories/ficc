# SPDX-License-Identifier: Apache-2.0
"""Hold external tokens in memory and issue short identity verification leases."""

import json
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from urllib.parse import urlencode

from .config import Config, binding, text, timestamp
from .tokens import MAX_TOKEN, Verifier, introspection
from .transport import CONNECTIONS, Transport, discovery

LEASE_SECONDS = 30
MAX_SESSIONS = 1024
REFRESH_SECONDS = 45
BATCH_SECONDS = 20


@dataclass(repr=False)
class Session:
    handle: str
    subject: str
    auth_time: float
    expires_at: float
    access: str
    refresh: str
    token_expiry: float
    identity_expiry: float
    nonce: str
    acr: str
    verified_at: float
    lock: threading.Lock = field(default_factory=threading.Lock)

    def erase(self) -> None:
        self.access = self.refresh = self.nonce = ""


def handles(value: object) -> list[str]:
    if (not isinstance(value, list) or not 1 <= len(value) <= 64
            or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", item)
                   for item in value) or len(set(value)) != len(value)):
        raise ValueError("Use from 1 to 64 distinct identity handles.")
    return value


class Provider:
    def __init__(self, config: Config):
        self.issuer = config.issuer
        self.config = config
        self._lock = threading.Lock()
        self._closed = False
        self._sessions: dict[str, Session] = {}
        self._admission = threading.BoundedSemaphore(CONNECTIONS)
        self._renewing = threading.Lock()
        self.transport = Transport(config)
        try:
            self.endpoints = discovery(config, self.transport)
            self.verifier = Verifier(config, self.transport, self.endpoints["jwks_uri"])
        except Exception:
            self.transport.close()
            raise ValueError("The identity provider could not be initialized.") from None
        self._workers = ThreadPoolExecutor(max_workers=CONNECTIONS, thread_name_prefix="ficc-identity")

    def authorization(self, state: str, nonce: str, challenge: str) -> str:
        state, nonce, challenge = binding(state), binding(nonce), binding(challenge, challenge=True)
        with self._lock:
            if self._closed:
                raise ValueError("The identity provider is closed.")
        return self.endpoints["authorization_endpoint"] + "?" + urlencode({
            "client_id": self.config.client_id, "redirect_uri": self.config.callback,
            "response_type": "code", "response_mode": "query", "scope": "openid",
            "state": state, "nonce": nonce, "code_challenge": challenge,
            "code_challenge_method": "S256", "max_age": str(self.config.max_age),
            "acr_values": " ".join(self.config.acr),
            "claims": json.dumps({"id_token": {"acr": {"essential": True,
                                                       "values": list(self.config.acr)}}},
                                 separators=(",", ":")),
        })

    def _tokens(self, response: dict, nonce: str, *, initial: bool,
                deadline: float | None = None) -> tuple[str, str, dict, float, float]:
        if response.get("token_type", "").lower() != "bearer" or "error" in response:
            raise ValueError("The identity token response is invalid.")
        access = text(response.get("access_token"), MAX_TOKEN)
        refresh = text(response.get("refresh_token"), MAX_TOKEN)
        lifetime = timestamp(response.get("expires_in"))
        if not 0 < lifetime <= 86400:
            raise ValueError("The identity access token lifetime is invalid.")
        claims = self.verifier.claims(response.get("id_token"), access, nonce, initial=initial,
                                      deadline=deadline)
        token_expiry = time.time() + lifetime
        verified_at = time.time()
        result = self.transport.request(self.endpoints["introspection_endpoint"],
                                        {"token": access, "token_type_hint": "access_token"},
                                        deadline=deadline)
        token_expiry = min(token_expiry, introspection(result, self.config, claims["sub"]))
        return access, refresh, claims, token_expiry, verified_at

    def _assertion(self, session: Session) -> dict:
        now = time.time()
        valid_until = min(session.verified_at + LEASE_SECONDS, session.expires_at,
                          session.token_expiry, session.identity_expiry)
        if valid_until <= now:
            raise ValueError("The external session has expired.")
        return {"handle": session.handle, "issuer": self.issuer, "subject": session.subject,
                "auth_time": session.auth_time, "expires_at": session.expires_at,
                "valid_until": valid_until}

    def complete(self, code: str, verifier: str, nonce: str) -> dict:
        code, nonce = text(code, 4096), binding(nonce)
        if not isinstance(verifier, str) or not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier):
            raise ValueError("The authentication verifier is invalid.")
        if not self._admission.acquire(blocking=False):
            raise ValueError("The identity provider is busy.")
        try:
            deadline = time.monotonic() + BATCH_SECONDS
            with self._lock:
                if self._closed or len(self._sessions) >= MAX_SESSIONS:
                    raise ValueError("The identity provider cannot admit a session.")
            response = self.transport.request(self.endpoints["token_endpoint"], {
                "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
                "redirect_uri": self.config.callback,
            }, deadline=deadline)
            access, refresh, claims, expiry, verified_at = self._tokens(response, nonce, initial=True,
                                                                       deadline=deadline)
            now, authenticated = time.time(), timestamp(claims["auth_time"])
            session = Session(secrets.token_urlsafe(32), claims["sub"], authenticated,
                              min(now + self.config.session_seconds, authenticated + self.config.max_age),
                              access, refresh, expiry, timestamp(claims["exp"]), nonce, claims["acr"],
                              verified_at)
            result = self._assertion(session)
            with self._lock:
                if self._closed or len(self._sessions) >= MAX_SESSIONS:
                    session.erase()
                    raise ValueError("The identity provider cannot admit a session.")
                self._sessions[session.handle] = session
            return result
        except Exception:
            raise ValueError("External authentication failed.") from None
        finally:
            self._admission.release()

    def _renew(self, handle: str, deadline: float) -> dict:
        denied = {"handle": handle, "valid": False}
        with self._lock:
            session = self._sessions.get(handle)
        if session is None:
            return denied
        with session.lock:
            try:
                with self._lock:
                    if self._closed or self._sessions.get(handle) is not session:
                        return denied
                now = time.time()
                if now >= session.expires_at or time.monotonic() >= deadline:
                    raise ValueError("The external session has expired.")
                if min(session.token_expiry, session.identity_expiry) - now <= REFRESH_SECONDS:
                    # Any uncertain response destroys this handle; rotating refresh tokens are not replayed.
                    response = self.transport.request(self.endpoints["token_endpoint"], {
                        "grant_type": "refresh_token", "refresh_token": session.refresh,
                    }, deadline=deadline)
                    access, refresh, claims, expiry, verified_at = self._tokens(
                        response, session.nonce, initial=False, deadline=deadline)
                    if (claims["sub"] != session.subject or claims["acr"] != session.acr
                            or timestamp(claims["auth_time"]) != session.auth_time
                            or refresh == session.refresh):
                        raise ValueError("The refreshed identity or token rotation is invalid.")
                    session.access, session.refresh = access, refresh
                    session.token_expiry, session.identity_expiry = expiry, timestamp(claims["exp"])
                    session.verified_at = verified_at
                else:
                    verified_at = time.time()
                    result = self.transport.request(self.endpoints["introspection_endpoint"],
                                                     {"token": session.access,
                                                     "token_type_hint": "access_token"},
                                                    deadline=deadline)
                    session.token_expiry = min(session.token_expiry,
                                              introspection(result, self.config, session.subject))
                    session.verified_at = verified_at
                assertion = self._assertion(session)
                with self._lock:
                    if self._closed or self._sessions.get(handle) is not session:
                        return denied
                return {**assertion, "valid": True}
            except Exception:
                with self._lock:
                    self._sessions.pop(handle, None)
                session.erase()
                return denied

    def renew(self, values: list[str]) -> list[dict]:
        values = handles(values)
        # One batch at a time prevents unbounded executor queues from overlapping callers.
        if not self._renewing.acquire(blocking=False):
            return [{"handle": handle, "valid": False} for handle in values]
        try:
            with self._lock:
                if self._closed:
                    return [{"handle": handle, "valid": False} for handle in values]
                deadline = time.monotonic() + BATCH_SECONDS
                futures = [self._workers.submit(self._renew, handle, deadline) for handle in values]
            return [future.result() for future in futures]
        finally:
            self._renewing.release()

    def _revoke(self, session: Session, deadline: float) -> None:
        with session.lock:
            token = session.refresh
            session.erase()
        endpoint = self.endpoints.get("revocation_endpoint")
        if endpoint and token:
            try:
                self.transport.request(endpoint, {"token": token, "token_type_hint": "refresh_token"},
                                       empty=True, deadline=deadline)
            except ValueError:
                pass

    def forget(self, values: list[str]) -> None:
        values = handles(values)
        with self._lock:
            removed = [self._sessions.pop(handle) for handle in values if handle in self._sessions]
            if self._closed:
                return
        # Local removal precedes every external request, including a failed revocation request.
        deadline = time.monotonic() + BATCH_SECONDS
        for session in removed:
            self._revoke(session, deadline)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            removed = list(self._sessions.values())
            self._sessions.clear()
        self._workers.shutdown(wait=True, cancel_futures=False)
        for _ in range(CONNECTIONS):
            self._admission.acquire()
        self.transport.close()
        for session in removed:
            with session.lock:
                session.erase()
        self.config = replace(self.config, secret="")
        self.transport.config = self.config
        self.verifier.config = self.config
        for _ in range(CONNECTIONS):
            self._admission.release()
