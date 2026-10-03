# SPDX-License-Identifier: Apache-2.0
"""Bind browser logins and renewable external authority to current local identities."""

import asyncio
import base64
import hashlib
import secrets
import time

from . import identity_provider
from .auth import digest
from .errors import Failure
from .external_identity_store import ExternalIdentities
from .identity_store import LOCAL_OWNER


class RemoteAuth:
    def __init__(self, service):
        self.service = service
        self.records = ExternalIdentities(service.store)
        self.configuration = identity_provider.configuration(service.settings.state_dir)
        self.provider = None
        self.pending: dict[str, dict] = {}
        self.bindings: dict[str, dict] = {}
        self.retired: set[str] = set()
        self.slots = asyncio.Semaphore(8)
        self.loading = asyncio.Lock()
        self.error = False
        service.auth.external_check = self.check
        service.auth.external_rotate = self.rotate
        service.auth.external_revoke = self.remove
        # External tokens are memory-only, so persisted sessions cannot survive restart.
        with service.store.lock, service.store.db:
            service.store.db.execute("DELETE FROM credentials WHERE kind='remote'")

    @property
    def callback(self):
        return self.service.settings.origin + "/auth/callback"

    def status(self):
        return {"remote": self.service.settings.remote is not None,
                "configured": self.configuration is not None,
                "ready": self.provider is not None, "verification_seconds": 30,
                "issuer": self.provider.issuer if self.provider else None}

    async def start(self):
        if self.configuration is None or self.service.settings.remote is None:
            return
        async with self.loading:
            if self.provider is not None:
                return
            try:
                self.provider = await asyncio.to_thread(identity_provider.create, self.configuration, self.callback)
                self.error = False
            except Exception:
                self.error = True

    async def begin(self):
        if self.slots.locked():
            raise Failure("capacity", "Wait before starting another sign-in.", 429)
        async with self.slots:
            await self.start()
            if self.provider is None:
                raise Failure("identity_unavailable", "External sign-in is unavailable. Contact the installation administrator.", 503)
            now = time.monotonic()
            self.pending = {key: value for key, value in self.pending.items() if value["deadline"] > now}
            if len(self.pending) >= 128:
                raise Failure("capacity", "The sign-in limit was reached. Try again shortly.", 429)
            state, nonce, verifier, browser = (secrets.token_urlsafe(32) for _ in range(4))
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            self.pending[state] = {"nonce": nonce, "verifier": verifier, "browser": digest(browser),
                                   "deadline": now + 300, "provider": self.provider}
            ready = False
            try:
                url = await asyncio.to_thread(self.provider.authorization, state, nonce, challenge)
                from urllib.parse import urlsplit

                from .remote_settings import https_url
                if not isinstance(url, str) or len(url) > 8192:
                    raise ValueError("Invalid authorization URL")
                parsed = urlsplit(url)
                https_url(parsed._replace(query="").geturl())
                ready = True
                return url, browser
            except Exception:
                raise Failure("identity_unavailable", "External sign-in could not be started.", 503) from None
            finally:
                if not ready:
                    self.pending.pop(state, None)

    async def complete(self, state, code, browser, issuer=None):
        pending = self.pending.pop(state, None)
        if (pending is None or pending["deadline"] <= time.monotonic()
                or not isinstance(browser, str) or len(browser) > 128
                or not secrets.compare_digest(pending["browser"], digest(browser))
                or pending["provider"] is not self.provider
                or issuer is not None and issuer != self.provider.issuer):
            raise Failure("login_invalid", "The sign-in request expired or does not belong to this browser.", 401)
        if self.slots.locked():
            raise Failure("capacity", "The sign-in service is busy. Start a new sign-in.", 429)
        assertion = None
        credential_id = None
        async with self.slots:
            try:
                result = await asyncio.to_thread(self.provider.complete, code, pending["verifier"], pending["nonce"])
                assertion = identity_provider.assertion(result, self.provider.issuer)
                with self.service.store.lock, self.service.store.db:
                    mapping = self.records.find(assertion["issuer"], assertion["subject"])
                    if mapping is None or mapping["disabled"] or mapping["subject_id"] == LOCAL_OWNER:
                        raise Failure("identity_unapproved", "An administrator must approve this identity before sign-in.", 403)
                    identities = self.service.auth.identities
                    if identities.user(mapping["subject_id"])["disabled"]:
                        raise Failure("identity_unapproved", "This local identity is disabled.", 403)
                    projects = identities.projects(mapping["subject_id"])
                    if not projects:
                        raise Failure("identity_unapproved", "An administrator must assign this identity to a project.", 403)
                    lifetime = max(1, int(assertion["expires_at"] - time.time()))
                    secret, principal = self.service.auth.issue("remote", subject_id=mapping["subject_id"],
                                                                project_id=projects[0]["id"], lifetime=lifetime)
                    credential_id = principal.id
                    self.bindings[principal.id] = {"assertion": assertion, "mapping": mapping}
                    self.service.store.audit("session.external", principal.id, actor=principal.id,
                                             subject_id=principal.subject_id, project_id=principal.project_id)
                return secret, principal
            except Failure:
                if credential_id is not None:
                    self.bindings.pop(credential_id, None)
                if assertion:
                    self.retired.add(assertion["handle"])
                raise
            except Exception:
                if credential_id is not None:
                    self.bindings.pop(credential_id, None)
                if assertion:
                    self.retired.add(assertion["handle"])
                raise Failure("login_invalid", "The identity service could not verify this sign-in.", 401) from None

    def check(self, credential_id, subject_id):
        bound = self.bindings.get(credential_id)
        if bound is None or bound["assertion"]["valid_until"] <= time.time():
            raise Failure("unauthenticated", "External authority expired. Sign in again.", 401)
        assertion, expected = bound["assertion"], bound["mapping"]
        current = self.records.find(assertion["issuer"], assertion["subject"])
        if current != expected or current["disabled"] or current["subject_id"] != subject_id:
            raise Failure("unauthenticated", "External identity approval changed. Sign in again.", 401)

    def rotate(self, previous, current):
        if previous in self.bindings:
            self.bindings[current] = self.bindings.pop(previous)

    def remove(self, credential_id):
        bound = self.bindings.pop(credential_id, None)
        if bound:
            self.retired.add(bound["assertion"]["handle"])

    async def renew(self, selected):
        handles = [item["assertion"]["handle"] for item in selected]
        values = None
        try:
            provider = self.provider
            if provider is None:
                raise ValueError("Identity provider unavailable")
            values = await asyncio.to_thread(provider.renew, handles)
            if (not isinstance(values, list) or len(values) != len(handles)
                    or any(not isinstance(value, dict) or value.get("handle") != handle
                           or type(value.get("valid")) is not bool for value, handle in zip(values, handles, strict=True))):
                raise ValueError("Invalid renewal batch")
            checked = []
            for value, previous in zip(values, selected, strict=True):
                if value["valid"]:
                    checked.append(identity_provider.assertion({key: item for key, item in value.items() if key != "valid"},
                                   provider.issuer, previous["assertion"]))
                elif set(value) == {"handle", "valid"}:
                    checked.append(None)
                else:
                    raise ValueError("Invalid renewal refusal")
        except Exception:
            checked = [None] * len(selected)
        with self.service.store.lock:
            for previous, result in zip(selected, checked, strict=True):
                active = [key for key, bound in self.bindings.items() if bound is previous]
                for identity in active:
                    if result is None:
                        self.service.auth.revoke(identity)
                    else:
                        previous["assertion"] = result

    async def poll(self):
        while True:
            if self.provider is not None:
                with self.service.store.lock:
                    for identity in list(self.bindings):
                        try:
                            self.service.auth.current(identity)
                        except Failure:
                            self.service.auth.revoke(identity)
                    selected = list(self.bindings.values())
                for offset in range(0, len(selected), 64):
                    await self.renew(selected[offset:offset + 64])
                while self.retired:
                    handles = list(self.retired)[:64]
                    self.retired.difference_update(handles)
                    try:
                        await asyncio.to_thread(self.provider.forget, handles)
                    except Exception:
                        pass
            await asyncio.sleep(5)

    def close(self):
        self.pending.clear()
        self.bindings.clear()
        self.retired.clear()
        if self.provider is not None:
            self.provider.close()
            self.provider = None
