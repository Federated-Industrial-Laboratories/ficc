# SPDX-License-Identifier: Apache-2.0
"""Deliver bounded executor commands once through the current authenticated node lease."""

import asyncio
from dataclasses import dataclass
from typing import Callable, Literal

from pydantic import Field

from ..errors import Failure
from ..execution.protocol import MESSAGE, Message
from ..execution.spec import Identity, encoded
from ..execution.wire import MAX_REPLY, REPLY
from ..schema import Model


class Exchange(Model):
    version: Literal[1]
    session_id: Identity
    response: dict | None = Field(default=None)


@dataclass
class Pending:
    message: Message
    session_id: str
    fingerprint: str
    check: Callable
    future: asyncio.Future
    delivered: bool = False


class Channel:
    def __init__(self, service):
        self.service = service
        self.pending: dict[str, Pending] = {}
        self.polling: set[str] = set()
        self.closed = False

    def session(self, node_id):
        nodes = self.service.contributors
        session = nodes.sessions.get(node_id)
        if session is None:
            raise Failure("contributor_disconnected", "The contributor has no current connection.", 409)
        nodes.guard(node_id, session["id"], session["fingerprint"])
        return session

    async def request(self, node_id, message, check, *, timeout=12):
        message = MESSAGE.validate_python(message.model_dump())
        if message.action == "set_offer":
            raise Failure("local_consent", "Change the offer through the authenticated local owner interface.", 403)
        if self.closed or node_id in self.pending:
            raise Failure("executor_busy", "The contributor command channel is busy or stopped.", 409)
        current = self.session(node_id)
        check()
        future = asyncio.get_running_loop().create_future()
        pending = Pending(message, current["id"], current["fingerprint"], check, future)
        self.pending[node_id] = pending
        try:
            async with asyncio.timeout(timeout):
                reply = await future
            self.service.contributors.guard(node_id, pending.session_id, pending.fingerprint)
            check()
            return reply
        except TimeoutError:
            raise Failure("executor_reply_unknown", "The executor reply was not received. Reconcile the same attempt.", 504) from None
        finally:
            if self.pending.get(node_id) is pending:
                self.pending.pop(node_id, None)

    async def exchange(self, fingerprint, message: Exchange):
        nodes = self.service.contributors
        node, _certificate = nodes.records.authenticate(fingerprint)
        identity = node["id"]
        nodes.guard(identity, message.session_id, fingerprint)
        if identity in self.polling:
            raise Failure("executor_busy", "One execution poll is already active for this contributor.", 409)
        self.polling.add(identity)
        try:
            pending = self.pending.get(identity)
            if message.response is not None:
                if len(encoded(message.response)) > MAX_REPLY:
                    raise Failure("response_limit", "The executor response exceeds the control limit.", 413)
                reply = REPLY.validate_python(message.response)
                if (reply.node_id != identity or reply.deployment_id != nodes.settings.deployment_id):
                    raise Failure("executor_identity", "The executor response belongs to another deployment or node.", 403)
                # A response from a lost controller session is discarded, never applied to another command.
                if pending and pending.delivered and reply.id == pending.message.id:
                    self.bound(identity, pending, message.session_id, fingerprint)
                    if not pending.future.done():
                        pending.future.set_result(reply)
            for _ in range(10):
                nodes.guard(identity, message.session_id, fingerprint)
                pending = self.pending.get(identity)
                if pending and not pending.delivered:
                    self.bound(identity, pending, message.session_id, fingerprint)
                    try:
                        pending.check()
                    except Exception as exc:
                        if not pending.future.done():
                            pending.future.set_exception(exc)
                        raise
                    pending.delivered = True
                    return self.envelope(node, message, pending.message.model_dump())
                await asyncio.sleep(0.1)
            nodes.guard(identity, message.session_id, fingerprint)
            return self.envelope(node, message, None)
        finally:
            self.polling.discard(identity)

    def bound(self, identity, pending, session_id, fingerprint):
        if (pending.session_id, pending.fingerprint) != (session_id, fingerprint):
            failure = Failure("node_lease_changed", "The contributor connection changed during an executor command.", 409)
            if not pending.future.done():
                pending.future.set_exception(failure)
            raise failure
        self.service.contributors.guard(identity, session_id, fingerprint)

    def envelope(self, node, message, command):
        return {"version": 1, "deployment_id": self.service.contributors.settings.deployment_id,
                "node_id": node["id"], "session_id": message.session_id, "command": command}

    def close(self):
        self.closed = True
        for pending in self.pending.values():
            if not pending.future.done():
                pending.future.set_exception(Failure("executor_stopped", "The controller execution channel stopped.", 503))
        self.pending.clear()
