# SPDX-License-Identifier: Apache-2.0
"""Invoke stateless module actions with current grants and complete cancellation."""

import asyncio
from collections.abc import Callable

from ..errors import Failure
from . import protocol
from .broker_protocol import Broker, Conversation
from .manifest import HOST_CAPABILITIES, validate_parameters
from .registry import Registry, targets
from .sandbox import Sandbox, entry_command, execute
from .validation import dumps, identifier, loads


class Runtime:
    def __init__(self, registry: Registry):
        self.registry = registry
        self.sandbox = Sandbox()
        self.active: dict[asyncio.Task, str] = {}
        self.lock = asyncio.Lock()

    async def invoke(self, digest: str, action: str, target_ids: list[str], parameters: dict,
                     check: Callable[[], None], *, broker: Broker | None = None) -> dict:
        """Own a child task so stop waits for cleanup without cancelling its caller."""
        frozen_targets = list(targets(target_ids))
        frozen_parameters = loads(dumps(parameters))
        task = asyncio.create_task(self._invoke(digest, action, frozen_targets, frozen_parameters, check, broker))
        return await task

    async def _invoke(self, digest: str, action: str, target_ids: list[str], parameters: dict,
                      check: Callable[[], None], broker: Broker | None) -> dict:
        identifier(action)
        targets(target_ids)
        check()
        async with self.lock:
            if len(self.active) >= 4:
                raise Failure("capacity", "The module operation limit was reached.", 409)
            current = self.registry.acquire(digest)
            task = asyncio.current_task()
            assert task is not None
            self.active[task] = digest
        try:
            manifest = current["manifest"]
            if manifest.get("role", "module") != "module":
                raise Failure("module_action_unavailable", "A provider adapter requires a host provider binding.", 409)
            if manifest["runtime"]["kind"] == "declarative":
                raise Failure("module_action_unavailable", "This module has no executable runtime.", 409)
            actions = [item for item in manifest["actions"] if item["id"] == action]
            if not actions:
                raise Failure("module_action_unavailable", "The module action was not found.", 404)
            selected = actions[0]
            version = manifest["runtime"].get("protocol", 1)
            capabilities = selected["capabilities"]
            if capabilities and (version != 2 or broker is None or set(capabilities) & HOST_CAPABILITIES):
                raise Failure("module_capability_unavailable",
                              "The executable action has no supported broker authority.", 409)
            validate_parameters(selected["parameters"], parameters)

            def guard():
                check()
                self.registry.check(digest, current["revision"])
                for capability in capabilities:
                    self.registry.require(digest, capability, target_ids)

            guard()
            status = await self.sandbox.probe()
            if not status.available:
                raise Failure("module_sandbox_unavailable", status.reason, 503)
            guard()
            if version == 2:
                conversation = Conversation(digest, action, target_ids, parameters, capabilities, guard, broker)
                output = await execute(self.registry.root / digest, entry_command(manifest),
                                       conversation.payload, guard, conversation=conversation)
                guard()
                return protocol.result_frame(protocol.frames(output)[1], conversation.id, target_ids, version=2)
            request_id, payload = protocol.request(action, target_ids, parameters)
            output = await execute(self.registry.root / digest, entry_command(manifest), payload, guard)
            guard()
            return protocol.response(output, request_id, target_ids)
        finally:
            self.active.pop(task, None)
            self.registry.release(digest)

    async def stop(self, digest: str | None = None) -> None:
        tasks = [task for task, value in self.active.items()
                 if (digest is None or value == digest) and task is not asyncio.current_task()]
        for task in tasks:
            if not task.cancelling():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
