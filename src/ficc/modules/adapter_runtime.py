# SPDX-License-Identifier: Apache-2.0
"""Run controller provider adapters with existing verified isolation and pipe bounds."""

from pathlib import Path

from ..errors import Failure
from .adapter_manifest import ROLE
from .adapter_protocol import Conversation
from .sandbox import Sandbox, entry_command, execute
from .validation import loads


class ControllerRuntime:
    def __init__(self):
        self.sandbox = Sandbox()

    async def qualify(self, check):
        check()
        status = await self.sandbox.probe()
        check()
        if not status.available:
            raise Failure("module_sandbox_unavailable", status.reason, 503)

    async def execute(self, package: Path, manifest: dict, conversation: Conversation) -> dict:
        if (manifest.get("role") != ROLE or manifest["adapter"]["execution"] != "controller"
                or manifest["adapter"]["transport"] != "winrm-jea"):
            raise Failure("adapter_transport_mismatch", "This package requires a different adapter execution boundary.", 409)
        await self.qualify(conversation.check)
        output = await execute(package, entry_command(manifest), conversation.payload, conversation.check,
                               conversation=conversation, adapter_apply=conversation.phase == "apply")
        return conversation.result(loads(output))
