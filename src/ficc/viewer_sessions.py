# SPDX-License-Identifier: Apache-2.0
"""Issue short-lived opaque viewer references and one-use attachment tickets."""

import asyncio
import secrets
import time
from pathlib import Path

from .errors import Failure
from .modules.validation import fields


class Viewers:
    def __init__(self, service):
        self.service = service
        self.references: dict[str, dict] = {}
        self.tickets: dict[str, dict] = {}
        self.active: dict[str, asyncio.Task] = {}
        self.pending = 0

    def purge(self):
        now = time.monotonic()
        self.references = {key: value for key, value in self.references.items()
                           if key in self.active or value["expires"] > now}
        self.tickets = {key: value for key, value in self.tickets.items() if value["expires"] > now}

    async def issue(self, actor, call, instance_id, *, provider="libvirt"):
        self.purge()
        if len(self.references) + self.pending >= 64:
            raise Failure("viewer_capacity", "The display reference limit was reached.", 429)
        if "vm:console" not in call.action_capabilities:
            raise Failure("module_primitive_denied", "This action does not permit a VM console.", 403)
        host = self.service.vm_providers.adapter(provider)
        self.pending += 1
        try:
            select = getattr(host, "console_request", None)
            if select is not None:
                descriptor = await select(actor, call, instance_id)
                node_id = descriptor["node_id"]
                if node_id not in call.target_ids:
                    raise Failure("viewer_selection", "The display is outside this panel's selected systems.", 403)
            else:
                fields(call.parameters, {"vm_ids"})
                ids = call.parameters["vm_ids"]
                if not isinstance(ids, list) or len(ids) != 1:
                    raise Failure("viewer_selection", "Select exactly one VM for a display session.")
                _, grouped = host.groups(call.target_ids, ids)
                node_id = next(iter(grouped))
                descriptor = await host.console(actor, call.package_digest, instance_id,
                                                node_id, ids[0], call.check)
            call.check()
            reference = secrets.token_hex(16)
            self.references[reference] = {"actor": actor, "descriptor": descriptor, "check": call.check,
                                          "expires": time.monotonic() + 60}
            return [{"target": target, "data": {"viewer_ref": reference if target == node_id else None}}
                    for target in call.target_ids]
        finally:
            self.pending -= 1

    def current(self, reference, actor):
        value = self.references.get(reference)
        if (value is None or value["actor"] != actor
                or reference not in self.active and value["expires"] <= time.monotonic()):
            raise Failure("viewer_expired", "Request a new display reference from the module panel.", 409)
        descriptor = value["descriptor"]
        host = self.service.vm_providers.adapter(descriptor.get("provider", "libvirt"))
        host.guard(actor, descriptor["digest"], descriptor["node_id"], "vm:console",
                   descriptor["profile"], value["check"])
        return value

    def ticket(self, reference, actor):
        self.purge()
        value = self.current(reference, actor)
        runtime = self.service.settings.viewer_runtime
        if runtime is None or not (Path(runtime) / "sbin/guacd").is_file():
            raise Failure("viewer_unavailable", self.service.settings.viewer_runtime_error or "Install the native viewer runtime before opening a display.", 503)
        if reference in self.active or len(self.active) >= 4 or len(self.tickets) >= 64:
            raise Failure("viewer_capacity", "Close an active display session before attaching another.", 409)
        descriptor = value["descriptor"]
        host = self.service.vm_providers.adapter(descriptor.get("provider", "libvirt"))
        system, _ = host.profile(descriptor.get("profile_id", descriptor["node_id"]))
        token = secrets.token_hex(32)
        self.tickets[token] = {"reference": reference, "actor": actor, "expires": time.monotonic() + 15}
        return {"ticket": token, "expires_in": 15, "audio": False, "vm_id": descriptor["vm_id"],
                "system": system["name"]}

    def consume(self, reference, token):
        if not isinstance(token, str) or len(token) != 64:
            raise Failure("viewer_ticket", "The display ticket is invalid.", 403)
        value = self.tickets.pop(token, None)
        if value is None or value["reference"] != reference or value["expires"] <= time.monotonic():
            raise Failure("viewer_ticket", "The display ticket expired or was already used.", 403)
        self.current(reference, value["actor"])
        if reference in self.active or len(self.active) >= 4:
            raise Failure("viewer_capacity", "The active display limit was reached.", 409)
        task = asyncio.current_task()
        assert task is not None
        self.active[reference] = task
        return value["actor"]

    async def close(self):
        tasks = list(self.active.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.references.clear()
        self.tickets.clear()
