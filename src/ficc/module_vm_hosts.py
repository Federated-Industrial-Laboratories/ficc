# SPDX-License-Identifier: Apache-2.0
"""Select fixed VM providers from host-owned previews and durable receipts."""

import asyncio
from typing import TYPE_CHECKING

from .errors import Failure

if TYPE_CHECKING:
    from .module_adapter_vm import AdapterVMs
    from .module_proxmox import Proxmox
    from .module_vm import VMs


class VMHosts:
    def __init__(self, service):
        self.hosts: dict[str, VMs | Proxmox | AdapterVMs] = {
            "libvirt": service.vms, "proxmox": service.proxmox, "adapter": service.adapter_vms}
        self.admission = asyncio.Lock()

    def adapter(self, name):
        if not isinstance(name, str) or name not in self.hosts:
            raise Failure("vm_provider_unavailable", "The requested VM provider is unavailable.", 409)
        return self.hosts[name]

    @staticmethod
    def unique(matches, *, preview=False):
        if len(matches) > 1:
            raise Failure("vm_identity_conflict", "Multiple VM providers contain this operation identity.", 409)
        if not matches:
            if preview:
                raise Failure("vm_preview_expired", "Create a new VM preview.", 409)
            raise Failure("not_found", "The VM operation was not found.", 404)
        return matches[0]

    def preview(self, actor, preview_id):
        return self.unique([(host, host.previews[preview_id]) for host in self.hosts.values()
            if preview_id in host.previews and host.previews[preview_id]["actor"] == actor], preview=True)

    def existing(self, actor, key):
        matches = []
        if key:
            for host in self.hosts.values():
                value = host.records.existing(actor, key)
                if value is not None:
                    matches.append((host, value))
        return self.unique(matches) if matches else None

    def operation(self, operation_id):
        matches = []
        for host in self.hosts.values():
            try:
                matches.append((host, host.records.get(operation_id)))
            except Failure as exc:
                if exc.status != 404:
                    raise
        return self.unique(matches)

    def retained(self, node_id):
        return any(host.records.retained(node_id) for host in self.hosts.values())
