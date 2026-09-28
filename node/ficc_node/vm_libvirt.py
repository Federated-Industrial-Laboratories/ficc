# SPDX-License-Identifier: Apache-2.0
"""Use local libvirt APIs without shell commands or user-supplied URIs."""

import hashlib
import importlib
import uuid
import xml.etree.ElementTree as ET

from .vm_spec import CONNECTIONS, STATES, integer, text


class ProviderError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)


def error(code, message):
    return {"code": code, "message": message}


class Libvirt:
    def __init__(self, connection, writable=False):
        try:
            self.api = importlib.import_module("libvirt")
        except ImportError as exc:
            raise ProviderError("vm_dependency_missing", "Install python3-libvirt on the enrolled system.") from exc
        # Libvirt otherwise prints detailed endpoint errors on stderr.
        self.api.registerErrorHandler(lambda *_: None, None)
        try:
            self.conn = (self.api.open if writable else self.api.openReadOnly)(CONNECTIONS[connection])
            if self.conn is None:
                raise ProviderError("vm_unavailable", "The local libvirt connection is unavailable.")
        except self.api.libvirtError as exc:
            raise ProviderError("vm_access_denied", "The enrolled SSH account cannot open this libvirt connection.") from exc

    def close(self):
        self.conn.close()

    def domain(self, domain_id):
        return self.conn.lookupByUUIDString(str(uuid.UUID(hex=domain_id)))

    def describe(self, domain):
        state, maximum, memory, cpus, _ = domain.info()
        definition = domain.XMLDesc(self.api.VIR_DOMAIN_XML_INACTIVE if domain.isPersistent() else 0)
        if len(definition.encode()) > 1024 * 1024:
            raise ProviderError("vm_definition_limit", "The VM definition exceeds the limit.")
        return {"uuid": uuid.UUID(domain.UUIDString()).hex, "name": text(domain.name()),
                "state": STATES.get(state, "unknown"), "vcpus": integer(cpus, 0, 65536),
                "memory_kib": integer(memory, 0, 9007199254740991),
                "max_memory_kib": integer(maximum, 0, 9007199254740991),
                "definition": hashlib.sha256(definition.encode()).hexdigest()}

    def status(self, ids):
        results = []
        for domain_id in ids:
            try:
                data = self.describe(self.domain(domain_id))
                results.append({"uuid": domain_id, "data": data})
            except (self.api.libvirtError, ProviderError, ValueError):
                results.append({"uuid": domain_id, "error": error("vm_unavailable", "The VM cannot be read.")})
        return {"results": results}

    def inventory(self, offset, limit):
        domains = self.conn.listAllDomains(0)
        if len(domains) > 4096:
            raise ProviderError("vm_inventory_limit", "This connection exceeds the 4096 VM inventory limit.")
        ids = sorted(uuid.UUID(domain.UUIDString()).hex for domain in domains)
        selected = ids[offset:offset + limit]
        data = self.status(selected) if selected else {"results": []}
        end = offset + len(selected)
        return {**data, "total": len(ids), "next_offset": end if end < len(ids) else None,
                "truncated": end < len(ids), "inventory_digest": hashlib.sha256("".join(ids).encode()).hexdigest()}

    def apply(self, action, expected):
        domain = self.domain(expected["uuid"])
        current = self.describe(domain)
        if any(current[key] != expected[key] for key in ("uuid", "state", "definition")):
            return {"state": "refused", "error": error("vm_changed", "The VM changed after preview.")}
        allowed = {"start": {"off"}, "shutdown": {"running", "blocked", "paused"}}
        if current["state"] not in allowed[action]:
            return {"state": "refused", "error": error("vm_state_conflict", "This action is unavailable in the current VM state.")}
        # A returned error does not prove that no effect occurred.
        try:
            if action == "start":
                domain.create()
            else:
                domain.shutdown()
        except self.api.libvirtError:
            return {"state": "unknown", "error": error("vm_outcome_unknown", "The provider did not confirm the request outcome.")}
        return {"state": "accepted"}

    def console(self, domain_id, open_fd=False):
        domain = self.domain(domain_id)
        if not domain.isActive():
            raise ProviderError("vm_console_unavailable", "The VM is not active.")
        xml = domain.XMLDesc(0)
        if len(xml.encode()) > 1024 * 1024 or "<!DOCTYPE" in xml or "<!ENTITY" in xml:
            raise ProviderError("vm_console_unavailable", "The VM graphics definition cannot be read.")
        graphics = ET.fromstring(xml).findall("./devices/graphics")
        for index, item in enumerate(graphics):
            if item.get("type") == "vnc":
                # Authentication remains enabled. The host viewer negotiates RFB.
                result = {"uuid": domain_id, "protocol": "vnc", "graphics_index": index,
                          "audio": False, "authentication": "rfb"}
                if open_fd:
                    return result, domain.openGraphicsFD(index, 0)
                return result
        raise ProviderError("vm_console_unsupported", "This VM has no supported VNC graphics device.")
