# SPDX-License-Identifier: Apache-2.0
"""Read systemd state and dispatch fixed, noninteractive administration actions."""

import os
import subprocess
from pathlib import Path

from . import admin_spec as spec
from .admin_process import run

DEFINITION = ("Type", "FragmentPath", "DropInPaths", "ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost",
              "ExecReload", "Environment", "EnvironmentFiles", "User", "Group", "WorkingDirectory", "RootDirectory",
              "KillMode", "TimeoutStopUSec", "Restart", "RemainAfterExit", "Requires", "Wants", "BindsTo", "PartOf",
              "Conflicts", "Before", "After", "RefuseManualStart", "RefuseManualStop", "NeedDaemonReload")
RELATIONS = {"Requires", "Wants", "BindsTo", "PartOf", "Conflicts", "Before", "After"}
STATE = ("Id", "LoadState", "ActiveState", "SubState", "InvocationID")


class Systemd:
    def __init__(self, request):
        self.manager = request["manager"]
        self.command = ["/usr/bin/systemctl", "--" + self.manager, "--no-pager", "--no-ask-password"]
        code, raw, _ = run(["/usr/bin/systemctl", "--version"], maximum=8192)
        version = raw.decode("utf-8").splitlines()[0].split()
        if code or len(version) < 2 or version[0] != "systemd" or int(version[1]) < 248:
            raise spec.ProviderError("admin_prerequisite", "Systemd 248 or newer is required.")
        self.version = version[1]
        machine = spec.identity(Path("/etc/machine-id").read_text().strip())
        self.system_id = spec.digest({"machine": machine})
        self.boot = spec.identity(Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", ""))
        self.binding = spec.digest({"machine": machine, "uid": os.getuid(), "manager": self.manager})
        if request["binding"] not in {None, self.binding}:
            raise spec.ProviderError("admin_identity", "The service manager or account identity changed.")
        self.properties([])

    def close(self):
        pass

    def probe(self):
        return {"binding": self.binding, "provider": "systemd", "version": self.version, "account_uid": os.getuid(), "system_id": self.system_id}

    def pointer(self, kind, name):
        return {"kind": kind, "name": name, "id": spec.digest({"binding": self.binding, "kind": kind, "name": name})}

    def properties(self, names):
        fields = (*STATE, *DEFINITION) if names else ("SystemState", "Version")
        code, raw, _ = run([*self.command, "show", "--property=" + ",".join(fields), "--", *names])
        if code:
            raise spec.ProviderError("admin_unavailable", "The selected service manager is not available to this account.")
        blocks = []
        for block in raw.decode("utf-8").strip().split("\n\n"):
            values = {}
            for line in block.splitlines():
                key, separator, value = line.partition("=")
                if not separator or key in values or key not in fields:
                    raise ValueError("Invalid service property response.")
                values[key] = value
            blocks.append(values)
        if len(blocks) != max(1, len(names)):
            raise ValueError("Invalid service property count.")
        return blocks

    def power_access(self):
        result = {action: "na" if self.manager == "user" else "unavailable" for action in spec.POWER}
        if self.manager == "user":
            return result
        for action, method in (("reboot", "CanReboot"), ("poweroff", "CanPowerOff")):
            try:
                code, raw, _ = run(["/usr/bin/busctl", "--system", "--json=short", "--timeout=1", "call",
                    "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", method],
                    timeout=2, maximum=4096)
                value = spec.decode(raw)
                if (not code and value.get("type") == "s" and isinstance(value.get("data"), list)
                        and len(value["data"]) == 1 and value["data"][0] in spec.POWER_ACCESS):
                    result[action] = value["data"][0]
            except (OSError, ValueError, TypeError):
                pass
        return result

    def describe(self, pointer, values):
        if pointer["kind"] == "system":
            memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
            metrics = {"uptime_seconds": int(float(Path("/proc/uptime").read_text().split()[0])),
                       "memory_total": int(memory["MemTotal"].split()[0]) * 1024,
                       "memory_available": int(memory["MemAvailable"].split()[0]) * 1024}
            state, invocation = values.get("SystemState", "unknown"), ""
            definition = spec.digest({"binding": self.binding, "version": self.version})
            detail = os.uname().release[:128]
        else:
            if values.get("Id") != pointer["name"] or values.get("LoadState") != "loaded":
                raise spec.ProviderError("admin_identity", "The selected service is absent, an alias or not loaded.")
            state, invocation = values["ActiveState"], values["InvocationID"]
            definition = spec.digest({key: sorted(values.get(key, "").split()) if key in RELATIONS else values.get(key, "")
                                      for key in DEFINITION})
            metrics, detail = None, values["SubState"]
        value = {"resource": pointer, "state": state, "definition": definition, "boot_id": self.boot,
                 "invocation": invocation, "detail": detail, "metrics": metrics}
        if pointer["kind"] == "system":
            value["power"] = self.power_access()
        value["revision"] = spec.digest({key: value[key] for key in ("resource", "state", "definition", "boot_id", "invocation")})
        return value

    def status_batch(self, pointers):
        for pointer in pointers:
            spec.pointer(pointer)
            if pointer != self.pointer(pointer["kind"], pointer["name"]):
                raise spec.ProviderError("admin_identity", "The resource does not belong to this service manager.")
        names = [item["name"] for item in pointers if item["kind"] == "service"]
        properties = iter(self.properties(names) if names else [])
        system = self.properties([])[0] if any(item["kind"] == "system" for item in pointers) else None
        rows = []
        for pointer in pointers:
            values = system if pointer["kind"] == "system" else next(properties)
            try:
                rows.append({"resource": pointer, "data": self.describe(pointer, values)})
            except spec.ProviderError as exc:
                rows.append({"resource": pointer, "error": spec.error(exc.code, exc.message)})
        return {"results": rows}

    def status(self, pointer):
        row = self.status_batch([pointer])["results"][0]
        if "error" in row:
            raise spec.ProviderError(**row["error"])
        return row["data"]

    def inventory(self, kind, offset, limit):
        pointers = [self.pointer("system", "system")] if kind in {"system", "all"} else []
        if kind in {"service", "all"}:
            code, raw, _ = run(["/usr/bin/busctl", "--" + self.manager, "--json=short", "--timeout=4", "call",
                "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "ListUnitFiles"])
            value = spec.decode(raw)
            if code or value.get("type") != "a(ss)" or not isinstance(value.get("data"), list) or len(value["data"]) != 1:
                raise ValueError("Invalid installed service list.")
            entries = value["data"][0]
            if not isinstance(entries, list) or len(entries) > 4096:
                raise spec.ProviderError("admin_inventory_limit", "The installed unit list exceeds 4096 entries.")
            names = set()
            for entry in entries:
                if not isinstance(entry, list) or len(entry) != 2:
                    raise ValueError("Invalid installed unit entry.")
                name = entry[0].rsplit("/", 1)[-1]
                if name.endswith(".service") and not name.endswith("@.service") and entry[1] not in {"alias", "masked", "masked-runtime"}:
                    spec.unit(name)
                    names.add(name)
            pointers.extend(self.pointer("service", name) for name in sorted(names))
        page = pointers[offset:offset + limit]
        rows = self.status_batch(page)["results"] if page else []
        more = offset + len(page) < len(pointers)
        return {"results": rows, "truncated": more, "next_offset": offset + len(page) if more else None}

    def logs(self, pointer, tail, limit):
        if pointer["kind"] != "service":
            raise spec.ProviderError("admin_kind", "Select service rows to read logs.")
        self.status(pointer)
        selector = "--user-unit=" if self.manager == "user" else "--unit="
        args = ["/usr/bin/journalctl", "--" + self.manager, selector + pointer["name"], "--boot", "--no-pager",
                "--output=cat", "--lines=" + str(tail), "--quiet"]
        code, raw, clipped = run(args, maximum=limit, truncate=True)
        if code:
            raise spec.ProviderError("admin_denied", "The account cannot read these service logs.")
        return {"text": raw.decode("utf-8", errors="replace"), "truncated": clipped}

    def apply_batch(self, action, expected):
        current = self.status_batch([item["resource"] for item in expected])["results"]
        results, selected = [], []
        for frozen, row in zip(expected, current, strict=True):
            pointer = frozen["resource"]
            result = {"resource": pointer, "state": "refused"}
            if "error" in row:
                result["error"] = row["error"]
            elif any(row["data"][key] != frozen[key] for key in spec.EXPECTED):
                result["error"] = spec.error("admin_stale", "The boot, service definition or state changed after preview.")
            elif (action in spec.POWER and (pointer["kind"] != "system" or self.manager != "system")
                  or action not in spec.POWER and pointer["kind"] != "service"):
                result["error"] = spec.error("admin_kind", "Select services for service actions or system rows for power actions.")
            elif action in spec.POWER and row["data"].get("power", {}).get(action) != "yes":
                result["error"] = spec.error("admin_power_denied", "Noninteractive power permission is unavailable. Check account policy and refresh.")
            else:
                selected.append(result)
            results.append(result)
        if selected:
            if action in spec.POWER:
                if len(selected) != 1:
                    raise ValueError("Select this system once for a power action.")
                args = [*self.command, "--check-inhibitors=yes", "--no-block", action]
                try:
                    code, _, _ = run([*args[:-1], "--dry-run", action], timeout=3, maximum=16384)
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    code = 1
                if code:
                    selected[0]["error"] = spec.error("admin_power_blocked",
                        "The power check failed. Check inhibitors and close other sessions, then refresh.")
                    return results
            else:
                args = [*self.command, "--no-block", action, "--", *[row["resource"]["name"] for row in selected]]
            code, _, _ = run(args, timeout=15, maximum=16384)
            for row in selected:
                row["state"] = "accepted" if code == 0 else "unknown"
                if code:
                    row["error"] = spec.error("admin_outcome_unknown", "The manager did not confirm dispatch. Inspect the outcome.")
        return results
