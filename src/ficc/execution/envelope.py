# SPDX-License-Identifier: Apache-2.0
"""Keep attempt resource ceilings and supervisor dependencies in the system manager."""

import os
import time
from pathlib import Path

from .process import command, properties
from .storage import processes

FIELDS = ("LoadState", "ActiveState", "SubState", "Description", "ControlGroup", "Result",
          "ExecMainCode", "ExecMainStatus", "ExecMainExitTimestampMonotonic", "DevicePolicy", "DeviceAllow",
          "BindsTo", "After", "KillMode", "OOMPolicy", "RuntimeMaxUSec", "LimitCORE", "LimitCORESoft")


def context(settings, slot, value):
    plan = value["plan"]
    unit = "ficc-work-" + settings.installation_id + "-" + plan["attempt_id"] + ".service"
    return {"plan": plan, "plan_digest": value["plan_digest"], "slot": slot.model_dump(),
            "binding": value["binding"], "directory": str(Path(slot.mount) / plan["attempt_id"]),
            "unit": unit, "description": "FICC attempt " + settings.installation_id + ":" + plan["attempt_id"],
            "cgroup": "/system.slice/" + unit, "supervisor": settings.service}


class Envelope:
    def supervisor(self, settings):
        value = properties(settings.service, ("MainPID", "ActiveState", "Type", "WatchdogUSec", "WatchdogSignal",
                                              "NotifyAccess", "KillMode", "LimitCORE", "LimitCORESoft"))
        if (value.get("MainPID") != str(os.getpid()) or value.get("ActiveState") not in {"active", "activating"}
                or value.get("Type") != "notify" or value.get("NotifyAccess") != "main"
                or value.get("WatchdogUSec") != "2s" or value.get("WatchdogSignal") != "9"
                or value.get("LimitCORE") != "0" or value.get("LimitCORESoft") != "0"
                or value.get("KillMode") != "control-group"):
            raise ValueError("The supervisor must run in its configured service with the two-second watchdog.")

    def launch(self, ctx, prepared):
        limits = ctx["plan"]["job"]["limits"]
        if limits["cpu_millis"] < 10:
            raise ValueError("This executor requires at least ten CPU milliseconds per second.")
        root = Path(ctx["directory"])
        props = {"Type": "exec", "RemainAfterExit": "yes", "Delegate": "cpu memory pids",
                 "DelegateSubgroup": "manager", "BindsTo": ctx["supervisor"], "After": ctx["supervisor"],
                 "CPUQuota": str(limits["cpu_millis"] / 10) + "%", "CPUQuotaPeriodSec": "100ms",
                 "MemoryHigh": str(limits["memory_bytes"]), "MemoryMax": str(limits["memory_bytes"]),
                 "MemorySwapMax": str(limits["swap_bytes"]), "TasksMax": str(limits["processes"]),
                 "OOMPolicy": "kill", "KillMode": "control-group", "TimeoutStopSec": "2s",
                 "UMask": "0077", "LimitCORE": "0", "DevicePolicy": "closed", "StandardOutput": "append:" + str(root / "service.stdout"),
                 "StandardError": "append:" + str(root / "service.stderr"), "CPUAccounting": "yes",
                 "MemoryAccounting": "yes", "TasksAccounting": "yes", "IOAccounting": "yes"}
        argv = ["/usr/bin/systemd-run", "--quiet", "--no-ask-password", "--expand-environment=no",
                "--unit=" + ctx["unit"], "--description=" + ctx["description"], "--slice=system.slice",
                "--uid=" + ctx["slot"]["account"], "--gid=" + ctx["slot"]["account"],
                "--working-directory=" + str(root / "runtime")]
        argv += ["--property=" + key + "=" + value for key, value in props.items()]
        argv += ["--property=DeviceAllow=" + node["source"] + " rw" for node in prepared["devices"]]
        command(argv + ["--", *prepared["argv"]])

    def inspect(self, ctx):
        value = properties(ctx["unit"], FIELDS)
        if value.get("LoadState") != "not-found" and value.get("Description") != ctx["description"]:
            raise ValueError("The attempt service identity changed.")
        return value

    def controls(self, ctx, prepared):
        unit = self.inspect(ctx)
        if (unit.get("ControlGroup") != ctx["cgroup"] or unit.get("DevicePolicy") != "closed"
                or ctx["supervisor"] not in unit.get("BindsTo", "").split()
                or ctx["supervisor"] not in unit.get("After", "").split()
                or unit.get("KillMode") != "control-group" or unit.get("OOMPolicy") != "kill"
                or unit.get("RuntimeMaxUSec") != "infinity" or unit.get("LimitCORE") != "0"
                or unit.get("LimitCORESoft") != "0"):
            raise ValueError("The attempt ancestor or supervisor dependency changed.")
        devices = unit.get("DeviceAllow", "").split()
        expected = sorted((item["source"], "rw") for item in prepared["devices"])
        if len(devices) % 2 or sorted(zip(devices[::2], devices[1::2])) != expected:
            raise ValueError("The actual device allow-list differs from the selected device set.")
        group = Path("/sys/fs/cgroup") / ctx["cgroup"].lstrip("/")
        limits = ctx["plan"]["job"]["limits"]
        values = {name: (group / name).read_text().strip() for name in
                  ("cpu.max", "memory.max", "memory.high", "memory.swap.max", "memory.oom.group", "pids.max")}
        if values["cpu.max"] != f"{limits['cpu_millis'] * 100} 100000" or values["memory.oom.group"] != "1":
            raise ValueError("The kernel CPU or memory-group limit differs.")
        page = os.sysconf("SC_PAGE_SIZE")
        for name, key in (("memory.max", "memory_bytes"), ("memory.high", "memory_bytes"),
                          ("memory.swap.max", "swap_bytes")):
            if values[name] != str(limits[key] // page * page):
                raise ValueError("A kernel memory or swap limit differs.")
        if values["pids.max"] != str(limits["processes"]):
            raise ValueError("The kernel process limit differs.")
        return {"unit": unit, "limits": values}

    def stop(self, ctx):
        before = self.inspect(ctx)
        if before.get("LoadState") != "not-found":
            # Lease enforcement cannot wait out the unit's shutdown grace period.
            # A concurrent exit may leave no process to signal; idle() is authoritative.
            command(["/usr/bin/systemctl", "kill", "--signal=SIGKILL", "--kill-whom=all", ctx["unit"]], okay=(0, 1))
            command(["/usr/bin/systemctl", "stop", ctx["unit"]], timeout=4)
        # Process exit and orphan reaping can trail the stop acknowledgement.
        deadline = time.monotonic() + 0.75
        while True:
            try:
                self.idle(ctx)
                break
            except ValueError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
        return before

    def idle(self, ctx):
        """Observe an inactive service and an empty workload tree without stopping work."""
        after = self.inspect(ctx)
        if after.get("LoadState") != "not-found" and after.get("ActiveState") not in {"inactive", "failed"}:
            raise ValueError("The attempt service has not stopped.")
        group = Path("/sys/fs/cgroup") / ctx["cgroup"].lstrip("/")
        if group.exists() and any(path.read_text().strip() for path in group.rglob("cgroup.procs")):
            raise ValueError("The attempt cgroup still contains processes.")
        if processes(ctx["slot"]["uid"]):
            raise ValueError("The workload account still has processes. Keep its reservations.")
        return {"unit": ctx["unit"], "state": after.get("ActiveState"), "uid": ctx["slot"]["uid"], "idle": True}
