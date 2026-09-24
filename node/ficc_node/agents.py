# SPDX-License-Identifier: Apache-2.0
"""Launch exact registered agent commands and exchange bounded private spools."""

import json
import os
import sys
import time
from pathlib import Path

from . import agent_spool as spool
from . import terminals
from .job_state import read as terminal_read
from .job_state import write as terminal_write


def profile(value):
    if not isinstance(value, dict) or set(value) != {"argv", "workspace", "adapter"}:
        raise ValueError("Invalid agent command profile.")
    argv, workspace = value["argv"], value["workspace"]
    if (not isinstance(argv, list) or not 1 <= len(argv) <= 32 or any(
            not isinstance(part, str) or not part or len(part) > 2048 or "\x00" in part for part in argv)):
        raise ValueError("The agent command argument list is invalid.")
    if not Path(argv[0]).is_absolute() or not Path(argv[0]).is_file() or not os.access(argv[0], os.X_OK):
        raise ValueError("Register an installed absolute executable path.")
    if not isinstance(workspace, str) or not Path(workspace).is_absolute() or not Path(workspace).is_dir() or "\x00" in workspace:
        raise ValueError("Register an existing absolute workspace directory.")
    if value["adapter"] not in {"omp", "codex", "generic"}:
        raise ValueError("Unsupported agent adapter.")
    return {**value, "workspace": str(Path(workspace).resolve())}


def probe(value):
    checked = profile(value)
    version = "unversioned"
    method = "inbox"
    if checked["adapter"] != "generic":
        from .agent_process import version as runtime_version
        version = runtime_version(checked["argv"])
        expected = {"omp/18.1.12", "omp v18.1.12", "omp 18.1.12"} if checked["adapter"] == "omp" else {"codex-cli 0.156.1"}
        if version in expected:
            method = "direct"
    return {**checked, "version": version[:240], "delivery_method": method}


def launch(request):
    controller, agent = spool.identity(request["controller_id"]), spool.identity(request["agent_id"])
    spec = request["spec"]
    expected = {"agent_id", "controller_id", "terminal_id", "terminal_controller", "run_id", "profile",
                "version", "delivery_method", "cols", "rows"}
    if not isinstance(spec, dict) or set(spec) != expected or spec["agent_id"] != agent or spec["controller_id"] != controller:
        raise ValueError("Invalid launch identity.")
    for name in ("terminal_id", "terminal_controller", "run_id"):
        spool.identity(spec[name])
    verified = probe(spec["profile"])
    if verified["version"] != spec["version"] or verified["delivery_method"] != spec["delivery_method"]:
        raise ValueError("The agent runtime changed after preview.")
    cols, rows = spec["cols"], spec["rows"]
    if type(cols) is not int or type(rows) is not int or not 2 <= cols <= 300 or not 2 <= rows <= 120:
        raise ValueError("Invalid agent terminal dimensions.")
    with spool.locked(controller, agent) as folder:
        path = folder / "spec.json"
        if path.exists():
            if spool.read(path) != spec:
                raise ValueError("The agent launch conflicts with its saved intent.")
            return status_locked(folder, spec)
        spool.write(path, spec)
        spool.write(folder / "runtime.json", {"session_id": None, "state": "starting"})
        with terminals.locked(spec["terminal_controller"]) as terminal_folder:
            target = terminal_folder / (spec["terminal_id"] + ".json")
            if target.exists() or terminals.call(spec["terminal_controller"], "has-session", "-t", "=" + spec["terminal_id"]) == 0:
                raise ValueError("The agent terminal identity is already in use.")
            if len(list(terminal_folder.glob("*.json"))) >= 512:
                raise ValueError("The terminal namespace is full.")
            terminal_write(target, {"id": spec["terminal_id"], "state": "creating", "cols": cols, "rows": rows,
                                    "agent_id": agent, "agent_controller": controller})
            helper = str(Path(sys.argv[0]).absolute())
            result = terminals.call(spec["terminal_controller"], "new-session", "-d", "-s", spec["terminal_id"],
                                    "-x", str(cols), "-y", str(rows), "-c", verified["workspace"],
                                    sys.executable, helper, "--run-agent", controller, agent)
            value = terminal_read(target)
            value["state"] = "unknown" if result else "detached"
            terminal_write(target, value)
        return status_locked(folder, spec)


def status_locked(folder, spec):
    runtime = spool.read(folder / "runtime.json")
    present = terminals.call(spec["terminal_controller"], "has-session", "-t", "=" + spec["terminal_id"]) == 0
    state = runtime.get("state", "unknown")
    if not present and state not in {"stopped", "starting"}:
        state = "exited"
    elif not present and state == "starting":
        state = "unknown"
    return {"state": state, "runtime_session_id": runtime.get("session_id"),
            "observed_session_id": runtime.get("observed_session_id"), "last_contact": time.time()}


def exchange(folder, spec, request):
    items, acks = request.get("deliveries", []), request.get("outbox_acks", [])
    if not isinstance(items, list) or len(items) > 8 or not isinstance(acks, list) or len(acks) > 8:
        raise ValueError("The exchange batch exceeds capacity.")
    for item in items:
        expected = {"id", "run_id", "message_id", "agent_id", "sender_id", "type", "body", "method", "authorization_expires_at"}
        if not isinstance(item, dict) or set(item) != expected:
            raise ValueError("Invalid agent delivery fields.")
        spool.identity(item["id"])
        spool.identity(item["message_id"])
        if item["agent_id"] != spec["agent_id"] or item["run_id"] != spec["run_id"] or item["method"] not in {"direct", "inbox"}:
            raise ValueError("The delivery does not match its registered recipient and run.")
        if len(json.dumps(item, ensure_ascii=False).encode()) > 12288:
            raise ValueError("The delivery exceeds capacity.")
        path = folder / ("inbox-" + item["id"] + ".json")
        receipt = folder / ("receipt-" + item["id"] + ".json")
        if path.exists():
            saved = spool.read(path)
            if {k: v for k, v in saved.items() if k != "authorization_expires_at"} != {k: v for k, v in item.items() if k != "authorization_expires_at"}:
                raise ValueError("The delivery identity conflicts with saved content.")
        else:
            if len(list(folder.glob("inbox-*.json"))) >= 256:
                raise ValueError("The retained inbox is full.")
            spool.write(path, item)
        if not receipt.exists():
            spool.receipt(folder, item["id"], "node-stored")
    from .agent_outbox import acknowledge
    for acknowledgement in acks:
        acknowledge(folder, acknowledgement)
    requested = request.get("receipt_ids", [])
    if not isinstance(requested, list) or len(requested) > 8:
        raise ValueError("The receipt batch exceeds capacity.")
    receipts = []
    for identity in requested:
        spool.identity(identity)
        path = folder / ("receipt-" + identity + ".json")
        if not path.exists() and (folder / ("inbox-" + identity + ".json")).exists():
            spool.receipt(folder, identity, "node-stored")
        receipts.append(spool.read(path) if path.exists() else {"id": identity, "state": "missing", "detail": "No inbox item was admitted."})
    outbox = [spool.read(path) for path in sorted(folder.glob("outbox-*.json"))[:8]]
    return {**status_locked(folder, spec), "receipts": receipts, "outbox": outbox}


def dispatch(request):
    action = request.get("action")
    if action == "agent.archive":
        if set(request) != {"version", "action", "controller_id", "agent_id"}:
            raise ValueError("Invalid agent archive fields.")
        from .agent_archive import retire
        return retire(request["controller_id"], request["agent_id"])
    if action == "agent.probe":
        if set(request) != {"version", "action", "profile"}:
            raise ValueError("Invalid agent probe fields.")
        return probe(request["profile"])
    if action == "agent.launch":
        if set(request) != {"version", "action", "controller_id", "agent_id", "spec"}:
            raise ValueError("Invalid agent launch fields.")
        return launch(request)
    if set(request) - {"version", "action", "controller_id", "agent_id", "deliveries", "outbox_acks", "receipt_ids", "runtime_session_id"}:
        raise ValueError("Invalid agent request fields.")
    with spool.locked(request["controller_id"], request["agent_id"]) as folder:
        spec = spool.read(folder / "spec.json")
        if spec["controller_id"] != request["controller_id"] or spec["agent_id"] != request["agent_id"]:
            raise ValueError("The registered agent identity changed.")
        if action == "agent.exchange":
            return exchange(folder, spec, request)
        if action == "agent.stop":
            terminals.dispatch({"version": "3", "action": "terminal.stop", "controller_id": spec["terminal_controller"], "terminal_id": spec["terminal_id"]})
            for path in folder.glob("receipt-*.json"):
                receipt = spool.read(path)
                if receipt["state"] == "node-stored":
                    spool.receipt(folder, receipt["id"], "cancelled", "The recipient stopped before runtime admission or tool read.")
            spool.write(folder / "runtime.json", {"state": "stopped", "session_id": None})
            return status_locked(folder, spec)
        if action == "agent.rebind":
            from .agent_binding import rebind
            rebind(folder, spec, request.get("runtime_session_id"))
        elif action != "agent.status":
            raise ValueError("Unsupported agent action.")
        return status_locked(folder, spec)
