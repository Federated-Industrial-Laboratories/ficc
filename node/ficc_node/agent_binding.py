# SPDX-License-Identifier: Apache-2.0
"""Confirm runtime bindings without moving unresolved admission identities."""

from pathlib import Path

from . import agent_spool as spool
from .agent_rpc import RPC


def read(controller, agent):
    with spool.locked(controller, agent) as folder:
        return spool.read(folder / "runtime.json")


def rebind(folder, spec, identity):
    runtime = spool.read(folder / "runtime.json")
    if runtime.get("observed_session_id") != identity or runtime.get("state") != "suspended":
        raise ValueError("The requested session is not the suspended observed runtime session.")
    if runtime["session_id"] != identity:
        for path in folder.glob("receipt-*.json"):
            if spool.read(path)["state"] in {"uncertain", "adapter-submitted"}:
                raise ValueError("Resolve old-session direct receipts before changing the runtime binding.")
    if spec.get("profile", {}).get("adapter") == "codex":
        endpoint = runtime.get("rpc_endpoint")
        if not isinstance(endpoint, str) or not Path(endpoint).is_absolute():
            raise ValueError("The owned Codex endpoint is unavailable; retain the suspended binding.")
        rpc = RPC(Path(endpoint))
        try:
            result = rpc.call("thread/read", {"threadId": identity, "includeTurns": False})
            if result.get("thread", {}).get("id") != identity:
                raise ValueError("The owned Codex server did not confirm the requested thread.")
        finally:
            rpc.close()
    runtime.update(session_id=identity, state="ready", binding_revision=runtime.get("binding_revision", 0) + 1)
    runtime.pop("observed_session_id", None)
    spool.write(folder / "runtime.json", runtime)
    return runtime
