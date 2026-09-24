# SPDX-License-Identifier: Apache-2.0
"""Reconcile bounded SSH delivery batches without replaying runtime submissions."""

from .agent_store import SETTLED
from .errors import Failure

STATES = {"node-stored", "adapter-submitted", "session-included", "tool-read", "uncertain", "failed", "cancelled", "missing"}


async def exchange(manager, agent):
    bus = manager.service.bus
    deliveries = [value for value in bus.deliveries(agent["run_id"]) if value["agent_id"] == agent["id"] and value["state"] not in SETTLED]
    selected = []
    for value in deliveries:
        if value["state"] != "host-stored":
            continue
        try:
            selected.append((value, bus.delivery_payload(value)))
        except Failure:
            value.update(state="cancelled", detail="The originating delivery credential expired or was revoked before dispatch.")
            manager.store.save("bus_deliveries", value)
        if len(selected) >= 8:
            break
    def check():
        for value, _ in selected:
            manager.service.authorize(value["actor"], "bus:send", value["node_id"])
        if manager.service.store.node(agent["node_id"])["fingerprint"] != agent["fingerprint"]:
            raise Failure("identity_changed", "The agent node identity changed.", 409)
    pending = [value for value in deliveries if value["state"] != "host-stored"]
    start = manager.cursors.get(agent["id"], 0) % max(1, len(pending))
    receipt_ids = [value["id"] for value in (pending[start:] + pending[:start])[:8]]
    manager.cursors[agent["id"]] = start + 8
    # Newly stored items return receipts on the next exchange, keeping both bounds at eight.
    for value, _ in selected:
        value.update(state="host-uncertain", detail="Dispatch started; node storage is not yet confirmed.")
        manager.store.save("bus_deliveries", value)
    result = await manager.remote(agent["node_id"], "exchange", {"controller_id": manager.controller,
        "agent_id": agent["id"], "deliveries": [payload for _, payload in selected],
        "receipt_ids": receipt_ids, "outbox_acks": agent.get("outbox_acks", [])[:8]}, check)
    manager.observed(agent, result)
    for value, _ in selected:
        value.update(state="node-stored", detail="The node confirmed durable inbox storage.")
        manager.store.save("bus_deliveries", value)
    receipts, outbox = result.get("receipts"), result.get("outbox")
    if not isinstance(receipts, list) or len(receipts) > 8 or not isinstance(outbox, list) or len(outbox) > 8:
        raise Failure("invalid_agent_response", "The exchange response exceeds its record limit.", 502)
    for receipt in receipts:
        if not isinstance(receipt, dict) or receipt.get("id") not in receipt_ids or receipt.get("state") not in STATES:
            raise Failure("invalid_agent_response", "The node returned an unrequested delivery receipt.", 502)
        saved = manager.store.get("bus_deliveries", receipt["id"])
        if saved["agent_id"] != agent["id"]:
            raise Failure("invalid_agent_response", "The delivery receipt names a different agent.", 502)
        if saved["state"] not in SETTLED:
            state = receipt["state"]
            if state == "missing":
                if saved["state"] != "host-uncertain":
                    raise Failure("invalid_agent_response", "A previously confirmed node delivery is missing.", 502)
                state = "host-stored"
            saved.update(state=state, detail=str(receipt.get("detail") or "")[:240])
            manager.store.save("bus_deliveries", saved)
    from .agent_outbox import collect
    collect(manager, agent, outbox)
