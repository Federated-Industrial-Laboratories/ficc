# SPDX-License-Identifier: Apache-2.0
"""Acknowledge each reply independently and retain permanent refusal evidence."""

import re
import time

from .agent_schema import Message
from .agent_store import fingerprint
from .errors import Failure

PERMANENT = {"invalid_message", "invalid_reply", "invalid_recipient", "invalid_recipients",
             "direct_unsupported", "run_closed", "idempotency_conflict"}


def collect(manager, agent, outbox):
    agent["outbox_acks"] = []
    for item in outbox:
        acknowledgement: str | dict
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not re.fullmatch(r"[a-f0-9]{32}", item["id"]):
            raise Failure("invalid_agent_response", "The outbox entry has no valid durable identity.", 502)
        try:
            # Validate the saved launch grant before classifying content failures.
            manager.service.bus.check_run(agent["run_id"], agent["actor"], "bus:send")
            try:
                if set(item) != {"id", "type", "body", "recipient_ids", "reply_to", "idempotency_key", "delivery"} or item["id"] != item["idempotency_key"]:
                    raise ValueError()
                request = Message.model_validate({key: value for key, value in item.items() if key != "id"} | {
                    "confirm_delivery": True}).model_dump()
            except ValueError:
                raise Failure("invalid_message", "The agent outbox message failed validation.") from None
            manager.service.bus.send(agent["run_id"], request, agent["actor"], sender=agent)
            acknowledgement = item["id"]
        except Failure as exc:
            if exc.code not in PERMANENT:
                continue
            previous = agent.get("outbox_rejections", [])
            rejection = next((r for r in previous if r["id"] == item["id"]), None)
            if rejection is None:
                rejection = {"id": item["id"], "code": exc.code, "detail": exc.message[:240], "rejected_at": time.time()}
            agent["outbox_rejections"] = [r for r in previous if r["id"] != item["id"]][-15:] + [rejection]
            acknowledgement = {**rejection, "state": "host-rejected", "sha256": fingerprint(item)}
        agent["outbox_acks"].append(acknowledgement)
        # A later item or lost reply cannot erase an earlier durable decision.
        manager.store.save("agents", agent)
    manager.store.save("agents", agent)
