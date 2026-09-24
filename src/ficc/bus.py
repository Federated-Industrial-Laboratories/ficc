# SPDX-License-Identifier: Apache-2.0
"""Persist canonical bus messages and explicit recipient delivery intents."""

import time

from .agent_store import CLOSED, SETTLED, AgentStore, public
from .bus_schema import validate
from .errors import Failure


class Bus:
    def __init__(self, service):
        self.service = service
        self.store = AgentStore(service.store)

    def messages(self, run_id):
        return [value for value in self.store.all("bus_messages") if value["run_id"] == run_id]

    def deliveries(self, run_id=None):
        return [value for value in self.store.all("bus_deliveries") if run_id is None or value["run_id"] == run_id]

    def agents(self, run_id):
        return [value for value in self.store.all("agents") if value["run_id"] == run_id]

    def check_run(self, run_id, actor, scope):
        run = self.store.get("bus_runs", run_id)
        principal = self.service.auth.current(actor)
        principal.require(scope)
        agents = self.agents(run_id)
        if not agents and principal.node_ids is not None and run["actor"] != actor:
            raise Failure("denied", "This credential cannot access the selected bus run.", 403)
        for value in agents:
            principal.require(scope, value["node_id"])
        return run

    def view_run(self, value):
        return {**public(value), "agent_ids": [agent["id"] for agent in self.agents(value["id"])],
                "message_count": len(self.messages(value["id"]))}

    def create(self, request, actor):
        self.service.live()
        self.service.authorize(actor, "bus:send")
        intent = {"name": request["name"]}
        with self.service.store.lock:
            saved = self.store.retry("bus_runs", actor, request["idempotency_key"], intent)
            if saved:
                return self.view_run(saved)
            run = self.store.new("bus_runs", actor, request["idempotency_key"], intent,
                                 name=request["name"], state="open")
            self.store.save("bus_runs", run)
        return self.view_run(run)

    def send(self, run_id, request, actor, sender=None):
        self.service.live()
        run = self.check_run(run_id, actor, "bus:send")
        sender_id = sender["id"] if sender else "operator-" + actor
        if sender and sender["run_id"] != run_id:
            raise Failure("denied", "The sending agent is not enrolled in this run.", 403)
        intent = {"run_id": run_id, **{key: value for key, value in request.items() if key != "idempotency_key"}}
        owner = "agent-" + sender_id if sender else actor
        with self.service.store.lock:
            previous = self.store.retry("bus_messages", owner, request["idempotency_key"], intent)
            if previous:
                return {"message": public(previous), "deliveries": [public(value) for value in self.deliveries(run_id) if value["message_id"] == previous["id"]]}
            if run["state"] != "open":
                raise Failure("run_closed", "The selected bus run is closed.", 409)
            recipients = request["recipient_ids"]
            if len(set(recipients)) != len(recipients):
                raise Failure("invalid_recipients", "Select distinct recipient agents.")
            enrolled = {value["id"]: value for value in self.agents(run_id)}
            targets = []
            for identity in recipients:
                if identity not in enrolled or enrolled[identity]["state"] in CLOSED:
                    raise Failure("invalid_recipient", "Select a running agent enrolled in this run.", 409)
                target = enrolled[identity]
                self.service.authorize(actor, "bus:send", target["node_id"])
                if request["delivery"] == "direct" and target["delivery_method"] != "direct":
                    raise Failure("direct_unsupported", "This recipient supports inbox delivery only.", 409)
                targets.append(target)
            all_deliveries = self.deliveries()
            if sum(value["state"] not in SETTLED for value in all_deliveries) + len(targets) > 4096:
                raise Failure("capacity", "The unresolved delivery queue is full.", 409)
            if len(all_deliveries) + len(targets) > 32768 or len(self.store.all("bus_messages")) >= 16384:
                raise Failure("capacity", "Archive a closed run to release message capacity.", 409)
            messages = self.messages(run_id)
            sequence = max((v["sequence"] for v in messages if v["sender_id"] == sender_id), default=0) + 1
            references = {f'{v["sender_id"]}-{v["sequence"]}': v for v in messages}
            try:
                body = validate(request["type"], request["body"], f"{sender_id}-{sequence}", references)
            except (ValueError, TypeError, RecursionError) as exc:
                raise Failure("invalid_message", str(exc)) from None
            if request.get("reply_to") is not None and not any(value["id"] == request["reply_to"] for value in messages):
                raise Failure("invalid_reply", "The reply must name an earlier message in this run.")
            message = self.store.new("bus_messages", owner, request["idempotency_key"], intent,
                run_id=run_id, run_name=run["name"], sender_id=sender_id, sequence=sequence,
                ordinal=len(messages) + 1, type=request["type"], body=body, reply_to=request.get("reply_to"),
                recipient_ids=recipients)
            deliveries = []
            for target in targets:
                value = self.store.new("bus_deliveries", actor, message["id"] + target["id"], {},
                    run_id=run_id, message_id=message["id"], agent_id=target["id"], node_id=target["node_id"],
                    method=request["delivery"], state="host-stored", detail=None)
                deliveries.append(value)
            db = self.service.store.db
            try:
                db.execute("BEGIN IMMEDIATE")
                self.store.save("bus_messages", message, commit=False)
                for value in deliveries:
                    self.store.save("bus_deliveries", value, commit=False)
                db.commit()
            except BaseException:
                db.rollback()
                raise
            self.service.store.audit("bus.send", message["id"], actor=actor)
            return {"message": public(message), "deliveries": [public(value) for value in deliveries]}

    def close(self, run_id, actor):
        run = self.check_run(run_id, actor, "bus:send")
        if any(value["state"] not in CLOSED or value.get("outbox_acks") for value in self.agents(run_id)):
            raise Failure("run_busy", "Stop all enrolled agents before closing this run.", 409)
        if any(value["state"] not in SETTLED for value in self.deliveries(run_id)):
            raise Failure("run_busy", "Resolve all delivery outcomes before closing this run.", 409)
        run["state"] = "closed"
        self.store.save("bus_runs", run)
        return self.view_run(run)

    def cancel_unsubmitted(self, agent_id):
        for value in self.deliveries():
            if value["agent_id"] == agent_id and value["state"] == "host-stored":
                value.update(state="cancelled", detail="The recipient was stopped before node admission.")
                self.store.save("bus_deliveries", value)

    def delivery_payload(self, value):
        self.service.authorize(value["actor"], "bus:send", value["node_id"])
        principal = self.service.auth.current(value["actor"])
        message = self.store.get("bus_messages", value["message_id"])
        return {"id": value["id"], "run_id": value["run_id"], "message_id": message["id"],
                "agent_id": value["agent_id"], "sender_id": message["sender_id"], "type": message["type"],
                "body": message["body"], "method": value["method"],
                "authorization_expires_at": min(principal.expires_at, time.time() + 15)}
