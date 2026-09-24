# SPDX-License-Identifier: Apache-2.0
"""Expose scoped agent execution and explicit addressed bus delivery."""

from typing import Annotated, Literal

from fastapi import Query, Request
from pydantic import Field

from .agent_schema import AgentLaunch, AgentPreview, AgentStop, Message, RunClose, RunCreate
from .agent_store import public
from .errors import Failure
from .schema import Model


class Rebind(Model):
    runtime_session_id: Annotated[str, Field(min_length=1, max_length=100)]
    confirm_rebind: Literal[True]


def install(app, service, principal):
    manager, bus = service.agents, service.bus

    @app.get("/api/v1/agent-profiles")
    async def profiles(request: Request):
        actor = principal(request, "agents:read")
        return {"profiles": [public(value) for value in manager.store.all("agent_profiles")
                             if actor.node_ids is None or value["node_id"] in actor.node_ids]}

    @app.get("/api/v1/agents")
    async def agents(request: Request):
        actor = principal(request, "agents:read")
        return {"agents": [public(value) for value in manager.all()
                           if actor.node_ids is None or value["node_id"] in actor.node_ids]}

    @app.get("/api/v1/agents/{identity}")
    async def agent(identity: str, request: Request):
        value = manager.store.get("agents", identity)
        principal(request, "agents:read", value["node_id"])
        return public(value)

    @app.post("/api/v1/agent-previews")
    async def preview(body: AgentPreview, request: Request):
        actor = principal(request, "agents:execute")
        return await manager.preview(body.model_dump(), actor.id)

    @app.post("/api/v1/agents")
    async def launch(body: AgentLaunch, request: Request):
        actor = principal(request, "agents:execute")
        return await manager.launch(body.model_dump(), actor.id)

    @app.post("/api/v1/agents/{identity}/stop")
    async def stop(identity: str, body: AgentStop, request: Request):
        actor = principal(request, "agents:stop")
        return await manager.action(identity, actor.id, "stop")

    @app.post("/api/v1/agents/{identity}/reconcile")
    async def reconcile(identity: str, request: Request):
        actor = principal(request, "agents:execute")
        return await manager.action(identity, actor.id, "status")

    @app.post("/api/v1/agents/{identity}/rebind")
    async def rebind(identity: str, body: Rebind, request: Request):
        actor = principal(request, "agents:execute")
        return await manager.action(identity, actor.id, "rebind", {"runtime_session_id": body.runtime_session_id})

    @app.get("/api/v1/bus/runs")
    async def runs(request: Request):
        actor = principal(request, "bus:read")
        visible = []
        for value in bus.store.all("bus_runs"):
            try:
                bus.check_run(value["id"], actor.id, "bus:read")
            except Failure as exc:
                if exc.status != 403:
                    raise
                continue
            visible.append(bus.view_run(value))
        return {"runs": visible}

    @app.post("/api/v1/bus/runs")
    async def create_run(body: RunCreate, request: Request):
        actor = principal(request, "bus:send")
        return bus.create(body.model_dump(), actor.id)

    @app.post("/api/v1/bus/runs/{identity}/close")
    async def close_run(identity: str, body: RunClose, request: Request):
        actor = principal(request, "bus:send")
        return bus.close(identity, actor.id)

    @app.get("/api/v1/bus/runs/{identity}/messages")
    async def messages(identity: str, request: Request,
                       after: Annotated[int, Query(ge=0)] = 0,
                       limit: Annotated[int, Query(ge=1, le=100)] = 100):
        actor = principal(request, "bus:read")
        bus.check_run(identity, actor.id, "bus:read")
        rows = [public(value) for value in bus.messages(identity) if value["ordinal"] > after][:limit + 1]
        return {"messages": rows[:limit], "next_after": rows[limit - 1]["ordinal"] if len(rows) > limit else None}

    @app.post("/api/v1/bus/runs/{identity}/messages")
    async def send(identity: str, body: Message, request: Request):
        actor = principal(request, "bus:send")
        return bus.send(identity, body.model_dump(), actor.id)

    @app.get("/api/v1/bus/deliveries")
    async def deliveries(request: Request, run_id: str | None = None):
        actor = principal(request, "bus:read")
        allowed = set()
        for run in bus.store.all("bus_runs"):
            if run_id is not None and run["id"] != run_id:
                continue
            try:
                bus.check_run(run["id"], actor.id, "bus:read")
            except Failure as exc:
                if exc.status != 403:
                    raise
                continue
            allowed.add(run["id"])
        return {"deliveries": [public(value) for value in bus.deliveries(run_id) if value["run_id"] in allowed][-1000:]}
