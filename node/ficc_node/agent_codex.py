# SPDX-License-Identifier: Apache-2.0
"""Reconcile Codex delivery IDs against exact persisted user-message items."""

from . import agent_adapter as adapter
from . import agent_spool as spool
from .agent_rpc import RPCError


def page(rpc, thread, params):
    try:
        return rpc.call("thread/items/list", params), 64
    except RPCError as exc:
        if exc.code != -32601:
            raise
    # Newly active threads can lack the paginated history projection. Read the
    # supported thread representation with the same byte and identity bounds.
    result = rpc.call("thread/read", {"threadId": thread, "includeTurns": True})
    value = result.get("thread", {})
    turns = value.get("turns")
    if value.get("id") != thread or not isinstance(turns, list) or len(turns) > 64:
        raise ValueError("The runtime thread history identity or size is invalid.")
    items: list[dict] = []
    for turn in turns:
        rows = turn.get("items")
        if not isinstance(rows, list) or len(items) + len(rows) > 256:
            raise ValueError("The runtime thread history exceeds capacity.")
        items.extend({"item": item} for item in rows)
    return {"data": items, "nextCursor": None}, 256


def reconcile(rpc, controller, agent, thread, revision=0):
    with spool.locked(controller, agent) as folder:
        runtime = spool.read(folder / "runtime.json")
        if runtime["session_id"] != thread or runtime.get("binding_revision", 0) != revision:
            return
        expected = {}
        for path in folder.glob("receipt-*.json"):
            value = spool.read(path)
            if value["state"] in {"uncertain", "adapter-submitted"} and value.get("session_id", thread) == thread:
                item = spool.read(folder / ("inbox-" + value["id"] + ".json"))
                if item["method"] == "direct":
                    expected[value["id"]] = adapter.text(item)
    cursor = None
    if not expected:
        rpc.call("thread/read", {"threadId": thread, "includeTurns": False})
    for _ in range(4 if expected else 0):
        params = {"threadId": thread, "limit": 64, "sortDirection": "desc"}
        if cursor:
            params["cursor"] = cursor
        result, maximum = page(rpc, thread, params)
        rows = result.get("data")
        if not isinstance(rows, list) or len(rows) > maximum:
            raise ValueError("The runtime item response exceeds capacity.")
        for row in rows:
            item = row.get("item", {})
            identity = item.get("clientId")
            if item.get("type") != "userMessage" or identity not in expected:
                continue
            content = item.get("content")
            if not isinstance(content, list) or len(content) != 1 or content[0].get("type") != "text" or content[0].get("text") != expected[identity]:
                raise ValueError("The runtime user-message identity has conflicting content.")
            adapter.dispatch(controller, agent, "receipt", {"session_id": thread, "delivery_id": identity,
                "state": "session-included", "detail": "The exact Codex thread contains this client ID and message content."})
            expected.pop(identity)
        cursor = result.get("nextCursor")
        if not cursor or not expected:
            break
    for event in rpc.events:
        if event.get("method") == "thread/started":
            identity = event.get("params", {}).get("thread", {}).get("id")
            if identity and identity != thread:
                adapter.dispatch(controller, agent, "suspend", {"session_id": identity,
                    "expected_session_id": thread, "binding_revision": revision})
    rpc.events.clear()


def observe(rpc, controller, agent, thread, revision=0):
    try:
        reconcile(rpc, controller, agent, thread, revision)
        return True
    except (OSError, ValueError, KeyError, TypeError):
        adapter.dispatch(controller, agent, "suspend", {"session_id": thread,
            "expected_session_id": thread, "binding_revision": revision})
        return False
