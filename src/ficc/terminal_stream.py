# SPDX-License-Identifier: Apache-2.0
"""Bridge authenticated terminal bytes with bounded callback acknowledgements."""

import asyncio
import json
import time
from contextlib import suppress

from starlette.websockets import WebSocket, WebSocketDisconnect

from .errors import Failure
from .process import ready
from .terminal_pty import TerminalPTY
from .terminals import TERMINAL

WINDOW = 262144
STALL_SECONDS = 30
IDLE_SECONDS = 1800


async def bridge(socket: WebSocket, pty: TerminalPTY, check) -> str:
    pending = 0
    last_ack = time.monotonic()
    last_input = last_ack
    changed = asyncio.Event()
    changed.set()

    async def output():
        nonlocal pending, last_ack
        while True:
            if pending >= WINDOW:
                changed.clear()
                await changed.wait()
                continue
            chunk = await pty.read(min(32768, WINDOW - pending))
            if not chunk:
                return "exited"
            if pending == 0:
                last_ack = time.monotonic()
            pending += len(chunk)
            async with asyncio.timeout(STALL_SECONDS):
                await socket.send_bytes(chunk)

    async def receive():
        nonlocal pending, last_ack, last_input
        start, count, size = time.monotonic(), 0, 0
        while True:
            message = await socket.receive()
            if message["type"] == "websocket.disconnect":
                return "detached"
            check()
            now = time.monotonic()
            if now - start >= 1:
                start, count, size = now, 0, 0
            count += 1
            if count > 256:
                raise Failure("rate_limit", "Terminal input arrived too quickly.", 429)
            data = message.get("bytes")
            if data is not None:
                size += len(data)
                if not 0 < len(data) <= 16384 or size > 1048576:
                    raise Failure("input_limit", "Terminal input exceeds the limit.", 413)
                last_input = now
                await pty.write(data)
                continue
            text = message.get("text", "")
            if len(text) > 1024:
                raise ValueError("Invalid terminal control frame.")
            value = json.loads(text)
            if not isinstance(value, dict):
                raise ValueError("Invalid terminal control frame.")
            if set(value) == {"type", "bytes"} and value["type"] == "ack":
                amount = value["bytes"]
                if type(amount) is not int or not 0 < amount <= pending:
                    raise ValueError("Invalid output acknowledgement.")
                pending -= amount
                last_ack = now
                changed.set()
            elif set(value) == {"type", "cols", "rows"} and value["type"] == "resize":
                pty.resize(value["cols"], value["rows"])
            else:
                raise ValueError("Invalid terminal control frame.")

    async def guard():
        while True:
            await asyncio.sleep(1)
            check()
            now = time.monotonic()
            if pending and now - last_ack > STALL_SECONDS:
                raise Failure("output_gap", "Output was not acknowledged. The attachment was closed.", 409)
            if now - last_input > IDLE_SECONDS:
                raise Failure("idle", "The idle terminal attachment was closed.", 409)

    async def child():
        assert pty.pidfd is not None
        await ready(pty.pidfd)
        await asyncio.sleep(1)
        raise Failure("output_gap", "The SSH process exited before its output channel closed.", 409)

    tasks = [asyncio.create_task(f()) for f in (output, receive, guard, child)]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if task.exception():
                raise task.exception()  # type: ignore[misc]
        return next(iter(done)).result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def stream(socket: WebSocket, manager, terminal_id: str, origins: set[str], hosts: set[str]):
    # Own an attachment task, rather than the ASGI server's enclosing request task.
    task = asyncio.create_task(attachment(socket, manager, terminal_id, origins, hosts))
    await task


async def attachment(socket: WebSocket, manager, terminal_id: str, origins: set[str], hosts: set[str]):
    if (socket.headers.get("host") not in hosts or socket.headers.get("origin") not in origins
            or socket.headers.get("sec-fetch-site") == "cross-site" or socket.url.query):
        await socket.close(code=1008)
        return
    await socket.accept()
    pty, actor, owned = None, None, False
    outcome = "interrupted"
    try:
        async with asyncio.timeout(5):
            first = await socket.receive_text()
            if len(first) > 512:
                raise ValueError("Invalid terminal ticket frame.")
            value = json.loads(first)
            if not isinstance(value, dict) or set(value) != {"type", "ticket"} or value["type"] != "auth":
                raise ValueError("Invalid terminal ticket frame.")
            actor = manager.consume(terminal_id, value["ticket"])
        async with manager.lock:
            value = manager.get(terminal_id)
            if terminal_id in manager.active or value["state"] in TERMINAL:
                raise Failure("terminal_busy", "The terminal is attached or closed.", 409)
            task = asyncio.current_task()
            assert task is not None
            manager.active[terminal_id] = task
            owned = True
            value["state"] = "connecting"
            manager.save(value)
        args = await manager.arguments(value, actor)
        manager.check(actor, "terminals:execute", value)
        pty = TerminalPTY(args, value["cols"], value["rows"])
        value["state"] = "attached"
        manager.save(value)
        manager.store.audit("terminal.attach", terminal_id, actor=actor)
        await socket.send_json({"type": "status", "state": "attached"})
        outcome = await bridge(socket, pty, lambda: manager.check(actor, "terminals:execute", value))
        if outcome == "exited":
            await socket.send_json({"type": "status", "state": "exited"})
    except Failure as exc:
        state = "denied" if exc.status in (401, 403) else "output_gap" if exc.code == "output_gap" else "error"
        with suppress(WebSocketDisconnect, RuntimeError, OSError):
            await socket.send_json({"type": "status", "state": state, "message": exc.message})
    except (ValueError, TypeError, KeyError, OSError, TimeoutError):
        with suppress(WebSocketDisconnect, RuntimeError, OSError):
            await socket.send_json({"type": "status", "state": "error",
                                    "message": "The terminal attachment failed or exceeded its limits."})
    except (WebSocketDisconnect, asyncio.CancelledError):
        outcome = "detached"
    finally:
        if pty:
            await pty.close()
        if owned:
            manager.active.pop(terminal_id, None)
            value = manager.get(terminal_id)
            if value["state"] not in TERMINAL and value["state"] != "unknown":
                value["state"] = ("detached" if value["mode"] == "tmux" else
                                  "exited" if outcome in {"exited", "detached"} else "interrupted")
                manager.save(value)
            manager.store.audit("terminal.detach", terminal_id, outcome, actor or "unknown")
        with suppress(WebSocketDisconnect, RuntimeError, OSError):
            await socket.close()
