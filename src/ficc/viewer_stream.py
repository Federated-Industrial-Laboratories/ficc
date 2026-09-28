# SPDX-License-Identifier: Apache-2.0
"""Relay one bound provider descriptor through the isolated native viewer."""

import asyncio
import json
import os
import signal
import subprocess
import time

from .errors import Failure
from .modules.sandbox import finish_cleanup
from .process import ready
from .viewer import configuration, wire
from .viewer_output import Output, OutputError
from .viewer_process import ViewerProcess
from .viewer_tcp import TCPProviderStream

WINDOW = 2 * 1024 * 1024


class ProviderStream:
    def __init__(self, arguments):
        self.process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True, bufsize=0)
        assert self.process.stdin and self.process.stdout
        self.pipes = self.process.stdin, self.process.stdout
        for pipe in self.pipes:
            os.set_blocking(pipe.fileno(), False)

    async def read(self, size=32768):
        while True:
            try:
                return os.read(self.pipes[1].fileno(), size)
            except BlockingIOError:
                await ready(self.pipes[1].fileno())

    async def write(self, data):
        async with asyncio.timeout(10):
            offset = 0
            while offset < len(data):
                try:
                    offset += os.write(self.pipes[0].fileno(), data[offset:offset + 8192])
                except BlockingIOError:
                    await ready(self.pipes[0].fileno(), writing=True)

    async def start(self, header, authentication="none"):
        async with asyncio.timeout(8):
            await self.write(header)
            response = bytearray()
            while len(response) < 1024:
                byte = await self.read(1)
                if not byte:
                    raise Failure("viewer_attach_failed", "The provider closed the display connection.", 502)
                response.extend(byte)
                if byte == b"\n":
                    return configuration.ready(response, authentication)
            raise ValueError("The graphics helper response exceeds its limit.")

    async def close(self):
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            if self.process.poll() is None:
                fd = os.pidfd_open(self.process.pid)
                try:
                    await ready(fd)
                finally:
                    os.close(fd)
        finally:
            self.process.wait()
            for pipe in self.pipes:
                pipe.close()


async def bridge(socket, runtime, arguments, header, check, *, authentication="none", connection=None):
    native = None
    provider: ProviderStream | TCPProviderStream | None = None
    tasks = []
    pending, started = 0, time.monotonic()
    last_ack = last_input = started
    changed = asyncio.Event()
    changed.set()
    output = Output()
    try:
        check()
        if connection is None:
            provider = ProviderStream(arguments)
            password = await provider.start(header, authentication)
            config = {"version": 1, "protocol": "vnc"}
            if password is not None:
                config["password"] = password
            data = json.dumps(config).encode("ascii")
        else:
            if arguments or header or authentication != "none":
                raise ValueError("Display transports cannot be combined.")
            provider = TCPProviderStream()
            data = await provider.start(connection, check)
        check()
        native = ViewerProcess(runtime, protocol=configuration.settings(data)["protocol"])
        await native.start(check)
        await native.send(wire.CONFIG, data)

        async def provider_output():
            while data := await provider.read():
                await native.send(wire.PROVIDER, data)

        async def native_output():
            nonlocal pending, last_ack
            while True:
                kind, data = await native.receive()
                if kind == wire.PROVIDER:
                    await provider.write(data)
                elif kind == wire.DISPLAY:
                    try:
                        for packet in output.iter_feed(data):
                            while pending + len(packet) > WINDOW:
                                changed.clear()
                                await changed.wait()
                            if pending == 0:
                                last_ack = time.monotonic()
                            pending += len(packet)
                            async with asyncio.timeout(10):
                                await socket.send_bytes(packet)
                            while len(output.syncs) >= 3:
                                changed.clear()
                                await changed.wait()
                    except OutputError as exc:
                        raise Failure("viewer_output_rejected", str(exc), 502) from exc
                elif kind != wire.READY:
                    raise ValueError("Unexpected native viewer response.")

        async def browser_input():
            nonlocal pending, last_ack, last_input
            start, count, size = time.monotonic(), 0, 0
            while True:
                text = await socket.receive_text()
                check()
                now = time.monotonic()
                if now - start >= 1:
                    start, count, size = now, 0, 0
                count += 1
                size += len(text)
                if len(text) > 8192 or size > 1048576 or count > 512:
                    raise Failure("viewer_input_limit", "Display input exceeds its rate or size limit.", 413)
                value = json.loads(text)
                if not isinstance(value, dict):
                    raise ValueError("Invalid viewer control message.")
                if set(value) == {"type", "bytes"} and value["type"] == "ack":
                    amount = value["bytes"]
                    if type(amount) is not int or not 0 < amount <= pending:
                        raise ValueError("Invalid display acknowledgement.")
                    pending -= amount
                    last_ack = now
                    changed.set()
                elif set(value) == {"type", "instruction"} and value["type"] == "input":
                    if not isinstance(value["instruction"], str):
                        raise ValueError("Invalid display input.")
                    data = wire.permitted_input(value["instruction"].encode("ascii"))
                    data = output.acknowledge(data)
                    changed.set()
                    await native.send(wire.DISPLAY, data)
                    if wire.parse(data.decode("ascii"))[0] in {"mouse", "key", "size"}:
                        last_input = now
                else:
                    raise ValueError("Invalid viewer control message.")

        async def authority():
            while True:
                await asyncio.sleep(0.25)
                check()
                now = time.monotonic()
                if now - started > 3600 or now - last_input > 1800:
                    raise Failure("viewer_expired", "The display session reached its time limit.", 409)
                if (pending or output.syncs) and now - last_ack > 15:
                    raise Failure("viewer_stalled", "Display output was not acknowledged.", 409)

        tasks = [asyncio.create_task(action()) for action in
                 (provider_output, native_output, browser_input, authority)]
        tasks.append(native.errors)
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        async def cleanup():
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            try:
                if native is not None:
                    await native.close()
            finally:
                if provider is not None:
                    await provider.close()
        await finish_cleanup(cleanup())
