# SPDX-License-Identifier: Apache-2.0
"""Connect one isolated provider stream to a private Guacamole daemon.

Input and output use bounded private frames. No provider address, user path or
command is accepted. Exit zero only after a controlled session disconnect.
"""

import asyncio
import os
import signal
import sys

from .configuration import settings as private_settings
from .connection import settings as connection_settings
from .wire import (
    CONFIG,
    DISPLAY,
    END,
    PROVIDER,
    READY,
    frame,
    instruction,
    parse,
    permitted_input,
    read_frame,
)


async def main():
    if len(os.sched_getaffinity(0)) != 1:
        raise ValueError("The native viewer requires one assigned processor.")
    loop = asyncio.get_running_loop()
    incoming = asyncio.StreamReader(limit=131072)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(incoming), sys.stdin.buffer)
    output_reader = asyncio.StreamReader()
    outgoing = asyncio.StreamReaderProtocol(output_reader)
    transport, _ = await loop.connect_write_pipe(lambda: outgoing, sys.stdout.buffer)
    output = asyncio.StreamWriter(transport, outgoing, None, loop)
    lock = asyncio.Lock()

    async def send(kind, data):
        async with lock, asyncio.timeout(10):
            output.write(frame(kind, data))
            await output.drain()

    async with asyncio.timeout(10):
        kind, data = await read_frame(incoming)
    if kind != CONFIG:
        raise ValueError("Unsupported viewer configuration.")
    config = private_settings(data)
    provider_connected = loop.create_future()

    async def provider(reader, writer):
        if provider_connected.done():
            writer.close()
            return
        provider_connected.set_result((reader, writer))

    server = await asyncio.start_server(provider, "127.0.0.1", 0, limit=65536)
    provider_port = server.sockets[0].getsockname()[1]
    daemon = await asyncio.create_subprocess_exec(
        "/viewer/sbin/guacd", "-f", "-b", "127.0.0.1", "-l", "4822", "-L", "warning",
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL, start_new_session=True)
    tasks = []
    tunnel = None
    provider_writer = None
    try:
        async with asyncio.timeout(8):
            while True:
                if daemon.returncode is not None:
                    raise ValueError("The private display daemon exited.")
                try:
                    tunnel_reader, tunnel = await asyncio.open_connection("127.0.0.1", 4822, limit=65536)
                    break
                except ConnectionRefusedError:
                    await asyncio.sleep(0.05)
            tunnel.write(instruction("select", config["protocol"]))
            await tunnel.drain()
            args = parse((await tunnel_reader.readuntil(b";")).decode("ascii"), 16384)
            if args[0] != "args" or len(args) < 3 or args[1] != "VERSION_1_5_0" or len(args) != len(set(args)):
                raise ValueError("Invalid display daemon arguments.")
            settings = connection_settings(config, provider_port, args[2:])
            tunnel.write(instruction("size", 1024, 768, 96) + instruction("audio")
                         + instruction("video") + instruction("image", "image/png")
                         + instruction("connect", args[1], *[settings.get(name, "") for name in args[2:]]))
            await tunnel.drain()
            provider_reader, provider_writer = await provider_connected
        server.close()

        async def provider_output():
            while data := await provider_reader.read(32768):
                await send(PROVIDER, data)

        async def display_output():
            while data := await tunnel_reader.read(32768):
                await send(DISPLAY, data)

        async def input_frames():
            while True:
                kind, data = await read_frame(incoming)
                if kind == PROVIDER:
                    destination = provider_writer
                elif kind == DISPLAY:
                    permitted_input(data)
                    destination = tunnel
                elif kind == END:
                    return
                else:
                    raise ValueError("Invalid viewer frame direction.")
                async with asyncio.timeout(10):
                    destination.write(data)
                    await destination.drain()

        await send(READY, b'{"version":1}')
        tasks = [asyncio.create_task(action()) for action in (provider_output, display_output, input_frames)]
        async with asyncio.timeout(3600):
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
    finally:
        server.close()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for writer in (tunnel, provider_writer):
            if writer is not None:
                writer.close()
        try:
            os.killpg(daemon.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await daemon.wait()
        async with asyncio.timeout(2):
            await server.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (OSError, ValueError, UnicodeError, asyncio.IncompleteReadError, TimeoutError):
        raise SystemExit(1) from None
