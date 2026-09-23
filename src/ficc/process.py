# SPDX-License-Identifier: Apache-2.0
"""Run child processes with finite output, time, and process lifetimes."""

import asyncio
import os
import signal

from .errors import Failure
from .settings import MAX_MESSAGE


async def run(command: list[str], payload: bytes = b"", timeout: float = 10,
              maximum: int = MAX_MESSAGE) -> tuple[int, bytes, bytes]:
    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, start_new_session=True)
    except OSError as exc:
        raise Failure("transport_unavailable", "The required program is unavailable.", 503) from exc

    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    stdin, stdout_pipe, stderr_pipe = process.stdin, process.stdout, process.stderr

    async def read(stream: asyncio.StreamReader) -> bytes:
        result = bytearray()
        while chunk := await stream.read(8192):
            result.extend(chunk)
            if len(result) > maximum:
                raise Failure("output_limit", "The remote response exceeds the limit.", 502)
        return bytes(result)

    async def write() -> None:
        try:
            stdin.write(payload)
            await stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            stdin.close()

    stdout_task = asyncio.create_task(read(stdout_pipe))
    stderr_task = asyncio.create_task(read(stderr_pipe))
    write_task = asyncio.create_task(write())
    tasks = [stdout_task, stderr_task, write_task]
    try:
        async with asyncio.timeout(timeout):
            await asyncio.gather(*tasks)
            stdout, stderr = stdout_task.result(), stderr_task.result()
            code = await process.wait()
            return code, stdout, stderr
    except TimeoutError as exc:
        raise Failure("unreachable", "The connection timed out.", 502) from exc
    finally:
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await process.wait()
