# SPDX-License-Identifier: Apache-2.0
"""Run the trusted Windows transport with bounded secret input and process lifetime."""

import asyncio
import os
import signal
import time

from . import module_windows_spec as spec
from .errors import Failure


class Runner:
    def __init__(self, runtime=None):
        self.runtime = runtime
        self.active = set()
        self.starting = 0
        self.closed = False
        self.readiness = (0.0, False)

    def path(self):
        from .windows_runtime import discover
        return discover(self.runtime)

    def ready(self):
        if self.closed:
            return False
        if time.monotonic() < self.readiness[0]:
            return self.readiness[1]
        try:
            available = self.path() is not None
        except (OSError, ValueError):
            available = False
        self.readiness = (time.monotonic() + 5, available)
        return available

    @staticmethod
    def kill(process):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    async def run(self, request, *, check, timeout):
        if self.closed or len(self.active) + self.starting >= 8:
            raise Failure('windows_busy', 'Windows transport capacity is unavailable.', 503)
        deadline = time.monotonic() + timeout
        check()
        path = self.path()
        if path is None:
            raise Failure('windows_runtime_missing', 'Install the Windows transport runtime for this host.', 409)
        data = spec.encode(request)
        check()
        self.starting += 1
        try:
            process = await asyncio.create_subprocess_exec(
                str(path / 'python/bin/python3'), '-I', '-B', str(path / 'helper/entry.py'),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null'},
                cwd=path, start_new_session=True, limit=spec.MAX_JSON + 1)
            self.active.add(process)
        finally:
            self.starting -= 1
        assert process.stdin is not None and process.stdout is not None and process.stderr is not None
        incoming, outgoing, errors = process.stdin, process.stdout, process.stderr
        async def read(stream, maximum):
            output = bytearray()
            while True:
                block = await stream.read(min(65536, maximum + 1 - len(output)))
                if not block:
                    return bytes(output)
                output.extend(block)
                if len(output) > maximum:
                    raise Failure('windows_output_limit', 'The Windows response exceeded its byte limit.', 502)
        async def exchange():
            incoming.write(data)
            await incoming.drain()
            incoming.close()
            output, _ = await asyncio.gather(read(outgoing, spec.MAX_JSON), read(errors, 8192))
            status = await process.wait()
            if status == 2:
                raise Failure('windows_identity_changed', 'The Windows machine identity changed.', 409)
            if status != 0:
                raise Failure('windows_transport', 'The Windows transport refused or failed the request.', 502)
            result = spec.decode(output)
            spec.fields(result, {'version', 'results'})
            if result['version'] != 1:
                raise Failure('windows_protocol', 'The Windows transport version differs.', 502)
            return result['results']
        task = asyncio.create_task(exchange())
        try:
            while not task.done():
                check()
                if self.closed or time.monotonic() >= deadline:
                    raise Failure('windows_timeout', 'The Windows request exceeded its time limit.', 504)
                await asyncio.wait({task}, timeout=min(0.1, deadline - time.monotonic()))
            check()
            return task.result()
        finally:
            self.kill(process)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await process.wait()
            self.active.discard(process)

    async def close(self):
        self.closed = True
        processes = list(self.active)
        for process in processes:
            self.kill(process)
        await asyncio.gather(*(process.wait() for process in processes))
