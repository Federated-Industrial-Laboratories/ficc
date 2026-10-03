# SPDX-License-Identifier: Apache-2.0
"""Bound authority requests by elapsed time, concurrency and response bytes."""

import asyncio
import threading
import time

import httpx

from .config import Config, document

MAX_RESPONSE = 65536


class Transport:
    def __init__(self, config: Config):
        self.config = config
        self._lock = threading.Lock()
        self._closed = False
        self._slots = threading.BoundedSemaphore(4)
        self._loop = asyncio.new_event_loop()
        self._tasks: set[asyncio.Task] = set()
        self._client = httpx.AsyncClient(
            verify=config.tls, trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(3.0),
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=4),
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
        )
        self._thread = threading.Thread(target=self._run, name="ficc-ca", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_forever()
        finally:
            self._loop.close()

    async def _request(self, path: str, body: dict, seconds: float) -> tuple[int, dict]:
        task = asyncio.current_task()
        assert task is not None
        self._tasks.add(task)
        try:
            async with asyncio.timeout(seconds):
                async with self._client.stream("POST", self.config.url + path, json=body) as response:
                    if response.status_code not in (200, 201, 400):
                        raise ValueError("The authority refused the request.")
                    if (response.headers.get("content-encoding", "identity") != "identity"
                            or response.headers.get("content-type", "").split(";", 1)[0]
                            != "application/json"):
                        raise ValueError("The authority response format is invalid.")
                    length = response.headers.get("content-length")
                    if length is not None and (not length.isdecimal() or int(length) > MAX_RESPONSE):
                        raise ValueError("The authority response exceeds its limit.")
                    raw = bytearray()
                    async for chunk in response.aiter_raw():
                        raw.extend(chunk)
                        if len(raw) > MAX_RESPONSE:
                            raise ValueError("The authority response exceeds its limit.")
                    return response.status_code, document(bytes(raw))
        finally:
            self._tasks.discard(task)

    def request(self, path: str, body: dict, deadline: float) -> tuple[int, dict]:
        if path not in ("/sign", "/revoke"):
            raise ValueError("The authority endpoint is invalid.")
        if not self._slots.acquire(blocking=False):
            raise ValueError("The certificate authority is busy.")
        future = None
        try:
            with self._lock:
                seconds = deadline - time.monotonic()
                if self._closed or seconds <= 0:
                    raise ValueError
                future = asyncio.run_coroutine_threadsafe(self._request(path, body, seconds),
                                                           self._loop)
            return future.result(timeout=seconds)
        except Exception:
            if future is not None:
                future.cancel()
            raise ValueError("The certificate authority request failed.") from None
        finally:
            self._slots.release()

    async def _close(self) -> None:
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self._client.aclose()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            future = asyncio.run_coroutine_threadsafe(self._close(), self._loop)
        try:
            future.result(timeout=2)
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=2)
