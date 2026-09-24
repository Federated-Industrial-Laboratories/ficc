# SPDX-License-Identifier: Apache-2.0
"""Keep local file workers owned until their descriptors can be closed safely."""

import asyncio
import threading
from contextlib import suppress


async def owned(function, *args, cancellable=False):
    cancel = threading.Event()
    kwargs = {"cancel": cancel} if cancellable else {}
    task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        cancel.set()
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        with suppress(Exception):
            task.result()
        raise
