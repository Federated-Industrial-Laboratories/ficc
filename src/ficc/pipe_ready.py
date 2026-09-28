# SPDX-License-Identifier: Apache-2.0
"""Wait for one nonblocking pipe without a thread pool."""

import asyncio


async def ready(fd: int, writing: bool = False) -> None:
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def notify() -> None:
        if not future.done():
            future.set_result(None)

    add = loop.add_writer if writing else loop.add_reader
    remove = loop.remove_writer if writing else loop.remove_reader
    add(fd, notify)
    try:
        await future
    finally:
        remove(fd)
