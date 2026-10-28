# SPDX-License-Identifier: Apache-2.0
"""Close an admitted response even when cancellation precedes its first yielded byte."""
class Stream:
    def __init__(self, iterator, cleanup):
        self.iterator, self.cleanup = iterator, cleanup
        self.closed = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.closed:
            raise StopAsyncIteration
        try:
            return await anext(self.iterator)
        except BaseException:
            await self.aclose()
            raise

    async def aclose(self):
        if not self.closed:
            self.closed = True
            try:
                await self.iterator.aclose()
            finally:
                await self.cleanup()
