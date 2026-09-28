# SPDX-License-Identifier: Apache-2.0
"""Check aggregate byte limits and cancellation on real nonblocking pipes."""

import asyncio
import os

import pytest

from ficc.errors import Failure
from ficc.modules.protocol import frame
from ficc.modules.sandbox_io import Channel


@pytest.fixture
def pipes():
    to_module, host_input = os.pipe()
    host_output, from_module = os.pipe()
    handles = [os.fdopen(fd, mode, buffering=0) for fd, mode in
               [(to_module, 'rb'), (host_input, 'wb'), (host_output, 'rb'), (from_module, 'wb')]]
    for handle in handles:
        os.set_blocking(handle.fileno(), False)
    yield handles
    for handle in handles:
        handle.close()


async def test_aggregate_response_bytes_are_bounded_across_frames(pipes, monkeypatch):
    import ficc.modules.sandbox_io as module

    _input, stdin, stdout, output = pipes
    data = frame({'value': 'bounded'})
    monkeypatch.setattr(module, 'MAX_OUTPUT', len(data) + 4)
    channel = Channel(stdin, stdout, 0, b'')
    output.write(data + data)
    assert await channel.receive() == {'value': 'bounded'}
    with pytest.raises(Failure) as error:
        await channel.receive()
    assert error.value.code == 'module_output_limit'


async def test_host_response_aggregate_has_the_same_bound(pipes, monkeypatch):
    import ficc.modules.sandbox_io as module

    _input, stdin, stdout, _output = pipes
    monkeypatch.setattr(module, 'MAX_OUTPUT', 16)
    channel = Channel(stdin, stdout, 16, b'')
    with pytest.raises(Failure) as error:
        await channel.send(b'x')
    assert error.value.code == 'module_output_limit'


def test_cancel_frame_is_one_nonblocking_write(pipes):
    reader, stdin, stdout, _output = pipes
    cancel = frame({'version': 2, 'type': 'cancel', 'id': 'a' * 32})
    channel = Channel(stdin, stdout, 0, cancel)
    channel.cancel_nowait()
    assert reader.read() == cancel
    while True:
        try:
            os.write(stdin.fileno(), b'x' * 4096)
        except BlockingIOError:
            break
    channel.cancel_nowait()
    stdin.close()
    channel.cancel_nowait()


async def test_pipelining_interrupts_an_awaited_callback(pipes):
    _reader, stdin, stdout, output = pipes
    channel = Channel(stdin, stdout, 0, b'')
    entered, cleaned = asyncio.Event(), asyncio.Event()

    async def callback():
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.set()

    task = asyncio.create_task(channel.dispatch(callback()))
    await entered.wait()
    output.write(b'x')
    with pytest.raises(Failure, match='pipelined'):
        await task
    assert cleaned.is_set()
