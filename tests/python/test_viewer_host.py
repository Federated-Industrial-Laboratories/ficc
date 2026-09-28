# SPDX-License-Identifier: Apache-2.0
"""Qualify the native viewer in its real private network and resource boundary."""

import asyncio
import os
from pathlib import Path

import pytest

from ficc.viewer import wire
from ficc.viewer_process import ViewerProcess

pytestmark = pytest.mark.skipif(os.environ.get("FICC_VIEWER_HOST_TESTS") != "1",
                               reason="Set FICC_VIEWER_HOST_TESTS=1 for native viewer qualification")


async def test_native_vnc_handshake_and_complete_cleanup():
    runtime = Path(os.environ["FICC_VIEWER_RUNTIME"])
    worker = ViewerProcess(runtime)
    group = None
    try:
        await worker.start(lambda: None)
        group = worker.group
        assert group is not None
        await worker.send(wire.CONFIG, b'{"version":1,"protocol":"vnc"}')
        async with asyncio.timeout(15):
            while True:
                kind, _ = await worker.receive()
                if kind == wire.READY:
                    break
            await worker.send(wire.PROVIDER, b"RFB 003.008\n")
            while True:
                kind, data = await worker.receive()
                if kind == wire.PROVIDER:
                    assert data == b"RFB 003.008\n"
                    break
            # This untrusted display command cannot create a clipboard stream.
            await worker.send(wire.DISPLAY, wire.instruction("clipboard", 0, "text/plain"))
            with pytest.raises(EOFError):
                while True:
                    await worker.receive()
    finally:
        await worker.close()
    assert worker.process.poll() is not None
    assert group is not None
    assert not group.exists() or "populated 0" in (group / "cgroup.events").read_text()
