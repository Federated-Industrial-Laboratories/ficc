# SPDX-License-Identifier: Apache-2.0
"""Check actual isolated VMConnect framing and complete native process cleanup."""

import asyncio
import json
import os
from pathlib import Path

import pytest
from test_viewer_configuration import rdp_config

from ficc.viewer import wire
from ficc.viewer_process import ViewerProcess

pytestmark = pytest.mark.skipif(os.environ.get("FICC_VIEWER_RDP_HOST_TESTS") != "1",
                               reason="Set FICC_VIEWER_RDP_HOST_TESTS=1 with an RDP runtime")


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_native_rdp_private_connection_and_owned_process_cleanup(count):
    runtime = Path(os.environ["FICC_VIEWER_RUNTIME"])
    for index in range(count):
        config = rdp_config(index)
        worker = ViewerProcess(runtime, protocol="rdp")
        group = None
        try:
            await worker.start(lambda: None)
            group = worker.group
            assert group is not None
            await worker.send(wire.CONFIG, json.dumps(config).encode())
            provider = bytearray()
            ready = False
            async with asyncio.timeout(15):
                while not ready or config["vm_id"].encode("utf-16-le") not in provider:
                    kind, data = await worker.receive()
                    if kind == wire.PROVIDER:
                        provider.extend(data)
                        assert len(provider) <= 4096
                    elif kind == wire.READY:
                        ready = True
            assert config["password"].encode() not in provider
            await worker.send(wire.END, b"{}")
        finally:
            await worker.close()
        assert worker.process.poll() is not None
        assert group is not None
        assert not group.exists() or "populated 0" in (group / "cgroup.events").read_text()
