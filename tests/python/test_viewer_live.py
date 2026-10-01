# SPDX-License-Identifier: Apache-2.0
"""Qualify the complete bounded native display bridge on an explicit fixture VM."""

import asyncio
import json
import os
from pathlib import Path

import pytest
from test_module_vm_live_support import live_vm as live_vm

from ficc.viewer.wire import instruction, parse
from ficc.viewer_stream import bridge

pytestmark = pytest.mark.skipif(os.environ.get("FICC_VIEWER_HOST_TESTS") != "1",
                               reason="Explicit native viewer qualification required")


def test_live_domain_display_and_cleanup(live_vm):
    live = live_vm
    rows = live.fixture_rows()
    selected = rows["ficc-vm-a"]["id"]
    live.activate(live.grants + [{"capability": "vm:console", "target_ids": [live.node["id"]]}])

    def guard():
        live.service.authorize(live.actor, "vm:console", live.node["id"])
        live.service.modules.require(live.digest, "vm:console", [live.node["id"]])

    class Complete(Exception):
        pass

    async def run():
        queue = asyncio.Queue()
        counts = {"img": 0, "end": 0, "size": 0, "sync": 0}

        class Socket:
            async def send_bytes(self, data):
                values = parse(data.decode(), 65536)
                if values[0] in counts:
                    counts[values[0]] += 1
                await queue.put(json.dumps({"type": "ack", "bytes": len(data)}))
                if values[0] == "sync":
                    if counts["sync"] > 1 and counts["end"] > 0 and counts["size"] > 0:
                        raise Complete()
                    await queue.put(json.dumps({"type": "input", "instruction": instruction("sync", values[1]).decode()}))

            async def receive_text(self):
                return await queue.get()

        descriptor = await live.service.vms.console(live.actor, live.digest, live.context["instance_id"],
                                                    live.node["id"], selected, guard)
        arguments, header = await live.service.vms.console_command(descriptor, guard)
        with pytest.raises(Complete):
            async with asyncio.timeout(30):
                await bridge(Socket(), Path(os.environ["FICC_VIEWER_RUNTIME"]), arguments, header, guard,
                             authentication=descriptor["graphics"]["authentication"])
        assert counts["img"] and counts["end"] and counts["size"] and counts["sync"]
    live.client.portal.call(run)
