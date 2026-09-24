# SPDX-License-Identifier: Apache-2.0
"""Detect surviving descendants after supervision ends."""

import asyncio
import os
import signal
import sys
from pathlib import Path

import pytest

from ficc.errors import Failure
from ficc.process import run


@pytest.mark.parametrize("ending", ["timeout", "cancel", "overflow"])
async def test_cleanup_when_parent_exits_before_descendant(tmp_path, ending):
    pid_file = tmp_path / "child"
    emit = "os.write(1,b'x'*4096)" if ending == "overflow" else "pass"
    script = ("import os,time,pathlib\n"
              "if os.fork() == 0:\n"
              f" p=pathlib.Path({str(pid_file)!r})\n"
              " p.with_suffix('.pending').write_text(str(os.getpid()))\n"
              " p.with_suffix('.pending').rename(p)\n"
              f" {emit}\n time.sleep(30)\n"
              "else:\n os._exit(0)\n")
    pending = asyncio.create_task(run([sys.executable, "-c", script],
                                      timeout=0.3, maximum=1024))
    try:
        async with asyncio.timeout(2):
            while not pid_file.exists():
                await asyncio.sleep(0.01)
        if ending == "cancel":
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        else:
            with pytest.raises(Failure) as result:
                await pending
            assert result.value.code == ("output_limit" if ending == "overflow" else "unreachable")
        pid = int(pid_file.read_text())
        status = Path(f"/proc/{pid}/stat")
        async with asyncio.timeout(2):
            while True:
                try:
                    if status.read_text().split()[2] == "Z":
                        break
                except (FileNotFoundError, ProcessLookupError):
                    break
                await asyncio.sleep(0.01)
    finally:
        if not pending.done():
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
