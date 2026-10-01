# SPDX-License-Identifier: Apache-2.0
"""Exercise bounded helper exchange, revocation, admission and descendant cleanup."""

import asyncio
import sys
from pathlib import Path

import pytest

from ficc.errors import Failure
from ficc.windows_process import Runner


@pytest.fixture
def helper(tmp_path):
    (tmp_path / 'python/bin').mkdir(parents=True)
    (tmp_path / 'python/bin/python3').symlink_to(sys.executable)
    (tmp_path / 'helper').mkdir()
    runner = Runner()
    runner.path = lambda: tmp_path
    return runner, tmp_path / 'helper/entry.py'


@pytest.mark.parametrize('count', [1, 64])
async def test_helper_complete_distinct_batch(helper, count):
    runner, script = helper
    script.write_text('import json,sys\nv=json.load(sys.stdin)\njson.dump({"version":1,"results":v["items"]},sys.stdout)\n')
    value = [{'index': index} for index in range(count)]
    assert await runner.run({'items': value}, check=lambda: None, timeout=2) == value
    assert not runner.active


@pytest.mark.parametrize('mode', ['timeout', 'output', 'stderr', 'error'])
async def test_helper_timeout_and_output_never_expose_secret(helper, mode):
    runner, script = helper
    programs = {'timeout': 'import time;time.sleep(30)',
                'output': 'import sys;sys.stdout.write("x"*1048577);sys.stdout.flush()',
                'stderr': 'import sys;sys.stderr.write("secret-value"*1000);sys.stderr.flush()',
                'error': 'import sys;sys.stderr.write("secret-value");sys.exit(2)'}
    script.write_text(programs[mode])
    with pytest.raises(Failure) as caught:
        await runner.run({}, check=lambda: None, timeout=0.3)
    assert 'secret-value' not in str(caught.value)
    assert not runner.active


async def test_helper_current_authority_cancels_waiting_process(helper):
    runner, script = helper
    script.write_text('import time;time.sleep(30)')
    allowed = True
    def check():
        if not allowed:
            raise Failure('denied', 'The test grant was revoked.', 403)
    task = asyncio.create_task(runner.run({}, check=check, timeout=5))
    await asyncio.sleep(0.05)
    allowed = False
    with pytest.raises(Failure, match='revoked'):
        await task
    assert not runner.active


async def test_helper_identity_refusal_has_a_fixed_error_and_no_secret(helper):
    runner, script = helper
    script.write_text('import sys;sys.stderr.write("private-test-marker");sys.exit(2)')
    with pytest.raises(Failure) as caught:
        await runner.run({}, check=lambda: None, timeout=2)
    assert caught.value.code == 'windows_identity_changed'
    assert 'private-test-marker' not in str(caught.value)
    assert not runner.active


async def test_helper_refuses_ninth_concurrent_child_and_close_reaps_all(helper):
    runner, script = helper
    script.write_text('import time;time.sleep(30)')
    tasks = [asyncio.create_task(runner.run({}, check=lambda: None, timeout=5)) for _ in range(8)]
    await asyncio.sleep(0.1)
    assert len(runner.active) == 8
    with pytest.raises(Failure, match='capacity'):
        await runner.run({}, check=lambda: None, timeout=5)
    await runner.close()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert all(isinstance(value, Failure) for value in results)
    assert not runner.active


async def test_helper_kills_child_holding_pipes_after_parent_exits(helper, tmp_path):
    runner, script = helper
    pid = tmp_path / 'child.pid'
    script.write_text('import os,time,pathlib\nchild=os.fork()\nif child:\n'
                      f' pathlib.Path({str(pid)!r}).write_text(str(child))\n os._exit(0)\n'
                      'time.sleep(30)\n')
    with pytest.raises(Failure, match='time limit'):
        await runner.run({}, check=lambda: None, timeout=0.4)
    child = int(pid.read_text())
    status = Path(f'/proc/{child}/stat')
    for _ in range(25):
        if not status.exists() or status.read_text().split()[2] == 'Z':
            break
        await asyncio.sleep(0.02)
    assert not status.exists() or status.read_text().split()[2] == 'Z'
    assert not runner.active
