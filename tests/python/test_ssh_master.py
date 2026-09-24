# SPDX-License-Identifier: Apache-2.0
"""Check observation identity, bounds and per-dispatch access checks."""

import asyncio
import json
import sys
from types import SimpleNamespace

import pytest
from conftest import node, sample

from ficc.errors import Failure
from ficc.settings import Settings
from ficc.ssh import SSH
from ficc.ssh_master import Master, Masters, options


def test_option_replacement_preserves_first_option_policy():
    args = ["ssh", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o",
            "SessionType=default", "-o", "ForwardAgent=no", "--", "fixture"]
    changed = options(args, ControlMaster="yes", ControlPath="/private/control", SessionType="none")
    assert "ControlMaster=no" not in changed and changed.count("ControlMaster=yes") == 1
    assert "SessionType=default" not in changed and "SessionType=none" in changed
    assert "ForwardAgent=no" in changed and changed[-2:] == ["--", "fixture"]
    assert args[2] == "ControlMaster=no"
    assert options(["ssh", "-F", "ControlPath=config"], ControlPath="changed") == [
        "ssh", "-F", "ControlPath=config"]


async def test_repeated_config_values_are_part_of_identity(tmp_path, monkeypatch):
    transport = SSH(Settings(state_dir=tmp_path / "state"))
    output = b"hostname machine.example\nuser operator\nport 22\nidentityfile first\nidentityfile second\n"

    async def run(*args, **kwargs):
        return 0, output, b""

    monkeypatch.setattr("ficc.ssh.run", run)
    first = await transport.config("fixture")
    output = output.replace(b"second", b"changed")
    second = await transport.config("fixture")
    assert first["identityfile"] == second["identityfile"] == "first"
    assert first["resolved_digest"] != second["resolved_digest"]


@pytest.mark.parametrize("count", [1, 64])
async def test_distinct_observation_identities_and_fresh_commands(tmp_path, monkeypatch, count):
    transport = SSH(Settings(state_dir=tmp_path / "state"))
    acquired, calls, grants = [], [], []

    async def config(profile):
        index = int(profile.split("-")[-1])
        return {"hostname": node(index)["host"], "user": "operator", "port": 22,
                "resolved_digest": str(index)}

    async def acquire(node_id, identity, args, check):
        check()
        acquired.append((node_id, identity, args))
        return SimpleNamespace(socket=tmp_path / node_id)

    async def run(args, payload=b"", **kwargs):
        calls.append(args)
        return 0, json.dumps(sample()).encode(), b""

    monkeypatch.setattr(transport, "config", config)
    monkeypatch.setattr(transport.masters, "acquire", acquire)
    monkeypatch.setattr("ficc.ssh.run", run)
    for index in range(count):
        value = node(index)
        await transport.probe(value, check=lambda: grants.append(index))
        await transport.command(value, "fixed", b"")
    assert len(acquired) == count and len({r[1] for r in acquired}) == count
    assert len(grants) == count * 3
    for index in range(count):
        assert acquired[index][0] == node(index)["id"]
        assert f"ControlPath={tmp_path / node(index)['id']}" in calls[index * 2]
        assert "ControlPath=none" in calls[index * 2 + 1]
        assert "ControlMaster=no" in calls[index * 2 + 1]


async def test_revoked_grant_after_startup_cannot_dispatch(tmp_path, monkeypatch):
    transport = SSH(Settings(state_dir=tmp_path / "state"))
    value = node()
    revoked = False
    dispatched = []

    async def config(profile):
        return {"hostname": value["host"], "user": value["account"], "port": 22,
                "resolved_digest": "configured"}

    async def acquire(*args):
        nonlocal revoked
        revoked = True
        return SimpleNamespace(socket=tmp_path / "control")

    def check():
        if revoked:
            raise Failure("denied", "The credential is revoked.", 403)

    async def run(*args, **kwargs):
        dispatched.append(args)
        return 0, json.dumps(sample()).encode(), b""

    monkeypatch.setattr(transport, "config", config)
    monkeypatch.setattr(transport.masters, "acquire", acquire)
    monkeypatch.setattr("ficc.ssh.run", run)
    with pytest.raises(Failure, match="revoked"):
        await transport.probe(value, check=check)
    assert not dispatched


async def test_master_capacity_counts_unreaped_owners(monkeypatch):
    pool = Masters()
    blockers = [asyncio.create_task(asyncio.sleep(60)) for _ in range(64)]
    pool.watchers.update(blockers)
    try:
        with pytest.raises(Failure) as failure:
            await pool.acquire("node-new", "identity", [])
        assert failure.value.code == "capacity"
    finally:
        for task in blockers:
            task.cancel()
        await asyncio.gather(*blockers, return_exceptions=True)


async def test_master_output_limit_stops_and_reaps():
    master = Master("output-limit", [sys.executable, "-c",
                    "import os,time;os.write(2,b'x'*20000);time.sleep(60)"])
    await asyncio.wait_for(master.watcher, 3)
    assert len(master.stderr) == 16384
    assert not master.alive() and not master.directory.exists()
    assert master.process is not None and master.process.returncode is not None


async def test_master_startup_timeout_closes_owner(monkeypatch):
    monkeypatch.setattr("ficc.ssh_master.STARTUP", .05)
    pool = Masters()
    try:
        with pytest.raises(TimeoutError):
            await pool.acquire("waiting", "identity", [sys.executable, "-c", "import time;time.sleep(60)"])
        assert not pool.current
    finally:
        await pool.close()
    assert not pool.watchers


async def test_closed_pool_refuses_late_start():
    pool = Masters()
    await pool.close()
    with pytest.raises(Failure) as failure:
        await pool.acquire("late", "identity", [])
    assert failure.value.code == "transport_unavailable" and not pool.current
