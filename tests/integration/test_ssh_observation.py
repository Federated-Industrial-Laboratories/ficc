# SPDX-License-Identifier: Apache-2.0
"""Exercise owned observation reuse, identity changes and finite process lifetime."""

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from test_ssh import ssh_fixture  # noqa: F401

from ficc import ssh as ssh_module
from ficc.auth import Auth
from ficc.errors import Failure
from ficc.settings import MAX_NODES
from ficc.store import Store


@pytest.fixture
async def observer(request):
    transport, _, root = request.getfixturevalue("ssh_fixture")
    try:
        value = await transport.preview("fixture-node", "Observer")
        await transport.install(value)
        value["id"] = "owned-observation"
        yield transport, value, root
    finally:
        await transport.close()


async def test_real_observation_reuses_and_reset_reaps(observer):
    transport, node, _ = observer
    first = await transport.probe(node)
    master = transport.masters.current[node["id"]]
    directory = master.directory
    assert master.process is not None
    pid = master.process.pid
    second = await transport.probe(node)
    assert first["boot_id"] == second["boot_id"]
    assert transport.masters.current[node["id"]] is master
    assert (await transport.command(node, "exec /usr/bin/true", b""))[0] == 0
    assert master.alive()
    transport.reset()
    assert not master.alive() and not transport.masters.current
    await master.watcher
    assert not directory.exists()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    await transport.probe(node)
    assert transport.masters.current[node["id"]] is not master


async def test_real_second_identity_change_replaces_master(observer):
    transport, node, root = observer
    await transport.probe(node)
    old = transport.masters.current[node["id"]]
    config = root / "ssh_config"
    config.write_text(config.read_text() + f"  IdentityFile {root / 'additional'}\n")
    await transport.probe(node)
    assert transport.masters.current[node["id"]] is not old
    await old.watcher
    assert not old.directory.exists()


@pytest.mark.parametrize("change", ["key", "identity", "destination"])
async def test_real_changed_trust_does_not_use_old_master(observer, change):
    transport, node, root = observer
    await transport.probe(node)
    old = transport.masters.current[node["id"]]
    expected = "host_key_changed"
    if change == "key":
        node["key"] = (root / "other.pub").read_text().split()[1]
    else:
        config = root / "ssh_config"
        if change == "identity":
            config.write_text(config.read_text().replace(str(root / "client"), str(root / "other")))
            expected = "authentication_failed"
        else:
            config.write_text(config.read_text().replace("HostName 127.0.0.1", "HostName 127.0.0.2"))
            expected = "profile_changed"
    with pytest.raises(Failure) as failure:
        await transport.probe(node)
    assert failure.value.code == expected
    await old.watcher
    assert not old.directory.exists() and not transport.masters.current


async def test_real_master_expiration_removes_socket(observer, monkeypatch):
    monkeypatch.setattr("ficc.ssh_master.LIFETIME", 1)
    monkeypatch.setattr("ficc.ssh_master.PROBE_RESERVE", .2)
    transport, node, _ = observer
    await transport.probe(node)
    master = transport.masters.current[node["id"]]
    await asyncio.wait_for(master.watcher, 4)
    assert not master.alive() and not master.directory.exists()
    await transport.probe(node)
    assert transport.masters.current[node["id"]] is not master


async def test_master_supervisor_expires_after_owner_crash(observer, tmp_path):
    transport, node, _ = observer
    args = await transport.arguments(node)
    request = tmp_path / "master-arguments.json"
    request.write_text(json.dumps(args))
    code = """import asyncio,json,os,sys
from pathlib import Path
from ficc import ssh_master
ssh_master.LIFETIME=1
async def main():
 m=ssh_master.Master('crash-fixture',json.loads(Path(sys.argv[1]).read_text()))
 await m.wait_ready()
 print(json.dumps({'pid':m.process.pid,'directory':str(m.directory)}),flush=True)
 os._exit(0)
asyncio.run(main())
"""
    result = await asyncio.to_thread(subprocess.run, [sys.executable, "-c", code, str(request)],
                                     capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        stat = Path(f"/proc/{value['pid']}/stat")
        if not stat.exists() or stat.read_text().rpartition(")")[2].split()[0] == "Z":
            break
        await asyncio.sleep(.05)
    else:
        pytest.fail("The master supervisor survived its finite lifetime.")
    directory = Path(value["directory"])
    (directory / "control").unlink(missing_ok=True)
    directory.rmdir()


async def test_real_dead_master_reconnects(observer):
    transport, node, _ = observer
    await transport.probe(node)
    old = transport.masters.current[node["id"]]
    assert old.process is not None
    os.killpg(old.process.pid, signal.SIGKILL)
    await old.watcher
    result = await transport.probe(node)
    assert result["version"] == "1"
    assert transport.masters.current[node["id"]] is not old


async def test_real_replaced_control_socket_fails_closed(observer, tmp_path):
    transport, node, _ = observer
    await transport.probe(node)
    old = transport.masters.current[node["id"]]
    target = tmp_path / "preserved"
    target.write_text("unrelated")
    old.socket.unlink()
    old.socket.symlink_to(target)
    with pytest.raises(Failure) as failure:
        await transport.probe(node)
    assert failure.value.code == "transport_unavailable"
    await old.watcher
    assert target.read_text() == "unrelated" and not old.directory.exists()


async def test_real_probe_renews_before_master_deadline(observer, monkeypatch):
    monkeypatch.setattr("ficc.ssh_master.LIFETIME", 2)
    monkeypatch.setattr("ficc.ssh_master.PROBE_RESERVE", .5)
    monkeypatch.setattr(ssh_module, "PROBE", "sleep 0.5; " + ssh_module.PROBE)
    transport, node, _ = observer
    await transport.probe(node)
    old = transport.masters.current[node["id"]]
    await asyncio.sleep(max(0, old.expires - time.monotonic() - .25))
    assert old.alive()
    result = await transport.probe(node)
    assert result["version"] == "1"
    assert transport.masters.current[node["id"]] is not old
    await old.watcher
    assert not old.directory.exists()


def owned_processes(masters):
    pids = set()
    for master in masters:
        assert master.process is not None and master.alive() and master.socket_ready()
        pid = master.process.pid
        children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
        assert len(children) == 1
        pids.update([pid, int(children[0])])
    assert len(pids) == 2 * len(masters)
    return pids


async def assert_reaped(masters, pids):
    await asyncio.wait_for(asyncio.gather(*(master.watcher for master in masters)), 5)
    for _ in range(100):
        if all(not Path(f"/proc/{pid}").exists() for pid in pids):
            break
        await asyncio.sleep(.05)
    assert all(not Path(f"/proc/{pid}").exists() for pid in pids)
    assert all(not master.directory.exists() and not master.socket.exists() for master in masters)


@pytest.mark.parametrize("count", [1, 64])
async def test_real_observation_pool_lifecycle(observer, count):
    """Use distinct owners on one isolated endpoint, not separate physical machines."""
    transport, template, root = observer
    nodes = [dict(template, id=f"observation-{index}") for index in range(count)]
    for node in nodes:
        assert (await transport.probe(node))["version"] == "1"
    owners = dict(transport.masters.current)
    assert len(owners) == len(transport.masters.watchers) == count
    assert len({master.identity for master in owners.values()}) == count
    assert len({master.socket for master in owners.values()}) == count
    pids = owned_processes(list(owners.values()))
    for node in nodes:
        assert (await transport.probe(node))["version"] == "1"
        assert transport.masters.current[node["id"]] is owners[node["id"]]
    assert owned_processes(list(owners.values())) == pids
    if count == MAX_NODES:
        with pytest.raises(Failure) as failure:
            await transport.probe(dict(template, id="observation-over-capacity"))
        assert failure.value.code == "capacity"
        assert transport.masters.current == owners
        assert len(transport.masters.watchers) == MAX_NODES

    config = root / "ssh_config"
    config.write_text(config.read_text() + config.read_text().replace("fixture-node", "fixture-last"))
    nodes[-1]["profile"] = "fixture-last"
    last = owners[nodes[-1]["id"]]
    last_pids = owned_processes([last])
    assert (await transport.probe(nodes[-1]))["version"] == "1"
    assert transport.masters.current[nodes[-1]["id"]] is not last
    await assert_reaped([last], last_pids)
    for node in nodes[:-1]:
        assert (await transport.probe(node))["version"] == "1"
        assert transport.masters.current[node["id"]] is owners[node["id"]]
    assert len(transport.masters.current) == len(transport.masters.watchers) == count

    owners = list(transport.masters.current.values())
    pids = owned_processes(owners)
    store = Store(root / "credentials" / "state.sqlite3")
    try:
        auth = Auth(store)
        auth.on_revoke = transport.reset
        token, principal = auth.issue("token")
        assert auth.resolve(token).id == principal.id
        auth.revoke(principal.id)
        with pytest.raises(Failure) as failure:
            auth.resolve(token)
        assert failure.value.code == "unauthenticated"
        assert not transport.masters.current
        await assert_reaped(owners, pids)
        assert not transport.masters.watchers
    finally:
        store.close()

    for node in nodes:
        assert (await transport.probe(node))["version"] == "1"
    owners = list(transport.masters.current.values())
    assert len(owners) == count
    pids = owned_processes(owners)
    await transport.close()
    await assert_reaped(owners, pids)
    assert not transport.masters.current and not transport.masters.watchers


async def test_real_replacement_rechecks_grant_after_reaping(observer):
    transport, node, root = observer
    await transport.probe(node)
    old = transport.masters.current[node["id"]]
    pids = owned_processes([old])
    config = root / "ssh_config"
    config.write_text(config.read_text() + f"  IdentityFile {root / 'additional'}\n")

    def check():
        if old.closed:
            assert not transport.masters.current, "A replacement started before access was checked."
            raise Failure("denied", "The credential is revoked.", 403)

    with pytest.raises(Failure) as failure:
        await transport.probe(node, check=check)
    assert failure.value.code == "denied"
    await assert_reaped([old], pids)
    assert not transport.masters.current and not transport.masters.watchers
