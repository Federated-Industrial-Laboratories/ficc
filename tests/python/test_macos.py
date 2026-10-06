# SPDX-License-Identifier: Apache-2.0
"""Exercise native resource parsing and portable kernel ownership checks."""

import asyncio
import os
import select
import socket
import subprocess
import sys
import time

import pytest
from ficc_node.collect_macos import memory_available, network_counters

from ficc.posix_host import kill_group, peer_uid, process_descriptor
from ficc.process import run


@pytest.mark.parametrize("directory", [False, True])
def test_atomic_archive_rename_preserves_existing_destination(tmp_path, directory):
    from ficc_node.file_access import rename

    source, target = tmp_path / "source", tmp_path / "target"
    if directory:
        source.mkdir()
        target.mkdir()
    else:
        source.write_bytes(b"source")
        target.write_bytes(b"target")
    original, existing = source.stat().st_ino, target.stat().st_ino
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(FileExistsError):
            rename(descriptor, b"source", descriptor, b"target")
        assert source.stat().st_ino == original and target.stat().st_ino == existing
        if directory:
            target.rmdir()
        else:
            target.unlink()
        rename(descriptor, b"source", descriptor, b"target")
        assert not source.exists() and target.stat().st_ino == original
    finally:
        os.close(descriptor)


def test_atomic_exchange_preserves_both_objects(tmp_path):
    from ficc_node.file_access import rename

    first, second = tmp_path / "first", tmp_path / "second"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        rename(descriptor, b"first", descriptor, b"second", 2)
        assert first.read_bytes() == b"second" and second.read_bytes() == b"first"
    finally:
        os.close(descriptor)


def test_memory_available_uses_page_size_without_double_counting_purgeable():
    sample = """Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free: 10.
Pages inactive: 20.
Pages speculative: 3.
Pages purgeable: 8.
Pages occupied by compressor: 50.
"""
    assert memory_available(sample) == 33 * 16384
    with pytest.raises(ValueError):
        memory_available("invalid")


def test_network_uses_link_rows_with_and_without_a_hardware_address():
    sample = """Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
lo0 16384 <Link#1> 10 0 100 20 0 200 0
lo0 16384 127 127.0.0.1 10 - 100 20 - 200 -
en0 1500 <Link#2> aa:bb:cc:dd:ee:ff 30 0 300 40 0 400 0
gif0* 1280 <Link#3> 0 0 0 0 0 0 0
"""
    assert network_counters(sample) == [
        {"name": "lo0", "rx_bytes": 100, "tx_bytes": 200},
        {"name": "en0", "rx_bytes": 300, "tx_bytes": 400},
        {"name": "gif0", "rx_bytes": 0, "tx_bytes": 0}]


def test_peer_credentials_come_from_the_kernel():
    first, second = socket.socketpair()
    try:
        assert peer_uid(first) == os.getuid()
        first.close()
        with pytest.raises(OSError):
            peer_uid(first)
    finally:
        first.close()
        second.close()


@pytest.mark.parametrize("already_exited", [False, True])
def test_process_descriptor_preserves_unreaped_child_identity(already_exited):
    process = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(.1)"],
                               start_new_session=True)
    descriptor = None
    try:
        if already_exited:
            time.sleep(.3)
        descriptor = process_descriptor(process.pid)
        assert select.select([descriptor], [], [], 3)[0]
        # Readiness remains observable without reaping or consuming an event.
        assert select.select([descriptor], [], [], 0)[0]
        assert process.returncode is None
    finally:
        kill_group(process.pid)
        process.wait(timeout=3)
        if descriptor is not None:
            os.close(descriptor)


def test_command_round_trip_after_immediate_and_delayed_exit():
    async def check():
        for delay in (0, .1):
            code, stdout, stderr = await run([sys.executable, "-c",
                f"import time,sys;time.sleep({delay});sys.stdout.buffer.write(sys.stdin.buffer.read())"],
                b"native byte round trip\x00\xff")
            assert code == 0 and stdout == b"native byte round trip\x00\xff" and stderr == b""
    asyncio.run(check())


def test_agent_version_probe_reaps_a_finished_process():
    from ficc_node.agent_process import version

    assert version([sys.executable]) == "Python " + sys.version.split()[0]


@pytest.mark.skipif(sys.platform != "darwin", reason="Requires native macOS counters")
def test_native_resource_sample_matches_controller_protocol():
    from ficc_node.collect import collect
    from ficc_node.job_system import capability

    from ficc.schema import Sample

    value = collect()
    Sample.model_validate(value)
    assert value["capabilities"]["source"] == "macos-mach-sysctl"
    assert value["resources"]["memory_total_bytes"] > 0
    assert capability()["jobs"] is False
