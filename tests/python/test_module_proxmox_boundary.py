# SPDX-License-Identifier: Apache-2.0
"""Check private console peer binding and bounded fixed-dispatcher I/O."""

import contextlib
import os
import stat
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from ficc_node import proxmox_console as console
from ficc_node import proxmox_process as process
from ficc_node.vm_libvirt import ProviderError
from test_module_proxmox_protocol import identity


@pytest.mark.parametrize("fault", [None, "pid", "uid", "start", "path", "uuid"])
def test_console_peer_is_bound_before_config_lock_release(monkeypatch, fault):
    events = []
    domain = identity(100)
    value = {"parameters": {"uuids": [domain]}}
    descriptor = {"uuid": domain, "protocol": "vnc", "audio": False, "authentication": "rfb-password",
                  "pid": 123, "start": 999, "path": "/var/run/qemu-server/100.vnc"}
    if fault == "path":
        descriptor["path"] = "/tmp/other.vnc"
    if fault == "uuid":
        descriptor["uuid"] = identity(101)

    @contextlib.contextmanager
    def lock(vmid):
        assert vmid == 100
        events.append("locked")
        try:
            yield
        finally:
            events.append("released")

    class Socket:
        closed = False

        def settimeout(self, timeout):
            assert timeout == 2

        def connect(self, path):
            assert events == ["locked"] and path == "/run/qemu-server/100.vnc"
            events.append("connected")

        def getsockopt(self, *args):
            return struct.pack("3i", 124 if fault == "pid" else 123, 1000 if fault == "uid" else 0, 0)

        def close(self):
            self.closed = True

    stream = Socket()
    monkeypatch.setattr(console, "config_lock", lock)
    monkeypatch.setattr(console, "directory", lambda _: None)
    monkeypatch.setattr(console, "run", lambda _: descriptor)
    monkeypatch.setattr(Path, "lstat", lambda _: SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=0))
    counter = [0]

    def start(pid):
        assert pid == 123
        counter[0] += 1
        return 1000 if fault == "start" and counter[0] == 2 else 999

    monkeypatch.setattr(console, "process_start", start)
    monkeypatch.setattr(console.socket, "socket", lambda _: stream)
    if fault:
        with pytest.raises(ValueError):
            console.connect(value, "abcd1234")
        if "connected" in events:
            assert stream.closed
    else:
        assert console.connect(value, "abcd1234") is stream
        assert events == ["locked", "connected", "released"]
    assert events[-1] == "released"


@pytest.mark.parametrize("size", [1, 64])
@pytest.mark.parametrize("kind", ["stdout", "stderr", "timeout"])
def test_fixed_bridge_output_deadline_and_cleanup(monkeypatch, size, kind):
    original = subprocess.Popen
    children = []
    scripts = {"stdout": "import os,sys;sys.stdin.buffer.read();os.write(1,b'x'*(1048576+1))",
               "stderr": "import os,sys;sys.stdin.buffer.read();os.write(2,b'private-provider-detail'*500)",
               "timeout": "import time;time.sleep(60)"}

    def launch(arguments, **kwargs):
        assert arguments == ["/usr/bin/perl", "-e", process.SOURCE]
        child = original([sys.executable, "-c", scripts[kind]], **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(process.subprocess, "Popen", launch)
    with pytest.raises(ProviderError) as failure:
        process.run({"action": "status", "parameters": {"uuids": [identity(100 + i) for i in range(size)]}})
    assert failure.value.code == ("proxmox_timeout" if kind == "timeout" else "proxmox_output_limit")
    assert "private-provider-detail" not in str(failure.value)
    assert children[0].poll() is not None
    assert all(stream.closed for stream in (children[0].stdin, children[0].stdout, children[0].stderr))
    with pytest.raises(ProcessLookupError):
        os.kill(children[0].pid, 0)
