# SPDX-License-Identifier: Apache-2.0
"""Bind a verified Proxmox QEMU Unix peer before releasing its config lock."""

import fcntl
import os
import secrets
import signal
import socket
import stat
import string
import struct
from contextlib import contextmanager
from pathlib import Path

from . import proxmox_spec as spec
from . import proxmox_state, vm_state
from .proxmox_compat import require_console, require_provider
from .proxmox_process import run
from .vm_console import relay


def directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("Unsafe provider console directory.")


@contextmanager
def config_lock(vmid):
    # This is QemuConfig::config_file_lock in the qualified implementation.
    base = Path("/run/lock/qemu-server")
    directory(base)
    fd = os.open(base / f"lock-{vmid}.conf", os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
            raise ValueError("Unsafe provider configuration lock.")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def process_start(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    if len(raw) > 8192:
        raise ValueError("Invalid provider process status.")
    return int(raw.rsplit(")", 1)[1].split()[19])


def connect(value, password):
    domain_id = value["parameters"]["uuids"][0]
    vmid = spec.vmid(domain_id)
    with config_lock(vmid):
        descriptor = run({"action": "console-bind", "parameters": {"uuids": [domain_id], "password": password}})
        spec.fields(descriptor, {"uuid", "protocol", "audio", "authentication", "pid", "start", "path"})
        if (descriptor["uuid"] != domain_id or descriptor["protocol"] != "vnc"
                or descriptor["audio"] is not False or descriptor["authentication"] != "rfb-password"):
            raise ValueError("The provider console identity changed.")
        pid = spec.integer(descriptor["pid"], 2, 2**31 - 1)
        start = spec.integer(descriptor["start"], 1, 9007199254740991)
        path = Path(f"/run/qemu-server/{vmid}.vnc")
        if descriptor["path"] != f"/var/run/qemu-server/{vmid}.vnc":
            raise ValueError("Unexpected provider console path.")
        directory(path.parent)
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or process_start(pid) != start:
            raise ValueError("The provider console process changed.")
        stream = socket.socket(socket.AF_UNIX)
        try:
            stream.settimeout(2)
            stream.connect(str(path))
            peer, uid, _ = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer != pid or uid != 0 or process_start(pid) != start:
                raise ValueError("The provider console peer changed.")
            return stream
        except BaseException:
            stream.close()
            raise


def main():
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(6)
    session_fd = None
    stream = None
    try:
        raw = bytearray()
        while len(raw) <= 4096:
            byte = os.read(0, 1)
            if byte == b"\n":
                break
            if not byte:
                raise ValueError("Missing console header.")
            raw.extend(byte)
        if len(raw) > 4096:
            raise ValueError("The console header exceeds its byte limit.")
        header = spec.decode(bytes(raw))
        spec.fields(header, {"request"})
        value = spec.request(header["request"])
        if value["action"] != "console":
            raise ValueError("Invalid console action.")
        require_provider(value["provider"])
        require_console(value["provider"])
        domain_id = value["parameters"]["uuids"][0]
        # QEMU has one VNC password. Keep one FICC attachment per VM so a
        # second attachment cannot replace credentials during authentication.
        with proxmox_state.locked() as base:
            session_fd = vm_state.checked_fd(base / ("console-" + domain_id + ".lock"), os.O_CREAT | os.O_RDWR)
            fcntl.flock(session_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        password = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        stream = connect(value, password)
        signal.alarm(3600)
        os.write(1, spec.encode({"version": 1, "ready": True, "password": password}) + b"\n")
        password = ""
        relay(stream.fileno())
        return 0
    except Exception:
        # No credentials or provider details are written to the error channel.
        return 1
    finally:
        if stream is not None:
            stream.close()
        if session_fd is not None:
            os.close(session_fd)


if __name__ == "__main__":
    raise SystemExit(main())
