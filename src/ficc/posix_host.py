# SPDX-License-Identifier: Apache-2.0
"""Host primitives for Linux and macOS controllers."""

import ctypes
import os
import select
import signal
import socket
import struct
import subprocess
import sys


def peer_uid(connection) -> int:
    """Read kernel credentials; never infer identity from socket permissions."""
    if sys.platform == "darwin":
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        getpeereid = ctypes.CDLL(None, use_errno=True).getpeereid
        getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint),
                              ctypes.POINTER(ctypes.c_uint)]
        getpeereid.restype = ctypes.c_int
        if getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)):
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return uid.value
    peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", peer)[1]


def process_descriptor(pid: int) -> int:
    """Return a readable-on-exit descriptor for an owned, unreaped child.

    The caller must retain the child without polling/waiting until it has killed
    the process group, preserving the existing protection against PID reuse.
    """
    if sys.platform != "darwin":
        return os.pidfd_open(pid)
    queue = select.kqueue()
    try:
        event = select.kevent(pid, filter=select.KQ_FILTER_PROC,
                              flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                              fflags=select.KQ_NOTE_EXIT)
        try:
            queue.control([event], 0, 0)
        except ProcessLookupError:
            # Darwin refuses registration for an already exited child. A pipe
            # at EOF supplies the same level-triggered readiness in that case.
            reader, writer = os.pipe()
            os.close(writer)
            return reader
        return os.dup(queue.fileno())
    finally:
        queue.close()


def kill_group(pid: int, sig: int = signal.SIGKILL) -> None:
    """Kill an owned group before its leader is reaped, including on Darwin."""
    try:
        os.killpg(pid, sig)
    except ProcessLookupError:
        return
    except PermissionError:
        if sys.platform != "darwin":
            raise
        # Darwin returns EPERM for groups containing only zombies. Confirm
        # there are no live members before accepting this as completed cleanup.
        result = subprocess.run(["/bin/ps", "-axo", "pgid=,stat="], capture_output=True,
                                text=True, timeout=3, check=True)
        for line in result.stdout.splitlines():
            group, state = line.split()
            if int(group) == pid and not state.startswith("Z"):
                raise
