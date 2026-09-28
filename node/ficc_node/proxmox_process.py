# SPDX-License-Identifier: Apache-2.0
"""Run the fixed local Perl bridge with byte, time and lifetime bounds."""

import ctypes
import functools
import os
import selectors
import signal
import subprocess
import time

from . import proxmox_spec as spec
from .proxmox_compat import ENVIRONMENT
from .proxmox_shim import SOURCE
from .vm_libvirt import ProviderError


def child(parent):
    # The bridge dies with its helper. Registered Proxmox task children have
    # their own sessions and provider receipts, and deliberately survive it.
    if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(126)


def run(value):
    raw = spec.encode(value)
    process = subprocess.Popen(["/usr/bin/perl", "-e", SOURCE], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENVIRONMENT, cwd="/",
        start_new_session=True, preexec_fn=functools.partial(child, os.getpid()))
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    deadline, sent = time.monotonic() + spec.BRIDGE_SECONDS, 0
    buffers = [bytearray(), bytearray()]
    try:
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((process.stdout, process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, 2)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise ProviderError("proxmox_timeout", "The local Proxmox request exceeded its time limit.")
                for key, _ in selector.select(0.05):
                    if key.data == 2:
                        sent += os.write(process.stdin.fileno(), raw[sent:sent + 65536])
                        if sent == len(raw):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                        continue
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    maximum = spec.MAX_MESSAGE if key.data == 0 else 8192
                    if len(buffers[key.data]) + len(chunk) > maximum:
                        raise ProviderError("proxmox_output_limit", "The local Proxmox response exceeded its byte limit.")
                    buffers[key.data].extend(chunk)
        if process.wait(timeout=max(0.01, deadline - time.monotonic())):
            raise ProviderError("proxmox_unavailable", "The local Proxmox dispatcher did not complete the request.")
        return spec.decode(bytes(buffers[0]))
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProviderError("proxmox_unavailable", "The local Proxmox dispatcher is unavailable.") from exc
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
