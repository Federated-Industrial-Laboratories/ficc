# SPDX-License-Identifier: Apache-2.0
"""Bridge one domain-bound graphics FD to SSH without a listening socket."""

import os
import selectors
import signal
import socket
import time

from .vm_libvirt import Libvirt
from .vm_spec import decode, encode, fields, integer, request


def relay(fd, maximum_seconds=3600):
    # A finite queue and finite lifetime bound slow or abandoned viewers.
    endpoints = (0, 1, fd)
    for item in endpoints:
        os.set_blocking(item, False)
    buffers = {1: bytearray(), fd: bytearray()}
    deadline = time.monotonic() + maximum_seconds
    provider_open = True
    with selectors.DefaultSelector() as selector:
        while time.monotonic() < deadline:
            if not provider_open and not buffers[1]:
                return
            for key in list(selector.get_map().values()):
                selector.unregister(key.fd)
            if provider_open and len(buffers[fd]) < 65536:
                selector.register(0, selectors.EVENT_READ)
            events = (selectors.EVENT_READ if len(buffers[1]) < 65536 else 0)
            events |= selectors.EVENT_WRITE if buffers[fd] else 0
            if provider_open and events:
                selector.register(fd, events)
            if buffers[1]:
                selector.register(1, selectors.EVENT_WRITE)
            for key, event in selector.select(timeout=min(1, max(0, deadline - time.monotonic()))):
                if event & selectors.EVENT_READ:
                    data = os.read(key.fd, 65536 - len(buffers[fd if key.fd == 0 else 1]))
                    if not data:
                        if key.fd == 0:
                            return
                        # The provider can close immediately after its last RFB
                        # message. Drain only that bounded output before exit.
                        provider_open = False
                        buffers[fd].clear()
                    else:
                        buffers[fd if key.fd == 0 else 1].extend(data)
                if event & selectors.EVENT_WRITE and (key.fd != fd or provider_open):
                    buffer = buffers[key.fd]
                    del buffer[:os.write(key.fd, buffer)]


def main():
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(6)
    provider = None
    fd = None
    try:
        # Read the header without buffered read-ahead into the RFB stream.
        raw = bytearray()
        while len(raw) <= 4096:
            byte = os.read(0, 1)
            if byte == b"\n":
                break
            if not byte:
                raise ValueError("Missing console header.")
            raw.extend(byte)
        value = decode(bytes(raw))
        fields(value, {"request", "graphics_index"})
        request(value["request"])
        if value["request"]["action"] != "console":
            raise ValueError("Invalid console action.")
        index = integer(value["graphics_index"], 0, 63)
        provider = Libvirt(value["request"]["connection"], writable=True)
        descriptor, fd = provider.console(value["request"]["parameters"]["uuids"][0], open_fd=True)
        if descriptor["graphics_index"] != index:
            raise ValueError("The VM graphics device changed.")
        with socket.socket(fileno=fd) as stream:
            fd = None
            signal.alarm(3600)
            os.write(1, encode({"version": 1, "ready": True}) + b"\n")
            relay(stream.fileno())
        return 0
    except Exception:
        # No provider details, XML or credentials are written to the transport.
        return 1
    finally:
        if fd is not None:
            os.close(fd)
        if provider is not None:
            provider.close()


if __name__ == "__main__":
    raise SystemExit(main())
