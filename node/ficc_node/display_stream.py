# SPDX-License-Identifier: Apache-2.0
"""Relay one verified display stream with finite queues and lifetime."""

import os
import selectors
import time


def relay(fd, maximum_seconds=3600, check=lambda: None):
    # A finite queue and finite lifetime bound slow or abandoned viewers.
    endpoints = (0, 1, fd)
    for item in endpoints:
        os.set_blocking(item, False)
    buffers = {1: bytearray(), fd: bytearray()}
    deadline = time.monotonic() + maximum_seconds
    provider_open = True
    with selectors.DefaultSelector() as selector:
        while time.monotonic() < deadline:
            check()
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

