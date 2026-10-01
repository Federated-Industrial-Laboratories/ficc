# SPDX-License-Identifier: Apache-2.0
"""Bridge one domain-bound graphics FD to SSH without a listening socket."""

import os
import signal
import socket

from .display_stream import relay
from .vm_libvirt import Libvirt
from .vm_spec import decode, encode, fields, integer, request


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
