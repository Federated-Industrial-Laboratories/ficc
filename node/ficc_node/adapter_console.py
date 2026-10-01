# SPDX-License-Identifier: Apache-2.0
"""Open one process-bound display with private authentication over SSH."""

import os
import re
import signal

from ficc.modules.validation import dumps, fields, loads

from . import adapter_binding, adapter_display
from .adapter_store import root
from .display_stream import relay


def main():
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(6)
    try:
        raw = bytearray()
        while len(raw) <= 4096:
            byte = os.read(0, 1)
            if byte == b"\n":
                break
            if not byte:
                raise ValueError("Missing display header.")
            raw.extend(byte)
        value = fields(loads(bytes(raw)), {"binding_id", "display", "password"})
        if not isinstance(value["password"], str) or re.fullmatch(r"[A-Za-z0-9]{8}", value["password"]) is None:
            raise ValueError("Invalid private display credential.")
        base = root()

        def check():
            with adapter_binding.selected(base, value["binding_id"]):
                adapter_display.check(value["display"])

        check()
        with adapter_display.connect(value["display"]) as stream:
            signal.alarm(3600)
            os.write(1, dumps({"version": 1, "ready": True, "password": value["password"]}) + b"\n")
            relay(stream.fileno(), check=check)
        return 0
    except Exception:
        # The transport must not expose a provider path or private credential.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
