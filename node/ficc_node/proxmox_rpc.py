# SPDX-License-Identifier: Apache-2.0
"""Serve one exact, bounded request on an enrolled local Proxmox system."""

import signal
import sys
import time

from . import proxmox_spec as spec
from .proxmox_compat import discover, require_console, require_provider
from .proxmox_process import run
from .proxmox_state import receipt
from .vm_libvirt import ProviderError, error


def dispatch(value):
    spec.request(value)
    if value["action"] == "discover":
        return discover()
    if value["action"] == "forget":
        # Terminal journal removal does not call a changed provider API.
        return receipt(value)
    require_provider(value["provider"])
    if value["action"] in {"apply", "receipt"}:
        return receipt(value)
    if value["action"] == "console":
        require_console(value["provider"])
    return run(value)


def main():
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    started = time.monotonic()
    signal.alarm(spec.REQUEST_SECONDS)
    try:
        value = spec.decode(sys.stdin.buffer.read(spec.MAX_MESSAGE + 1))
        if isinstance(value, dict) and value.get("action") == "apply":
            # Include input time in the total bound. Durable intent and its
            # final receipt need time beyond the fixed dispatcher deadline.
            remaining = max(0.001, spec.APPLY_SECONDS - (time.monotonic() - started))
            signal.setitimer(signal.ITIMER_REAL, remaining)
        result = {"version": 1, "data": dispatch(value)}
    except ProviderError as exc:
        result = {"version": 1, "error": error(exc.code, exc.message)}
    except (ValueError, TypeError, KeyError, RecursionError):
        result = {"version": 1, "error": error("vm_invalid_request", "The Proxmox request or provider data is invalid.")}
    except Exception:
        result = {"version": 1, "error": error("proxmox_unavailable", "The Proxmox helper could not complete the request.")}
    sys.stdout.buffer.write(spec.encode(result))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
