# SPDX-License-Identifier: Apache-2.0
"""Serve one bounded VM request through the fixed SSH helper entrypoint."""

import signal
import sys

from .vm_libvirt import Libvirt, ProviderError, error
from .vm_spec import decode, encode, request
from .vm_state import receipt


def dispatch(value):
    request(value)
    action, params = value["action"], value["parameters"]
    if action in {"receipt", "forget"}:
        return receipt(None, value)
    provider = Libvirt(value["connection"], writable=action in {"apply", "console"})
    try:
        if action == "list":
            return provider.inventory(params["offset"], params["limit"])
        if action == "status":
            return provider.status(params["uuids"])
        if action == "console":
            return provider.console(params["uuids"][0])
        return receipt(provider, value)
    finally:
        provider.close()


def main():
    # Kernel termination also bounds a blocked libvirt C call. Durable receipts
    # retain an unknown outcome if termination follows dispatch.
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(6)
    try:
        value = decode(sys.stdin.buffer.read(1024 * 1024 + 1))
        result = {"version": 1, "data": dispatch(value)}
    except ProviderError as exc:
        result = {"version": 1, "error": error(exc.code, exc.message)}
    except (ValueError, TypeError, KeyError, RecursionError):
        result = {"version": 1, "error": error("vm_invalid_request", "The VM request or provider data is invalid.")}
    except Exception:
        result = {"version": 1, "error": error("vm_unavailable", "The VM helper could not complete the request.")}
    sys.stdout.buffer.write(encode(result))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
