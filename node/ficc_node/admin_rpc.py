# SPDX-License-Identifier: Apache-2.0
"""Serve one bounded admin request through the enrolled SSH helper."""

import signal
import sys

from . import admin_spec as spec
from .admin_state import receipt
from .admin_systemd import Systemd


def dispatch(value):
    spec.request(value)
    provider = Systemd(value)
    action, params = value["action"], value["parameters"]
    try:
        if action == "probe":
            return provider.probe()
        if action == "list":
            return provider.inventory(params["kind"], params["offset"], params["limit"])
        if action in {"apply", "receipt", "forget"}:
            return receipt(provider, value)
        if action == "status":
            return provider.status_batch(params["resources"])
        results = []
        for resource in params["resources"]:
            try:
                data = (provider.status(resource) if action == "status" else provider.logs(resource, params["tail"], params["byte_limit"]))
                results.append({"resource": resource, "data": data})
            except spec.ProviderError as exc:
                results.append({"resource": resource, "error": spec.error(exc.code, exc.message)})
        return {"results": results}
    finally:
        provider.close()


def main():
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(20)
    try:
        request = spec.decode(sys.stdin.buffer.read(spec.MAX_MESSAGE + 1))
        if isinstance(request, dict) and request.get("action") == "apply":
            signal.alarm(20)
        value = {"version": 1, "data": dispatch(request)}
    except spec.ProviderError as exc:
        value = {"version": 1, "error": spec.error(exc.code, exc.message)}
    except (ValueError, KeyError, TypeError, RecursionError):
        value = {"version": 1, "error": spec.error("admin_invalid", "The admin request, configuration or provider response is invalid.")}
    except Exception:
        value = {"version": 1, "error": spec.error("admin_unavailable", "The admin request could not be completed.")}
    sys.stdout.buffer.write(spec.encode(value))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
