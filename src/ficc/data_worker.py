# SPDX-License-Identifier: Apache-2.0
"""Run one trusted source driver inside the supervised filesystem boundary."""

import base64
import logging
import resource
import sys

from .data_sdk import MAX_FRAME, Context, DataError, encoded, load


def send(value):
    raw = encoded(value)
    if len(raw) > MAX_FRAME:
        raise DataError("frame_limit", "The source response exceeds its frame limit.")
    sys.stdout.buffer.write(raw + b"\n")
    sys.stdout.buffer.flush()


def main():
    import json
    logging.disable(logging.CRITICAL)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    try:
        raw = sys.stdin.buffer.readline(MAX_FRAME + 1)
        if len(raw) > MAX_FRAME or not raw.endswith(b"\n"):
            raise ValueError("Invalid request")
        value = json.loads(raw)
        module, identity = load(value["provider"])
        if identity["digest"] != value["provider_digest"]:
            raise DataError("provider_changed", "The installed source package changed. Approve a new connection.")
        context = Context(value)
        events = module.execute(context, value["action"], value["request"])
        encoder = None
        if value.get("format") and value["format"] != "original":
            formatter, _ = load(value["format"], "ficc.format")
            encoder = formatter.encoder(value["format"])
        for event in events:
            if event["kind"] == "schema" and encoder:
                encoder.start(event["schema"])
                send({"kind": "schema", "schema": getattr(encoder, "schema", event["schema"])})
            elif event["kind"] == "rows" and encoder:
                for chunk in encoder.write(event["rows"]):
                    send({"kind": "bytes", "data": base64.b64encode(chunk).decode()})
            elif event["kind"] == "receipt" and encoder:
                for chunk in encoder.finish():
                    send({"kind": "bytes", "data": base64.b64encode(chunk).decode()})
                send(event)
            else:
                send(event)
        return 0
    except DataError as exc:
        send({"kind": "error", "code": exc.code, "message": exc.message})
    except Exception:
        send({"kind": "error", "code": "source_failed", "message": "The data operation failed. Check the approved source, account and registered query."})
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
