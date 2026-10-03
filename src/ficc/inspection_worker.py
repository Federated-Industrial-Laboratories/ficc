# SPDX-License-Identifier: Apache-2.0
"""Execute one trusted scanner behind the existing bounded worker supervision."""

import json
import resource
import sys

from .data_sdk import MAX_FRAME, encoded
from .inspection_sdk import Context, InspectionError, load, result


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    try:
        line = sys.stdin.buffer.readline(MAX_FRAME + 1)
        if len(line) > MAX_FRAME or not line.endswith(b"\n"):
            raise InspectionError("inspection_protocol", "The scanner request exceeds its bound.")
        packet = json.loads(line)
        module, installed = load(packet["provider"])
        if installed != packet["installed"]:
            raise InspectionError("inspection_provider_changed", "The approved scanner package changed.")
        context = Context(packet)
        context.verify()
        value = result(module.inspect(context))
        context.verify()
        event = {"kind": "receipt", **value, "sha256": context.source["sha256"], "bytes": context.source["size"]}
    except BaseException as exc:
        event = {"kind": "error", "code": "inspection_failed", "message": "The local inspection worker failed."}
        if isinstance(exc, InspectionError):
            event.update(code=exc.code, message=exc.message)
    sys.stdout.buffer.write(encoded(event) + b"\n")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
