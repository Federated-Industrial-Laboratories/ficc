# SPDX-License-Identifier: Apache-2.0
"""Read declared result files in bounded chunks without following workload links."""

import base64
import os
from pathlib import Path

from .files import identity, open_below
from .spec import digest


def collect(ctx, request, complete):
    root = Path(ctx["directory"])
    if request.object in {"stdout", "stderr"}:
        base, relative = root / "runtime", request.object
    else:
        name = request.object.removeprefix("output:")
        paths = {item["name"]: item["path"] for item in ctx["plan"]["job"]["outputs"]}
        if name not in paths or not complete:
            raise ValueError("Read a declared output only after confirmed workload cleanup.")
        base, relative = root / "runtime/work", paths[name]
    fd = open_below(base, relative)
    try:
        before = os.fstat(fd)
        if before.st_dev != ctx["binding"]["device"]:
            raise ValueError("The output is outside the reserved storage device.")
        if request.offset > before.st_size:
            raise ValueError("The output offset is beyond the current file size.")
        data = os.pread(fd, request.length, request.offset)
        after = os.fstat(fd)
        if identity(before) != identity(after):
            raise ValueError("The output changed during this read. Reload its identity.")
        return {"object": request.object, "offset": request.offset, "data": base64.b64encode(data).decode("ascii"),
                "next_offset": request.offset + len(data), "total_bytes": before.st_size,
                "eof": request.offset + len(data) == before.st_size, "complete": complete,
                "identity": digest(identity(before))}
    finally:
        os.close(fd)
