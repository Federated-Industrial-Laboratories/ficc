# SPDX-License-Identifier: Apache-2.0
"""Version-one source runtime contract, usable from separately installed wheels."""

import base64
import datetime
import decimal
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path

API_VERSION = 1
MAX_FRAME = 262144
MAX_CELL = 65536
MAX_ROWS = 128


class DataError(ValueError):
    """A safe, predefined provider outcome; never include driver diagnostics."""

    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)


def encoded(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False).encode()


def load(name, group="ficc.data", *, api_version=None):
    expected = API_VERSION if api_version is None else api_version
    matches = list(importlib.metadata.entry_points(group=group, name=name))
    if len(matches) != 1:
        raise DataError("provider_unavailable", "Install exactly one matching data runtime package.")
    module = matches[0].load()
    if module.API_VERSION != expected:
        raise DataError("provider_version", "The data runtime interface is not supported.")
    folder = Path(module.__file__).parent
    fingerprint = hashlib.sha256()
    for path in sorted(folder.rglob("*.py")):
        fingerprint.update(str(path.relative_to(folder)).encode() + b"\0" + path.read_bytes())
    version = matches[0].dist.version if matches[0].dist else "unknown"
    fingerprint.update(version.encode())
    return module, {"name": name, "version": version, "digest": fingerprint.hexdigest(), "api_version": expected}


def cell(value):
    if isinstance(value, (datetime.date, datetime.time, datetime.datetime)):
        value = value.isoformat()
    elif isinstance(value, decimal.Decimal):
        value = str(value)
    elif isinstance(value, (bytes, bytearray, memoryview)):
        value = {"base64": base64.b64encode(value).decode()}
    elif isinstance(value, float) and not math.isfinite(value):
        raise DataError("nonfinite_value", "The result contains a non-finite number.")
    if len(encoded(value)) > MAX_CELL:
        raise DataError("cell_limit", "A result cell exceeds the 64 KiB stream limit.")
    return value


def rows(iterator):
    """Bound both row count and serialized bytes; never accumulate a result set."""
    batch: list[list] = []
    size = 0
    for original in iterator:
        row = [cell(value) for value in original]
        length = len(encoded(row))
        if length > MAX_FRAME // 2:
            raise DataError("row_limit", "A result row exceeds the 128 KiB stream limit.")
        if batch and (len(batch) == MAX_ROWS or size + length > MAX_FRAME // 2):
            yield {"kind": "rows", "rows": batch}
            batch, size = [], 0
        batch.append(row)
        size += length
    if batch:
        yield {"kind": "rows", "rows": batch}


def schema(names, types=None):
    return {"fields": [{"name": str(name), "type": str(kind), "nullable": True}
                       for name, kind in zip(names, types or ["string"] * len(names), strict=True)], "description": ""}


class Context:
    """The worker receives one approved capability and one scoped credential."""

    def __init__(self, value):
        self.configuration = value["configuration"]
        self.endpoint = value.get("endpoint")
        self.secret = value.get("secret", {})
        self.source = value.get("source")
        self.limit = value.get("limit")
        self.receipt_path = value.get("part_receipts")

    def part_receipts(self):
        if self.receipt_path is None:
            return
        with open(self.receipt_path, "rb") as stream:
            while line := stream.readline(MAX_FRAME + 1):
                if len(line) > MAX_FRAME or not line.endswith(b"\n"):
                    raise DataError("receipt_limit", "A retained part receipt exceeds the stream limit.")
                yield json.loads(line)

    def open_source(self):
        from contextlib import contextmanager

        from ficc_node.file_access import identity, parts, same

        @contextmanager
        def opened():
            if self.source is None:
                raise DataError("source_required", "Select a registered local source file.")
            import os
            import stat
            root, ref = self.source["root"], self.source["reference"]
            fd = os.open(root["path"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                first = identity(os.fstat(fd))
                if not same(first, root["identity"], True):
                    raise DataError("source_changed", "The source root changed.")
                names = parts(ref)
                for index, name in enumerate(names):
                    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                                    (os.O_DIRECTORY if index < len(names) - 1 else 0), dir_fd=fd)
                    os.close(fd)
                    fd = child
                    if os.fstat(fd).st_dev != first["dev"]:
                        raise DataError("source_changed", "The source path crosses a mounted filesystem.")
                current = identity(os.fstat(fd))
                if current["type"] != stat.S_IFREG or not same(current, ref["identity"]):
                    raise DataError("source_changed", "The selected source changed.")
                with os.fdopen(os.dup(fd), "rb") as stream:
                    yield stream
            finally:
                os.close(fd)
        return opened()

    def source_unchanged(self):
        with self.open_source():
            pass

    def ca_file(self):
        """Pass approved trust to native drivers without a persistent secret file."""
        import os
        from contextlib import contextmanager

        @contextmanager
        def opened():
            fd = os.memfd_create("ficc-source-ca", os.MFD_CLOEXEC)
            try:
                os.write(fd, self.endpoint["ca_pem"].encode())
                yield f"/proc/self/fd/{fd}"
            finally:
                os.close(fd)
        return opened()
