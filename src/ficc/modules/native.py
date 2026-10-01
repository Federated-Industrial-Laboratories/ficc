# SPDX-License-Identifier: Apache-2.0
"""Check native executable headers and loader availability without running code."""

import os
import struct
from pathlib import Path, PurePosixPath

from ..errors import Failure

MACHINES = {"x86_64": 62, "aarch64": 183}
SYSTEM_ROOTS = ("/usr", "/lib", "/lib64", "/bin", "/sbin")


def loader_path(value: str, package: Path) -> Path:
    """Resolve only paths visible through the module's read-only mounts."""
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("The native loader path must be absolute and contain no parent traversal.")
    roots: tuple[Path, ...]
    if path.is_relative_to("/module"):
        candidate = package / path.relative_to("/module")
        roots = (package.resolve(),)
    else:
        candidate = Path(path)
        roots = tuple(Path(root).resolve() for root in SYSTEM_ROOTS)
        if not any(path.is_relative_to(root) for root in SYSTEM_ROOTS):
            raise ValueError("The native loader is outside the module sandbox mounts.")
    if not any(candidate.resolve().is_relative_to(root) for root in roots):
        raise ValueError("The native loader resolves outside the module sandbox mounts.")
    if not candidate.is_file() or not os.access(candidate, os.R_OK | os.X_OK):
        raise ValueError("The native module requires an available executable loader: " + value)
    return candidate


def require_native(package: Path, runtime: dict) -> None:
    """Accept bounded ELF64 Linux headers for the declared native architecture."""
    try:
        with (package / runtime["entry"]).open("rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            header = stream.read(64)
            if (len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01"
                    or header[7] not in (0, 3)):
                raise ValueError("The native module requires a Linux ELF64 executable.")
            kind, machine, version = struct.unpack_from("<HHI", header, 16)
            offset = struct.unpack_from("<Q", header, 32)[0]
            header_size, entry_size, count = struct.unpack_from("<HHH", header, 52)
            if (kind not in (2, 3) or machine != MACHINES.get(runtime["architecture"])
                    or version != 1 or header_size != 64 or entry_size != 56
                    or not 1 <= count <= 1024 or offset < 64 or offset + count * 56 > size):
                raise ValueError("The native executable format or architecture is incompatible.")
            stream.seek(offset)
            table = stream.read(count * 56)
            interpreter = None
            loadable = False
            for index in range(count):
                entry = struct.unpack_from("<IIQQQQQQ", table, index * 56)
                segment, _, start, _, _, length, memory, _ = entry
                if start + length > size or (segment == 1 and length > memory):
                    raise ValueError("The native executable segment is invalid.")
                loadable |= segment == 1
                if segment == 3:
                    if interpreter is not None or not 2 <= length <= 4096:
                        raise ValueError("The native executable loader header is invalid.")
                    stream.seek(start)
                    raw = stream.read(length)
                    if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
                        raise ValueError("The native executable loader path is invalid.")
                    interpreter = raw[:-1].decode("utf-8")
            if not loadable:
                raise ValueError("The native executable has no loadable segment.")
    except (OSError, ValueError, struct.error) as exc:
        raise Failure("module_runtime_unavailable", str(exc), 409) from exc
    if interpreter is not None:
        try:
            loader_path(interpreter, package)
        except (OSError, ValueError) as exc:
            raise Failure("module_runtime_unavailable", str(exc), 503) from exc
