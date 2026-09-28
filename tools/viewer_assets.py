#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Build viewer assets from pinned source. Inputs: cache/output paths; exit: 0 on success.
"""Verify the upstream archive and assemble its unmodified JavaScript sources."""

import argparse
import hashlib
import io
import os
import stat
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

VERSION = "1.6.0"
NAME = f"guacamole-client-{VERSION}.tar.gz"
URL = f"https://downloads.apache.org/guacamole/{VERSION}/source/{NAME}"
SHA256 = "81f9fd5a7b4377fb0ee295d0d4fec92e9667f2aafaa3d0ed8937f535deabdee4"
MAX_ARCHIVE = 64 * 1024 * 1024
ROOT = f"guacamole-client-{VERSION}/"
SOURCE = ROOT + "guacamole-common-js/src/main/webapp/"


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARCHIVE:
            raise ValueError("The viewer source cache is invalid.")
        data = stream.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("The viewer source archive does not match its pinned digest.")
    return data


def source(cache):
    cache.mkdir(parents=True, exist_ok=True)
    if cache.is_symlink():
        raise ValueError("The viewer source cache must not be a link.")
    archive = cache / NAME
    if archive.exists() or archive.is_symlink():
        return read(archive)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, response, code, message, headers, url):
            raise ValueError("The pinned viewer source redirected.")

    fd, temporary = tempfile.mkstemp(prefix=".source-", dir=cache)
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with os.fdopen(fd, "wb") as stream, opener.open(URL, timeout=30) as response:
            deadline, total = time.monotonic() + 120, 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_ARCHIVE or time.monotonic() > deadline:
                    raise ValueError("The viewer source exceeds its download limit.")
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        data = read(Path(temporary))
        os.link(temporary, archive)
        return data
    finally:
        Path(temporary).unlink(missing_ok=True)


def build(data, output):
    output.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise ValueError("The viewer asset directory must not be a link.")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = {item.name: item for item in archive.getmembers()}
        names = sorted(name for name in members if name.startswith(SOURCE + "modules/") and name.endswith(".js"))
        if not 1 <= len(names) <= 128:
            raise ValueError("The viewer source module count is invalid.")

        def member(name):
            item = members.get(name)
            if item is None or not item.isfile() or not 0 < item.size <= 1024 * 1024:
                raise ValueError("The viewer source member is invalid.")
            stream = archive.extractfile(item)
            assert stream is not None
            return stream.read()

        script = b"\n".join(member(name) for name in [SOURCE + "common/license.js", *names])
        if len(script) > 4 * 1024 * 1024:
            raise ValueError("The viewer script exceeds its size limit.")
        files = {"all.js": script, "LICENSE": member(ROOT + "LICENSE"), "NOTICE": member(ROOT + "NOTICE"),
                 "SOURCE.txt": f"Apache Guacamole {VERSION}\n{URL}\nSHA256 {SHA256}\n".encode()}
        for name, content in files.items():
            with (output / name).open("xb") as stream:
                stream.write(content)
    print(f"Viewer assets built from {len(names)} verified source modules.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(source(args.cache), args.output)


if __name__ == "__main__":
    main()
