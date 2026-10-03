# SPDX-License-Identifier: Apache-2.0
"""Version-one local inspection contract for separately installed providers."""

import hashlib
import os
import stat
from contextlib import contextmanager

from ficc_node.file_access import identity, same

from .data_sdk import DataError, encoded
from .data_sdk import load as load_provider

API_VERSION = 1
MAX_RESULT = 65536
OUTCOMES = {"no_detection", "detected", "incomplete", "unavailable", "error"}
InspectionError = DataError


def load(name):
    return load_provider(name, "ficc.inspection", api_version=API_VERSION)


def result(value):
    if (not isinstance(value, dict) or value.get("outcome") not in OUTCOMES
            or not isinstance(value.get("coverage"), dict) or not isinstance(value.get("engine"), dict)
            or not isinstance(value.get("signatures"), dict) or len(encoded(value)) > MAX_RESULT):
        raise InspectionError("inspection_protocol", "The scanner returned an invalid bounded result.")
    return value


class Context:
    """One exact read-only file and approved scanner assets, without networking."""

    def __init__(self, packet):
        self.configuration = packet["configuration"]
        self.assets = packet["assets"]
        self.source = packet["source"]
        self.path = "/input/file"

    @contextmanager
    def opened(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            current = identity(os.fstat(fd))
            if current["type"] != stat.S_IFREG or not same(current, self.source["identity"]):
                raise InspectionError("source_changed", "The inspection source changed.")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                yield stream
        finally:
            os.close(fd)

    def verify(self):
        digest = hashlib.sha256()
        with self.opened() as stream:
            while chunk := stream.read(262144):
                digest.update(chunk)
            if not same(identity(os.fstat(stream.fileno())), self.source["identity"]):
                raise InspectionError("source_changed", "The inspection source changed.")
        if digest.hexdigest() != self.source["sha256"]:
            raise InspectionError("source_changed", "The inspection source differs from its manifest digest.")
