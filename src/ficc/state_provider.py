# SPDX-License-Identifier: Apache-2.0
"""Load explicitly configured, trusted state drivers through a versioned interface."""

import importlib.metadata
import json
import os
import secrets
import sqlite3
import stat
import tempfile
from contextlib import closing, contextmanager
from pathlib import Path

CONFIG = "state-provider.json"
BINDING = "state-binding"
API_VERSION = 1


class StorageFailure(sqlite3.Error):
    """Report a storage failure without exposing connection settings or query data."""


def read_private(path: Path, maximum: int = 65536) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > maximum):
            raise ValueError("State provider configuration must be a private regular file.")
        raw = os.read(fd, maximum + 1)
        if len(raw) > maximum:
            raise ValueError("The state provider configuration is too large.")
        return raw
    finally:
        os.close(fd)


def configuration(state: Path) -> dict | None:
    path = state / CONFIG
    if not path.exists() and not path.is_symlink():
        return None
    value = json.loads(read_private(path))
    if (not isinstance(value, dict) or set(value) != {"provider", "configuration"}
            or not isinstance(value["provider"], str) or not value["provider"]
            or len(value["provider"]) > 80 or not isinstance(value["configuration"], dict)):
        raise ValueError("The state provider configuration is invalid.")
    return value


def open_provider(state: Path, *, initialize: bool = True):
    value = configuration(state)
    if value is None:
        return None
    matches = list(importlib.metadata.entry_points(group="ficc.state", name=value["provider"]))
    if len(matches) != 1:
        raise ValueError("Install exactly one trusted driver for the configured state provider.")
    provider = matches[0].load()
    if provider.API_VERSION != API_VERSION:
        raise ValueError("The state provider interface version is not supported.")
    path = state / BINDING
    if not path.exists() and not path.is_symlink() and initialize:
        encoded = secrets.token_hex(16).encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, encoded)
            os.fsync(fd)
        finally:
            os.close(fd)
        directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    identity = read_private(path, 32).decode("ascii")
    if len(identity) != 32 or any(char not in "0123456789abcdef" for char in identity):
        raise ValueError("The local state binding is invalid.")
    return provider.connect(value["configuration"], identity, initialize=initialize)


@contextmanager
def ownership(state: Path):
    """Hold network ownership across a complete stopped-controller operation."""
    if configuration(state) is None:
        yield None
        return
    if (state / "state.sqlite3").exists() or (state / "state.sqlite3").is_symlink():
        raise ValueError("Resume the pending state migration before using the configured database.")
    with closing(open_provider(state, initialize=False)) as provider:
        yield provider


@contextmanager
def backup_source(state: Path, local_path: Path, provider=None):
    if provider is None:
        with ownership(state) as selected:
            if selected is None:
                yield local_path
            else:
                with backup_source(state, local_path, selected) as path:
                    yield path
        return
    with tempfile.TemporaryDirectory(prefix="ficc-state-export-") as folder:
        path = Path(folder) / "state.sqlite3"
        provider.snapshot(path)
        yield path


class BoundConnection(sqlite3.Connection):
    """Bind shared named parameters while retaining native SQLite query support."""

    @staticmethod
    def parameters(sql, values):
        if ":p0" in sql and not isinstance(values, dict):
            return {f"p{index}": value for index, value in enumerate(values)}
        return values

    def execute(self, sql, parameters=(), /):
        return super().execute(sql, self.parameters(sql, parameters))

    def executemany(self, sql, parameters, /):
        return super().executemany(sql, (self.parameters(sql, row) for row in parameters))


class AtomicConnection(BoundConnection):
    """Keep nested state writes inside the outer transaction."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.depth = 0
        self.rollback_only = False

    def execute(self, sql, parameters=(), /):
        try:
            return super().execute(sql, parameters)
        except BaseException:
            self.rollback_only = self.in_transaction
            raise

    def executemany(self, sql, parameters, /):
        try:
            return super().executemany(sql, parameters)
        except BaseException:
            self.rollback_only = self.in_transaction
            raise

    def __enter__(self):
        if not self.in_transaction:
            self.execute("BEGIN IMMEDIATE")
        self.depth += 1
        return self

    def __exit__(self, kind, value, traceback):
        self.depth -= 1
        if kind is not None:
            self.rollback_only = True
        if self.depth == 0:
            if self.rollback_only:
                self.rollback()
                if kind is None:
                    raise StorageFailure("The state transaction was rolled back after an earlier failure.")
            else:
                self.commit()

    def commit(self):
        if not self.depth:
            if self.rollback_only:
                self.rollback()
                raise StorageFailure("The state transaction was rolled back after an earlier failure.")
            super().commit()

    def rollback(self):
        super().rollback()
        self.rollback_only = False
