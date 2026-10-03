# SPDX-License-Identifier: Apache-2.0
"""Provide AES-GCM authenticated records with separately managed local key custody."""

import base64
import fcntl
import json
import os
import secrets
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ficc import secret_io as files
from ficc.secret_sdk import MAX_SECRET, SecretError, SecretValue, payload, reference, revision
from ficc.settings import private_directory

API_VERSION = 1
CHECK = b"ficc-secret-local-key-check-v1"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def key_path(value, directory):
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise SecretError("secret_key_location")
    path = Path(value)
    if path.resolve().is_relative_to(Path(directory).parent.resolve()):
        raise SecretError("secret_key_location")
    return path


class Local:
    def __init__(self, configuration, directory):
        if (not isinstance(configuration, dict) or set(configuration) != {"key_file", "store_id"}
                or not isinstance(configuration["store_id"], str)
                or len(configuration["store_id"]) != 32
                or any(char not in "0123456789abcdef" for char in configuration["store_id"])):
            raise SecretError("secret_configuration")
        self.directory = Path(directory) / "records"
        self.key_file = key_path(configuration["key_file"], directory)
        self.identity = configuration["store_id"]

    def key(self):
        value = files.private_file(self.key_file, 32)
        if len(value) != 32:
            raise SecretError()
        return value

    @contextmanager
    def access(self, write=False):
        with files.directory(self.directory) as folder:
            lock = None
            try:
                if write:
                    lock = os.open(".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=folder)
                    files.checked(os.fstat(lock))
                    fcntl.flock(lock, fcntl.LOCK_EX)
                yield folder
            finally:
                if lock is not None:
                    os.close(lock)

    def encrypt(self, value, identity, version, key, kind="secret"):
        header = {"version": 1, "store": self.identity, "kind": kind, "reference": identity, "revision": version}
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, value, encoded(header))
        return encoded({**header, "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ciphertext).decode()})

    def decrypt(self, raw, identity, key, kind="secret"):
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {"version", "store", "kind", "reference", "revision", "nonce", "ciphertext"}
                or value["version"] != 1 or value["store"] != self.identity
                or value["kind"] != kind or value["reference"] != identity):
            raise SecretError()
        version = revision(value["revision"])
        nonce = base64.b64decode(value.pop("nonce"), validate=True)
        ciphertext = base64.b64decode(value.pop("ciphertext"), validate=True)
        if len(nonce) != 12 or not 16 <= len(ciphertext) <= MAX_SECRET + 16:
            raise SecretError()
        return SecretValue(AESGCM(key).decrypt(nonce, ciphertext, encoded(value)), version)

    def health(self):
        with self.access() as folder:
            value = self.decrypt(files.read(folder, ".seal"), "key-check", self.key(), "health")
        if value.value != CHECK or value.revision != "0" * 64:
            raise SecretError()

    def record(self, folder, identity, key):
        try:
            raw = files.read(folder, identity + ".json")
        except FileNotFoundError:
            raise SecretError("secret_missing") from None
        return self.decrypt(raw, identity, key)

    def get(self, identity):
        reference(identity)
        with self.access() as folder:
            return self.record(folder, identity, self.key())

    def put(self, identity, value, expected_revision, updated):
        reference(identity)
        payload(value)
        revision(updated)
        if expected_revision is not None:
            revision(expected_revision)
        with self.access(True) as folder:
            key = self.key()
            try:
                current = self.record(folder, identity, key)
            except SecretError as exc:
                if exc.code != "secret_missing":
                    raise
                current = None
            if (current.revision if current else None) != expected_revision:
                raise SecretError("secret_conflict")
            files.publish(folder, identity + ".json", self.encrypt(value, identity, updated, key), replace=current is not None)

    def delete(self, identity, expected_revision):
        reference(identity)
        revision(expected_revision)
        with self.access(True) as folder:
            if self.record(folder, identity, self.key()).revision != expected_revision:
                raise SecretError("secret_conflict")
            os.unlink(identity + ".json", dir_fd=folder)
            os.fsync(folder)


def configure(configuration, directory):
    return Local(configuration, directory)


def initialize(configuration, directory):
    """Explicitly create or recover a local store without replacing any key."""
    if not isinstance(configuration, dict) or set(configuration) != {"key_file", "create_key"} or type(configuration["create_key"]) is not bool:
        raise SecretError("secret_configuration")
    path = key_path(configuration["key_file"], directory)
    if configuration["create_key"]:
        with files.directory(path.parent) as parent:
            files.publish(parent, path.name, AESGCM.generate_key(bit_length=256))
    key = files.private_file(path, 32)
    if len(key) != 32:
        raise SecretError()
    records = Path(directory) / "records"
    private_directory(records)
    with files.directory(records) as folder:
        try:
            identity = json.loads(files.read(folder, ".seal"))["store"]
        except FileNotFoundError:
            with os.scandir(folder) as entries:
                if next(entries, None) is not None:
                    raise SecretError("secret_configuration")
            identity = secrets.token_hex(16)
            value = {"key_file": str(path), "store_id": identity}
            driver = Local(value, directory)
            files.publish(folder, ".seal", driver.encrypt(CHECK, "key-check", "0" * 64, key, "health"))
    value = {"key_file": str(path), "store_id": identity}
    Local(value, directory).health()
    return value
