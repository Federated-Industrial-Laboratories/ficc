# SPDX-License-Identifier: Apache-2.0
"""Administer encrypted secret references without displaying or accepting argument values."""

import hmac
import json
import os
import sys
from contextlib import closing
from pathlib import Path

from . import secret_io
from .secret_sdk import MAX_SECRET, SecretError, reference
from .secrets import CONFIG, PRIVATE, Secrets, load
from .settings import default_state_dir, private_directory
from .state_lock import StateLock

ACTIONS = {"secret-init", "secret-configure", "secret-put", "secret-status", "secret-delete", "secret-migrate-source"}


def prepare(state):
    private_directory(Path(state))
    private = Path(state) / PRIVATE
    private_directory(private)
    with secret_io.directory(private) as folder:
        try:
            secret_io.read(folder, CONFIG)
        except FileNotFoundError:
            return private
    raise SecretError("secret_configuration")


def save(private, value):
    with secret_io.directory(private) as folder:
        secret_io.publish(folder, CONFIG, json.dumps(value, sort_keys=True).encode() + b"\n")


def initialize(state, key_path, *, existing_key=False):
    private = prepare(state)
    try:
        module = load("local")
        configuration = module.initialize({"key_file": str(Path(key_path).absolute()), "create_key": not existing_key}, private)
        module.configure(configuration, private).health()
        save(private, {"provider": "local", "configuration": configuration})
    except SecretError:
        raise
    except Exception:
        raise SecretError() from None
    return {"provider": "local", "configured": True, "key_created": not existing_key}


def configure(state, raw):
    private = prepare(state)
    try:
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {"provider", "configuration"} or not isinstance(value["configuration"], dict):
            raise SecretError("secret_configuration")
        driver = load(value["provider"]).configure(value["configuration"], private)
        if any(not callable(getattr(driver, method, None)) for method in ("health", "get", "put", "delete")):
            raise SecretError("secret_provider_version")
        driver.health()
        save(private, value)
        return {"provider": value["provider"], "configured": True}
    except SecretError:
        raise
    except Exception:
        raise SecretError("secret_configuration") from None


def migrate_source(state, identity, *, remove_plaintext=False):
    """Retain the original source approval revision through an explicit migration."""
    from .store import Store
    reference(identity)
    legacy = Path(state) / "data-secrets"
    try:
        with secret_io.directory(legacy) as folder:
            raw = secret_io.read(folder, identity, MAX_SECRET)
        with closing(Store(Path(state) / "state.sqlite3")) as store:
            key = store.get_setting("file_reference_key", None)
            if not isinstance(key, str) or len(key) != 64:
                raise SecretError("secret_legacy")
            version = hmac.digest(bytes.fromhex(key), b"ficc-source-secret\0" + raw, "sha256").hex()
    except (OSError, ValueError):
        raise SecretError("secret_legacy") from None
    host = Secrets(state)
    try:
        current = host.resolve(identity)
    except SecretError as exc:
        if exc.code != "secret_missing":
            raise
        result = host.put(identity, raw, imported_revision=version)
    else:
        if current.value != raw or current.revision != version:
            raise SecretError("secret_conflict")
        result = host.status(identity)
    # Verify the durable encrypted result before removing an explicitly selected source.
    retained = host.resolve(identity)
    if retained.value != raw or retained.revision != version:
        raise SecretError()
    if remove_plaintext:
        with secret_io.directory(legacy) as folder:
            if secret_io.read(folder, identity, MAX_SECRET) != raw:
                raise SecretError("secret_conflict")
            os.unlink(identity, dir_fd=folder)
            os.fsync(folder)
    return {**result, "migrated": True, "plaintext_retained": not remove_plaintext}


def input_bytes(path):
    if str(path) != "-":
        try:
            return secret_io.private_file(path, MAX_SECRET)
        except (OSError, ValueError):
            raise SecretError("secret_value") from None
    if sys.stdin.isatty():
        raise SecretError("secret_value")
    raw = sys.stdin.buffer.read(MAX_SECRET + 1)
    if len(raw) > MAX_SECRET:
        raise SecretError("secret_value")
    return raw


def add_commands(commands):
    for name in sorted(ACTIONS):
        item = commands.add_parser(name)
        item.add_argument("--state-dir", type=Path, default=default_state_dir())
        if name == "secret-init":
            item.add_argument("--key-file", type=Path, required=True)
            item.add_argument("--existing-key", action="store_true", help="Recover using an existing private key; never replace it.")
        if name in {"secret-put", "secret-configure"}:
            item.add_argument("--input", type=Path, required=True, help="Private file, or '-' for non-terminal stdin.")
        if name in {"secret-put", "secret-status", "secret-delete", "secret-migrate-source"}:
            item.add_argument("--reference", required=name != "secret-status")
        if name in {"secret-put", "secret-delete"}:
            item.add_argument("--revision", required=name == "secret-delete", help="Current metadata revision; omit to create without replacement.")
        if name == "secret-migrate-source":
            item.add_argument("--remove-plaintext", action="store_true", help="Remove the verified old source file after durable encryption.")


def execute(args):
    state = args.state_dir.absolute()
    host = Secrets(state)
    if args.command in {"secret-init", "secret-configure", "secret-migrate-source"}:
        with StateLock(state):
            if args.command == "secret-init":
                result = initialize(state, args.key_file, existing_key=args.existing_key)
            elif args.command == "secret-configure":
                result = configure(state, input_bytes(args.input))
            else:
                result = migrate_source(state, args.reference, remove_plaintext=args.remove_plaintext)
    elif args.command == "secret-put":
        result = host.put(args.reference, input_bytes(args.input), args.revision)
    elif args.command == "secret-delete":
        result = host.delete(args.reference, args.revision)
    else:
        result = host.status(args.reference)
    print(json.dumps(result, sort_keys=True))
