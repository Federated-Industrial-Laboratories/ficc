# SPDX-License-Identifier: Apache-2.0
"""Configure trusted state drivers and migrate verified state into a new directory."""

import json
import os
import tempfile
from contextlib import closing
from pathlib import Path

from . import backup
from .settings import default_state_dir, private_directory
from .state_lock import StateLock
from .state_provider import CONFIG, configuration, open_provider, read_private
from .store import Store


def write_configuration(state: Path, source: Path):
    raw = read_private(source)
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {"provider", "configuration"}:
        raise ValueError("Select a state provider configuration file.")
    fd = os.open(state / CONFIG, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    configuration(state)


def configure(state: Path, source: Path):
    private_directory(state)
    with StateLock(state):
        if (state / "state.sqlite3").exists() or (state / "state.sqlite3").is_symlink():
            raise ValueError("Use state-migrate to copy an existing local database into a new state directory.")
        write_configuration(state, source)
        with closing(open_provider(state)):
            pass
    selected = configuration(state)
    assert selected is not None
    return {"provider": selected["provider"], "configured": True}


def resume(state: Path):
    with StateLock(state):
        if configuration(state) is None:
            raise ValueError("No state provider migration is configured in this directory.")
        source = state / "state.sqlite3"
        if not source.exists():
            raise ValueError("No portable database remains for this migration.")
        with backup.files.directory(state) as folder, backup.files.member(folder, "state.sqlite3"):
            pass
        with closing(open_provider(state)) as provider:
            receipt = provider.import_snapshot(source)
        source.unlink()
        directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    selected = configuration(state)
    assert selected is not None
    return {"provider": selected["provider"], "migrated": True, "snapshot_sha256": receipt,
            "credentials_removed": True, "members_disabled": True}


def migrate(state: Path, source: Path, destination: Path, confirm_remote_idle: bool):
    if confirm_remote_idle is not True:
        raise ValueError("Confirm that remote work is idle before migrating controller state.")
    if destination.exists() or destination.is_symlink():
        raise ValueError("Select a new destination directory, or resume its pending migration explicitly.")
    with tempfile.TemporaryDirectory(prefix="ficc-state-migrate-") as folder:
        bundle = Path(folder) / "backup"
        backup.export(state, bundle)
        backup.restore(bundle, destination, True)
    with StateLock(destination):
        # Upgrade old portable schemas without starting remote workers.
        Store(destination / "state.sqlite3").close()
        write_configuration(destination, source)
    return resume(destination)


def add_commands(commands):
    configure_parser = commands.add_parser("state-configure", help="Configure an installed, trusted state driver for a new controller.")
    configure_parser.add_argument("--state-dir", type=Path, default=default_state_dir())
    configure_parser.add_argument("--input", type=Path, required=True)
    migrate_parser = commands.add_parser("state-migrate", help="Copy stopped controller state into a new database-backed installation.")
    migrate_parser.add_argument("--state-dir", type=Path, default=default_state_dir())
    migrate_parser.add_argument("--input", type=Path)
    migrate_parser.add_argument("--output", type=Path)
    migrate_parser.add_argument("--confirm-remote-idle", action="store_true")
    migrate_parser.add_argument("--resume", action="store_true")


def execute(args):
    if args.command == "state-configure":
        result = configure(args.state_dir.absolute(), args.input.absolute())
    elif args.resume:
        if args.input or args.output:
            raise ValueError("Resume uses the pending state directory and its existing provider configuration.")
        result = resume(args.state_dir.absolute())
    else:
        if not args.input or not args.output:
            raise ValueError("Set --input and --output for a new state migration.")
        result = migrate(args.state_dir.absolute(), args.input.absolute(), args.output.absolute(), args.confirm_remote_idle)
    print(json.dumps(result, indent=2))
