# SPDX-License-Identifier: Apache-2.0
"""Configure and inspect audit delivery under exclusive local administration."""

import asyncio
import json
import secrets
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

from . import audit_state, secret_io
from .audit_delivery import Delivery
from .audit_sdk import AuditError, encoded, load
from .secret_cli import input_bytes
from .settings import default_state_dir, private_directory
from .state_lock import StateLock
from .store import Store


def configure(state, raw, store):
    try:
        requested = json.loads(raw)
        requested["stream_id"] = secrets.token_hex(16)
        config = audit_state.configuration(encoded(requested))
        load(config["provider"]).configure(config["configuration"])
        private = Path(state) / audit_state.PRIVATE
        private_directory(private)
        with secret_io.directory(private) as folder:
            try:
                secret_io.read(folder, audit_state.CONFIG)
            except FileNotFoundError:
                pass
            else:
                raise AuditError("audit_configuration")
            # Restore must preserve required enforcement even without destination custody.
            if config["required"]:
                store.set_setting(audit_state.REQUIRED, True)
            secret_io.publish(folder, audit_state.CHECKPOINT, encoded(audit_state.initial(config["stream_id"])))
            secret_io.publish(folder, audit_state.CONFIG, encoded(config))
        return {"configured": True, "required": config["required"], "stream_id": config["stream_id"]}
    except AuditError:
        raise
    except Exception:
        raise AuditError("audit_configuration") from None


def mode(state, required, store):
    try:
        with secret_io.directory(Path(state) / audit_state.PRIVATE) as folder:
            config = audit_state.configuration(secret_io.read(folder, audit_state.CONFIG, 32768))
            config["required"] = required
            if required:
                store.set_setting(audit_state.REQUIRED, True)
            secret_io.publish(folder, audit_state.CONFIG, encoded(config), replace=True)
            if not required:
                store.set_setting(audit_state.REQUIRED, False)
        return {"required": required}
    except Exception:
        raise AuditError("audit_configuration") from None


async def flush(host):
    host.start()
    try:
        async with asyncio.timeout(30):
            while True:
                await asyncio.sleep(0.05)
                if host.error:
                    raise AuditError(host.error)
                status = host.status()
                if status["state"] == "current" and status["last_ack_at"] is not None:
                    return status
                if host.task is None:
                    return status
    except TimeoutError:
        raise AuditError("audit_backpressure") from None
    finally:
        await host.close()


def add_commands(commands):
    for name in ("audit-configure", "audit-mode", "audit-status", "audit-flush"):
        item = commands.add_parser(name)
        item.add_argument("--state-dir", type=Path, default=default_state_dir())
        if name == "audit-configure":
            item.add_argument("--input", type=Path, required=True, help="Private configuration file, or '-' for non-terminal stdin.")
        if name == "audit-mode":
            group = item.add_mutually_exclusive_group(required=True)
            group.add_argument("--required", action="store_true", dest="required")
            group.add_argument("--best-effort", action="store_false", dest="required")


def execute(args):
    state = args.state_dir.absolute()
    with StateLock(state), closing(Store(state / "state.sqlite3")) as store:
        if args.command == "audit-configure":
            result = configure(state, input_bytes(args.input), store)
        elif args.command == "audit-mode":
            result = mode(state, args.required, store)
        else:
            host = Delivery(SimpleNamespace(store=store, settings=SimpleNamespace(state_dir=state)))
            result = asyncio.run(flush(host)) if args.command == "audit-flush" else host.status()
    print(json.dumps(result, sort_keys=True))
