# SPDX-License-Identifier: Apache-2.0
"""Configure remote ingress and trusted identity providers on a stopped controller."""

import json
from pathlib import Path

from . import identity_provider, remote_settings
from .launcher_config import write_file
from .settings import default_state_dir, private_directory
from .state_lock import StateLock
from .state_provider import read_private


def add_commands(commands):
    remote = commands.add_parser("remote-configure", help="Configure an HTTPS gateway over a protected Unix socket.")
    remote.add_argument("--state-dir", type=Path, default=default_state_dir())
    remote.add_argument("--origin", required=True)
    remote.add_argument("--socket", type=Path, required=True)
    remote.add_argument("--gateway-secret-file", type=Path, required=True)
    identity = commands.add_parser("identity-provider-configure", help="Select an installed trusted identity provider.")
    identity.add_argument("--state-dir", type=Path, default=default_state_dir())
    identity.add_argument("--input", type=Path, required=True)


def execute(args):
    state = args.state_dir.absolute()
    private_directory(state)
    if args.command == "remote-configure":
        remote_settings.https_url(args.origin, origin=True)
        value = {"origin": args.origin, "socket": str(args.socket.absolute()),
                 "gateway_secret_file": str(args.gateway_secret_file.absolute())}
        name, check = remote_settings.CONFIG, remote_settings.configuration
    else:
        value = json.loads(read_private(args.input))
        name, check = identity_provider.CONFIG, identity_provider.configuration
    with StateLock(state):
        path = state / name
        previous = read_private(path) if path.exists() or path.is_symlink() else None
        try:
            write_file(path, json.dumps(value, indent=2) + "\n")
            check(state)
        except BaseException:
            if previous is None:
                path.unlink(missing_ok=True)
            else:
                write_file(path, previous.decode())
            raise
    print(json.dumps({"configured": True, "restart_required": True}))
