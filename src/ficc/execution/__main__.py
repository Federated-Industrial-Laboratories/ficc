# SPDX-License-Identifier: Apache-2.0
"""Start the local executor or send a validated command to its private socket."""

import argparse
import asyncio
import json
import secrets
import sys
from pathlib import Path

from .client import Client
from .offer import OfferSettings
from .protocol import MAX_MESSAGE, SetOffer, Snapshot, decode
from .providers import Providers, distribution
from .recovery import recover
from .service import Service
from .settings import load
from .spec import Fence
from .supervisor import Supervisor


async def local_control(arguments):
    client = Client(arguments.socket)
    reply = await client.request(Snapshot(version=1, id=secrets.token_hex(16), action="snapshot", after=None))
    if arguments.command == "status" or not reply["ok"]:
        return reply
    offer = reply["snapshot"]["offer"]
    request = SetOffer(version=1, id=secrets.token_hex(16), action="set_offer", expected_revision=offer["revision"],
                       settings=OfferSettings.model_validate({key: value for key, value in offer.items()
                                                              if key not in {"revision", "mode", "control"}}),
                       control=arguments.control)
    return await client.request(request)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Run the installed administrator service.")
    serve.add_argument("--config", required=True, type=Path)
    request = commands.add_parser("request", help="Send one versioned JSON batch from standard input.")
    request.add_argument("--socket", required=True, type=Path)
    package = commands.add_parser("provider-digest", help="Print the verified digest of an installed trusted executor.")
    package.add_argument("provider")
    status = commands.add_parser("status", help="Read the current local offer, capacity, and attempt page.")
    status.add_argument("--socket", required=True, type=Path)
    control = commands.add_parser("control", help="Change the local offer control without broadening its resource limits.")
    control.add_argument("--socket", required=True, type=Path)
    control.add_argument("control", choices=("active", "paused", "draining", "stopped"))
    recovery = commands.add_parser("recover-storage", help="Confirm an empty remounted slot while its service is stopped.")
    recovery.add_argument("--config", required=True, type=Path)
    recovery.add_argument("--attempt", required=True)
    recovery.add_argument("--generation", required=True, type=int)
    recovery.add_argument("--plan-digest", required=True)
    recovery.add_argument("--old-slot-generation", required=True, type=int)
    arguments = parser.parse_args()
    try:
        if arguments.command == "provider-digest":
            print(distribution(arguments.provider)[1])
        elif arguments.command == "request":
            message = decode(sys.stdin.buffer.read(MAX_MESSAGE + 1))
            print(json.dumps(asyncio.run(Client(arguments.socket).request(message)), indent=2))
        elif arguments.command in {"status", "control"}:
            print(json.dumps(asyncio.run(local_control(arguments)), indent=2))
        elif arguments.command == "recover-storage":
            asked = Fence(attempt_id=arguments.attempt, generation=arguments.generation, plan_digest=arguments.plan_digest)
            print(json.dumps(recover(load(arguments.config), asked, arguments.old_slot_generation), indent=2))
        else:
            settings = load(arguments.config)
            supervisor = Supervisor(settings, Providers(settings.providers))
            asyncio.run(Service(supervisor).serve())
        return 0
    except (ValueError, OSError, TimeoutError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
