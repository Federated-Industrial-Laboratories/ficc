# SPDX-License-Identifier: Apache-2.0
"""Configure trusted evaluators and administer runtime policy through authenticated requests."""

import base64
import json
import time
from pathlib import Path

import httpx

from .launcher_config import write_file
from .policy_packages import HASH, MAX_ARCHIVE, identifier
from .policy_provider import CONFIG
from .settings import default_state_dir, private_directory
from .state_lock import StateLock


def add_commands(commands):
    for name in ("policy-list", "policy-trust", "policy-install", "policy-activate", "policy-roles",
                 "policy-bind", "policy-preview", "policy-provider-configure"):
        parser = commands.add_parser(name)
        parser.add_argument("--state-dir", type=Path, default=default_state_dir())
        if name == "policy-trust":
            parser.add_argument("--publisher", required=True)
            parser.add_argument("--public-key", type=Path, required=True)
            parser.add_argument("--revision", type=int, default=0)
            parser.add_argument("--disable", action="store_true")
        if name == "policy-install":
            parser.add_argument("source", help="Local signed package path or verified HTTPS URL.")
        if name == "policy-activate":
            parser.add_argument("digest")
            parser.add_argument("--revision", type=int, required=True)
        if name in {"policy-roles", "policy-bind", "policy-preview"}:
            parser.add_argument("--project", required=name != "policy-preview")
        if name in {"policy-bind", "policy-preview"}:
            parser.add_argument("--subject", required=name != "policy-preview")
        if name == "policy-bind":
            parser.add_argument("--role", action="append", default=[])
            parser.add_argument("--revision", type=int, required=True)
        if name == "policy-preview":
            parser.add_argument("--action", action="append", required=True)
            parser.add_argument("--node")
            parser.add_argument("--root")
            parser.add_argument("--digest")
        if name == "policy-provider-configure":
            parser.add_argument("--provider", default="opa")
            parser.add_argument("--binary", type=Path, required=True)
            parser.add_argument("--sha256", required=True)


def package_bytes(source):
    if source.startswith("https://"):
        target = httpx.URL(source)
        if target.userinfo or target.fragment:
            raise ValueError("Use a policy URL without credentials or a fragment.")
        data = bytearray()
        deadline = time.monotonic() + 20
        with httpx.Client(trust_env=False, timeout=20, follow_redirects=False) as client:
            with client.stream("GET", target) as response:
                if response.status_code != 200:
                    raise ValueError("The policy source did not return a successful package response.")
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise ValueError("Serve the signed policy archive without HTTP content encoding.")
                for chunk in response.iter_raw():
                    if time.monotonic() > deadline:
                        raise ValueError("The policy download exceeded its time limit.")
                    data.extend(chunk)
                    if len(data) > MAX_ARCHIVE:
                        raise ValueError("The policy archive exceeds its size limit.")
        return bytes(data)
    if "://" in source:
        raise ValueError("Remote policy sources require verified HTTPS.")
    with Path(source).open("rb") as stream:
        local_data = stream.read(MAX_ARCHIVE + 1)
    if len(local_data) > MAX_ARCHIVE:
        raise ValueError("The policy archive exceeds its size limit.")
    return local_data


def execute(args):
    from .cli import local_request
    from .local_client import client as local_client
    if args.command == "policy-provider-configure":
        identifier(args.provider)
        if not args.binary.is_absolute() or not HASH.fullmatch(args.sha256):
            raise ValueError("Select an absolute evaluator path and its SHA256 digest.")
        private_directory(args.state_dir)
        with StateLock(args.state_dir):
            write_file(args.state_dir / CONFIG, json.dumps({"provider": args.provider,
                "configuration": {"binary": str(args.binary), "sha256": args.sha256}}, indent=2) + "\n")
        print(json.dumps({"configured": args.provider, "restart_required": True}))
        return
    body = None
    method, path = "GET", "/policies"
    if args.command == "policy-trust":
        method, path = "PUT", "/policy-publishers"
        with args.public_key.open() as stream:
            key = stream.read(1025)
        body = {"id": args.publisher, "public_key": key, "enabled": not args.disable, "revision": args.revision}
    elif args.command == "policy-install":
        method, path = "POST", "/policy-packages"
        body = {"archive_base64": base64.b64encode(package_bytes(args.source)).decode()}
    elif args.command == "policy-activate":
        method, path = "POST", "/policy-activation"
        body = {"digest": args.digest, "revision": args.revision}
    elif args.command in {"policy-bind", "policy-roles"}:
        path = "/projects/" + args.project + "/policy-roles"
        if args.command == "policy-bind":
            method, path = "PUT", path + "/" + args.subject
            body = {"roles": args.role, "revision": args.revision}
    elif args.command == "policy-preview":
        method, path = "POST", "/policy-preview"
        body = {"requests": [{"action": action, "node_id": args.node, "root_id": args.root} for action in args.action],
                "subject_id": args.subject, "project_id": args.project, "digest": args.digest}
    grant = local_request(args.state_dir, {"action": "ephemeral"})
    try:
        with local_client(grant, args.state_dir, timeout=60, base_path="/api/v1") as client:
            response = client.request(method, path, json=body)
            if response.status_code >= 400:
                raise ValueError(response.json().get("error", {}).get("message", "The policy request failed."))
            print(json.dumps(response.json(), indent=2))
    finally:
        try:
            local_request(args.state_dir, {"action": "revoke", "id": grant["id"]})
        except (OSError, ValueError):
            pass
