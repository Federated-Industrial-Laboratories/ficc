# SPDX-License-Identifier: Apache-2.0
"""Manage models, services and inference through the authenticated local interface."""
import hashlib
import json
import time
from pathlib import Path

from ..settings import default_state_dir


def add_commands(commands):
    endpoints = commands.add_parser("inference-endpoints-configure")
    endpoints.add_argument("--state-dir", type=Path, default=default_state_dir())
    endpoints.add_argument("--input", type=Path, required=True)
    configuration = commands.add_parser("model-store-configure")
    configuration.add_argument("--state-dir", type=Path, default=default_state_dir())
    configuration.add_argument("--directory", type=Path, required=True)
    configuration.add_argument("--https-host", action="append")
    hub = commands.add_parser("model-hub-import")
    hub.add_argument("--state-dir", type=Path, default=default_state_dir())
    hub.add_argument("--project")
    hub.add_argument("--repository", required=True)
    hub.add_argument("--filename", required=True)
    hub.add_argument("--revision", default="main")
    hub.add_argument("--licence")
    for name in ("inference-token", "model-list", "model-create", "model-upload", "model-acquire", "model-pause", "model-get", "model-remove",
                 "inference-list", "inference-replace", "inference-create", "inference-preview", "inference-get", "inference-start",
                 "inference-stop", "inference-drain", "inference-remove", "inference-chat"):
        parser = commands.add_parser(name)
        parser.add_argument("--state-dir", type=Path, default=default_state_dir())
        parser.add_argument("--project")
        if name.endswith(("create", "preview")):
            parser.add_argument("--input", type=Path, required=True)
        elif not name.endswith("list"):
            parser.add_argument("id")
        if name == "inference-replace":
            parser.add_argument("--input", type=Path, required=True)
            parser.add_argument("--revision", type=int, required=True)
        if name == "model-upload":
            parser.add_argument("--directory", type=Path, required=True)
        if name.endswith(("start", "stop", "drain", "remove")) and name.startswith("inference-"):
            parser.add_argument("--revision", type=int, required=True)
        if name == "inference-start":
            parser.add_argument("--acknowledge-unknown", action="store_true",
                                help="Start new attempts after released replicas with unknown outcomes; previous requests are not replayed.")
        if name == "inference-chat":
            parser.add_argument("--prompt", required=True)
            parser.add_argument("--max-tokens", type=int, default=128)


def execute(args):
    if args.command == "inference-endpoints-configure":
        from .attached import configure as configure_endpoints
        print(json.dumps(configure_endpoints(args.state_dir, args.input)))
        return
    if args.command == "model-store-configure":
        from ..models.configure import configure
        print(json.dumps(configure(args.state_dir, args.directory, args.https_host)))
        return
    from ..cli import local_request
    from ..local_client import client
    kind, action = args.command.split("-", 1)
    scopes = ["models:read", "models:manage"] if kind == "model" else ["inference:read", "inference:manage", "inference:invoke", "models:read", "jobs:read", "jobs:execute", "jobs:cancel", "contributors:read", "tokens:manage"]
    token = {"action": "token", "label": "Inference operation", "lifetime": 3600, "scopes": scopes}
    if args.project:
        token["project_id"] = args.project
    grant = local_request(args.state_dir, token)
    path = "/api/v1/models" if kind == "model" else "/api/v1/inference"
    try:
        with client(grant, args.state_dir) as http:
            if action == "hub-import":
                response = http.post(path + "/hub-preview", json={"repository": args.repository, "filename": args.filename,
                    "revision": args.revision, **({"licence": args.licence} if args.licence else {})})
                response.raise_for_status()
                selected = response.json()["manifests"]
                if len(selected) != 1:
                    raise ValueError("Choose one exact GGUF filename before registration.")
                response = http.post(path, json=selected[0])
            elif action == "list":
                response = http.get(path)
            elif action in {"create", "preview"}:
                response = http.post(path + ("/preview" if action == "preview" else ""), json=json.loads(args.input.read_text()))
            elif action == "replace":
                response = http.put(path + "/" + args.id, json={"revision": args.revision, "spec": json.loads(args.input.read_text())})
            elif action == "get":
                response = http.get(path + "/" + args.id)
            elif action == "upload":
                response = http.get(path + "/" + args.id)
                response.raise_for_status()
                for index, item in enumerate(response.json()["files"]):
                    if item["complete"]:
                        continue
                    if item["offset"] == item["bytes"]:
                        response = http.post(path + f"/{args.id}/files/{index}/bytes", params={"offset": item["offset"]},
                                             content=b"", headers={"Content-Type": "application/octet-stream"}, timeout=600)
                        response.raise_for_status()
                        continue
                    source = args.directory / item["name"]
                    with source.open("rb") as stream:
                        if "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest() != item["digest"] or source.stat().st_size != item["bytes"]:
                            raise ValueError("The local model file differs from its immutable manifest.")
                        offset = item["offset"]
                        stream.seek(offset)
                        while data := stream.read(16 * 1024 * 1024):
                            response = http.post(path + f"/{args.id}/files/{index}/bytes", params={"offset": offset},
                                                 content=data, headers={"Content-Type": "application/octet-stream"}, timeout=600)
                            response.raise_for_status()
                            offset = response.json()["offset"]
                response = http.get(path + "/" + args.id)
            elif action == "token":
                response = http.post(path + "/" + args.id + "/tokens", json={"lifetime": 3600})
            elif action == "chat":
                response = http.post(path + "/" + args.id + "/v1/chat/completions", json={"messages": [{"role": "user", "content": args.prompt}], "max_tokens": args.max_tokens, "stream": False}, timeout=600)
            elif kind == "model" and action == "acquire":
                response = http.post(path + "/" + args.id + "/acquire")
                response.raise_for_status()
                end = time.monotonic() + 3500
                try:
                    while time.monotonic() < end:
                        response = http.get(path + "/" + args.id)
                        response.raise_for_status()
                        state = response.json()
                        if state["ready"]:
                            break
                        if state["download"] != "downloading":
                            raise ValueError("Model acquisition stopped: " + str(state["download"]))
                        time.sleep(1)
                    else:
                        raise ValueError("Acquisition reached this command's deadline; resume its durable offset with another acquire.")
                except BaseException:
                    http.post(path + "/" + args.id + "/pause")
                    raise
            elif kind == "model":
                response = http.delete(path + "/" + args.id) if action == "remove" else http.post(path + "/" + args.id + "/" + action)
            else:
                body = {"revision": args.revision}
                if action == "start":
                    body["acknowledge_unknown"] = args.acknowledge_unknown
                response = http.post(path + "/" + args.id + "/control/" + action, json=body)
            response.raise_for_status()
            print(json.dumps(response.json(), indent=2))
    finally:
        local_request(args.state_dir, {"action": "revoke", "id": grant["id"]})
