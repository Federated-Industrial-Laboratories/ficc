# SPDX-License-Identifier: Apache-2.0
"""Manage local identities and project memberships through the private control socket."""

import json
from pathlib import Path

from .errors import Failure
from .settings import default_state_dir

ACTIONS = {"identity-list", "identity-create", "identity-update", "project-list", "project-create",
           "project-update", "project-members", "project-member-set", "project-resources", "project-resources-set",
           "identity-external-list", "identity-external-set"}


def add_commands(commands):
    for name in sorted(ACTIONS):
        item = commands.add_parser(name)
        item.add_argument("--state-dir", type=Path, default=default_state_dir())
        if name.endswith(("create", "update")):
            item.add_argument("--label", required=True)
        if name.endswith("update"):
            item.add_argument("id")
            item.add_argument("--revision", type=int, required=True)
            item.add_argument("--disabled", action="store_true")
        if name in {"project-members", "project-member-set", "project-resources", "project-resources-set"}:
            item.add_argument("--project", required=True)
        if name == "project-member-set":
            item.add_argument("--subject", required=True)
            item.add_argument("--scope", action="append", default=[])
            item.add_argument("--revision", type=int, required=True)
        if name == "project-resources-set":
            item.add_argument("--node", action="append", default=[])
            item.add_argument("--root", action="append", default=[])
            item.add_argument("--revision", type=int, required=True)
        if name == "identity-external-set":
            item.add_argument("--issuer", required=True)
            item.add_argument("--external-subject", required=True)
            item.add_argument("--subject", required=True)
            item.add_argument("--disabled", action="store_true")
            item.add_argument("--revision", type=int, required=True)


def control(service, request):
    from .identity_routes import Create, Membership, ResourceSelection, Update
    from .identity_store import LOCAL_OWNER
    action = request["action"]
    identities = service.auth.identities
    if action == "identity-external-list":
        return {"mappings": service.remote_auth.records.all(), "provider": service.remote_auth.status()}
    if action == "identity-external-set":
        from .remote_routes import Mapping
        mapping = Mapping(issuer=request["issuer"], external_subject=request["external_subject"],
                       subject_id=request["subject"], disabled=request["disabled"], revision=request["revision"])
        return service.remote_auth.records.save(mapping.issuer, mapping.external_subject, mapping.subject_id, mapping.disabled, mapping.revision)
    if action == "identity-list":
        return {"identities": identities.users()}
    if action == "project-list":
        return {"projects": identities.projects(LOCAL_OWNER)}
    if action == "project-members":
        return {"members": identities.members(request["project"])}
    if action == "project-resources":
        identities.project(request["project"])
        return service.auth.resources.get(request["project"])
    if action == "project-resources-set":
        selection = ResourceSelection(node_ids=request.get("node", []), root_ids=request.get("root", []), revision=request["revision"])
        result = service.auth.resources.save(request["project"], selection.node_ids, selection.root_ids, selection.revision)
        service.store.audit("project.resources", request["project"])
        return result
    if action == "project-member-set":
        body = Membership(scopes=request.get("scope", []), revision=request["revision"])
        result = identities.membership(request["project"], request["subject"], body.scopes, body.revision)
        service.store.audit("project.membership", request["project"] + "/" + request["subject"])
        return result
    kind = "user" if action.startswith("identity-") else "project"
    if action.endswith("create"):
        result = identities.create(kind, Create(label=request["label"]).label)
    elif action.endswith("update"):
        update = Update(label=request["label"], disabled=request["disabled"], revision=request["revision"])
        result = identities.update(kind, request["id"], update.label, update.disabled, update.revision)
    else:
        raise Failure("invalid_action", "The identity action is not supported.")
    service.store.audit(action.replace("-", "."), result["id"])
    return result


def execute(args):
    from .cli import local_request
    request = {key: value for key, value in vars(args).items() if key not in {"command", "state_dir"}}
    print(json.dumps(local_request(args.state_dir, {"action": args.command, **request}), indent=2))
