# SPDX-License-Identifier: Apache-2.0
"""Bind source workers to approved files, endpoint identities and secret revisions."""

import asyncio
import copy
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import stat
from pathlib import Path

from ficc_node.file_access import identity, opened, parts, root_fd, same

from .data_sdk import DataError, load
from .errors import Failure
from .file_worker import owned
from .secrets import Secrets


def provider(name):
    try:
        return load(name)
    except DataError as exc:
        raise Failure(exc.code, exc.message, 409) from None


def secret(service, reference):
    if not reference:
        return {}, None
    try:
        resolved = Secrets(service.settings.state_dir).resolve(reference)
        value = json.loads(resolved.value)
        if (not isinstance(value, dict) or set(value) - {"username", "password", "access_key_id", "secret_access_key", "session_token"}
                or any(not isinstance(item, str) or len(item) > 8192 for item in value.values())):
            raise ValueError("Credential format")
        return value, resolved.revision
    except (OSError, ValueError):
        raise Failure("secret_unavailable", "The approved encrypted source credential is unavailable or invalid.", 409) from None


async def endpoint(value):
    if value is None:
        return None
    value = copy.deepcopy(value)
    try:
        approved = {str(ipaddress.ip_address(item)) for item in value["addresses"]}
        if any(not ipaddress.ip_address(item).is_global for item in approved) and not value["private_network"]:
            raise ValueError("Private networks require explicit approval")
        if any(ipaddress.ip_address(item).is_link_local or ipaddress.ip_address(item).is_multicast or ipaddress.ip_address(item).is_unspecified for item in approved):
            raise ValueError("Link-local and multicast endpoints are not supported")
        ssl.create_default_context(cadata=value["ca_pem"])
        if value.get("fixed_address"):
            fixed = str(ipaddress.ip_address(value["fixed_address"]))
            if fixed not in approved:
                raise ValueError("Fixed address is not approved")
            value["address"] = fixed
            return value
        async with asyncio.timeout(10):
            resolved = await owned(socket.getaddrinfo, value["host"], value["port"], 0, socket.SOCK_STREAM)
        actual = {str(ipaddress.ip_address(item[4][0])) for item in resolved}
        if not actual or not actual.issubset(approved):
            raise ValueError("DNS approval changed")
        value["address"] = sorted(actual)[0]
        return value
    except (OSError, ValueError, TimeoutError):
        raise Failure("endpoint_unapproved", "The endpoint DNS addresses or verified TLS trust differ from their approval.", 409) from None


def local(service, source, actor, mutable=False):
    if source is None:
        return None
    root = service.files.store.root(source["root_id"])
    service.files.check(actor, "files:read", root)
    location, private = Path(root["path"]).resolve(), service.settings.state_dir.resolve()
    if location.is_relative_to(private) or private.is_relative_to(location):
        raise Failure("source_private", "Controller private state cannot be mounted into a data worker.", 403)
    if root["revision"] != source["root_revision"] or root.get("node_id") is not None:
        raise Failure("source_changed", "The approved local root changed or is unavailable.", 409)
    ref = copy.deepcopy(source["reference"])
    with root_fd(root) as directory:
        fd = opened(directory, b"/".join(parts(ref)), os.O_RDONLY | os.O_NONBLOCK)
        try:
            current = identity(os.fstat(fd))
            if current["type"] != stat.S_IFREG or not same(current, ref["identity"], mutable):
                raise Failure("source_changed", "The selected source changed. Register a new source version.", 409)
            ref["identity"] = current
        finally:
            os.close(fd)
    return {"root": root, "reference": ref}


async def packet(service, connection, actor, action, request, *, write=False, limit=None, format=None):
    module, installed = provider(connection["provider"])
    if installed != connection["installed"]:
        raise Failure("provider_changed", "The installed source provider changed. Register a newly approved connection.", 409)
    credential = "write" if write else "read"
    value, revision = secret(service, connection.get(credential + "_secret"))
    if revision != connection[credential + "_secret_revision"]:
        raise Failure("secret_changed", "The source credential changed. Register a newly approved connection.", 409)
    remote = await endpoint(connection["endpoint"])
    return {"provider": connection["provider"], "provider_digest": installed["digest"], "configuration": connection["configuration"],
            "source": local(service, connection.get("source"), actor, module.METADATA["source_consistency"] == "transaction"),
            "endpoint": remote, "secret": value, "action": action, "request": request, "limit": limit, "format": format}


def parameter_digest(value):
    from .dataset_store import encoded
    return hashlib.sha256(encoded(value)).hexdigest()
