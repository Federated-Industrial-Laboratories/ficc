# SPDX-License-Identifier: Apache-2.0
"""Check exported image identities without extracting archives or running engines."""

import hashlib
import json
import os
import re
import tarfile
from pathlib import PurePosixPath

from ficc.execution.files import identity

MAXIMUM = 4 * 1024 * 1024


def contents(archive, members, name):
    member = members.get(name)
    if member is None or not member.isfile() or not 0 < member.size <= MAXIMUM:
        raise ValueError("Image archive metadata must be a bounded regular file.")
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError("Image archive metadata cannot be read.")
    with stream:
        data = stream.read(MAXIMUM + 1)
    if len(data) != member.size:
        raise ValueError("Image archive metadata has an invalid length.")
    return data


def blob(archive, members, descriptor):
    digest = descriptor["digest"]
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Export image metadata with SHA256 descriptors.")
    data = contents(archive, members, "blobs/sha256/" + digest[7:])
    if descriptor["size"] != len(data) or "sha256:" + hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("Image archive metadata differs from its descriptor.")
    return json.loads(data)


def images(archive):
    members: dict[str, tarfile.TarInfo] = {}
    for member in archive:
        name = PurePosixPath(member.name)
        if name.is_absolute() or ".." in name.parts or str(name) in members or len(members) >= 8192:
            raise ValueError("Image archive entries are ambiguous or exceed their bound.")
        members[str(name)] = member
    result: set[str] = set()
    if "index.json" in members:
        index = json.loads(contents(archive, members, "index.json"))
        entries = index["manifests"]
        if index["schemaVersion"] != 2 or not isinstance(entries, list) or not 1 <= len(entries) <= 64:
            raise ValueError("Export a bounded OCI image index.")
        for entry in entries:
            manifest = blob(archive, members, entry)
            config = manifest["config"]
            if not isinstance(blob(archive, members, config), dict):
                raise ValueError("The OCI image configuration is not an object.")
            result.add(config["digest"])
    elif "manifest.json" in members:
        entries = json.loads(contents(archive, members, "manifest.json"))
        if not isinstance(entries, list) or not 1 <= len(entries) <= 64:
            raise ValueError("Export a bounded Docker image manifest.")
        for entry in entries:
            data = contents(archive, members, str(PurePosixPath(entry["Config"])))
            if not isinstance(json.loads(data), dict):
                raise ValueError("The Docker image configuration is not an object.")
            result.add("sha256:" + hashlib.sha256(data).hexdigest())
    else:
        raise ValueError("Export the approved image as an OCI or Docker image archive.")
    return result


def verify(path, expected, saved):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = identity(os.fstat(fd))
        if any(before[key] != saved[key] for key in before):
            raise ValueError("The approved image archive changed before metadata inspection.")
        try:
            with os.fdopen(os.dup(fd), "rb") as stream, tarfile.open(fileobj=stream, mode="r:*") as archive:
                exported = images(archive)
        except (KeyError, TypeError, AttributeError, UnicodeError, json.JSONDecodeError, tarfile.TarError) as exc:
            raise ValueError("The approved image archive has invalid bounded image metadata.") from exc
        if identity(os.fstat(fd)) != before:
            raise ValueError("The approved image archive changed during metadata inspection.")
        if expected not in exported:
            available = ", ".join(sorted(exported)[:4])
            raise ValueError("The approved image ID differs from the exported archive. Use its config ID: " + available)
    finally:
        os.close(fd)
