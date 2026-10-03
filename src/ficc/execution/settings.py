# SPDX-License-Identifier: Apache-2.0
"""Read administrator-owned executor identities, providers, and storage slots."""

import json
import os
import stat
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from ..schema import Model
from .offer import Offer, OfferSettings, validate_offer
from .spec import Digest, Identity, Name, Positive, Revision, distinct, encoded

Account = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]{0,30}$")]
UserID = Annotated[int, Field(ge=1, le=2**31 - 1)]
Absolute = Annotated[str, Field(min_length=2, max_length=4096)]


def absolute(value: str) -> str:
    path = Path(value)
    if (not path.is_absolute() or str(path) != value or ".." in path.parts
            or any(ord(item) <= 32 or ord(item) == 127 or item in ":,\\" for item in value)):
        raise ValueError("Use an absolute path without aliases or parent components.")
    return value


def read_owned(path: Path, maximum: int = 262144, *, owner: int = 0) -> bytes:
    """Open each path component without following links before reading private data."""
    absolute(str(path))
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
            info = os.fstat(directory)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in {0, owner} or info.st_mode & 0o022 and not sticky_root:
                raise ValueError("An executor configuration parent is writable by another account.")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o077
                    or info.st_nlink != 1 or info.st_size > maximum):
                raise ValueError("Executor configuration must be a private administrator-owned regular file.")
            data = bytearray()
            while chunk := os.read(fd, maximum + 1 - len(data)):
                data.extend(chunk)
                if len(data) > maximum:
                    raise ValueError("Executor configuration exceeds its control-message limit.")
            return bytes(data)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


class Slot(Model):
    id: Name
    generation: Revision
    mount: Absolute
    filesystem_uuid: Annotated[str, Field(pattern=r"^[A-Za-z0-9-]{8,80}$")]
    account: Account
    uid: UserID
    gid: UserID
    storage_bytes: Positive
    storage_inodes: Positive

    _mount = field_validator("mount")(absolute)


class Provider(Model):
    id: Name
    package_digest: Digest
    configuration: dict

    @field_validator("configuration")
    @classmethod
    def bounded(cls, value):
        if len(encoded(value)) > 65536:
            raise ValueError("Provider configuration exceeds 64 KiB.")
        return value


class Settings(Model):
    version: Literal[1]
    installation_id: Identity
    deployment_id: Identity
    node_id: Identity
    mode: Literal["managed", "voluntary"]
    transport_uid: UserID
    local_owner_uids: Annotated[list[UserID], Field(max_length=64)]
    maximum_lease_seconds: Annotated[int, Field(ge=5, le=30)]
    service: Annotated[str, Field(pattern=r"^ficc-executor-[0-9a-f]{32}\.service$")]
    state: Absolute
    sockets: Absolute
    ceiling: OfferSettings
    initial_offer: Offer
    slots: Annotated[list[Slot], Field(min_length=1, max_length=64)]
    providers: Annotated[list[Provider], Field(min_length=1, max_length=64)]

    _paths = field_validator("state", "sockets")(absolute)
    _owners = field_validator("local_owner_uids")(distinct)

    @model_validator(mode="after")
    def consistent(self):
        if self.service != "ficc-executor-" + self.installation_id + ".service":
            raise ValueError("The supervisor service must bind the installation identity.")
        if self.initial_offer.mode != self.mode or self.initial_offer.revision != 1:
            raise ValueError("The initial offer must bind the installed mode and first revision.")
        if self.mode == "managed" and self.local_owner_uids:
            raise ValueError("Managed offers can be changed only by the machine administrator.")
        validate_offer(self.initial_offer, self.ceiling)
        for values in ([slot.id for slot in self.slots], [slot.mount for slot in self.slots],
                       [slot.uid for slot in self.slots], [slot.account for slot in self.slots],
                       [slot.gid for slot in self.slots],
                       [provider.id for provider in self.providers]):
            distinct(values)
        workload_uids = {slot.uid for slot in self.slots}
        if self.transport_uid in workload_uids or set(self.local_owner_uids) & (workload_uids | {self.transport_uid}):
            raise ValueError("Transport, workload, and local owner accounts must be separate.")
        paths = [Path(self.state), Path(self.sockets), *[Path(slot.mount) for slot in self.slots]]
        if any(a == b or a in b.parents or b in a.parents for index, a in enumerate(paths) for b in paths[index + 1:]):
            raise ValueError("State, sockets, and storage slots must use separate directories.")
        providers = {item.id: item.package_digest for item in self.providers}
        if any(providers.get(runtime.provider) != runtime.package_digest for runtime in self.ceiling.runtimes):
            raise ValueError("Approved runtimes must bind an installed provider package.")
        return self

    def check_identity(self, plan):
        if (plan.deployment_id, plan.node_id) != (self.deployment_id, self.node_id):
            raise ValueError("The attempt belongs to another deployment or contributor.")


def load(path: Path) -> Settings:
    if os.geteuid() != 0:
        raise ValueError("The executor supervisor requires the machine administrator.")
    raw = read_owned(path)
    return Settings.model_validate(json.loads(raw))
