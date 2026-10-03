# SPDX-License-Identifier: Apache-2.0
"""Bind SSH connection lifetime to its actual handshake and current private trust."""

import asyncio
import json
import os
import shlex
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from cryptography.hazmat.primitives.serialization import SSHCertificate, SSHCertificateType

from .modules.sandbox import finish_cleanup
from .ssh_trust import (
    CA_KEY_TYPE,
    MAX_CERTIFICATE,
    MAX_KRL,
    TRUST_ERRORS,
    certificate,
    denied,
    private_path,
    read_private,
    revocation,
    snapshot,
    write_private,
)

STARTUP = 7
GUARD_INTERVAL = 1


class Arguments(list[str]):
    def __init__(self, args: list[str], trust: "Connection"):
        super().__init__(args)
        self.trust = trust


class Connection:
    def __init__(self, state: Path, profile: str, selected: dict):
        self.state, self.profile, self.selected = state, profile, selected
        self.directory = Path(tempfile.mkdtemp(prefix="ficc-ssh-trust-"))
        self.proof = self.directory / "host.pub"
        self.closed = False
        self.deadline = time.monotonic() + STARTUP
        self.valid_until: float | None = None
        self.checked_krl: bytes | None = None
        self.checked_host: bytes | None = None
        self.host: SSHCertificate | None = None
        self.user: SSHCertificate | None = None
        try:
            write_private(self.directory / "binding.json", json.dumps({
                "state": str(state), "profile": profile, "digest": selected["digest"],
            }).encode())
            write_private(self.directory / "ca.pub", selected["ca"].encode())
            if selected["user_certificate"]:
                write_private(self.directory / "user.pub", selected["user_certificate"].encode())
                write_private(self.directory / "identity.pub", selected["user_certificate"].encode())
                (self.directory / "identity").symlink_to(selected["profile"]["user"]["identity_file"])
                self.user = certificate(selected["user_certificate"].encode(), SSHCertificateType.USER,
                                        selected["profile"]["user"]["principal"])
                self.valid_until = time.monotonic() + max(0, self.user.valid_before - time.time())
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self) -> None:
        if self.closed:
            raise denied()
        try:
            current = snapshot(self.state, self.profile)
            if current is None or current["digest"] != self.selected["digest"]:
                raise denied()
            now = time.monotonic()
            if self.valid_until is not None and now >= self.valid_until:
                raise denied()
            if self.user is not None and not self.user.valid_after <= time.time() < self.user.valid_before:
                raise denied()
            krl = read_private(Path(current["profile"]["revoked_keys"]), MAX_KRL)
            paths = [self.directory / "ca.pub"]
            if self.user is not None:
                paths.append(self.directory / "user.pub")
            if self.proof.exists() or self.proof.is_symlink():
                raw = read_private(self.proof, MAX_CERTIFICATE)
                if self.checked_host is None:
                    self.host = certificate(raw, SSHCertificateType.HOST,
                                            current["profile"]["host_principal"], current["ca"].encode())
                    expiry = now + max(0, self.host.valid_before - time.time())
                    self.valid_until = min(self.valid_until, expiry) if self.valid_until is not None else expiry
                    self.checked_host = raw
                    self.checked_krl = None
                if raw != self.checked_host or self.host is None:
                    raise denied()
                if not self.host.valid_after <= time.time() < self.host.valid_before:
                    raise denied()
                paths.append(self.proof)
            elif now >= self.deadline or self.checked_host is not None:
                raise denied()
            if krl != self.checked_krl:
                revocation(krl, paths, self.directory)
                self.checked_krl = krl
        except TRUST_ERRORS as exc:
            raise denied() from exc

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            shutil.rmtree(self.directory)


def check(args: list[str]) -> Callable[[], None]:
    return args.trust.check if isinstance(args, Arguments) else lambda: None


def release(args: list[str]) -> None:
    if isinstance(args, Arguments):
        args.trust.close()


def identity(args: list[str]) -> list[str]:
    if not isinstance(args, Arguments):
        return args
    return ["KnownHostsCommand=" + args.trust.selected["digest"] if part.startswith("KnownHostsCommand=")
            else "CertificateFile=bound" if part.startswith("CertificateFile=")
            else "IdentityFile=bound" if part.startswith("IdentityFile=")
            else part for part in args]


def completed(args: list[str]) -> None:
    if isinstance(args, Arguments):
        args.trust.check()
        if args.trust.checked_host is None:
            raise denied()


def prepare(state: Path, node: dict, config: dict) -> tuple[Connection, list[str]]:
    try:
        selected = snapshot(state, node["profile"])
        if (selected is None or node["key_type"] != CA_KEY_TYPE
                or node["key"] != selected["ca"].split()[1]
                or node["host_principal"] != selected["profile"]["host_principal"]):
            raise denied()
        if any(value != "none" for value in config.get("certificatefiles", [])):
            raise ValueError("Select client certificates only in the private SSH trust configuration.")
        user = selected["profile"].get("user")
        if user:
            path = private_path(user["identity_file"])
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
                raise ValueError("The SSH identity file must be private and regular.")
            files = [str(Path(value).expanduser()) for value in config.get("identityfiles", []) if value != "none"]
            if files != [str(path)]:
                raise ValueError("The SSH profile must select exactly the configured user identity file.")
        algorithms = config.get("hostkeyalgorithms", "").split(",")
        hosts = ",".join(value for value in algorithms if "-cert-v01@openssh.com" in value)
        algorithms = config.get("pubkeyacceptedalgorithms", "").split(",")
        users = ",".join(value for value in algorithms if bool("-cert-v01@openssh.com" in value) == bool(user))
        if not hosts or not users:
            raise ValueError("The SSH profile has no permitted certificate or identity algorithms.")
        connection = Connection(state, node["profile"], selected)
        # OpenSSH parses this fixed command as arguments, without a shell.
        command = shlex.join([sys.executable, "-m", "ficc.ssh_trust_command",
                              str(connection.directory), "%I", "%t", "%K"])
        options = ["UserKnownHostsFile=/dev/null", "GlobalKnownHostsFile=/dev/null",
                   f"HostKeyAlias={selected['profile']['host_principal']}",
                   f"HostKeyAlgorithms={hosts}", f"PubkeyAcceptedAlgorithms={users}",
                   f"RevokedHostKeys={selected['profile']['revoked_keys']}",
                   f"KnownHostsCommand={command}"]
        if user:
            options += ["CertificateFile=none", f"IdentityFile={connection.directory / 'identity'}", "IdentitiesOnly=yes",
                        "IdentityAgent=none", "PreferredAuthentications=publickey"]
        return connection, options
    except TRUST_ERRORS as exc:
        raise denied() from exc


async def guarded(args: list[str], work):
    if not isinstance(args, Arguments):
        return await work
    task = asyncio.create_task(work)
    try:
        while True:
            args.trust.check()
            done, _ = await asyncio.wait({task}, timeout=GUARD_INTERVAL)
            if done:
                args.trust.check()
                result = task.result()
                if result[0] == 0:
                    completed(args)
                return result
    finally:
        if not task.done():
            task.cancel()
        async def cleanup():
            await asyncio.gather(task, return_exceptions=True)
        await finish_cleanup(cleanup())
