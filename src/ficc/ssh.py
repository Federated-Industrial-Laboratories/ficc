# SPDX-License-Identifier: Apache-2.0
"""Verify approved OpenSSH profiles and invoke the fixed node helper."""

import base64
import hashlib
import importlib.resources
import io
import json
import os
import shlex
import time
import zipfile
from collections.abc import Callable
from pathlib import Path

from pydantic import ValidationError

from .errors import Failure
from .process import run
from .schema import Sample
from .settings import Settings, private_directory

PROBE = 'test -f "$HOME/.local/lib/ficc/node.pyz" || exit 42; exec python3 "$HOME/.local/lib/ficc/node.pyz"'
INSTALL_SCRIPT = """import os,pathlib,sys,tempfile,zipfile,io
p=pathlib.Path.home()/'.local/lib/ficc'
p.mkdir(mode=0o700,parents=True,exist_ok=True)
if p.is_symlink(): raise ValueError('Invalid directory')
b=sys.stdin.buffer.read(1048577)
if len(b)>1048576: raise ValueError('Invalid size')
with zipfile.ZipFile(io.BytesIO(b)) as z:
 if z.testzip() is not None: raise ValueError('Invalid archive')
f,name=tempfile.mkstemp(prefix='.node-',dir=p)
try:
 with os.fdopen(f,'wb') as s: s.write(b);s.flush();os.fsync(s.fileno())
 os.replace(name,p/'node.pyz')
finally:
 if os.path.exists(name): os.unlink(name)
"""
INSTALL = "exec python3 -c " + shlex.quote(INSTALL_SCRIPT)


def archive() -> bytes:
    output = io.BytesIO()
    root = importlib.resources.files("ficc_node")
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("__main__.py", "from ficc_node.__main__ import main\nraise SystemExit(main())\n")
        for name in ("__init__.py", "__main__.py", "collect.py"):
            bundle.writestr("ficc_node/" + name, root.joinpath(name).read_bytes())
    return output.getvalue()


def fingerprint(key: str) -> str:
    try:
        raw = base64.b64decode(key, validate=True)
    except ValueError as exc:
        raise Failure("invalid_host_key", "The saved host key is invalid.") from exc
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def transport_failure(stderr: bytes) -> Failure:
    if b"REMOTE HOST IDENTIFICATION HAS CHANGED" in stderr or b"Host key verification failed" in stderr:
        return Failure("host_key_changed", "The host key does not match the trusted key.", 409)
    if b"Permission denied" in stderr or b"sign_and_send_pubkey" in stderr:
        return Failure("authentication_failed", "SSH authentication failed. Check the local key agent.", 502)
    return Failure("unreachable", "The SSH connection could not be completed.", 502)


class SSH:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.prefix = ["ssh"]
        if settings.ssh_config:
            self.prefix += ["-F", str(settings.ssh_config)]
        self.trust_dir = settings.state_dir / "trust"
        private_directory(self.trust_dir)

    async def config(self, profile: str) -> dict:
        code, output, _ = await run(self.prefix + ["-G", "--", profile])
        if code:
            raise Failure("profile_failed", "The approved SSH profile could not be read.", 502)
        config: dict = {}
        for line in output.decode("utf-8", errors="replace").splitlines():
            key, _, value = line.partition(" ")
            config.setdefault(key, value)
        host, user = config.get("hostname", ""), config.get("user", "")
        if not host or not user or len(host) > 253 or len(user) > 128:
            raise Failure("profile_failed", "The SSH destination is invalid.")
        if any(c.isspace() for c in host) or host.startswith("-"):
            raise Failure("profile_failed", "The SSH destination is invalid.")
        config["port"] = int(config.get("port", "22"))
        return config

    async def known_key(self, config: dict) -> tuple[str, str] | None:
        host = config.get("hostkeyalias", config["hostname"])
        if host == "none":
            host = config["hostname"]
        lookup = host if config["port"] == 22 else f"[{host}]:{config['port']}"
        paths = shlex.split(config.get("userknownhostsfile", ""))
        paths += shlex.split(config.get("globalknownhostsfile", ""))
        keys = []
        revoked = set()
        for filename in paths[:8]:
            if filename == "none":
                continue
            path = Path(filename).expanduser()
            if not path.is_file():
                continue
            code, result, _ = await run(["ssh-keygen", "-F", lookup, "-f", str(path)])
            if code not in (0, 1):
                continue
            for line in result.decode("ascii", errors="replace").splitlines():
                if line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "@revoked":
                    revoked.add(parts[3])
                elif len(parts) >= 3 and not parts[0].startswith("@"):
                    keys.append((parts[1], parts[2]))
        keys = [key for key in keys if key[1] not in revoked]
        keys.sort(key=lambda key: key[0] != "ssh-ed25519")
        return keys[0] if keys else None

    async def preview(self, profile: str, name: str, check: Callable[[], None] | None = None) -> dict:
        config = await self.config(profile)
        key = await self.known_key(config)
        trusted = key is not None
        if key is None:
            if check:
                check()
            code, output, _ = await run(["ssh-keyscan", "-T", "3", "-p", str(config["port"]),
                                         config["hostname"]], timeout=5)
            keys = [line.split() for line in output.decode("ascii", errors="replace").splitlines()
                    if line and not line.startswith("#")]
            if code or not keys or len(keys[0]) != 3:
                raise Failure("untrusted_host", "No trusted host key is available. Verify the host locally.", 409)
            key = (keys[0][1], keys[0][2])
        value = {"profile": profile, "name": name, "host": config["hostname"],
                 "account": config["user"], "port": config["port"],
                 "fingerprint": fingerprint(key[1]), "key_type": key[0], "key": key[1],
                 "trust": "trusted" if trusted else "untrusted", "helper_version": None,
                 "helper_install_required": True, "warnings": [], "expires_at": time.time() + 120}
        if trusted:
            sample = await self.probe(value, allow_missing=True, check=check)
            if sample:
                value["helper_version"] = sample["helper_version"]
                value["helper_install_required"] = False
        else:
            value["warnings"] = ["Verify this key independently and add it to local known hosts before enrollment."]
        return value

    async def command(self, node: dict, command: str, payload: bytes,
                      check: Callable[[], None] | None = None) -> tuple[int, bytes, bytes]:
        config = await self.config(node["profile"])
        if (config["hostname"], config["user"], config["port"]) != (
            node["host"], node["account"], node["port"]
        ):
            raise Failure("profile_changed", "The approved SSH destination changed. Enroll it again.", 409)
        key_path = self.trust_dir / hashlib.sha256(node["key"].encode()).hexdigest()
        content = f"ficc-pin {node['key_type']} {node['key']}\n".encode()
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            if key_path.is_symlink() or key_path.read_bytes() != content:
                raise Failure("invalid_host_key", "The pinned host key file is invalid.", 409) from None
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
        algorithms = node["key_type"]
        if algorithms == "ssh-rsa":
            algorithms = "rsa-sha2-512,rsa-sha2-256"
        options = ["BatchMode=yes", "StrictHostKeyChecking=yes", "ControlPath=none",
                   "ControlMaster=no", "ControlPersist=no", "ForwardAgent=no", "ForwardX11=no",
                   "ClearAllForwardings=yes", "ConnectTimeout=5", "ConnectionAttempts=1",
                   "ServerAliveInterval=3", "ServerAliveCountMax=1", "UpdateHostKeys=no",
                   "GlobalKnownHostsFile=/dev/null", f"UserKnownHostsFile={key_path}",
                   "HostKeyAlias=ficc-pin", f"HostKeyAlgorithms={algorithms}",
                   "PermitLocalCommand=no", "RequestTTY=no"]
        args = self.prefix + [part for option in options for part in ("-o", option)]
        if check:
            check()
        return await run(args + ["--", node["profile"], command], payload)

    async def install(self, node: dict, check: Callable[[], None] | None = None) -> None:
        code, _, stderr = await self.command(node, INSTALL, archive(), check=check)
        if code:
            raise transport_failure(stderr)

    async def probe(self, node: dict, allow_missing: bool = False,
                    check: Callable[[], None] | None = None) -> dict | None:
        code, output, stderr = await self.command(
            node, PROBE, b'{"version":"1","action":"resources"}\n', check=check)
        if code == 42 and allow_missing:
            return None
        if code == 42:
            raise Failure("helper_missing", "The node helper is not installed.", 409)
        if code:
            raise transport_failure(stderr)
        try:
            sample = Sample.model_validate_json(output).model_dump()
            return sample
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            raise Failure("invalid_sample", "The node returned an unsupported resource sample.", 502) from exc
