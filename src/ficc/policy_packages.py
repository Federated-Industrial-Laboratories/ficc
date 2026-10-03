# SPDX-License-Identifier: Apache-2.0
"""Verify signed policy manifests and every bounded archive member before use."""

import base64
import hashlib
import io
import json
import re
import stat
import struct
import subprocess
import tempfile
import zipfile
import zlib
from pathlib import Path

MAX_ARCHIVE = 512 * 1024
MAX_PAYLOAD = 8 * 1024 * 1024
NAMESPACE = "ficc-policy-v1"
IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("Use a policy identifier with lowercase letters, digits, underscores, or hyphens.")
    return value


def text(value, maximum):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(char) < 32 for char in value):
        raise ValueError("A policy label or version is invalid.")
    return value


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Policy JSON contains a duplicate field.")
        result[key] = value
    return result


def decode(raw):
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: invalid_json())
    except (UnicodeError, RecursionError, json.JSONDecodeError):
        raise ValueError("Policy JSON is invalid.") from None


def invalid_json():
    raise ValueError("Policy JSON must contain finite numbers.")


def public_key(value):
    if not isinstance(value, str) or len(value) > 1024 or "\n" in value.strip():
        raise ValueError("Select one Ed25519 public key.")
    fields = value.strip().split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise ValueError("Select one Ed25519 public key.")
    try:
        raw = base64.b64decode(fields[1], validate=True)
    except ValueError:
        raise ValueError("The policy public key is invalid.") from None
    if raw[:19] != struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) or len(raw) != 51:
        raise ValueError("The policy public key is invalid.")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    return "ssh-ed25519 " + fields[1], fingerprint


def payload_path(name):
    if (not isinstance(name, str) or len(name) > 160 or name.startswith("/")
            or any(not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*", part) for part in name.split("/"))
            or not name.endswith((".rego", ".json"))):
        raise ValueError("A policy payload path is invalid.")
    return name


def manifest(value):
    fields = {"format", "version", "id", "release", "publisher", "decision_api", "roles", "files"}
    if (not isinstance(value, dict) or set(value) != fields or value["format"] != "ficc-policy"
            or type(value["version"]) is not int or value["version"] != 1
            or type(value["decision_api"]) is not int or value["decision_api"] != 1):
        raise ValueError("The policy package format is not supported.")
    identifier(value["id"])
    identifier(value["publisher"])
    text(value["release"], 80)
    roles = value["roles"]
    if not isinstance(roles, list) or not 1 <= len(roles) <= 64:
        raise ValueError("A policy package must describe its roles.")
    seen = set()
    for role in roles:
        if not isinstance(role, dict) or set(role) != {"id", "label", "description"}:
            raise ValueError("A policy role description is invalid.")
        key = identifier(role["id"])
        text(role["label"], 80)
        text(role["description"], 400)
        if key in seen:
            raise ValueError("Policy role identifiers must be distinct.")
        seen.add(key)
    files = value["files"]
    if not isinstance(files, dict) or not 1 <= len(files) <= 64 or not any(name.endswith(".rego") for name in files):
        raise ValueError("A policy package must contain a declared policy.")
    for name, digest in files.items():
        payload_path(name)
        if not isinstance(digest, str) or not HASH.fullmatch(digest):
            raise ValueError("A policy payload digest is invalid.")
    return value


def inspect(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_ARCHIVE:
        raise ValueError("The policy archive exceeds its size limit.")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            names = [item.filename for item in members]
            if (len(names) != len(set(names)) or not 3 <= len(names) <= 66
                    or sum(item.file_size for item in members) > MAX_PAYLOAD
                    or any(item.is_dir() or item.flag_bits & 1 or item.file_size < 0
                           or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG) for item in members)):
                raise ValueError("The policy archive member set is invalid.")
            if archive.getinfo("manifest.json").file_size > 65536 or archive.getinfo("manifest.sig").file_size > 8192:
                raise ValueError("The policy signature or manifest exceeds its limit.")
            def read(name):
                info = archive.getinfo(name)
                with archive.open(info) as stream:
                    data = stream.read(info.file_size + 1)
                if len(data) != info.file_size:
                    raise ValueError("A policy member has an invalid size.")
                return data
            signed = read("manifest.json")
            value = manifest(decode(signed))
            expected = {"manifest.json", "manifest.sig"} | {"payload/" + name for name in value["files"]}
            if set(names) != expected:
                raise ValueError("Every policy archive member must be declared.")
            payload = {}
            for name, digest in value["files"].items():
                data = read("payload/" + name)
                if hashlib.sha256(data).hexdigest() != digest:
                    raise ValueError("A policy payload digest does not match.")
                payload[name] = data
            return value, signed, read("manifest.sig"), payload
    except (zipfile.BadZipFile, zlib.error, KeyError, RuntimeError, NotImplementedError, OSError):
        raise ValueError("The policy archive is invalid.") from None


def verify(raw, key):
    value, signed, signature, payload = inspect(raw)
    key, fingerprint = public_key(key)
    with tempfile.TemporaryDirectory(prefix="ficc-policy-signature-") as temporary:
        root = Path(temporary)
        (root / "signers").write_text(value["publisher"] + " namespaces=\"" + NAMESPACE + "\" " + key + "\n")
        (root / "signature").write_bytes(signature)
        try:
            result = subprocess.run(["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(root / "signers"),
                                     "-I", value["publisher"], "-n", NAMESPACE, "-s", str(root / "signature")],
                                    input=signed, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    env={"PATH": "/usr/bin:/bin", "LANG": "C"}, timeout=3, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise ValueError("The policy signature verifier is unavailable.") from None
        if result.returncode:
            raise ValueError("The policy signature does not match its trusted publisher.")
    return value, fingerprint, payload
