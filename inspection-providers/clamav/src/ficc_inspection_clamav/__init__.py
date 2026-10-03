# SPDX-License-Identifier: Apache-2.0
"""Use the local clamscan engine without network submission or file mutation."""

import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Annotated

from pydantic import Field

from ficc.inspection_sdk import InspectionError
from ficc.schema import Model

API_VERSION = 1
METADATA = {"description": "Local ClamAV, with bounded archive coverage and no network submission.", "location": "local"}


class Configuration(Model):
    engine: Annotated[str, Field(min_length=1, max_length=4096)] = "/usr/bin/clamscan"
    database: Annotated[str, Field(min_length=1, max_length=4096)] = "/var/lib/clamav"
    certificate_directory: Annotated[str | None, Field(min_length=1, max_length=4096)] = "/etc/clamav/certs"
    max_file_bytes: Annotated[int, Field(ge=1, le=2147483647)] = 104857600
    max_scan_bytes: Annotated[int, Field(ge=1, le=2**63 - 1)] = 419430400
    max_files: Annotated[int, Field(ge=1, le=2147483647)] = 10000
    max_recursion: Annotated[int, Field(ge=1, le=100)] = 16
    scan_milliseconds: Annotated[int, Field(ge=1, le=2147483647)] = 120000


def configuration(value):
    result = Configuration.model_validate(value).model_dump()
    for name in ("engine", "database", "certificate_directory"):
        if result[name] is not None and (not Path(result[name]).is_absolute() or "\0" in result[name]):
            raise ValueError("Approve absolute scanner asset paths.")
    return result


def assets(value):
    result = {"engine": value["engine"], "signatures": value["database"]}
    if value["certificate_directory"] is not None:
        result["certificates"] = value["certificate_directory"]
    return result


def fingerprint(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise InspectionError("scanner_assets", "A scanner asset is not an ordinary file.")
        digest = hashlib.sha256()
        while block := os.read(fd, 262144):
            digest.update(block)
        after = os.fstat(fd)
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise InspectionError("scanner_assets_changed", "The scanner assets changed during inspection.")
        return {"sha256": digest.hexdigest(), "bytes": before.st_size, "modified_at": before.st_mtime_ns / 1e9}
    finally:
        os.close(fd)


def inventory(path):
    location = Path(path)
    if location.is_dir():
        files: list[Path] = []
        for entry in location.iterdir():
            if entry.name.startswith(".") or entry.name in {"freshclam.dat", "freshclam.log"}:
                continue
            if len(files) == 128 or entry.is_symlink() or not entry.is_file():
                raise InspectionError("scanner_assets", "The approved signature directory contains unsupported assets.")
            files.append(entry)
    else:
        files = [location]
    if not files:
        raise InspectionError("scanner_assets", "The approved signature collection is empty.")
    return [{"name": file.name, **fingerprint(file)} for file in sorted(files)]


def signatures(path):
    return {"files": inventory(path),
            "provenance": "Owner-approved local signature bytes; hashes do not establish publisher trust."}


def bounded_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
    assert process.stdout is not None
    output = bytearray()
    overflow = False
    with process.stdout:
        while block := process.stdout.read(8192):
            if len(output) + len(block) > 65536:
                overflow = True
            output.extend(block[:max(0, 65536 - len(output))])
    return process.wait(), output.decode("utf-8", "replace"), overflow


def inspect(context):
    value = context.configuration
    engine, database = context.assets["engine"], context.assets["signatures"]
    engine_digest, rules = fingerprint(engine), signatures(database)
    certificates = inventory(context.assets["certificates"]) if "certificates" in context.assets else []
    code, version, overflow = bounded_command([engine, "--version", "--database=" + database])
    if code or overflow or not re.match(r"^ClamAV \d+\.\d+\.\d+", version):
        raise InspectionError("scanner_unavailable", "The approved ClamAV engine is unavailable.")
    result = {"engine": {"name": "ClamAV", "version": version.strip()[:256], **engine_digest,
                         "verification_certificates": certificates}, "signatures": rules,
              "coverage": {"limits": {key: item for key, item in value.items() if key not in {"engine", "database", "certificate_directory"}},
                           "scope": "ClamAV supported formats and engine parser limits", "encrypted_content": "not decrypted",
                           "parser_limits": "Additional format-specific engine defaults apply; arbitrary content is not guaranteed to be decoded.",
                           "archive_scan": True, "unsigned_bytecode": False, "reasons": []}, "findings": []}
    if context.source["size"] > value["max_file_bytes"]:
        result.update(outcome="incomplete")
        result["coverage"]["reasons"] = ["file_size_limit"]
        return result
    args = [engine, "--stdout", "--database=" + database, "--tempdir=/tmp", "--allmatch=yes", "--scan-archive=yes",
            "--heuristic-alerts=yes", "--alert-encrypted=yes", "--alert-exceeds-max=yes", "--alert-broken=yes",
            "--alert-broken-media=yes", "--bytecode-unsigned=no", "--follow-file-symlinks=0", "--follow-dir-symlinks=0",
            "--max-filesize=" + str(value["max_file_bytes"]), "--max-scansize=" + str(value["max_scan_bytes"]),
            "--max-files=" + str(value["max_files"]), "--max-recursion=" + str(value["max_recursion"]),
            "--max-scantime=" + str(value["scan_milliseconds"]), "--pcre-max-filesize=" + str(value["max_file_bytes"])]
    if "certificates" in context.assets:
        args += ["--cvdcertsdir=" + context.assets["certificates"]]
    args += ["--", context.path]
    code, output, overflow = bounded_command(args)
    reasons, findings = set(), set()
    for line in output.splitlines():
        match = re.fullmatch(r"/input/file: ([A-Za-z0-9_.:+-]{1,200}) FOUND", line)
        if match:
            name = match[1]
            if name.startswith(("Heuristics.Limits.Exceeded", "Heuristics.Encrypted", "Heuristics.Broken")):
                reasons.add(name)
            else:
                findings.add(name)
        elif "WARNING:" in line or " ERROR" in line or line.startswith("LibClamAV Error:"):
            reasons.add("engine_warning_or_parse_error")
    if overflow:
        reasons.add("diagnostic_output_limit")
    if code not in {0, 1}:
        reasons.add("engine_error")
    if not findings and not reasons and (code != 0 or not re.search(r"^Scanned files:\s+1\s*$", output, re.MULTILINE)):
        if context.source["size"] != 0:
            reasons.add("scan_not_confirmed")
    if (fingerprint(engine) != engine_digest or signatures(database) != rules
            or ("certificates" in context.assets and inventory(context.assets["certificates"]) != certificates)):
        raise InspectionError("scanner_assets_changed", "The scanner assets changed during inspection.")
    result["coverage"]["reasons"] = sorted(reasons)[:128]
    result["coverage"]["engine_exit_code"] = code
    result["findings"] = sorted(findings)[:128]
    result["outcome"] = "detected" if findings else "error" if code not in {0, 1} else "incomplete" if reasons else "no_detection"
    return result
