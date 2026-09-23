#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Check source size, license headers, private data and common secret formats.
# Inputs: source root. Output: findings and counts. Exit: 0 clean, 1 findings.
"""Inspect distributable source before publication."""

import argparse
import re
from pathlib import Path

SKIP = {".git", ".venv", "node_modules", "__pycache__", "dist", "build",
        ".pytest_cache", ".ruff_cache", ".mypy_cache"}
SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".css", ".sh"}
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|ENCRYPTED) PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)
PRIVATE_PATTERNS = (
    re.compile(r"/home/" + "federated-industrial"),
    re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"knowledge/" + r"(?:records|bus)/"),
)


def inspect(root: Path) -> tuple[int, list[str]]:
    """Return the inspected text count and specific findings."""
    count, findings = 0, []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in SKIP or part.endswith(".egg-info") for part in relative.parts[:-1]):
            continue
        if relative.parts[:3] == ("src", "ficc", "static"):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        count += 1
        if len(content.splitlines()) > 1000:
            findings.append(f"{relative}: more than 1000 lines")
        if path.suffix in SUFFIXES and "SPDX-License-Identifier: Apache-2.0" not in content[:500]:
            findings.append(f"{relative}: missing license identifier")
        for pattern in SECRET_PATTERNS + PRIVATE_PATTERNS:
            if pattern.search(content):
                findings.append(f"{relative}: restricted content ({pattern.pattern[:25]})")
        if "\u2014" in content and path.suffix in SUFFIXES | {".md"}:
            findings.append(f"{relative}: use ASCII punctuation")
    if not count:
        findings.append("No source text was inspected")
    return count, findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, nargs="?", default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    count, findings = inspect(args.root)
    for finding in findings:
        print(finding)
    print(f"Source checks: {count} text files, {len(findings)} findings")
    return int(bool(findings))


if __name__ == "__main__":
    raise SystemExit(main())
