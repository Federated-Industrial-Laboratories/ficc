#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check package bytes and protocol results from real example child processes."""

import argparse
import json
import os
import runpy
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# Use the same validator as the source tree that built these examples.
from ficc.modules import protocol  # noqa: E402
from ficc.modules.archive import inspect_archive, publish  # noqa: E402

FIXTURE = json.loads((ROOT / "sdk/fixtures/conformance.json").read_text())
LANGUAGES = ("c", "cpp", "rust", "python", "javascript", "typescript")


def invoke(command: list[str], payload: bytes) -> subprocess.CompletedProcess:
    # These are known SDK examples, run outside the host sandbox for conformance only.
    result = subprocess.run(command, input=payload, capture_output=True, timeout=10,
                            cwd="/tmp", env={"PATH": os.defpath, "LANG": "C.UTF-8"})
    if len(result.stdout) > protocol.MAX_OUTPUT or len(result.stderr) > protocol.MAX_STDERR:
        raise AssertionError("Example output exceeded the protocol limit")
    return result


def cases(command: list[str]) -> int:
    checks = 0
    for count in FIXTURE["counts"]:
        targets = [f"target-{index}" for index in range(count)]
        for message in FIXTURE["messages"]:
            request_id, payload = protocol.request(FIXTURE["action"], targets, {"message": message})
            result = invoke(command, payload)
            assert result.returncode == 0, result.stderr
            parsed = protocol.response(result.stdout, request_id, targets)
            assert parsed["results"] == [{"target": target, "data": {"message": message, "index": i}}
                                         for i, target in enumerate(targets)]
            checks += 1
        request_id, payload = protocol.request("unsupported", targets, {})
        result = invoke(command, payload)
        assert result.returncode == 0, result.stderr
        parsed = protocol.response(result.stdout, request_id, targets)
        assert all(item["error"]["code"] == "unsupported_action" for item in parsed["results"])
        checks += 1
    for character in FIXTURE["long_target_characters"]:
        targets = [character * 128]
        request_id, payload = protocol.request("echo", targets, {"message": "Long target"})
        result = invoke(command, payload)
        assert result.returncode == 0, result.stderr
        parsed = protocol.response(result.stdout, request_id, targets)
        assert parsed["results"] == [{"target": targets[0],
                                      "data": {"message": "Long target", "index": 0}}]
        checks += 1
    _, valid = protocol.request("echo", ["target"], {"message": "Hello"})
    hello, request = protocol.frames(valid)
    malformed = {
        "truncated_header": valid[:3],
        "truncated_body": valid[:-1],
        "oversized_frame": struct.pack(">I", 1048577),
        "invalid_json": struct.pack(">I", 1) + b"!",
        "wrong_version": protocol.frame({**hello, "version": 2}) + protocol.frame(request),
        "extra_frame": valid + protocol.frame(hello),
        "duplicate_target": protocol.frame(hello) + protocol.frame({**request, "targets": ["a", "a"]}),
        "empty_targets": protocol.frame(hello) + protocol.frame({**request, "targets": []}),
        "too_many_targets": protocol.frame(hello) + protocol.frame(
            {**request, "targets": [f"target-{i}" for i in range(65)]}),
    }
    assert set(malformed) == set(FIXTURE["invalid_inputs"])
    for name, payload in malformed.items():
        result = invoke(command, payload)
        assert result.returncode != 0 and not result.stdout, name
        checks += 1
    return checks


def check_package(path: Path, python: str, node: str, *, broker: bool = False) -> int:
    inspection = inspect_archive(path.read_bytes())
    with tempfile.TemporaryDirectory(prefix="ficc-sdk-") as temporary:
        directory = publish(Path(temporary), inspection)
        runtime = inspection.manifest["runtime"]
        entry = str(directory / runtime["entry"])
        command = ([python, "-I", entry] if runtime["kind"] == "python" else
                   [node, "--no-addons", entry] if runtime["kind"] == "javascript" else [entry])
        try:
            if broker:
                return runpy.run_path(str(ROOT / "sdk/broker_conformance.py"))["cases"](command)
            return cases(command)
        finally:
            # Host publication is read-only; restore private write access for temporary cleanup.
            for parent, _, files in os.walk(directory):
                Path(parent).chmod(0o700)
                for name in files:
                    (Path(parent) / name).chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--node", default="node")
    parser.add_argument("--broker", action="store_true")
    args = parser.parse_args()
    total = 0
    for language in LANGUAGES:
        prefix = "resources" if args.broker else "echo"
        archive = args.packages / f"org.example.{prefix}.{language}-1.0.0.ficc-module.zip"
        count = check_package(archive, args.python, args.node, broker=args.broker)
        total += count
        print(f"{language}: {count} checks passed")
    print(f"Total: {total} checks passed. Host sandbox qualification is separate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
