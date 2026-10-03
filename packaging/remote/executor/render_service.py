# SPDX-License-Identifier: Apache-2.0
"""Render a validated executor unit from private configuration; write stdout; exit 0 or 1."""

import argparse
import sys
from pathlib import Path

from ficc.execution.files import fingerprint
from ficc.execution.settings import absolute, load


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--python", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        settings = load(arguments.config)
        executable = arguments.python.resolve(strict=True)
        absolute(str(arguments.python))
        if executable != arguments.python:
            raise ValueError("Use a root-owned Python environment made with --copies, without executable path aliases.")
        fingerprint(executable)
        text = (Path(__file__).parent / "ficc-executor.service.in").read_text()
        values = {"INSTALLATION": settings.installation_id, "CONFIG": str(arguments.config),
                  "PYTHON": str(arguments.python), "MOUNTS": " ".join([settings.state, *[item.mount for item in settings.slots]])}
        for name, value in values.items():
            text = text.replace("@" + name + "@", value)
        if "@" in text:
            raise ValueError("The service template has an unknown replacement field.")
        sys.stdout.write(text)
        return 0
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
