# SPDX-License-Identifier: Apache-2.0
"""Prepare a trusted, isolated OPA provider for the FICC policy interface."""

import platform
from pathlib import Path

from . import files
from .process import compile_source
from .runner import Runner

API_VERSION = 1


def prepare(configuration: dict, source: Path, run: Path) -> Runner:
    """Compile verified policy files and start the private decision service."""
    try:
        if platform.system() != "Linux":
            raise ValueError("The policy provider requires Linux.")
        source, run = files.directories(source, run)
        files.binary(configuration, run / "opa")
        (run / "work").mkdir(mode=0o700)
        capabilities = Path(__file__).with_name("capabilities.json").read_bytes()
        (run / "capabilities.json").write_bytes(capabilities)
        (run / "capabilities.json").chmod(0o400)
        compile_source(source, run)
        return Runner(source, run)
    except (OSError, ValueError, TypeError, RecursionError):
        raise ValueError("The policy evaluator could not be prepared.") from None
