# SPDX-License-Identifier: Apache-2.0
"""Map supported Python versions to native package ordering and artifact names."""

import re


def checked(version: str) -> str:
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:rc\d+|\.dev\d+|\.post[1-9]\d*)?", version):
        raise ValueError("Unsupported release version")
    return version


def debian(version: str) -> str:
    return checked(version).replace(".dev", "~dev").replace("rc", "~rc")


def arch(version: str) -> str:
    return checked(version).replace(".dev", "dev")


def arch_package(version: str) -> str:
    return f"ficc-bin-{arch(version)}-1-x86_64.pkg.tar.zst"


def deb_package(version: str) -> str:
    # Hosted release assets normalise '~'; keep Debian ordering in control metadata.
    return f"ficc_{checked(version)}_amd64.deb"


def prerelease(version: str) -> bool:
    checked(version)
    return ".dev" in version or "rc" in version
