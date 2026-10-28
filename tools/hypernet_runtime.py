# SPDX-License-Identifier: Apache-2.0
"""Install an explicitly trusted HyperNet SDK wheel and retain its exact provenance."""
import hashlib
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

from runtime_packages import metadata


def verify(wheel, checksum):
    wheel = Path(wheel)
    if (wheel.is_symlink() or not wheel.is_file() or wheel.stat().st_size > 4*1024*1024
            or not re.fullmatch(r"hypernet_streams-[A-Za-z0-9_.]+-py3-none-any.whl", wheel.name)
            or not re.fullmatch(r"[a-f0-9]{64}", checksum or "")):
        raise ValueError("Select a regular HyperNet SDK wheel and its trusted SHA-256.")
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != checksum:
        raise ValueError("The HyperNet SDK wheel differs from its trusted SHA-256.")
    package = metadata(wheel)
    if package["name"] != "hypernet-streams" or package["entry_points"]:
        raise ValueError("The selected wheel is not the HyperNet application-stream SDK.")
    with zipfile.ZipFile(wheel) as archive:
        if "hypernet_streams/__init__.py" not in archive.namelist():
            raise ValueError("The HyperNet SDK module is missing.")
    return {**package, "file": wheel.name, "sha256": checksum}


def install(python, wheel, checksum, destination, *, env=None):
    package = verify(wheel, checksum)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    copied = destination / package["file"]
    shutil.copyfile(wheel, copied)
    verify(copied, checksum)
    subprocess.run([str(python), "-I", "-m", "pip", "install", "--no-compile", "--no-deps", "--no-index", str(copied)], check=True, env=env)
    subprocess.run([str(python), "-I", "-c", "from hypernet_streams import Agent,Stream; assert all(callable(getattr(Agent,n,None)) for n in ('connect','accept','status','cancel'))"], check=True, env=env)
    (destination / "index.json").write_text(json.dumps(package, indent=2)+"\n")
    return package
