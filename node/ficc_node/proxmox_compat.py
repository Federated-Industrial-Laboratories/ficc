# SPDX-License-Identifier: Apache-2.0
"""Pin local Proxmox implementation identity before privileged provider calls."""

import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path

from . import proxmox_spec as spec
from .vm_libvirt import ProviderError

IMPLEMENTATION = (
    "API2/Qemu.pm", "API2/Tasks.pm", "QemuConfig.pm", "QemuServer.pm",
    "RPCEnvironment.pm", "RESTEnvironment.pm", "CLI/pvesh.pm",
    "AbstractConfig.pm", "QemuServer/Helpers.pm", "QemuServer/Monitor.pm",
    "pvecfg.pm", "HA/Config.pm",
)
PACKAGES = ("pve-manager", "qemu-server", "pve-qemu-kvm", "pve-cluster", "libpve-common-perl",
            "libpve-guest-common-perl", "libpve-storage-perl", "libpve-cluster-perl", "libpve-access-control")
READ_BUILDS = frozenset({("pve-manager/9.2.2/b9984c6d90a4bd80",
    "d89f96fdd413e8c3bbe4819eebaf48bd006609f57b81c1043cd7344b4b594f49")})
POWER_BUILDS = READ_BUILDS
CONSOLE_BUILDS = READ_BUILDS
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/root"}


def discover():
    if os.geteuid() != 0:
        raise ProviderError("proxmox_root_required", "The local Proxmox profile requires an enrolled root SSH account. No sudo is used.")
    try:
        versions = subprocess.run(["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}=${Version}\n", *PACKAGES],
                                  stdin=subprocess.DEVNULL, capture_output=True, timeout=2, check=True,
                                  env=ENVIRONMENT, cwd="/")
        if len(versions.stdout) > 65536:
            raise ValueError("The provider package inventory exceeds its bound.")
        parts = {"packages": hashlib.sha256(versions.stdout).hexdigest()}
        metadata = b""
        for name in IMPLEMENTATION:
            path = Path("/usr/share/perl5/PVE") / name
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                        or info.st_size > 2 * 1024 * 1024):
                    raise ValueError("Unsafe provider implementation file.")
                content = stream.read(2 * 1024 * 1024 + 1)
                if len(content) > 2 * 1024 * 1024:
                    raise ValueError("The provider source exceeds its byte limit.")
                parts[name] = hashlib.sha256(content).hexdigest()
                if name == "pvecfg.pm":
                    metadata = content
        # Read the fixed generated version literal; do not evaluate provider code
        # or load the full pveversion Perl command stack for every request.
        found = re.findall(rb"(?m)^sub version_text \{\n    return '([0-9.]+/[0-9a-f]+)';\n\}", metadata)
        if len(found) != 1 or b"return 'pve-manager';" not in metadata:
            raise ValueError("The provider version metadata is not supported.")
        version = "pve-manager/" + found[0].decode("ascii")
        value = {"version": version, "fingerprint": spec.digest(parts),
                 "node": os.uname().nodename.split(".", 1)[0],
                 "machine_id": Path("/etc/machine-id").read_text().strip()}
        return spec.provider(value)
    except (OSError, subprocess.SubprocessError, ValueError, IndexError) as exc:
        raise ProviderError("proxmox_unavailable", "A supported local Proxmox 9.2 installation could not be verified.") from exc


def require_provider(expected):
    actual = discover()
    if expected != actual:
        raise ProviderError("proxmox_provider_changed", "The Proxmox identity or implementation changed. Repeat compatibility checks before enabling this profile.")
    require_read(actual)
    return actual


def require_read(value):
    if (value["version"], value["fingerprint"]) not in READ_BUILDS:
        raise ProviderError("proxmox_read_unqualified", "This Proxmox build has no qualified inventory adapter.")


def require_power(value):
    if (value["version"], value["fingerprint"]) not in POWER_BUILDS:
        raise ProviderError("proxmox_power_unqualified", "This Proxmox build has no qualified lifecycle adapter.")


def require_console(value):
    if (value["version"], value["fingerprint"]) not in CONSOLE_BUILDS:
        raise ProviderError("vm_console_unqualified", "This Proxmox build has no qualified console adapter.")
