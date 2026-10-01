#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the free VirtualBox VNC extension with a private Unix display socket."""

import argparse
import gzip
import hashlib
import io
import subprocess
import tarfile
from pathlib import Path

SOURCE_SHA256 = "5c2138213b72f36c129b92c2c267f2a40e9c98513f4c86a584327f09f9be706d"
SOURCE_ROOT = "VirtualBox-7.2.20/"
VERSION = "7.2.20"
REVISION = "175154"


def pack(paths):
    """Return a source or extension archive with fixed metadata."""
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path, name in paths:
                info = archive.gettarinfo(path, arcname=name)
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                info.mode = 0o755 if info.isdir() else 0o644
                if info.isfile():
                    with path.open("rb") as stream:
                        archive.addfile(info, stream)
                else:
                    archive.addfile(info)
    return output.getvalue()


def compile_source(root, stage):
    for name in ("VBoxVNCMain", "VBoxVNC"):
        subprocess.run(["c++", "-std=c++17", "-O2", "-fPIC", "-shared", "-DIN_RING3", "-DRT_OS_LINUX", "-DRT_ARCH_AMD64",
            "-ffile-prefix-map=" + str(root) + "=/source", "-Wl,--build-id=none",
            "-I" + str(root / "include"), str(root / "src/VBox/ExtPacks/VNC" / (name + ".cpp")),
            "-L/usr/lib/virtualbox", "-l:VBoxRT.so", "-Wl,-rpath,/usr/lib/virtualbox", "-lvncserver",
            "-o", str(stage / "linux.amd64" / (name + ".so"))], check=True, timeout=120)


def patch(source, header):
    text = source.decode()
    marker = "#include <rfb/rfb.h>"
    if text.count(marker) != 1:
        raise ValueError("The VNC source layout changed.")
    text = text.replace(marker, marker + '\n#include "ficc_vnc_unix.h"')
    text = text.replace("    rfbScreenInfoPtr mVNCServer;", "    rfbScreenInfoPtr mVNCServer;\n    FiccVncSocket mFiccSocket;")
    text = text.replace("    rfbShutdownServer(instance->mVNCServer, TRUE);",
                        "    rfbShutdownServer(instance->mVNCServer, TRUE);\n    instance->mFiccSocket.clear();")
    start = text.index("#ifndef VBOX_USE_IPV6", text.index("VNCServerImpl::VRDEEnableConnections(HVRDESERVER hServer, bool fEnable)\n{"))
    end = text.index("    // let's get the password", start)
    text = text[:start] + '''    char socketPath[108] = {0};
    int rc = instance->queryVrdeFeature("Property/VNCUnixSocket", socketPath, sizeof(socketPath));
    if (RT_FAILURE(rc) || !instance->mFiccSocket.listen(vncServer, socketPath)) return VERR_ACCESS_DENIED;
    uint32_t cbOut = 0;
    vncServer->newClientHook = rfbNewClientEvent;
    vncServer->kbdAddEvent = vncKeyboardEvent;
    vncServer->ptrAddEvent = vncMouseEvent;
''' + text[end:]
    # The extension must not silently start an unauthenticated display.
    text = text.replace('        LogRel(("VNC: No password result = %Rrc\\n", rc));',
                        '        return VERR_ACCESS_DENIED;')
    return text.encode(), header


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    origin = parser.add_mutually_exclusive_group(required=True)
    origin.add_argument("--source", type=Path)
    origin.add_argument("--prepared-source", type=Path, help="Rebuild the included, already patched source tree")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.source and (args.source.is_symlink() or hashlib.file_digest(args.source.open("rb"), "sha256").hexdigest() != SOURCE_SHA256):
        raise ValueError("The VirtualBox source archive does not match its pinned SHA256.")
    args.output.mkdir(parents=True, exist_ok=False)
    selected = {}
    if args.source:
        with tarfile.open(args.source, "r:bz2") as archive:
            for member in archive:
                name = member.name.removeprefix(SOURCE_ROOT)
                if member.name == name or not (name.startswith("include/") or name.startswith("src/VBox/ExtPacks/VNC/")
                        or name in {"doc/License-gpl-3.0.txt", "COPYING"}):
                    continue
                if not member.isfile():
                    continue
                if ".." in Path(name).parts or member.size > 4 * 1024 * 1024:
                    raise ValueError("The selected source member is invalid.")
                selected[name] = archive.extractfile(member).read()
    else:
        for path in sorted(args.prepared_source.rglob("*")):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise ValueError("The prepared source contains a link or special file.")
            if path.is_file():
                if path.stat().st_size > 4 * 1024 * 1024:
                    raise ValueError("A prepared source member exceeds its limit.")
                selected[path.relative_to(args.prepared_source).as_posix()] = path.read_bytes()
    root = args.output / "source"
    for name, content in selected.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    source = root / "src/VBox/ExtPacks/VNC"
    if args.source:
        modified, header = patch((source / "VBoxVNC.cpp").read_bytes(), Path(__file__).with_name("ficc_vnc_unix.h").read_bytes())
        (source / "VBoxVNC.cpp").write_bytes(modified)
        (source / "ficc_vnc_unix.h").write_bytes(header)
    (root / "include/product-generated.h").write_text('#define VBOX_PRODUCT "VirtualBox"\n#define VBOX_VENDOR "Oracle and/or its affiliates"\n')
    (root / "include/version-generated.h").write_text('#define VBOX_VERSION_MAJOR 7\n#define VBOX_VERSION_MINOR 2\n#define VBOX_VERSION_BUILD 20\n'
        '#define VBOX_SVN_REV 175154\n#define VBOX_VERSION_STRING "7.2.20"\n#define VBOX_C_YEAR "2026"\n#define VBOX_PRIVATE_BUILD_DESC "FICC Unix display"\n')
    stage = args.output / "stage"
    (stage / "linux.amd64").mkdir(parents=True)
    compile_source(root, stage)
    (stage / "ExtPack.xml").write_text((source / "ExtPack.xml").read_text().replace("@VBOX_SVN_REV@", REVISION).replace("@VBOX_VERSION_STRING@", VERSION).replace("<Name>VNC</Name>", "<Name>FICC VNC</Name>").replace("VNC plugin module", "Private Unix VNC display module"))
    (stage / "ExtPack-license.txt").write_bytes((root / "doc/License-gpl-3.0.txt").read_bytes())
    (stage / "NOTICE.txt").write_text("FICC VNC is a modified free VirtualBox VNC extension. It is not the Oracle Extension Pack.\n"
        "Copyright (C) 2010-2025 Oracle and/or its affiliates; original contributors are named in the source.\n"
        "Unix listener changes: Copyright (C) 2026 Federated Industrial Laboratories. GPL-3.0-only.\n"
        "Dynamic prerequisites: VirtualBox 7.2.20 VBoxRT and LibVNCServer 0.9.15.\n"
        "The source.tar.gz member includes the complete matching extension source, headers and build script.\n"
        "Rebuild with: python3 build.py --prepared-source source --output rebuilt\n")
    # Include the complete corresponding patched extension source and build inputs.
    inputs = [(root, "source"), *[(path, "source/" + path.relative_to(root).as_posix()) for path in sorted(root.rglob("*"))]]
    inputs += [(Path(__file__), "build.py"), (source / "ficc_vnc_unix.h", "ficc_vnc_unix.h")]
    (stage / "source.tar.gz").write_bytes(pack(inputs))
    files = sorted(path for path in stage.rglob("*") if path.is_file())
    (stage / "ExtPack.manifest").write_text("".join("SHA256 (" + path.relative_to(stage).as_posix() + ") = "
        + hashlib.file_digest(path.open("rb"), "sha256").hexdigest() + "\n" for path in files))
    (stage / "ExtPack.signature").write_text("unsigned source build\n")
    target = args.output / "FICC_VNC-7.2.20.vbox-extpack"
    target.write_bytes(pack([(path, path.relative_to(stage).as_posix()) for path in sorted(stage.rglob("*"))]))
    print(target)


if __name__ == "__main__":
    main()
