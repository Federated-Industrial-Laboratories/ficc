# SPDX-License-Identifier: Apache-2.0
"""Retain runtime licences and corresponding upstream source archives."""

import json
import shutil
import subprocess
import tarfile
from pathlib import Path

from .common import archive_tree, write_json


def member(archive: Path, suffix: str) -> bytes:
    with tarfile.open(archive) as bundle:
        matches = [m for m in bundle.getmembers() if m.name.endswith("/" + suffix)]
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 8 * 1024 * 1024:
            raise ValueError("Expected one bounded licence or metadata member: " + suffix)
        stream = bundle.extractfile(matches[0])
        assert stream is not None
        return stream.read()


def install(payload: Path, inputs: dict[str, Path], lock: dict) -> list[dict]:
    target = payload / "licenses/appimage"
    target.mkdir(parents=True)
    for key, name, destination in (
        ("runtime-source", "LICENSE", "LICENSE.runtime"),
        ("fuse-source", "LGPL2.txt", "LICENSE.libfuse"),
        ("squashfuse-source", "LICENSE", "LICENSE.squashfuse"),
    ):
        (target / destination).write_bytes(member(inputs[key], name))
    for key in ("musl-license", "zstd-license", "zlib-license", "mimalloc-license"):
        shutil.copy2(inputs[key], target / inputs[key].name)
    python = payload / "licenses/python"
    (python / "LICENSE.liblzma.txt").write_bytes(member(inputs["python-build-source"], "LICENSE.liblzma.txt"))
    shutil.copy2(inputs["zlib-ng-license"], python / "LICENSE.zlib-ng.txt")
    downloads = json.loads(member(inputs["python-build-source"], "pythonbuild/downloads.json"))
    metadata = json.loads((python / "PYTHON.json").read_text())
    versions = json.loads(subprocess.check_output([
        str(payload / "python/bin/python3"), "-I", "-B", "-c",
        "import json,ssl,sqlite3,zlib;print(json.dumps({'openssl':ssl.OPENSSL_VERSION.split()[1],"
        "'sqlite':sqlite3.sqlite_version,'zlib':zlib.ZLIB_VERSION}))",
    ], text=True))
    libraries = {link["name"] for variants in metadata["build_info"]["extensions"].values()
                 for variant in variants for link in variant.get("links", []) if "path_static" in link}
    components = []
    for name, item in downloads.items():
        if name == "zlib-ng" or not libraries.intersection(item.get("library_names", [])):
            continue
        if name.startswith("openssl-") and item["version"] != versions["openssl"]:
            continue
        version = versions.get(name, item["version"])
        components.append({"type": "library", "name": name, "version": version,
                           "hashes": [{"alg": "SHA-256", "content": item["sha256"]}],
                           "externalReferences": [{"type": "distribution", "url": item["url"]}],
                           "properties": [{"name": "ficc:scope", "value": "CPython native dependency"}]})
    for name, key in (("AppImage type 2 runtime", "runtime-source"), ("libfuse", "fuse-source"),
                      ("squashfuse", "squashfuse-source")):
        item = next(i for i in lock["inputs"] if i["id"] == key)
        components.append({"type": "library", "name": name, "version": item["release"],
                           "externalReferences": [{"type": "distribution", "url": item["url"]}],
                           "properties": [{"name": "ficc:scope", "value": "AppImage outer runtime"}]})
    for name in ("musl", "zstd", "zlib", "mimalloc"):
        components.append({"type": "library", "name": name,
                           "properties": [{"name": "ficc:scope", "value": "AppImage build dependencies; versions not attested upstream"}]})
    (payload / "THIRD-PARTY.md").write_text(
        "# Bundled software\n\n"
        "FICC uses Apache-2.0. Bundled components retain their own licences.\n"
        "Python distributions keep their notices in python/lib/python3.12/site-packages.\n"
        "Web and font notices are beside the installed static assets. CPython and its\n"
        "native dependency notices are in licenses/python, with upstream build metadata.\n\n"
        "AppImage runtime notices are in licenses/appimage. Only the AppImage format\n"
        "contains that outer runtime. Its libfuse component uses LGPL-2.1-or-later.\n"
        "Modification and reverse engineering of that component for debugging are permitted.\n"
        "The matching third-party-sources release archive contains the runtime source,\n"
        "libfuse source, patch, build scripts and squashfuse source for rebuilding it.\n"
        "The runtime build scripts identify the remaining build dependencies. Their\n"
        "exact binary versions are not attested by the upstream runtime release.\n\n"
        "The same source archive includes CPython, Berkeley DB and the Python build\n"
        "scripts. FICC's complete source and locked dependency references are in the\n"
        "matching source release archive. Keep both source archives beside the binaries\n"
        "when distributing this release. No third-party licence is replaced by FICC's.\n")
    return components


def sources(inputs: dict[str, Path], lock: dict, work: Path, output: Path, version: str, epoch: int) -> None:
    target = work / f"ficc-{version}-third-party-sources"
    target.mkdir()
    selected = [i for i in lock["inputs"] if i["id"].endswith("-source")]
    for item in selected:
        shutil.copy2(inputs[item["id"]], target / item["name"])
    write_json(target / "inputs.json", selected)
    (target / "README.md").write_text(
        "# Runtime source\n\n"
        "These are unmodified source archives identified by inputs.json.\n"
        "For the AppImage runtime, extract type2-runtime and read BUILD.md.\n"
        "Its scripts/common/install-dependencies.sh gives the exact libfuse and\n"
        "squashfuse versions included here; patches/libfuse contains the required patch.\n"
        "Run its scripts/docker/build-with-docker.sh with ARCH=x86_64 to rebuild the runtime.\n"
        "The container build installs its remaining build dependencies from Alpine.\n"
        "FICC tools/release.py accepts the resulting runtime through packaging/inputs.json;\n"
        "update its digest and size before building an AppImage with a modified runtime.\n\n"
        "For Python, python-build-standalone contains build scripts, patches and all\n"
        "dependency source references in pythonbuild/downloads.json. CPython and\n"
        "Berkeley DB source archives are included. FICC source ships separately.\n"
        "The component archives retain their respective copyright and licence notices.\n")
    archive_tree(target, output / (target.name + ".tar.gz"), epoch)
