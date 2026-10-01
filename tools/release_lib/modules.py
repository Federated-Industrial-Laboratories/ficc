# SPDX-License-Identifier: Apache-2.0
"""Bind the release inventory to its shipped runtime module archives."""

import hashlib
import json
import zipfile
from pathlib import Path


def components(packages: Path) -> list[dict]:
    """Read built package identities and verify the index against their bytes."""
    index = json.loads((packages / "index.json").read_text())
    if index.get("version") != 1 or not index.get("modules"):
        raise ValueError("The supplied module index is missing or invalid.")
    result, names, identities = [], set(), set()
    for item in index["modules"]:
        name = item["filename"]
        if (Path(name).name != name or name != f"{item['id']}-{item['version']}.ficc-module.zip"
                or name in names or item["id"] in identities):
            raise ValueError("The supplied module index repeats or changes a package identity.")
        names.add(name)
        identities.add(item["id"])
        archive = packages / name
        if archive.is_symlink() or not archive.is_file():
            raise ValueError("A supplied module archive is not a regular file.")
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        if checksum != item["digest"]:
            raise ValueError("A supplied module archive differs from its indexed digest.")
        with zipfile.ZipFile(archive) as bundle:
            manifest = json.loads(bundle.read("manifest.json"))
        if (manifest["id"], manifest["version"]) != (item["id"], item["version"]):
            raise ValueError("A supplied module manifest differs from its indexed identity.")
        result.append({"type": "application", "bom-ref": "urn:ficc:module:" + checksum,
                       "name": item["id"], "version": item["version"],
                       "hashes": [{"alg": "SHA-256", "content": checksum}],
                       "properties": [{"name": "ficc:scope", "value": "Installable runtime module"},
                                      {"name": "ficc:archive", "value": name},
                                      {"name": "ficc:runtime", "value": manifest["runtime"]["kind"]}]})
    if {path.name for path in packages.glob("*.ficc-module.zip")} != names:
        raise ValueError("The supplied module archives differ from the complete index.")
    return result
