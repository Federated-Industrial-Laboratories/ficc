# SPDX-License-Identifier: Apache-2.0
"""Load only administrator-pinned executor distributions through the batch interface."""

import base64
import importlib.metadata
from pathlib import Path

from .files import fingerprint
from .spec import digest

API_VERSION = 1
METHODS = ("probe", "prepare", "start", "observe", "stop", "collect", "release")


def distribution(identity, *, owner=0):
    entries = list(importlib.metadata.entry_points(group="ficc.executor", name=identity))
    if len(entries) != 1 or entries[0].dist is None:
        raise ValueError("Install exactly one trusted distribution for this executor identity.")
    entry = entries[0]
    installed = entry.dist
    if installed is None:
        raise ValueError("The executor entry point has no installed distribution.")
    records = []
    for item in installed.files or ():
        if item.hash is None:
            continue
        if item.hash.mode != "sha256" or ".." in item.parts:
            raise ValueError("The executor distribution has an unsupported installed-file record.")
        info = fingerprint(Path(str(installed.locate_file(item))).absolute(), owner=owner)
        expected = "sha256:" + base64.urlsafe_b64decode(item.hash.value + "==").hex()
        if info["digest"] != expected or item.size != info["bytes"]:
            raise ValueError("An installed executor file differs from its package record.")
        records.append({"path": str(item), "bytes": info["bytes"], "digest": info["digest"]})
    if not records:
        raise ValueError("The executor distribution has no verified installed files.")
    value = {"name": installed.name, "version": installed.version, "entry": entry.value,
             "files": sorted(records, key=lambda item: item["path"])}
    return entry, digest(value)


class Providers:
    def __init__(self, configurations):
        self.drivers = {}
        for configured in configurations:
            entry, package = distribution(configured.id)
            if package != configured.package_digest:
                raise ValueError("The installed executor package does not match its approved digest.")
            module = entry.load()
            if module.API_VERSION != API_VERSION:
                raise ValueError("The executor provider interface version is not supported.")
            driver = module.configure(configured.configuration)
            if any(not callable(getattr(driver, name, None)) for name in METHODS):
                raise ValueError("The executor provider does not implement every batch method.")
            self.drivers[configured.id] = (package, driver)

    def call(self, identity, package_digest, method, rows):
        if method not in METHODS or not 1 <= len(rows) <= 64:
            raise ValueError("Select a supported executor operation with one to 64 rows.")
        package, driver = self.drivers[identity]
        if package != package_digest:
            raise ValueError("The attempt does not select the installed executor package.")
        output = getattr(driver, method)(rows)
        if not isinstance(output, list) or len(output) != len(rows) or any(not isinstance(item, dict) for item in output):
            raise ValueError("The executor provider returned an incomplete batch.")
        return output
