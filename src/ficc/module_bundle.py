# SPDX-License-Identifier: Apache-2.0
"""Read separately packaged default archives without registering or enabling them."""

import hashlib
import importlib.resources

from .errors import Failure
from .modules.validation import digest, fields, identifier, loads, text


def available() -> list[dict]:
    resource = importlib.resources.files("ficc").joinpath("module_packages", "index.json")
    if not resource.is_file():
        return []
    with resource.open("rb") as stream:
        value = loads(stream.read(65537), 65536)
    fields(value, {"version", "modules"})
    if type(value["version"]) is not int or value["version"] != 1 or not isinstance(value["modules"], list):
        raise Failure("module_bundle_invalid", "The supplied module index is invalid.", 503)
    if len(value["modules"]) > 32:
        raise Failure("module_bundle_invalid", "The supplied module index exceeds its limit.", 503)
    seen = set()
    for item in value["modules"]:
        fields(item, {"id", "version", "display_name", "filename", "digest"})
        identifier(item["id"])
        digest(item["digest"])
        text(item["version"], 64)
        text(item["display_name"], 160)
        expected = item["id"] + "-" + item["version"] + ".ficc-module.zip"
        if item["filename"] != expected or any(c in expected for c in "/\\:") or item["id"] in seen:
            raise Failure("module_bundle_invalid", "A supplied module entry is invalid.", 503)
        seen.add(item["id"])
    return value["modules"]


def read(package_id: str) -> bytes:
    selected = next((item for item in available() if item["id"] == package_id), None)
    if selected is None:
        raise Failure("not_found", "The supplied module was not found.", 404)
    resource = importlib.resources.files("ficc").joinpath("module_packages", selected["filename"])
    try:
        with resource.open("rb") as stream:
            data = stream.read(16 * 1024 * 1024 + 1)
    except OSError as exc:
        raise Failure("module_bundle_invalid", "The supplied module archive is unavailable.", 503) from exc
    if len(data) > 16 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != selected["digest"]:
        raise Failure("module_bundle_invalid", "The supplied module differs from its index.", 503)
    return data
