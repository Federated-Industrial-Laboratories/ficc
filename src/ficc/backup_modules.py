# SPDX-License-Identifier: Apache-2.0
"""Validate module payloads and workspace records before publishing recovered state."""

import hashlib
import json
import math
import os
import re
from pathlib import Path

from pydantic import ValidationError

from . import backup_io as files
from .errors import Failure
from .modules.manifest import validate_manifest
from .modules.registry import MAX_STORAGE, validate_grants
from .modules.validation import digest, identifier, loads
from .workspace_schema import AudioPreferences, SurfaceUpdate, ViewUpdate, WorkspaceUpdate


def identity(value):
    if not isinstance(value, str) or not re.fullmatch(files.HEX32, value):
        raise ValueError("A workspace identity is invalid.")


def timestamp(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("A stored timestamp is invalid.")


def document(raw, expected):
    if not isinstance(raw, str) or len(raw) > 1024 * 1024:
        raise ValueError("The workspace record exceeds its size limit.")
    from .backup import decode
    value = decode(raw.encode())
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("The workspace record fields are invalid.")
    return value


def workspaces(db):
    spaces: dict[str, set[str]] = {}
    instances: set[str] = set()
    for key, raw in db.execute("SELECT id,value FROM workspaces"):
        identity(key)
        value = document(raw, {"id", "name", "revision", "instances", "updated_at"})
        if value["id"] != key:
            raise ValueError("The workspace record identity changed.")
        timestamp(value["updated_at"])
        update = WorkspaceUpdate.model_validate({k: value[k] for k in ("name", "revision", "instances")})
        ids = {item.id for item in update.instances}
        if ids & instances:
            raise ValueError("A module instance belongs to more than one workspace.")
        instances.update(ids)
        spaces[key] = ids
    views = {}
    for key, space, raw in db.execute("SELECT id,workspace_id,value FROM workspace_views"):
        identity(key)
        value = document(raw, {"id", "workspace_id", "revision", "layout"})
        if value["id"] != key or value["workspace_id"] != space or space not in spaces:
            raise ValueError("The workspace view has an invalid owner.")
        view_update = ViewUpdate.model_validate({k: value[k] for k in ("revision", "layout")})
        if set(view_update.layout.get("panels", {})) - spaces[space]:
            raise ValueError("The workspace view refers to an unknown panel.")
        views[key] = space
    for key, raw in db.execute("SELECT id,value FROM workspace_surfaces"):
        identity(key)
        value = document(raw, {"id", "revision", "tiles", "layout"})
        if value["id"] != key:
            raise ValueError("The workspace surface identity changed.")
        surface = SurfaceUpdate.model_validate({k: value[k] for k in ("revision", "tiles", "layout")})
        if set(surface.layout.get("panels", {})) - {tile.id for tile in surface.tiles}:
            raise ValueError("The workspace surface refers to an unknown tile.")
        for tile in surface.tiles:
            if tile.workspace_id not in spaces or views.get(tile.view_id, tile.workspace_id) != tile.workspace_id:
                raise ValueError("The workspace surface refers to an invalid view.")
    row = db.execute("SELECT value FROM settings WHERE key='audio.preferences'").fetchone()
    if row:
        AudioPreferences.model_validate(json.loads(row[0]))


def records(db):
    """Return validated package metadata; missing packages remain visible in workspaces."""
    try:
        workspaces(db)
        packages, enabled = {}, set()
        for checksum, package_id, version, raw, installed, active, revision in db.execute(
                "SELECT digest,package_id,version,manifest,installed,enabled,revision FROM module_packages"):
            digest(checksum)
            manifest = validate_manifest(loads(raw, 65536))
            timestamp(installed)
            if (manifest["id"] != package_id or manifest["version"] != version
                    or type(active) is not int or active not in (0, 1)
                    or type(revision) is not int or not 1 <= revision <= 2**53 - 1):
                raise ValueError("The module package record is invalid.")
            if active and package_id in enabled:
                raise ValueError("More than one package version is enabled.")
            if active:
                enabled.add(package_id)
            packages[checksum] = {"manifest": manifest, "raw": raw, "enabled": active, "grants": {}}
        for checksum, capability, target in db.execute("SELECT digest,capability,target_id FROM module_grants"):
            if checksum not in packages or not packages[checksum]["enabled"]:
                raise ValueError("A module grant refers to an unavailable package.")
            packages[checksum]["grants"].setdefault(capability, []).append(target)
        for package in packages.values():
            if package["enabled"]:
                validate_grants([{"capability": k, "target_ids": v} for k, v in package["grants"].items()],
                                package["manifest"]["capabilities"],
                                optional=set(package["manifest"].get("optional_capabilities", [])))
        for key, package_id, previous, current, action, at in db.execute("SELECT * FROM module_history"):
            identifier(package_id)
            timestamp(at)
            if type(key) is not int or key < 1 or action not in {"install", "enable", "disable", "uninstall"}:
                raise ValueError("The module history record is invalid.")
            for checksum in (previous, current):
                if checksum is not None:
                    digest(checksum)
        return packages
    except (Failure, ValidationError, TypeError, KeyError, RecursionError) as exc:
        raise ValueError("The module or workspace state is invalid.") from exc


def payloads(db, root, names, seal=False):
    """Check the complete copied inventory before restoring executable permission bits."""
    packages = records(db)
    expected, modes = {}, {}
    directories: set[str] = set()
    for checksum, package in packages.items():
        manifest = package["manifest"]
        prefix = f"modules/{checksum}/"
        hashes = {"manifest.json": hashlib.sha256(package["raw"]).hexdigest(), **manifest["files"]}
        for name, value in hashes.items():
            path = prefix + name
            expected[path] = value
            native = manifest["runtime"]["kind"] == "native" and manifest["runtime"]["entry"] == name
            modes[path] = 0o500 if native else 0o400
            directories.update(str(parent) for parent in Path(path).parents if str(parent) not in {".", "modules"})
    if set(name for name in names if name.startswith("modules/")) != set(expected):
        raise ValueError("The module payload set differs from the database inventory.")
    total = 0
    for name, checksum in expected.items():
        data = files.read(root, name, files.limit(name))
        total += len(data)
        if total > MAX_STORAGE or hashlib.sha256(data).hexdigest() != checksum:
            raise ValueError("A module payload exceeds its limit or differs from its digest.")
    if seal:
        for name, mode in modes.items():
            with files.member(root, name) as fd:
                os.fchmod(fd, mode)
                os.fsync(fd)
        for name in sorted(directories, key=lambda value: value.count("/"), reverse=True):
            with files.subdirectory(root, name) as fd:
                os.fchmod(fd, 0o500)
                os.fsync(fd)
