# SPDX-License-Identifier: Apache-2.0
"""Store exact package grants, activation revisions and version history."""

from __future__ import annotations

import builtins
import os
import shutil
import stat
import threading
import time
from pathlib import Path

from ..errors import Failure
from ..module_capabilities import SUPPORTED
from .archive import Inspection, inspect_archive, publish, recover_stages, verify
from .manifest import required_capabilities
from .sandbox import require_runtime
from .ui import reference
from .validation import digest as valid_digest
from .validation import fields, invalid, loads, strings

MAX_PACKAGES = 64
MAX_STORAGE = 128 * 1024 * 1024
MAX_GRANTS = 16384
MAX_HISTORY = 1024


def initialize(db) -> None:
    """Create additive tables within the caller's database transaction."""
    db.execute("""CREATE TABLE IF NOT EXISTS module_packages (
        digest TEXT PRIMARY KEY, package_id TEXT NOT NULL, version TEXT NOT NULL,
        manifest BLOB NOT NULL, installed REAL NOT NULL, enabled INTEGER NOT NULL,
        revision INTEGER NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS module_grants (
        digest TEXT NOT NULL, capability TEXT NOT NULL, target_id TEXT NOT NULL,
        PRIMARY KEY (digest, capability, target_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS module_history (
        id INTEGER PRIMARY KEY, package_id TEXT NOT NULL, previous_digest TEXT,
        new_digest TEXT, action TEXT NOT NULL, at REAL NOT NULL)""")


class Registry:
    """Use the controller store lock; registry mutations never grant external access."""

    def __init__(self, store, root_dir: Path):
        self.store, self.root = store, Path(root_dir)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink() or not self.root.is_dir() or self.root.stat().st_uid != os.getuid():
            raise invalid("The module storage directory is invalid.")
        self.root.chmod(0o700)
        with self.store.lock:
            recover_stages(self.root)
        self._leases: dict[str, int] = {}
        self._lease_lock = threading.RLock()

    def install(self, inspection: Inspection, expected_digest: str) -> dict:
        valid_digest(expected_digest)
        checked = inspect_archive(inspection._archive)
        if checked.digest != expected_digest:
            raise Failure("module_changed", "The package differs from the inspected digest.", 409)
        with self.store.lock, self.store.db:
            if self.store.db.execute("SELECT 1 FROM module_packages WHERE digest=?",
                                     (checked.digest,)).fetchone():
                self.verify(checked.digest)
                return self.get(checked.digest)
            count = self.store.db.execute("SELECT count(*) FROM module_packages").fetchone()[0]
            if count >= MAX_PACKAGES:
                raise Failure("capacity", "The installed module limit was reached.", 409)
            if self._storage_bytes() + checked.expanded_bytes > MAX_STORAGE:
                raise Failure("capacity", "The module storage limit was reached.", 409)
            publish(self.root, checked)
            manifest = checked.manifest
            self.store.db.execute("INSERT INTO module_packages VALUES (?,?,?,?,?,0,1)",
                                  (checked.digest, manifest["id"], manifest["version"],
                                   checked._manifest, time.time()))
            self._history(manifest["id"], None, checked.digest, "install")
            return self.get(checked.digest)

    def list(self) -> builtins.list[dict]:
        with self.store.lock:
            rows = self.store.db.execute(
                "SELECT digest FROM module_packages ORDER BY package_id, installed, digest").fetchall()
            return [self.get(row[0]) for row in rows]

    def get(self, digest: str) -> dict:
        valid_digest(digest)
        with self.store.lock:
            row = self._row(digest)
            grants: dict[str, list[str]] = {}
            for capability, target in self.store.db.execute(
                    "SELECT capability,target_id FROM module_grants WHERE digest=? "
                    "ORDER BY capability,target_id", (digest,)):
                grants.setdefault(capability, []).append(target)
            return {"digest": digest, "manifest": loads(bytes(row[0]), 65536),
                    "enabled": bool(row[1]), "revision": row[2], "installed_at": row[3],
                    "publisher_verified": False,
                    "grants": [{"capability": key, "target_ids": value}
                               for key, value in grants.items()]}

    def _row(self, digest: str):
        row = self.store.db.execute(
            "SELECT manifest,enabled,revision,installed FROM module_packages WHERE digest=?",
            (digest,)).fetchone()
        if row is None:
            raise Failure("module_missing", "The module package was not found.", 404)
        return row

    def verify(self, digest: str) -> Path:
        valid_digest(digest)
        with self.store.lock:
            raw = bytes(self._row(digest)[0])
            path = self.root / digest
            try:
                verify(path, loads(raw, 65536), raw)
            except OSError as exc:
                raise invalid("The installed module files cannot be verified.") from exc
            return path

    def set_enabled(self, digest: str, enabled: bool, grants: builtins.list | None = None,
                    *, sandbox_ready: bool = False) -> dict:
        """Enable only inspected capabilities; executable callers must supply a fresh probe result."""
        if type(enabled) is not bool:
            raise invalid("The module enabled value must be boolean.")
        with self.store.lock, self.store.db:
            current = self.get(digest)
            manifest = current["manifest"]
            if enabled:
                package = self.verify(digest)
                require_runtime(manifest, package)
                if set(required_capabilities(manifest)) - SUPPORTED:
                    raise Failure("module_capability_unavailable",
                                  "This package requires a capability that is not available.", 409)
                if manifest["runtime"]["kind"] != "declarative" and sandbox_ready is not True:
                    raise Failure("module_sandbox_unavailable",
                                  "Executable modules require a successful sandbox check.", 503)
                accepted = validate_grants(grants, manifest["capabilities"],
                                           optional=set(manifest.get("optional_capabilities", [])))
                if any(grant["capability"] not in SUPPORTED for grant in accepted):
                    raise Failure("module_capability_unavailable",
                                  "A selected module permission is not available.", 409)
            else:
                accepted = []
            previous = None
            if enabled:
                rows = self.store.db.execute(
                    "SELECT digest FROM module_packages WHERE package_id=? AND enabled=1 AND digest<>?",
                    (manifest["id"], digest)).fetchall()
                for old in rows:
                    previous = old[0]
                    self._disable(previous)
            self._disable(digest)
            if enabled:
                count = self.store.db.execute("SELECT count(*) FROM module_grants").fetchone()[0]
                if count + sum(len(grant["target_ids"]) for grant in accepted) > MAX_GRANTS:
                    raise Failure("capacity", "The module grant limit was reached.", 409)
                self.store.db.execute("UPDATE module_packages SET enabled=1 WHERE digest=?", (digest,))
                for grant in accepted:
                    self.store.db.executemany("INSERT INTO module_grants VALUES (?,?,?)",
                                             [(digest, grant["capability"], target)
                                              for target in grant["target_ids"]])
            self._history(manifest["id"], previous or digest, digest, "enable" if enabled else "disable")
            return self.get(digest)

    def _disable(self, digest: str) -> None:
        self.store.db.execute("DELETE FROM module_grants WHERE digest=?", (digest,))
        self.store.db.execute(
            "UPDATE module_packages SET enabled=0,revision=revision+1 WHERE digest=?", (digest,))

    def revoke(self, digest: str) -> dict:
        return self.set_enabled(digest, False)

    def require(self, digest: str, capability: str, target_ids: builtins.list[str]) -> None:
        targets(target_ids)
        with self.store.lock:
            current = self.get(digest)
            if not current["enabled"]:
                raise Failure("module_disabled", "The module is disabled.", 403)
            matches = [g for g in current["grants"] if g["capability"] == capability]
            if not matches or set(target_ids) - set(matches[0]["target_ids"]):
                raise Failure("denied", "The module grant does not permit the selected targets.", 403)

    def acquire(self, digest: str) -> dict:
        with self.store.lock, self._lease_lock:
            current = self.get(digest)
            if not current["enabled"]:
                raise Failure("module_disabled", "The module is disabled.", 403)
            self.verify(digest)
            self._leases[digest] = self._leases.get(digest, 0) + 1
            return current

    def release(self, digest: str) -> None:
        with self._lease_lock:
            count = self._leases.get(digest, 0)
            if count <= 1:
                self._leases.pop(digest, None)
            else:
                self._leases[digest] = count - 1

    def check(self, digest: str, revision: int) -> None:
        with self.store.lock:
            row = self._row(digest)
            if not row[1] or row[2] != revision:
                raise Failure("module_revoked", "The module grant changed during the operation.", 403)

    def uninstall(self, digest: str) -> None:
        """Revoke first; refuse removal while a runtime lease still owns the package."""
        self.revoke(digest)
        with self.store.lock, self._lease_lock, self.store.db:
            if self._leases.get(digest, 0):
                raise Failure("module_busy", "Stop active module operations before removal.", 409)
            manifest = self.get(digest)["manifest"]
            path = self.verify(digest)
            for directory, _, _ in os.walk(path):
                os.chmod(directory, 0o700)
            shutil.rmtree(path)
            self.store.db.execute("DELETE FROM module_packages WHERE digest=?", (digest,))
            self._history(manifest["id"], digest, None, "uninstall")

    def history(self, package_id: str) -> builtins.list[dict]:
        with self.store.lock:
            rows = self.store.db.execute(
                "SELECT previous_digest,new_digest,action,at FROM module_history "
                "WHERE package_id=? ORDER BY id DESC LIMIT 128", (package_id,)).fetchall()
            return [dict(zip(("previous_digest", "new_digest", "action", "at"), row)) for row in rows]

    def _history(self, package_id: str, previous: str | None, current: str | None, action: str):
        self.store.db.execute(
            "INSERT INTO module_history(package_id,previous_digest,new_digest,action,at) VALUES (?,?,?,?,?)",
            (package_id, previous, current, action, time.time()))
        self.store.db.execute("DELETE FROM module_history WHERE id NOT IN "
                              "(SELECT id FROM module_history ORDER BY id DESC LIMIT ?)", (MAX_HISTORY,))

    def _storage_bytes(self) -> int:
        total, count = 0, 0
        for directory, directories, files in os.walk(self.root, followlinks=False):
            if any((Path(directory) / name).is_symlink() for name in directories):
                raise invalid("The module storage contains a directory link.")
            for name in files:
                info = (Path(directory) / name).lstat()
                count += 1
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or count > 16640:
                    raise invalid("The module storage contains invalid files.")
                total += info.st_size
                if total > MAX_STORAGE:
                    raise Failure("capacity", "The module storage limit was reached.", 409)
        return total


def targets(value) -> list[str]:
    result = strings(value, 64, 128)
    if not result:
        raise invalid("Select at least one module target.")
    for item in result:
        reference(item)
    return result


def validate_grants(value, declared: list[str], optional: set[str] | None = None) -> list[dict]:
    if (optional or set()) - set(declared):
        raise invalid("An optional grant must be declared by the package.")
    if not isinstance(value, list) or len(value) > 32:
        raise invalid("Supply an explicit module grant list.")
    names = set()
    for grant in value:
        fields(grant, {"capability", "target_ids"})
        name = grant["capability"]
        if not isinstance(name, str) or name not in declared or name in names:
            raise invalid("The module grant is repeated or undeclared.")
        names.add(name)
        targets(grant["target_ids"])
    if set(declared) - (optional or set()) - names:
        raise invalid("Every requested capability requires an explicit target grant.")
    return value
