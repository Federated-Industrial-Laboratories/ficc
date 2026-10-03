# SPDX-License-Identifier: Apache-2.0
"""Validate quiescent snapshots and remove credential storage."""

import json
import re
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from ficc_node.job_spec import TERMINAL as JOB_TERMINAL

from .backup_io import MAX_DATABASE
from .state_provider import BoundConnection

SCHEMA = 15
SUPPORTED = {4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, SCHEMA}
LEGACY_TABLES = {
    "nodes": ("id value", 64),
    "credentials": ("id digest kind label scopes nodes expires csrf roots", 512),
    "audit": ("id at action target outcome actor", 10000),
    "settings": ("key value", 64),
    "operations": ("id actor key digest value", 2048),
    "file_roots": ("id value", 64),
    "file_operations": ("id actor key value", 2048),
    "transfers": ("id actor key value", 2048),
    "terminals": ("id actor key digest value", 512),
    "sqlite_sequence": ("name seq", 1),
    "agent_profiles": ("id actor key digest value", 128),
    "agents": ("id actor key digest value", 512),
    "bus_runs": ("id actor key digest value", 128),
    "bus_messages": ("id actor key digest value", 16384),
    "bus_deliveries": ("id actor key digest value", 32768),
}
MODULE_TABLES = {**LEGACY_TABLES,
    "module_container_profiles": ("id node_id value", 64),
    "module_container_operations": ("id actor key digest value", 1024),
    "module_admin_profiles": ("id node_id value", 64),
    "module_admin_operations": ("id actor key digest value", 1024),
    "module_vm_profiles": ("node_id value", 64),
    "module_vm_operations": ("id actor key digest value", 1024),
    "module_proxmox_profiles": ("node_id value", 64),
    "module_proxmox_operations": ("id actor key digest value", 1024),
    "module_editor_operations": ("id actor key value", 128),
    "module_packages": ("digest package_id version manifest installed enabled revision", 64),
    "module_grants": ("digest capability target_id", 16384),
    "module_history": ("id package_id previous_digest new_digest action at", 1024),
    "workspaces": ("id value", 64),
    "workspace_views": ("id workspace_id value", 256),
    "workspace_surfaces": ("id value", 64),
}
ADAPTER_TABLES = {**MODULE_TABLES,
    "module_windows_endpoints": ("id value", 64),
    "module_adapter_profiles": ("id endpoint_id digest value", 64),
    "module_adapter_operations": ("id actor key digest value", 1024),
}
IDENTITY_TABLES = {**ADAPTER_TABLES,
    "identities": ("id label disabled revision", 256),
    "projects": ("id label disabled revision", 256),
    "project_memberships": ("project_id subject_id scopes revision", 4096),
    "credentials": ("id digest kind label scopes nodes expires csrf roots subject_id project_id", 512),
    "audit": ("id at action target outcome actor subject_id project_id", 10000),
    "workspaces": ("id value project_id", 64),
    "workspace_views": ("id workspace_id value subject_id", 256),
    "workspace_surfaces": ("id value project_id subject_id", 64),
    "settings": ("key value", 320),
}
RESOURCE_TABLES = {**IDENTITY_TABLES,
    "project_resources": ("project_id nodes roots revision", 256),
    "operations": ("id actor key digest value subject_id project_id", 2048),
    "file_operations": ("id actor key value subject_id project_id", 2048),
    "transfers": ("id actor key value subject_id project_id", 2048),
    "terminals": ("id actor key digest value subject_id project_id", 512),
}
POLICY_TABLES = {**RESOURCE_TABLES,
    "policy_publishers": ("id public_key enabled revision", 64),
    "policy_packages": ("digest publisher description archive installed", 64),
    "policy_bindings": ("project_id subject_id roles revision", 4096),
}
EXTERNAL_TABLES = {**POLICY_TABLES,
    "external_identities": ("id issuer external_subject subject_id disabled revision", 1024),
}
CONTRIBUTOR_TABLES = {**EXTERNAL_TABLES,
    "contributors": ("id project_id value", 64),
    "contributor_invitations": ("id digest project_id value", 128),
    "contributor_requests": ("id node_id receipt_digest value", 512),
    "contributor_certificates": ("fingerprint node_id value", 256),
}
WORKLOAD_TABLES = {**CONTRIBUTOR_TABLES,
    "workload_jobs": ("id subject_id project_id key digest value", 2048),
    "workload_attempts": ("id job_id node_id value", 8192),
    "workload_nodes": ("node_id value", 64),
}
DATASET_TABLES = {**WORKLOAD_TABLES, "datasets": ("id subject_id project_id key digest value", 2**63 - 1)}
SOURCE_TABLES = {**DATASET_TABLES, **{name: ("id subject_id project_id key digest value", 2**63 - 1)
                            for name in ("source_connections", "source_queries", "source_runs", "source_uploads")}}
TABLES = {**SOURCE_TABLES,
    "dataset_safety": ("id value", 2**63 - 1),
    "dataset_lineage": ("dataset_id parent_id", 2**63 - 1),
    "dataset_objects": ("dataset_id project_id kind path_key sha256 bytes", 2**63 - 1),
    "inspection_runs": ("id subject_id project_id dataset_id key digest value", 2**63 - 1),
    "inspection_files": ("run_id file_index value", 2**63 - 1),
}


def version(db):
    return db.execute("PRAGMA user_version").fetchone()[0]


def tables(db):
    revision = version(db)
    if revision not in SUPPORTED:
        raise ValueError("The state schema is not supported.")
    return {4: LEGACY_TABLES, 5: MODULE_TABLES, 6: ADAPTER_TABLES, 7: IDENTITY_TABLES,
            8: RESOURCE_TABLES, 9: POLICY_TABLES, 10: EXTERNAL_TABLES, 11: CONTRIBUTOR_TABLES, 12: WORKLOAD_TABLES, 13: DATASET_TABLES,
            14: SOURCE_TABLES, SCHEMA: TABLES}[revision]


def connect(path: Path, readonly=False):
    suffix = "?mode=ro" if readonly else "?mode=rw"
    db = sqlite3.connect(path.absolute().as_uri() + suffix, uri=True, timeout=1, factory=BoundConnection)
    db.execute("PRAGMA trusted_schema=OFF")
    deadline = time.monotonic() + 60
    db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
    return db


def records(db, table):
    for row in db.execute(f"SELECT value FROM {table}"):
        if not isinstance(row[0], str) or len(row[0]) > 1024 * 1024:
            raise ValueError("A state record exceeds the backup limit.")
        try:
            value = json.loads(row[0])
        except RecursionError:
            raise ValueError("A state record exceeds the nesting limit.") from None
        if not isinstance(value, dict):
            raise ValueError("A state record is invalid.")
        yield value


def schema(db):
    expected = tables(db)
    objects = db.execute("SELECT type,name,sql FROM sqlite_schema").fetchall()
    names = set()
    for kind, name, sql in objects:
        if kind == "index" and sql is None and name.startswith("sqlite_autoindex_"):
            continue
        indexes = {"dataset_objects_path": "project_id,path_key", "dataset_objects_digest": "project_id,sha256,bytes"} if version(db) >= 15 else {}
        if kind == "index" and name in indexes:
            normalized = re.sub(r"\s+", "", sql or "").lower()
            if normalized != f"createindex{name}ondataset_objects({indexes[name]})":
                raise ValueError("The dataset safety index definition is not supported.")
            continue
        if kind != "table" or name not in expected or "CREATE VIRTUAL" in (sql or "").upper():
            raise ValueError("The database contains an unsupported schema object.")
        names.add(name)
        columns = [row[1] for row in db.execute(f"PRAGMA table_info({name})")]
        if columns != expected[name][0].split():
            raise ValueError("The database table layout is not supported.")
        if db.execute(f"SELECT count(*) FROM {name}").fetchone()[0] > expected[name][1]:
            raise ValueError("The retained state exceeds its supported capacity.")
    if names != set(expected):
        raise ValueError("The database schema is incomplete.")
    if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ValueError("The database integrity check failed.")


def quiescent(db):
    schema(db)
    if version(db) >= 5:
        from .backup_modules import records as module_records
        module_records(db)
        from .module_editor_store import validate_records as editor_records
        editor_records(db, quiescent=True)
        from .module_vm_store import validate_records as vm_records
        vm_records(db.execute("SELECT node_id,value FROM module_vm_profiles").fetchall(),
                   db.execute("SELECT id,actor,key,digest,value FROM module_vm_operations").fetchall(),
                   {row[0] for row in db.execute("SELECT id FROM nodes")})
        from .module_proxmox_store import validate_records as proxmox_records
        proxmox_records(db.execute("SELECT node_id,value FROM module_proxmox_profiles").fetchall(),
                        db.execute("SELECT id,actor,key,digest,value FROM module_proxmox_operations").fetchall(),
                        {row[0] for row in db.execute("SELECT id FROM nodes")})
        from .module_containers_store import validate_records as container_records
        container_records(db.execute("SELECT id,node_id,value FROM module_container_profiles").fetchall(),
                          db.execute("SELECT id,actor,key,digest,value FROM module_container_operations").fetchall(),
                          {row[0] for row in db.execute("SELECT id FROM nodes")})
        from .module_admin_store import validate_records as admin_records
        admin_records(db.execute("SELECT id,node_id,value FROM module_admin_profiles").fetchall(),
                      db.execute("SELECT id,actor,key,digest,value FROM module_admin_operations").fetchall(),
                      {row[0] for row in db.execute("SELECT id FROM nodes")})
    if version(db) >= 6:
        from .backup_adapters import validate_records
        validate_records(db)
    if version(db) >= 7:
        from .backup_identities import records as identity_records
        identity_records(db)
        from .workspace_templates import validate_records as template_records
        template_records(db)
        from .workloads.templates import validate_records as workload_template_records
        workload_template_records(db)
    if version(db) >= 8:
        from .backup_resources import records as resource_records
        resource_records(db)
    if version(db) >= 9:
        from .backup_policies import records as policy_records
        policy_records(db)
    if version(db) >= 10:
        from .external_identity_store import validate_records
        validate_records(db)
    if version(db) >= 11:
        from .backup_contributors import validate_records
        validate_records(db)
    if version(db) >= 12:
        from .workloads.records import validate_records as workload_records
        workload_records(db)
    if version(db) >= 13:
        from .dataset_store import validate_records as dataset_records
        dataset_records(db)
    if version(db) >= 14:
        from .source_store import validate_records as source_records
        source_records(db)
    if version(db) >= 15:
        from .inspection_store import validate_records as inspection_records
        inspection_records(db)
    for node in records(db, "nodes"):
        if not isinstance(node.get("id"), str):
            raise ValueError("A machine record identity is invalid.")
    for operation in records(db, "operations"):
        targets = operation.get("targets")
        if (not isinstance(targets, list) or not 1 <= len(targets) <= 64
                or any(not isinstance(target, dict) or target.get("state") not in JOB_TERMINAL for target in targets)):
            raise ValueError("Resolve all active or unknown jobs before backup or restore.")
    for terminal in records(db, "terminals"):
        if terminal.get("state") not in {"exited", "interrupted", "stopped"}:
            raise ValueError("Stop or reconcile all terminal sessions before backup or restore.")
    for operation in records(db, "file_operations"):
        items = operation.get("items")
        if (operation.get("state") not in {"succeeded", "failed"} or not isinstance(items, list)
                or not 1 <= len(items) <= 64 or any(not isinstance(item, dict)
                or item.get("state") not in {"succeeded", "failed"} for item in items)):
            raise ValueError("Resolve all active or unknown file operations before backup or restore.")
    for operation in records(db, "transfers"):
        items = operation.get("items")
        if (operation.get("kind") not in {"upload", "download", "copy"} or not isinstance(items, list)
                or not 1 <= len(items) <= 64 or any(not isinstance(item, dict)
                or item.get("state") not in {"succeeded", "cancelled"} or item.get("cleanup_pending")
                or (operation["kind"] == "download" and item["state"] == "succeeded") for item in items)):
            raise ValueError("Finish or discard transfers, prepared downloads, and retained partials before backup or restore.")
    for agent in records(db, "agents"):
        if agent.get("state") not in {"exited", "stopped"}:
            raise ValueError("Stop or reconcile all coding agents before backup or restore.")
    for delivery in records(db, "bus_deliveries"):
        if delivery.get("state") not in {"session-included", "tool-read", "failed", "cancelled"}:
            raise ValueError("Resolve all bus delivery outcomes before backup or restore.")
    settings = dict(db.execute("SELECT key,value FROM settings"))
    controller = json.loads(settings.get("controller_id", "null"))
    if not isinstance(controller, str) or not re.fullmatch(r"[a-f0-9]{32}", controller):
        raise ValueError("The controller identity is missing or invalid.")
    return controller


def snapshot(source: Path, destination: Path):
    deadline = time.monotonic() + 60
    page_size = 65536
    def progress(status, remaining, total):
        if total * page_size > MAX_DATABASE or time.monotonic() > deadline:
            raise ValueError("The database backup exceeds its size or time limit.")
    with closing(connect(source, readonly=True)) as original, closing(connect(destination)) as copied:
        page_size = original.execute("PRAGMA page_size").fetchone()[0]
        original.backup(copied, pages=256, progress=progress, sleep=0.01)


def sanitize(path: Path, restored=False):
    with closing(connect(path)) as db:
        controller = quiescent(db)
        # DELETE alone leaves old credential bytes in free pages and WAL frames.
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA secure_delete=ON")
        with db:
            db.execute("DELETE FROM credentials")
            if version(db) >= 11:
                from .backup_contributors import suspend
                suspend(db)
            if version(db) >= 12:
                from .workloads.records import suspend as suspend_workloads
                suspend_workloads(db)
            if version(db) >= 14:
                for value in records(db, "source_connections"):
                    value.update(enabled=False, revision=value["revision"] + 1)
                    db.execute("UPDATE source_connections SET value=:p0 WHERE id=:p1", (json.dumps(value), value["id"]))
            if version(db) >= 15:
                # Preserve restrictions; expire exemptions and require review of scanner activation.
                db.execute("DELETE FROM settings WHERE key='inspection_approval'")
                for value in records(db, "dataset_safety"):
                    value.update(exemption=None, revision=value["revision"] + 1)
                    db.execute("UPDATE dataset_safety SET value=:p0 WHERE id=:p1", (json.dumps(value), value["id"]))
            if restored:
                if version(db) >= 10:
                    db.execute("UPDATE external_identities SET disabled=1,revision=revision+1")
                if version(db) >= 9:
                    from .backup_policies import deactivate
                    deactivate(db)
                if version(db) >= 7:
                    from .identity_store import LOCAL_OWNER
                    db.execute("UPDATE identities SET disabled=1,revision=revision+1 WHERE id!=:p0", (LOCAL_OWNER,))
                if version(db) >= 5:
                    db.execute("DELETE FROM module_grants")
                    db.execute("UPDATE module_packages SET enabled=0,revision=revision+1")
                    for table in ("module_vm_profiles", "module_proxmox_profiles"):
                        for value in records(db, table):
                            value.update(enabled=False, revision=value["revision"] + 1)
                            db.execute(f"UPDATE {table} SET value=:p0 WHERE node_id=:p1",
                                       (json.dumps(value), value["node_id"]))
                    for table in ("module_container_profiles", "module_admin_profiles"):
                        for value in records(db, table):
                            value.update(enabled=False, revision=value["revision"] + 1)
                            db.execute(f"UPDATE {table} SET value=:p0 WHERE id=:p1",
                                       (json.dumps(value), value["id"]))
                if version(db) >= 6:
                    from .module_windows_store import disable_restored
                    disable_restored(db)
                    for value in records(db, "module_adapter_profiles"):
                        value.update(enabled=False, revision=value["revision"] + 1)
                        db.execute("UPDATE module_adapter_profiles SET value=:p0 WHERE id=:p1",
                                   (json.dumps(value), value["id"]))
                for value in records(db, "nodes"):
                    value.update(resources=None, last_seen=None, capabilities={}, state="unconfigured",
                                 error={"code": "restored_state", "message": "Refresh this machine after restore."})
                    value.pop("observed_at", None)
                    value.pop("boot_id", None)
                    db.execute("UPDATE nodes SET value=:p0 WHERE id=:p1", (json.dumps(value), value["id"]))
        db.execute("VACUUM")
        schema(db)
        if db.execute("PRAGMA freelist_count").fetchone()[0] != 0 or db.execute("SELECT count(*) FROM credentials").fetchone()[0]:
            raise ValueError("The exported credential storage could not be cleared.")
    return controller
