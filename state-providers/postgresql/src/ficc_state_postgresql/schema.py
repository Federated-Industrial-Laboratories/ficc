# SPDX-License-Identifier: Apache-2.0
"""Define the PostgreSQL representation of the portable controller schema."""

from sqlalchemy import (
    BigInteger,
    Column,
    Double,
    ForeignKey,
    Identity,
    Index,
    LargeBinary,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.sql.schema import SchemaItem

from ficc.backup_database import (
    CONTRIBUTOR_TABLES,
    DATASET_TABLES,
    EXTERNAL_TABLES,
    IDENTITY_TABLES,
    POLICY_TABLES,
    RESOURCE_TABLES,
    SCHEMA,
    SOURCE_TABLES,
    TABLES,
    WORKLOAD_TABLES,
)
from ficc.identity_store import LOCAL_OWNER, LOCAL_PROJECT
from ficc.resource_store import OWNED_TABLES

ORDERED = frozenset({"operations", "file_roots", "file_operations", "transfers", "terminals",
                     "agent_profiles", "agents", "bus_runs", "bus_messages", "bus_deliveries",
                     "module_vm_operations", "module_proxmox_operations", "module_admin_operations",
                     "module_container_operations", "module_adapter_operations", "module_editor_operations"})
GENERATED = frozenset({"audit", "module_history"})


def metadata():
    if SCHEMA != 15:
        raise ValueError("This state driver does not support the controller schema.")
    result = MetaData()
    for name, (columns, _) in TABLES.items():
        if name == "sqlite_sequence":
            continue
        names = columns.split()
        keys = {names[0]}
        if name in {"project_memberships", "policy_bindings"}:
            keys = {"project_id", "subject_id"}
        elif name == "module_grants":
            keys = set(names)
        elif name == "dataset_lineage":
            keys = {"dataset_id", "parent_id"}
        elif name == "dataset_objects":
            keys = {"dataset_id", "kind", "path_key", "sha256"}
        elif name == "inspection_files":
            keys = {"run_id", "file_index"}
        fields: list[SchemaItem] = []
        for column in names:
            kind = (LargeBinary if column in {"manifest", "archive"} else Double if column in {"at", "installed", "expires"}
                    else BigInteger if column in {"enabled", "disabled", "revision", "bytes", "file_index"} or name in GENERATED and column == "id"
                    else Text)
            arguments: list[Identity | ForeignKey] = []
            if name in GENERATED and column == "id":
                arguments.append(Identity())
            if name in {"project_memberships", "policy_bindings"} and column in {"project_id", "subject_id"}:
                arguments.append(ForeignKey(("projects" if column == "project_id" else "identities") + ".id"))
            if name == "project_resources" and column == "project_id":
                arguments.append(ForeignKey("projects.id"))
            if name == "external_identities" and column == "subject_id":
                arguments.append(ForeignKey("identities.id"))
            if name in {"contributors", "contributor_invitations"} and column == "project_id":
                arguments.append(ForeignKey("projects.id"))
            if name in {"contributor_requests", "contributor_certificates"} and column == "node_id":
                arguments.append(ForeignKey("contributors.id"))
            nullable = (column in {"previous_digest", "new_digest"}
                        or name == "audit" and column in {"project_id", "subject_id"}
                        or name == "credentials" and column == "nodes"
                        or name in {"agent_profiles", "agents", "bus_runs", "bus_messages", "bus_deliveries"}
                        and column in {"actor", "key", "digest", "value"})
            fields.append(Column(column, kind, *arguments, primary_key=column in keys, nullable=nullable and column not in keys))
        if name in ORDERED:
            # Preserve insertion order independently of credentials, timestamps and record IDs.
            fields.append(Column("rowid", BigInteger, Identity(), nullable=False, unique=True))
        if "actor" in names and "key" in names:
            fields.append(UniqueConstraint("actor", "key"))
        if name in {"credentials", "contributor_invitations"}:
            fields.append(UniqueConstraint("digest"))
        if name in {"workload_jobs", "datasets", "source_connections", "source_queries", "source_runs", "source_uploads", "inspection_runs"}:
            fields.append(UniqueConstraint("subject_id", "project_id", "key"))
        if name == "external_identities":
            fields.append(UniqueConstraint("issuer", "external_subject"))
        Table(name, result, *fields)
    objects = result.tables["dataset_objects"]
    Index("dataset_objects_path", objects.c.project_id, objects.c.path_key)
    Index("dataset_objects_digest", objects.c.project_id, objects.c.sha256, objects.c.bytes)
    Table("ficc_state_metadata", result, Column("key", Text, primary_key=True), Column("value", Text, nullable=False))
    return result


def validate(connection, tables, *, legacy=False):
    from sqlalchemy import inspect
    inspector = inspect(connection)
    expected = set(tables) - {"sqlite_sequence"} | {"ficc_state_metadata"}
    if set(inspector.get_table_names()) != expected:
        raise ValueError("The configured database is not a complete controller state database.")
    for table, (columns, _) in tables.items():
        if table == "sqlite_sequence":
            continue
        actual = [item["name"] for item in inspector.get_columns(table)]
        required = columns.split() + (["rowid"] if table in ORDERED else [])
        matches = set(actual) == set(required) if table in OWNED_TABLES and not legacy else actual == required
        if not matches:
            raise ValueError("The controller table layout does not match this state driver.")


def initialize(connection, binding, *, create):
    from sqlalchemy import inspect, text
    names = set(inspect(connection).get_table_names())
    if not names:
        if not create:
            raise ValueError("The configured controller database is empty.")
        metadata().create_all(connection)
        connection.execute(text("INSERT INTO ficc_state_metadata VALUES ('schema',:schema),('binding',:binding)"),
                           {"schema": str(SCHEMA), "binding": binding})
        connection.execute(text("INSERT INTO identities VALUES (:id,'Local owner',0,0)"), {"id": LOCAL_OWNER})
        connection.execute(text("INSERT INTO projects VALUES (:id,'Local project',0,0)"), {"id": LOCAL_PROJECT})
    else:
        if "ficc_state_metadata" not in names:
            raise ValueError("The configured database is not a complete controller state database.")
        values = dict(connection.execute(text("SELECT key,value FROM ficc_state_metadata")).all())
        if (values.get("schema") not in {"7", "8", "9", "10", "11", "12", "13", "14", str(SCHEMA)} or values.get("binding") != binding
                or set(values) - {"schema", "binding", "import_sha256"}):
            raise ValueError("The database schema or local state binding does not match.")
        if values["schema"] == "7":
            validate(connection, IDENTITY_TABLES, legacy=True)
            for table in sorted(OWNED_TABLES):
                connection.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN subject_id TEXT NOT NULL DEFAULT '{LOCAL_OWNER}'")
                connection.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN project_id TEXT NOT NULL DEFAULT '{LOCAL_PROJECT}'")
            metadata().tables["project_resources"].create(connection)
        if values["schema"] in {"7", "8"}:
            validate(connection, RESOURCE_TABLES)
            model = metadata()
            for table in ("policy_publishers", "policy_packages", "policy_bindings"):
                model.tables[table].create(connection)
        if values["schema"] in {"7", "8", "9"}:
            validate(connection, POLICY_TABLES)
            metadata().tables["external_identities"].create(connection)
        if values["schema"] in {"7", "8", "9", "10"}:
            validate(connection, EXTERNAL_TABLES)
            model = metadata()
            for table in ("contributors", "contributor_invitations", "contributor_requests", "contributor_certificates"):
                model.tables[table].create(connection)
        if values["schema"] in {"7", "8", "9", "10", "11"}:
            validate(connection, CONTRIBUTOR_TABLES)
            model = metadata()
            for table in ("workload_jobs", "workload_attempts", "workload_nodes"):
                model.tables[table].create(connection)
        if values["schema"] in {"7", "8", "9", "10", "11", "12"}:
            validate(connection, WORKLOAD_TABLES)
            metadata().tables["datasets"].create(connection)
        if values["schema"] in {"7", "8", "9", "10", "11", "12", "13"}:
            validate(connection, DATASET_TABLES)
            model = metadata()
            for table in ("source_connections", "source_queries", "source_runs", "source_uploads"):
                model.tables[table].create(connection)
        if values["schema"] in {"7", "8", "9", "10", "11", "12", "13", "14"}:
            validate(connection, SOURCE_TABLES)
            model = metadata()
            for table in ("dataset_safety", "dataset_lineage", "dataset_objects", "inspection_runs", "inspection_files"):
                model.tables[table].create(connection)
            from ficc.inspection_store import backfill
            class Migration:
                def execute(self, query, values=()):
                    return connection.execute(text(query), {f"p{index}": value for index, value in enumerate(values)})
            backfill(Migration())
            connection.execute(text("UPDATE ficc_state_metadata SET value=:schema WHERE key='schema'"), {"schema": str(SCHEMA)})
        validate(connection, TABLES)
