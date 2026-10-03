# SPDX-License-Identifier: Apache-2.0
"""Produce exact supported pre-identity table layouts for upgrade fixtures."""

from ficc.backup_database import (
    ADAPTER_TABLES,
    EXTERNAL_TABLES,
    IDENTITY_TABLES,
    LEGACY_TABLES,
    MODULE_TABLES,
    POLICY_TABLES,
    RESOURCE_TABLES,
    TABLES,
)


def legacy_schema(db, revision):
    expected = {4: LEGACY_TABLES, 5: MODULE_TABLES, 6: ADAPTER_TABLES, 7: IDENTITY_TABLES, 8: RESOURCE_TABLES, 9: POLICY_TABLES, 10: EXTERNAL_TABLES}[revision]
    for table in sorted(set(TABLES) - set(expected), key=lambda name: name not in {"policy_bindings", "project_resources", "project_memberships"}):
        db.execute(f"DROP TABLE {table}")
    for table, (columns, _) in expected.items():
        for column in [row[1] for row in db.execute(f"PRAGMA table_info({table})")]:
            if column not in columns.split():
                db.execute(f"ALTER TABLE {table} DROP COLUMN {column}")
    db.execute(f"PRAGMA user_version={revision}")
