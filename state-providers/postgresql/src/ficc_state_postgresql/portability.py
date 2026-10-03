# SPDX-License-Identifier: Apache-2.0
"""Copy verified controller records without exporting database credentials."""

import hashlib
from contextlib import closing

from sqlalchemy import text

from ficc import backup_database
from ficc.identity_store import LOCAL_OWNER, LOCAL_PROJECT
from ficc.store import Store

from .schema import GENERATED, ORDERED


def checksum(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(262144):
            result.update(block)
    return result.hexdigest()


def snapshot(driver, destination):
    copied = Store(destination)
    try:
        copied.db.execute("PRAGMA foreign_keys=OFF")
        driver.begin()
        try:
            driver._ready().exec_driver_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            with copied.db:
                for table in reversed(backup_database.TABLES):
                    copied.db.execute(f"DELETE FROM {table}")
                for table, (fields, maximum) in backup_database.TABLES.items():
                    if table == "sqlite_sequence":
                        continue
                    names = fields.split()
                    if table in ORDERED:
                        names = ["rowid", *names]
                    columns = ",".join(names)
                    markers = ",".join(f":p{i}" for i in range(len(names)))
                    order = ("rowid" if table in ORDERED else "project_id,subject_id" if table == "project_memberships"
                             else "digest,capability,target_id" if table == "module_grants" else names[0])
                    result = driver._ready().execute(text(f"SELECT {columns} FROM {table} ORDER BY {order}").execution_options(yield_per=128))
                    count = 0
                    for batch in result.partitions(128):
                        count += len(batch)
                        if count > maximum:
                            raise ValueError("The state table exceeds its supported capacity.")
                        copied.db.executemany(f"INSERT INTO {table} ({columns}) VALUES ({markers})", [tuple(row) for row in batch])
                    result.close()
            driver.commit()
        except BaseException:
            driver.rollback()
            raise
    finally:
        copied.close()
    with closing(backup_database.connect(destination, readonly=True)) as database:
        backup_database.quiescent(database)


def import_snapshot(driver, source):
    identity = checksum(source)
    existing = driver.execute("SELECT value FROM ficc_state_metadata WHERE key='import_sha256'").fetchone()
    if existing:
        if existing[0] != identity:
            raise ValueError("The database already contains a different imported snapshot.")
        return identity
    with closing(backup_database.connect(source, readonly=True)) as original:
        if backup_database.version(original) != backup_database.SCHEMA:
            raise ValueError("Upgrade the portable state schema before importing it.")
        backup_database.quiescent(original)
        with driver:
            for table in backup_database.TABLES:
                if table == "sqlite_sequence":
                    continue
                expected = 1 if table in {"identities", "projects"} else 0
                if driver.execute(f"SELECT count(*) FROM {table}").fetchone()[0] != expected:
                    raise ValueError("Import requires an empty controller database.")
            if (driver.execute("SELECT id FROM identities").fetchone()[0] != LOCAL_OWNER
                    or driver.execute("SELECT id FROM projects").fetchone()[0] != LOCAL_PROJECT):
                raise ValueError("The empty controller database has invalid recovery identities.")
            for table in reversed(backup_database.TABLES):
                if table != "sqlite_sequence":
                    driver.execute(f"DELETE FROM {table}")
            # Membership foreign keys require their identities and projects first.
            tables = ["identities", "projects", *[name for name in backup_database.TABLES
                       if name not in {"identities", "projects", "sqlite_sequence"}]]
            for table in tables:
                names = backup_database.TABLES[table][0].split()
                if table in ORDERED:
                    names = [*names, "rowid"]
                columns = ",".join(names)
                markers = ",".join(f":p{i}" for i in range(len(names)))
                cursor = original.execute(f"SELECT {columns} FROM {table}")
                while batch := cursor.fetchmany(128):
                    driver.executemany(f"INSERT INTO {table} ({columns}) VALUES ({markers})", batch)
                if table in ORDERED or table in GENERATED:
                    column = "rowid" if table in ORDERED else "id"
                    driver._ready().execute(text(
                        f"SELECT setval(pg_get_serial_sequence(:table,:column), "
                        f"COALESCE((SELECT max({column}) FROM {table}),1), EXISTS(SELECT 1 FROM {table}))"),
                        {"table": table, "column": column})
            driver.execute("INSERT INTO ficc_state_metadata VALUES ('import_sha256',:p0)", (identity,))
    return identity
