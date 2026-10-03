# SPDX-License-Identifier: Apache-2.0
"""Consistent read-only SQLite transactions over an approved local namespace."""

import itertools
import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path

from ficc_node.file_access import parts
from pydantic import Field

from ficc.data_sdk import MAX_CELL, DataError, rows, schema
from ficc.dataset_schema import DataSchema
from ficc.schema import Model

API_VERSION = 1
METADATA = {"kind": "local", "source_consistency": "transaction", "write": False,
            "description": "Read-only SQLite transactions in a registered controller root."}


class Configuration(Model):
    timeout_seconds: int = Field(default=10, ge=1, le=60)


class Query(Model):
    statement: str = Field(min_length=1, max_length=32768)
    data_schema: DataSchema | None = Field(default=None, alias="schema")


def configuration(value):
    return Configuration.model_validate(value).model_dump()


def query(value, mode):
    if mode != "read":
        raise DataError("read_only", "SQLite source connections are read-only.")
    return Query.model_validate(value).model_dump(by_alias=True)


def execute(context, action, request):
    source = context.source
    with context.open_source() as handle:
        path = Path(os.fsdecode(os.fsencode(source["root"]["path"]) + b"/" + b"/".join(parts(source["reference"]))))
        db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=context.configuration["timeout_seconds"])
        try:
            # SQLite opens by filename so its WAL/journal participates in the same snapshot.
            current = os.stat(path, follow_symlinks=False)
            pinned = os.fstat(handle.fileno())
            if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
                raise DataError("source_changed", "The SQLite source was replaced during opening.")
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA query_only=ON")
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_CELL)
            db.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 256)
            db.execute("BEGIN")
            count = 0
            if action == "catalogue":
                cursor = request.get("cursor") or ""
                values = db.execute("SELECT name,type FROM sqlite_schema WHERE type IN ('table','view') AND name>? ORDER BY name LIMIT 101", (cursor,)).fetchall()
                yield {"kind": "catalogue", "resources": [{"id": row[0], "name": row[0], "kind": row[1]} for row in values[:100]],
                       "next_cursor": values[99][0] if len(values) > 100 else None}
            elif action == "describe":
                values = db.execute("SELECT name,type,\"notnull\" FROM pragma_table_info(?)", (request["resource"],)).fetchall()
                if not values:
                    raise DataError("not_found", "The SQLite table or view was not found.")
                yield {"kind": "schema", "schema": {"fields": [{"name": name, "type": kind or "string", "nullable": not bool(required)} for name, kind, required in values], "description": "SQLite declared column types."}}
            else:
                # This is SQLite's execution authorizer, not a SQL-text keyword filter.
                allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}
                db.set_authorizer(lambda code, first, second, database, trigger: sqlite3.SQLITE_OK if code in allowed and
                                  not (code == sqlite3.SQLITE_FUNCTION and str(second).lower() == "load_extension") else sqlite3.SQLITE_DENY)
                cursor = db.execute(request["specification"]["statement"], request["parameters"])
                if cursor.description is None:
                    raise DataError("read_only", "Register a query that returns rows.")
                first = cursor.fetchone()
                names = [column[0] for column in cursor.description]
                types = ["integer" if type(value) is int else "number" if type(value) is float else "binary" if isinstance(value, bytes) else "string" for value in first or [None] * len(names)]
                shape = request["specification"].get("schema") or schema(names, types)
                if [field["name"] for field in shape["fields"]] != names:
                    raise DataError("schema_changed", "The query columns differ from its registered schema.")
                yield {"kind": "schema", "schema": shape}
                iterator: Iterator = itertools.chain([first] if first is not None else [], cursor)
                if context.limit is not None:
                    iterator = itertools.islice(iterator, context.limit)
                for event in rows(iterator):
                    count += len(event["rows"])
                    yield event
            yield {"kind": "receipt", "consistency": "sqlite-read-transaction", "rows": count,
                   "source_identity": {"dev": pinned.st_dev, "ino": pinned.st_ino}, "sqlite_version": sqlite3.sqlite_version}
        finally:
            db.close()
