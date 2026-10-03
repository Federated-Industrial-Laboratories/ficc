# SPDX-License-Identifier: Apache-2.0
"""MariaDB/MySQL protocol driver with independently qualified server receipts."""

import itertools
import socket
import ssl

from pydantic import Field

from ficc.data_sdk import DataError, rows, schema
from ficc.schema import Model

API_VERSION = 1
METADATA = {"kind": "network", "source_consistency": "transaction", "write": True,
            "description": "MariaDB/MySQL catalogue, unbuffered reads and explicit writes over verified TLS."}


class Configuration(Model):
    database: str = Field(min_length=1, max_length=128)
    socket_timeout_seconds: int = Field(default=60, ge=1, le=3600)


class Query(Model):
    statement: str = Field(min_length=1, max_length=32768)


def configuration(value):
    return Configuration.model_validate(value).model_dump()


def query(value, mode):
    return Query.model_validate(value).model_dump()


def execute(context, action, request):
    import pymysql  # type: ignore[import-untyped]

    endpoint, config = context.endpoint, context.configuration
    tls = ssl.create_default_context(cadata=endpoint["ca_pem"])
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    db = pymysql.connect(host=endpoint["host"], port=endpoint["port"], user=context.secret["username"], password=context.secret["password"],
        database=config["database"], charset="utf8mb4", ssl=tls,
        local_infile=False, autocommit=False, defer_connect=True, connect_timeout=10,
        read_timeout=config["socket_timeout_seconds"], write_timeout=config["socket_timeout_seconds"])
    try:
        db.connect(sock=socket.create_connection((endpoint["address"], endpoint["port"]), timeout=10))
        if not isinstance(db._sock, ssl.SSLSocket) or db._sock.version() is None:
            raise DataError("tls_required", "The MariaDB/MySQL session did not negotiate verified TLS.")
        with db.cursor() as cursor:
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()[0]
            db.rollback()
            cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cursor.execute("START TRANSACTION" if action == "write" else "START TRANSACTION READ ONLY, WITH CONSISTENT SNAPSHOT")
            count = 0
            if action == "catalogue":
                cursor.execute("SELECT TABLE_NAME,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_NAME>%s ORDER BY TABLE_NAME LIMIT 101",
                               (config["database"], request.get("cursor") or ""))
                values = cursor.fetchall()
                yield {"kind": "catalogue", "resources": [{"id": row[0], "name": row[0], "kind": row[1]} for row in values[:100]],
                       "next_cursor": values[99][0] if len(values) > 100 else None}
            elif action == "describe":
                cursor.execute("SELECT COLUMN_NAME,DATA_TYPE,IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s ORDER BY ORDINAL_POSITION", (config["database"], request["resource"]))
                yield {"kind": "schema", "schema": {"fields": [{"name": name, "type": kind, "nullable": nullable == "YES"} for name, kind, nullable in cursor.fetchall()], "description": ""}}
            elif action == "write":
                yield {"kind": "committing"}
                try:
                    cursor.execute(request["specification"]["statement"], request["parameters"])
                    count = max(0, cursor.rowcount)
                except Exception:
                    db.rollback()
                    raise DataError("transaction_rolled_back", "The MariaDB/MySQL transaction was rejected and rolled back.") from None
                try:
                    db.commit()
                except Exception:
                    yield {"kind": "receipt", "outcome": "unknown", "rows": count, "consistency": "transaction", "reason": "commit_acknowledgement_missing"}
                    return
            else:
                with db.cursor(pymysql.cursors.SSCursor) as stream:
                    stream.execute(request["specification"]["statement"], request["parameters"])
                    yield {"kind": "schema", "schema": schema([item[0] for item in stream.description], [str(item[1]) for item in stream.description])}
                    for event in rows(stream if context.limit is None else itertools.islice(stream, context.limit)):
                        count += len(event["rows"])
                        yield event
                    if context.limit is not None:
                        # SSCursor.close() otherwise drains the entire query after a bounded preview.
                        # This dedicated read-only connection has no transaction to preserve.
                        stream._result.unbuffered_active = False
                        stream._result.connection = None
                        stream.connection = None
                        db.close()
        yield {"kind": "receipt", "rows": count, "outcome": "committed" if action == "write" else "read", "consistency": "repeatable-read",
               "server_version": str(version), "server_family": "mariadb" if "mariadb" in str(version).lower() else "mysql", "tls_verified": True}
    finally:
        if db.open:
            db.close()
