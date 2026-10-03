# SPDX-License-Identifier: Apache-2.0
"""PostgreSQL source sessions with verified TLS and server-side read cursors."""

import json

from pydantic import Field

from ficc.data_sdk import DataError, rows, schema
from ficc.schema import Model

API_VERSION = 1
METADATA = {"kind": "network", "source_consistency": "transaction", "write": True,
            "description": "PostgreSQL schemas, parameterized registered queries, cursor exports and explicit transactions."}


class Configuration(Model):
    database: str = Field(min_length=1, max_length=128)
    statement_timeout_ms: int = Field(default=300000, ge=1, le=3600000)


class Query(Model):
    statement: str = Field(min_length=1, max_length=32768)


def configuration(value):
    return Configuration.model_validate(value).model_dump()


def query(value, mode):
    return Query.model_validate(value).model_dump()


def execute(context, action, request):
    import psycopg
    from psycopg import IsolationLevel

    endpoint, config = context.endpoint, context.configuration
    with context.ca_file() as ca, psycopg.connect(host=endpoint["host"], hostaddr=endpoint["address"], port=endpoint["port"],
            dbname=config["database"], user=context.secret["username"], password=context.secret["password"],
            sslmode="verify-full", sslrootcert=ca, ssl_min_protocol_version="TLSv1.2", connect_timeout=10, passfile="/nonexistent",
            application_name="ficc-source", options="-c statement_timeout=" + str(config["statement_timeout_ms"])) as db:
        if not db.pgconn.ssl_in_use:
            raise DataError("tls_required", "The PostgreSQL session did not negotiate verified TLS.")
        db.isolation_level = IsolationLevel.REPEATABLE_READ
        db.read_only = action != "write"
        count = 0
        snapshot = db.execute("SELECT current_setting('server_version'),pg_current_snapshot()::text").fetchone()
        assert snapshot is not None
        if action == "catalogue":
            after = json.loads(request["cursor"]) if request.get("cursor") else ["", ""]
            values = db.execute("SELECT table_schema,table_name,table_type FROM information_schema.tables WHERE (table_schema,table_name)>(%s,%s) "
                                "AND table_schema NOT IN ('pg_catalog','information_schema') ORDER BY table_schema,table_name LIMIT 101", after).fetchall()
            yield {"kind": "catalogue", "resources": [{"id": json.dumps(list(row[:2])), "name": row[0] + "." + row[1], "kind": row[2]} for row in values[:100]],
                   "next_cursor": json.dumps(list(values[99][:2])) if len(values) > 100 else None}
        elif action == "describe":
            selected = json.loads(request["resource"])
            values = db.execute("SELECT column_name,data_type,is_nullable FROM information_schema.columns WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position", selected).fetchall()
            yield {"kind": "schema", "schema": {"fields": [{"name": name, "type": kind, "nullable": nullable == "YES"} for name, kind, nullable in values], "description": ""}}
        elif action == "write":
            yield {"kind": "committing"}
            try:
                cursor = db.execute(request["specification"]["statement"], request["parameters"], prepare=True)
                count = max(0, cursor.rowcount)
            except Exception:
                db.rollback()
                raise DataError("transaction_rolled_back", "The PostgreSQL transaction was rejected and rolled back.") from None
            try:
                db.commit()
            except Exception:
                db.close()
                yield {"kind": "receipt", "outcome": "unknown", "rows": count, "consistency": "transaction", "reason": "commit_acknowledgement_missing"}
                return
        else:
            with db.cursor(name="ficc_source_stream") as cursor:
                cursor.itersize = 128
                cursor.execute(request["specification"]["statement"], request["parameters"])
                columns = cursor.description or []
                yield {"kind": "schema", "schema": schema([item.name for item in columns], [str(item.type_code) for item in columns])}
                for event in rows(cursor if context.limit is None else __import__("itertools").islice(cursor, context.limit)):
                    count += len(event["rows"])
                    yield event
        yield {"kind": "receipt", "rows": count, "outcome": "committed" if action == "write" else "read",
               "consistency": "repeatable-read", "server_version": snapshot[0], "snapshot": snapshot[1], "tls_verified": True}
