# SPDX-License-Identifier: Apache-2.0
"""Exercise real registered sources, verified publication and no-replay outcomes."""

import asyncio
import csv
import io
import json
import sqlite3
from contextlib import closing

import pytest
from test_files import files_fixture as files_fixture
from test_files import listing

from ficc.backup_database import connect, sanitize, snapshot
from ficc.datasets import Datasets
from ficc.errors import Failure
from ficc.inspection_store import backfill, validate_records
from ficc.sources import Sources


async def source(service, actor, root, name, provider, configuration=None):
    entry = next(item for item in (await listing(service, actor, root))["entries"] if item["name"] == name)
    service.datasets = Datasets(service)
    if not hasattr(service, "sources"):
        service.sources = Sources(service)
    return await service.sources.create({"name": name, "provider": provider, "configuration": configuration or {},
        "source": {"root_id": root["id"], "entry_id": entry["entry_id"]}, "permissions": ["read", "export"]},
        "source-create-" + provider, actor)


async def exported(service, actor, root, query, parameters, name):
    result = await service.sources.submit(query["id"], {"parameters": parameters, "destination": {
        "root_id": root["id"], "entry_id": service.files.refs.issue(root, root["reference"])},
        "filename": name + ".csv", "dataset_name": name}, "source-export-" + name, actor)
    await asyncio.gather(*list(service.sources.tasks.values()))
    return service.sources.status(result["id"], actor)


async def test_sqlite_worker_catalogue_bound_query_verified_dataset(files_fixture):
    service, actor, root, path = files_fixture
    with sqlite3.connect(path / "source.sqlite") as db:
        db.execute("CREATE TABLE readings (id INTEGER, label TEXT)")
        db.executemany("INSERT INTO readings VALUES (?,?)", [(1, "first"), (2, "second"), (3, "last")])
    connection = await source(service, actor, root, "source.sqlite", "sqlite")
    catalogue = await service.sources.inspect(connection["id"], actor, "catalogue", {})
    assert catalogue["resources"][0]["id"] == "readings"
    shape = await service.sources.inspect(connection["id"], actor, "describe", {"resource": "readings"})
    assert [field["name"] for field in shape["schema"]["fields"]] == ["id", "label"]
    query = service.sources.register(connection["id"], {"name": "Selected readings", "specification": {
        "statement": "SELECT id,label FROM readings WHERE id >= :minimum ORDER BY id"},
        "parameters": [{"name": "minimum", "type": "integer"}]}, "source-query-readings", actor)
    preview = await service.sources.preview(query["id"], {"minimum": 2}, actor)
    assert preview["rows"] == [[2, "second"], [3, "last"]]
    result = await exported(service, actor, root, query, {"minimum": 2}, "readings-result")
    assert result["state"] == "completed", result
    assert list(csv.reader(io.StringIO((path / "readings-result.csv").read_text()))) == [["id", "label"], ["2", "second"], ["3", "last"]]
    manifest = service.datasets.get(result["dataset_id"], actor)
    assert manifest["manifest_digest"] == result["manifest_digest"]
    assert manifest["origin"]["query_id"] == query["id"] and manifest["origin"]["provider"]["name"] == "sqlite"
    assert (await service.datasets.inputs(result["dataset_id"], actor))["files"][0]["size"] == (path / "readings-result.csv").stat().st_size
    assert not list(path.glob(".ficc-source-*"))
    binding = service.store.db.execute("SELECT sha256,bytes FROM dataset_objects WHERE dataset_id=:p0 AND kind='input'", (manifest["id"],)).fetchone()
    assert binding == ("", (path / "source.sqlite").stat().st_size), "A path-bound connection must not invent a full content digest."
    entry = next(item for item in (await listing(service, actor, root))["entries"] if item["name"] == "source.sqlite")
    original = await service.datasets.create({"name": "Original database", "format": "sqlite", "schema": {"fields": []},
        "sources": [{"root_id": root["id"], "entry_id": entry["entry_id"]}]}, "source-original-dataset", actor)
    safety = service.datasets.safety
    safety.update(original["id"], {"revision": 1, "sensitive": True, "inspection_required": False,
        "quarantined": True, "reason": "Known local source is restricted."}, actor)
    with pytest.raises(Failure, match="blocked"):
        await service.datasets.inputs(manifest["id"], actor)
    # Schema migration reconstructs path-only source lineage from retained query origin.
    with service.store.lock, service.store.db:
        service.store.db.execute("DELETE FROM dataset_objects")
        service.store.db.execute("DELETE FROM dataset_lineage")
        backfill(service.store.db)
        validate_records(service.store.db)
    assert safety.effective(manifest)["sensitive"] and safety.effective(manifest)["blocked"]
    service.store.set_setting("controller_id", "1" * 32)
    restored = path.parent / "inspection-restored.sqlite3"
    restored.touch(mode=0o600, exist_ok=False)
    snapshot(service.settings.state_dir / "state.sqlite3", restored)
    sanitize(restored, restored=True)
    with closing(connect(restored)) as db:
        validate_records(db)
        policy = json.loads(db.execute("SELECT value FROM dataset_safety WHERE id=?", (original["id"],)).fetchone()[0])
        assert policy["sensitive"] and policy["quarantined"] and policy["exemption"] is None
        assert db.execute("SELECT sha256 FROM dataset_objects WHERE dataset_id=? AND kind='input'", (manifest["id"],)).fetchone() == ("",)


async def test_csv_schema_malformed_policy_and_literal_parameters(files_fixture):
    service, actor, root, path = files_fixture
    (path / "source.csv").write_text("id,label\n1,first\nbad,rejected\n3,'; DROP TABLE x; --\n")
    config = {"schema": {"fields": [{"name": "id", "type": "integer"}, {"name": "label", "type": "string"}]}, "malformed": "skip"}
    connection = await source(service, actor, root, "source.csv", "csv", config)
    query = service.sources.register(connection["id"], {"name": "Literal values", "specification": {"columns": ["label"],
        "filters": [{"column": "id", "operator": "ge", "parameter": "minimum"}]},
        "parameters": [{"name": "minimum", "type": "integer"}]}, "source-query-csv", actor)
    result = await exported(service, actor, root, query, {"minimum": 2}, "csv-result")
    assert result["state"] == "completed", result
    assert result["receipt"]["malformed_rows_skipped"] == 1
    assert list(csv.reader(io.StringIO((path / "csv-result.csv").read_text())))[1] == ["'; DROP TABLE x; --"]
    (path / "source.csv").write_text("id,label\n9,changed\n")
    with pytest.raises(Failure, match="changed"):
        await service.sources.preview(query["id"], {"minimum": 2}, actor)


def test_csv_encoder_coalesces_small_row_batches_without_changing_bytes():
    from ficc_data_csv import Encoder

    from ficc.data_sdk import rows

    encoder = Encoder()
    shape = {"fields": [{"name": name} for name in ("label", "flag", "empty")]}
    encoder.start(shape)
    chunks = []
    for event in rows([['café,"x\n', True, None]] * 20000):
        chunks.extend(encoder.write(event["rows"]))
    assert chunks and all(len(chunk) == 131072 for chunk in chunks)
    chunks.extend(encoder.finish())
    expected = b"label,flag,empty\n" + '"café,""x\n",true,\n'.encode() * 20000
    assert b"".join(chunks) == expected
    assert len(chunks) == (len(expected) + 131071) // 131072
    assert encoder.finish() == []
    empty = Encoder()
    empty.start(shape)
    assert empty.finish() == [b"label,flag,empty\n"]


async def test_source_export_authority_quota_cleanup_and_no_replay(files_fixture):
    service, actor, root, path = files_fixture
    (path / "source.csv").write_text("id\n1\n")
    connection = await source(service, actor, root, "source.csv", "csv", {"schema": {"fields": [{"name": "id", "type": "integer"}]}})
    query = service.sources.register(connection["id"], {"name": "Rows", "specification": {}}, "source-query-authority", actor)
    _, reader = service.auth.issue("token", scopes=["data:read", "files:read"])
    with pytest.raises(Failure, match="permit"):
        await service.sources.submit(query["id"], {}, "source-denied-export", reader.id)
    service.store.set_setting("source_limits", {"export_bytes": 2, "free_bytes": 0})
    result = await exported(service, actor, root, query, {}, "quota-result")
    assert result["state"] == "failed" and result["error"]["code"] == "export_quota"
    assert not (path / "quota-result.csv").exists() and not list(path.glob(".ficc-source-*"))
    stored = service.sources.store.get("source_runs", result["id"])
    stored.update(state="committing", action="write")
    service.sources.store.save("source_runs", stored)
    restored = Sources(service)
    assert restored.status(result["id"], actor)["state"] == "unknown" and not restored.tasks
    with service.store.lock:
        raw = service.store.db.execute("SELECT value FROM source_runs WHERE id=:p0", (result["id"],)).fetchone()[0]
    assert "parameters" not in json.loads(raw)


async def test_arrow_columnar_roundtrip_and_read_only_sql_authorizer(files_fixture):
    import pyarrow as pa
    import pyarrow.parquet as pq

    service, actor, root, path = files_fixture
    pq.write_table(pa.table({"count": pa.array([1, 2, 3], type=pa.int64()), "label": ["a", "b", "c"]}), path / "source.parquet")
    connection = await source(service, actor, root, "source.parquet", "arrow", {"format": "parquet"})
    query = service.sources.register(connection["id"], {"name": "Typed projection", "specification": {"columns": ["count"],
        "filters": [{"column": "count", "operator": "ge", "parameter": "minimum"}]},
        "parameters": [{"name": "minimum", "type": "integer"}]}, "source-query-arrow", actor)
    result = await service.sources.submit(query["id"], {"parameters": {"minimum": "2"}, "destination": {
        "root_id": root["id"], "entry_id": service.files.refs.issue(root, root["reference"])},
        "filename": "result.arrow", "dataset_name": "Typed result", "format": "arrow"}, "source-export-arrow", actor)
    await asyncio.gather(*list(service.sources.tasks.values()))
    result = service.sources.status(result["id"], actor)
    assert result["state"] == "completed", result
    with pa.ipc.open_stream(path / "result.arrow") as reader:
        assert reader.schema.field("count").type == pa.int64()
        assert reader.read_all().to_pydict() == {"count": [2, 3]}
    with sqlite3.connect(path / "locked.sqlite") as db:
        db.execute("CREATE TABLE original (id INTEGER)")
    sqlite = await source(service, actor, root, "locked.sqlite", "sqlite")
    write = service.sources.register(sqlite["id"], {"name": "Rejected read mutation", "specification": {
        "statement": "INSERT INTO original VALUES (1) RETURNING id"}}, "source-query-rejected-write", actor)
    with pytest.raises(Failure):
        await service.sources.preview(write["id"], {}, actor)
    with sqlite3.connect(path / "locked.sqlite") as db:
        assert db.execute("SELECT count(*) FROM original").fetchone()[0] == 0


async def test_optional_duckdb_bound_analytics_rejects_external_reads(files_fixture):
    import pyarrow as pa
    import pyarrow.parquet as pq

    service, actor, root, path = files_fixture
    service.store.set_setting("source_limits", {"seconds": 15})
    pq.write_table(pa.table({"value": [1, 2, 3]}), path / "analytics.parquet")
    connection = await source(service, actor, root, "analytics.parquet", "duckdb")
    query = service.sources.register(connection["id"], {"name": "Analytical projection", "specification": {
        "statement": "SELECT value*2 AS doubled FROM source WHERE value >= $minimum ORDER BY value"},
        "parameters": [{"name": "minimum", "type": "integer"}]}, "duckdb-query-analytics", actor)
    result = await exported(service, actor, root, query, {"minimum": 2}, "analytics")
    assert result["state"] == "completed" and result["receipt"]["external_access"] is False, result
    assert (path / "analytics.csv").read_text() == "doubled\n4\n6\n"
    external = service.sources.register(connection["id"], {"name": "Denied external read", "specification": {
        "statement": "SELECT * FROM read_csv('/etc/passwd')"}}, "duckdb-query-external", actor)
    with pytest.raises(Failure):
        await service.sources.preview(external["id"], {}, actor)


async def test_streamed_query_cancellation_reaps_worker_and_unpublishes_output(files_fixture, monkeypatch):
    import time

    import httpx
    from fastapi import FastAPI

    from ficc import source_output, source_routes

    service, actor, root, path = files_fixture
    service.store.set_setting("source_limits", {"seconds": 5})
    sqlite3.connect(path / "cancel.sqlite").close()
    connection = await source(service, actor, root, "cancel.sqlite", "sqlite")
    query = service.sources.register(connection["id"], {"name": "Cancellable rows", "specification": {
        "statement": "WITH RECURSIVE counter(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM counter WHERE n<1000000000) SELECT printf('%032768d', n) AS n FROM counter"}},
        "source-query-cancellation", actor)
    first = asyncio.Event()
    frames = 0
    original = source_output.Output.write

    def consume(output, chunk):
        nonlocal frames
        original(output, chunk)
        frames += 1
        first.set()
        # Keep the real producer ahead of its consumer, including cgroup CPU
        # throttling, so an always-readable pipe must yield for API requests.
        time.sleep(0.2)

    monkeypatch.setattr(source_output.Output, "write", consume)
    app = FastAPI()
    source_routes.install(app, service, lambda _request, _scope=None: service.auth.current(actor))
    run = await service.sources.submit(query["id"], {"destination": {
        "root_id": root["id"], "entry_id": service.files.refs.issue(root, root["reference"])},
        "filename": "cancelled.csv", "dataset_name": "Cancelled"}, "source-run-cancellation", actor)
    try:
        async with asyncio.timeout(10), httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://fixture") as http:
            await first.wait()
            status = await http.get("/api/v1/source-runs/" + run["id"])
            assert status.status_code == 200 and status.json()["state"] == "running", status.text
            assert frames <= 4, "A busy source stream starved the queued API request."
            cancelled = await http.post("/api/v1/source-runs/" + run["id"] + "/cancel")
            assert cancelled.status_code == 200 and cancelled.json()["state"] == "cancelled", cancelled.text
        assert not service.sources.tasks
        assert not (path / "cancelled.csv").exists() and not list(path.glob(".ficc-source-*"))
    finally:
        await service.sources.close()


async def test_cancel_before_upload_dispatch_leaves_no_unknown_creation(files_fixture):
    service, actor, _, _ = files_fixture
    sources = Sources(service)
    owner = sources.current(actor, "write")
    upload = {**sources.owner(owner), "state": "creating", "provider_upload_id": None}
    sources.store.insert("source_uploads", upload, "queued-upload", "0" * 64)
    run = {**sources.owner(owner), "state": "queued", "action": "write", "operation": "begin", "upload_id": upload["id"]}
    sources.store.insert("source_runs", run, "queued-upload-begin", "0" * 64)

    async def undispatched():
        pytest.fail("An operation cancelled before dispatch must never execute.")

    sources.tasks[run["id"]] = asyncio.create_task(undispatched())
    assert (await sources.cancel(run["id"], actor))["state"] == "cancelled"
    assert sources.store.get("source_uploads", upload["id"])["state"] == "aborted"
    assert not sources.tasks


def test_postgresql_lost_commit_ack_closes_without_context_manager_recommit(monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace

    import ficc_data_postgresql as driver
    import psycopg

    class Connection:
        __exit__ = psycopg.Connection.__exit__
        closed = False
        pgconn = SimpleNamespace(ssl_in_use=True)
        commits = 0
        mutations = 0

        def __enter__(self):
            return self

        def execute(self, statement, *args, **kwargs):
            if statement.startswith("SELECT current_setting"):
                return SimpleNamespace(fetchone=lambda: ("fixture", "snapshot"))
            self.mutations += 1
            return SimpleNamespace(rowcount=1)

        def commit(self):
            self.commits += 1
            raise OSError("Acknowledgement lost after external commit")

        def close(self):
            self.closed = True

    db = Connection()
    monkeypatch.setattr(psycopg, "connect", lambda **kwargs: db)
    context = SimpleNamespace(endpoint={"host": "database.example", "address": "127.0.0.1", "port": 5432},
        configuration={"database": "fixture", "statement_timeout_ms": 1000},
        secret={"username": "fixture", "password": "fixture"}, ca_file=lambda: nullcontext("/unused"))
    events = list(driver.execute(context, "write", {"specification": {"statement": "UPDATE readings SET value=%(value)s"}, "parameters": {"value": 2}}))
    assert events[-1]["outcome"] == "unknown" and events[-1]["reason"] == "commit_acknowledgement_missing"
    assert db.commits == db.mutations == 1 and db.closed
