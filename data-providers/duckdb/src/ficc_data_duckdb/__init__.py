# SPDX-License-Identifier: Apache-2.0
"""Optional local analytics over one approved columnar source, without external I/O."""

from typing import Literal

from pydantic import Field

from ficc.data_sdk import DataError, rows, schema
from ficc.schema import Model

API_VERSION = 1
METADATA = {"kind": "local", "source_consistency": "immutable", "write": False,
            "description": "Optional read-only DuckDB SQL over one approved Parquet or Arrow input, without extensions or spill."}


class Configuration(Model):
    format: Literal["parquet", "arrow"] = "parquet"
    memory_bytes: int = Field(default=128 * 1024**2, ge=16 * 1024**2)


class Query(Model):
    statement: str = Field(min_length=1, max_length=32768)


def configuration(value):
    return Configuration.model_validate(value).model_dump()


def query(value, mode):
    if mode != "read":
        raise DataError("read_only", "The optional analytical provider only reads its approved input.")
    return Query.model_validate(value).model_dump()


def execute(context, action, request):
    import duckdb
    # The module creates a default connection with a machine-sized thread pool.
    # This dedicated worker uses only its explicitly bounded connection below.
    duckdb.close()
    import pyarrow as pa  # type: ignore[import-untyped]
    import pyarrow.parquet as pq  # type: ignore[import-untyped]
    pa.set_cpu_count(1)
    pa.set_io_thread_count(1)

    with context.open_source() as handle:
        if context.configuration["format"] == "parquet":
            reader = pq.ParquetFile(handle, pre_buffer=False, thrift_string_size_limit=65536, thrift_container_size_limit=65536)
            shape, batches = reader.schema_arrow, reader.iter_batches(batch_size=128, use_threads=False)
        else:
            reader = pa.ipc.open_stream(handle)
            shape, batches = reader.schema, iter(reader)
        if action == "catalogue":
            yield {"kind": "catalogue", "resources": [{"id": "source", "name": "source", "kind": "table"}], "next_cursor": None}
        elif action == "describe":
            yield {"kind": "schema", "schema": schema(shape.names, [str(field.type) for field in shape])}
        else:
            def bounded():
                for batch in batches:
                    if batch.nbytes > 32 * 1024**2:
                        raise DataError("batch_limit", "An Arrow batch exceeds the 32 MiB parsing limit.")
                    yield batch

            settings: dict[str, str | bool | int | float | list[str]] = {"enable_external_access": False, "python_enable_replacements": False,
                "autoinstall_known_extensions": False, "autoload_known_extensions": False,
                "threads": 1, "memory_limit": str(context.configuration["memory_bytes"]) + "B",
                "temp_directory": "", "max_temp_directory_size": "0B"}
            with duckdb.connect(config=settings) as db:
                db.register("source", pa.RecordBatchReader.from_batches(shape, bounded()))
                statements = db.extract_statements(request["specification"]["statement"])
                if len(statements) != 1 or statements[0].type != duckdb.StatementType.SELECT:
                    raise DataError("read_only", "Register one analytical SELECT statement.")
                result = db.execute(statements[0], request["parameters"]).to_arrow_reader(batch_size=128)
                yield {"kind": "schema", "schema": schema(result.schema.names, [str(field.type) for field in result.schema])}
                count = 0
                for batch in result:
                    if context.limit is not None:
                        batch = batch.slice(0, max(0, context.limit - count))
                    for event in rows(([row[name] for name in result.schema.names] for row in batch.to_pylist())):
                        count += len(event["rows"])
                        yield event
                    if context.limit is not None and count >= context.limit:
                        break
                context.source_unchanged()
                yield {"kind": "receipt", "consistency": "immutable-file", "rows": count,
                       "duckdb_version": duckdb.__version__, "arrow_version": pa.__version__, "external_access": False, "spill": False}
                return
        context.source_unchanged()
        yield {"kind": "receipt", "consistency": "immutable-file", "rows": 0, "duckdb_version": duckdb.__version__}
