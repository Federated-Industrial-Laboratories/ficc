# SPDX-License-Identifier: Apache-2.0
"""Typed Parquet/Arrow reads and bounded record-batch output encoders."""

import datetime
import io
import json
from typing import Literal

from pydantic import Field

from ficc.data_sdk import DataError, rows
from ficc.schema import Model

API_VERSION = 1
METADATA = {"kind": "local", "source_consistency": "immutable", "write": False,
            "description": "Typed Parquet and Arrow IPC sources with projection and record-batch streaming."}


class Configuration(Model):
    format: Literal["parquet", "arrow"]


class Predicate(Model):
    column: str = Field(min_length=1, max_length=120)
    operator: Literal["eq", "ne", "lt", "le", "gt", "ge"]
    parameter: str = Field(min_length=1, max_length=64)


class Query(Model):
    columns: list[str] = Field(default=[], max_length=256)
    filters: list[Predicate] = Field(default=[], max_length=32)


def configuration(value):
    return Configuration.model_validate(value).model_dump()


def query(value, mode):
    if mode != "read":
        raise DataError("read_only", "Arrow sources are read-only; export a new dataset version.")
    return Query.model_validate(value).model_dump()


def description(shape):
    return {"fields": [{"name": field.name, "type": str(field.type), "nullable": field.nullable} for field in shape], "description": "Arrow typed schema."}


def execute(context, action, request):
    import pyarrow as pa  # type: ignore[import-untyped]
    import pyarrow.compute as pc  # type: ignore[import-untyped]
    import pyarrow.parquet as pq  # type: ignore[import-untyped]

    with context.open_source() as handle:
        if context.configuration["format"] == "parquet":
            reader = pq.ParquetFile(handle, memory_map=False, pre_buffer=False, thrift_string_size_limit=65536, thrift_container_size_limit=65536)
            shape = reader.schema_arrow
        else:
            reader = pa.ipc.open_stream(handle)
            shape = reader.schema
        if action == "catalogue":
            yield {"kind": "catalogue", "resources": [{"id": "file", "name": context.configuration["format"], "kind": "table"}], "next_cursor": None}
        elif action == "describe":
            yield {"kind": "schema", "schema": description(shape)}
        else:
            spec = request["specification"]
            columns = spec["columns"] or shape.names
            if len(columns) != len(set(columns)) or not set(columns).issubset(shape.names):
                raise DataError("invalid_projection", "Select distinct source columns.")
            required = list(dict.fromkeys(columns + [item["column"] for item in spec["filters"]]))
            if not set(required).issubset(shape.names):
                raise DataError("invalid_filter", "Select filters on declared source columns.")
            yield {"kind": "schema", "schema": description(pa.schema([shape.field(name) for name in columns]))}
            batches = reader.iter_batches(batch_size=128, columns=required, use_threads=False) if context.configuration["format"] == "parquet" else iter(reader)
            count = 0
            functions = {"eq": pc.equal, "ne": pc.not_equal, "lt": pc.less, "le": pc.less_equal, "gt": pc.greater, "ge": pc.greater_equal}
            for batch in batches:
                if batch.nbytes > 32 * 1024**2:
                    raise DataError("batch_limit", "An Arrow batch exceeds the 32 MiB parsing limit.")
                for item in spec["filters"]:
                    column = batch.column(batch.schema.get_field_index(item["column"]))
                    batch = batch.filter(functions[item["operator"]](column, request["parameters"][item["parameter"]]))
                batch = batch.select(columns)
                if context.limit is not None:
                    batch = batch.slice(0, max(0, context.limit - count))
                # Slices cap Python conversion while retaining the Arrow schema above.
                for start in range(0, len(batch), 128):
                    values = batch.slice(start, 128).to_pylist()
                    for event in rows(([row[name] for name in columns] for row in values)):
                        count += len(event["rows"])
                        yield event
                if context.limit is not None and count >= context.limit:
                    break
            context.source_unchanged()
            yield {"kind": "receipt", "consistency": "immutable-file", "rows": count, "arrow_version": pa.__version__,
                   "projection_pushdown": context.configuration["format"] == "parquet", "filter_execution": "record-batch"}
            return
        context.source_unchanged()
        yield {"kind": "receipt", "consistency": "immutable-file", "rows": 0, "arrow_version": pa.__version__}


class Sink(io.RawIOBase):
    def __init__(self):
        self.chunks = []
        self.offset = 0

    def writable(self):
        return True

    def tell(self):
        return self.offset

    def write(self, data):
        raw = bytes(data)
        self.chunks.extend(raw[index:index + 131072] for index in range(0, len(raw), 131072))
        self.offset += len(raw)
        return len(raw)

    def take(self):
        value, self.chunks = self.chunks, []
        return value


class Encoder:
    def __init__(self, format):
        self.format = format
        self.sink = Sink()

    def start(self, shape):
        import pyarrow as pa
        import pyarrow.parquet as pq
        self.columns = shape["fields"]
        types = {"integer": pa.int64(), "int64": pa.int64(), "int32": pa.int32(), "int16": pa.int16(),
                 "20": pa.int64(), "21": pa.int16(), "23": pa.int32(), "3": pa.int32(), "8": pa.int64(),
                 "number": pa.float64(), "double": pa.float64(), "float": pa.float32(), "float64": pa.float64(),
                 "700": pa.float32(), "701": pa.float64(), "4": pa.float32(), "5": pa.float64(),
                 "boolean": pa.bool_(), "bool": pa.bool_(), "16": pa.bool_(), "date": pa.date32(), "date32[day]": pa.date32()}
        self.shape = pa.schema([pa.field(field["name"], types.get(field["type"], pa.string()), nullable=field["nullable"]) for field in self.columns])
        self.schema = description(self.shape)
        # Unknown SQL/native types stay lossless textual values, with source schema in the manifest.
        self.writer = pq.ParquetWriter(self.sink, self.shape, compression="snappy", write_batch_size=128) if self.format == "parquet" else pa.ipc.new_stream(self.sink, self.shape)

    def write(self, records):
        import pyarrow as pa
        arrays = []
        for index, field in enumerate(self.shape):
            values = [row[index] for row in records]
            if pa.types.is_string(field.type):
                values = [None if value is None else value if isinstance(value, str) else json.dumps(value, separators=(",", ":")) for value in values]
            elif pa.types.is_date(field.type):
                values = [datetime.date.fromisoformat(value) if isinstance(value, str) else value for value in values]
            arrays.append(pa.array(values, type=field.type))
        batch = pa.RecordBatch.from_arrays(arrays, schema=self.shape)
        self.writer.write_batch(batch)
        return self.sink.take()

    def finish(self):
        self.writer.close()
        return self.sink.take()


def encoder(format):
    return Encoder(format)
