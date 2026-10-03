# SPDX-License-Identifier: Apache-2.0
"""Explicit typed CSV parsing, registered projections and incremental encoding."""

import csv
import datetime
import io
import json
import math
import operator
from typing import Literal

from pydantic import Field

from ficc.data_sdk import MAX_CELL, DataError, rows
from ficc.dataset_schema import DataSchema
from ficc.schema import Model

API_VERSION = 1
METADATA = {"kind": "local", "source_consistency": "immutable", "write": False,
            "description": "Typed CSV with explicit encoding, dialect, null and malformed-row policy."}
OPERATORS = {"eq": operator.eq, "ne": operator.ne, "lt": operator.lt, "le": operator.le, "gt": operator.gt, "ge": operator.ge}


class Configuration(Model):
    data_schema: DataSchema = Field(alias="schema")
    encoding: Literal["utf-8", "utf-8-sig", "utf-16", "latin-1"] = "utf-8"
    delimiter: str = Field(default=",", min_length=1, max_length=1)
    quotechar: str = Field(default='"', min_length=1, max_length=1)
    null: str = ""
    malformed: Literal["error", "skip"] = "error"
    timezone: Literal["UTC"] = "UTC"
    decimal: Literal["."] = "."


class Predicate(Model):
    column: str = Field(min_length=1, max_length=120)
    operator: Literal["eq", "ne", "lt", "le", "gt", "ge"] = "eq"
    parameter: str = Field(min_length=1, max_length=64)


class Query(Model):
    columns: list[str] = Field(default=[], max_length=256)
    filters: list[Predicate] = Field(default=[], max_length=32)


def configuration(value):
    config = Configuration.model_validate(value).model_dump(by_alias=True)
    if not config["schema"]["fields"] or any(field["type"] not in {"string", "integer", "number", "boolean", "date", "timestamp"} for field in config["schema"]["fields"]):
        raise DataError("schema_required", "CSV requires explicit supported column types.")
    return config


def query(value, mode):
    if mode != "read":
        raise DataError("read_only", "CSV sources are read-only; export a new dataset version.")
    return Query.model_validate(value).model_dump()


def convert(value, field, config):
    if value == config["null"]:
        if not field["nullable"]:
            raise ValueError("Null in required field")
        return None
    kind = field["type"]
    if kind == "integer":
        return int(value)
    if kind == "number":
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("Non-finite number")
        return result
    if kind == "boolean":
        if value not in {"true", "false"}:
            raise ValueError("Boolean spelling")
        return value == "true"
    if kind == "date":
        return datetime.date.fromisoformat(value).isoformat()
    if kind == "timestamp":
        timestamp = datetime.datetime.fromisoformat(value)
        return timestamp.replace(tzinfo=timestamp.tzinfo or datetime.UTC).isoformat()
    return value


def execute(context, action, request):
    config = context.configuration
    fields = config["schema"]["fields"]
    names = [field["name"] for field in fields]
    if action == "catalogue":
        yield {"kind": "catalogue", "resources": [{"id": "file", "name": "CSV file", "kind": "table"}], "next_cursor": None}
        yield {"kind": "receipt", "consistency": "immutable-file", "rows": 0}
        return
    if action == "describe":
        yield {"kind": "schema", "schema": config["schema"]}
        yield {"kind": "receipt", "consistency": "immutable-file", "rows": 0}
        return
    specification = request["specification"]
    selected = specification["columns"] or names
    if not set(selected).issubset(names) or len(set(selected)) != len(selected):
        raise DataError("invalid_projection", "Select distinct declared CSV columns.")
    indexes = [names.index(name) for name in selected]
    predicates = [(names.index(item["column"]), OPERATORS[item["operator"]], request["parameters"][item["parameter"]]) for item in specification["filters"]]
    yield {"kind": "schema", "schema": {"fields": [fields[index] for index in indexes], "description": ""}}
    count, skipped = 0, 0
    csv.field_size_limit(MAX_CELL)
    with context.open_source() as binary:
        with io.TextIOWrapper(binary, encoding=config["encoding"], newline="") as text:
            reader = csv.reader(text, delimiter=config["delimiter"], quotechar=config["quotechar"], strict=True)
            if next(reader, None) != names:
                raise DataError("schema_changed", "The CSV header differs from its explicit schema.")

            def records():
                nonlocal count, skipped
                for values in reader:
                    try:
                        if len(values) != len(fields):
                            raise ValueError("Column count")
                        record = [convert(value, field, config) for value, field in zip(values, fields, strict=True)]
                    except (ValueError, OverflowError):
                        if config["malformed"] == "error":
                            raise DataError("malformed_row", "A CSV record differs from the explicit schema.") from None
                        skipped += 1
                        continue
                    if not all(function(record[index], value) for index, function, value in predicates):
                        continue
                    count += 1
                    yield [record[index] for index in indexes]
                    if context.limit is not None and count >= context.limit:
                        return
            yield from rows(records())
    context.source_unchanged()
    yield {"kind": "receipt", "consistency": "immutable-file", "rows": count, "malformed_rows_skipped": skipped,
           "malformed_policy": config["malformed"]}


class Encoder:
    def __init__(self):
        self.pending = bytearray()

    def start(self, shape):
        self.pending.extend(self.encode([[field["name"] for field in shape["fields"]]]))

    @staticmethod
    def encode(records):
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerows([["" if value is None else json.dumps(value, separators=(",", ":")) if isinstance(value, (dict, list, bool)) else value for value in row] for row in records])
        return output.getvalue().encode("utf-8")

    def write(self, records):
        self.pending.extend(self.encode(records))
        while len(self.pending) >= 131072:
            chunk = bytes(self.pending[:131072])
            del self.pending[:131072]
            yield chunk

    def finish(self):
        remaining = bytes(self.pending)
        self.pending.clear()
        return [remaining] if remaining else []


def encoder(format):
    return Encoder()
