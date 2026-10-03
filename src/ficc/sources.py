# SPDX-License-Identifier: Apache-2.0
"""Project source catalogue, registered queries and durable export/write workflows."""

import asyncio
import base64
import copy
import importlib.metadata
import math
import secrets
import time

from . import source_capabilities as capabilities
from . import source_runtime
from .dataset_schema import DataSchema
from .dataset_store import encoded
from .errors import Failure
from .file_store import key_check
from .source_output import Output, cleanup
from .source_schema import Connection, RegisteredQuery, Run, SourceLimits
from .source_store import TERMINAL, SourceStore


class Sources:
    def __init__(self, service):
        self.service = service
        self.store = SourceStore(service.store)
        self.store.recover()
        self.tasks: dict[str, asyncio.Task] = {}
        self.admission = asyncio.Lock()
        self.workers = asyncio.Semaphore(self.limits()["workers"])
        from .source_objects import Uploads
        self.uploads = Uploads(self)

    def limits(self):
        return SourceLimits.model_validate(self.service.store.get_setting("source_limits", {})).model_dump()

    async def close(self):
        tasks = list(self.tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def current(self, actor, scope="read"):
        current = self.service.auth.current(actor)
        current.require("data:" + scope)
        return current

    def connection(self, identity, actor, permission="read"):
        current = self.current(actor, permission)
        value = self.store.get("source_connections", identity)
        current.require_record(value)
        if not value["enabled"] or permission not in value["permissions"]:
            raise Failure("source_denied", "This source is disabled or does not grant the requested data operation.", 403)
        if value.get("source"):
            self.service.files.check(actor, "files:read", self.service.files.store.root(value["source"]["root_id"]))
        return value

    def query(self, identity, actor, permission="read"):
        value = self.store.get("source_queries", identity)
        self.current(actor, permission).require_record(value)
        connection = self.connection(value["connection_id"], actor, permission)
        return value, connection

    @staticmethod
    def view(table, value):
        value = copy.deepcopy(value)
        if table == "source_connections" and value.get("source"):
            value["source"].pop("reference", None)
        if table == "source_runs":
            value.pop("actor", None)
            if value.get("staging"):
                value["staging"] = {key: item for key, item in value["staging"].items() if key not in {"parent", "identity"}}
        return value

    def all(self, table, actor, before=None):
        principal = self.current(actor)
        values = self.store.page(table, principal.project_id, before)
        return {"items": [self.view(table, value) for value in values[:50]],
                "next_cursor": values[49]["id"] if len(values) > 50 else None}

    def providers(self, actor):
        self.current(actor)
        result = []
        for entry in importlib.metadata.entry_points(group="ficc.data"):
            module, installed = capabilities.provider(entry.name)
            result.append({**installed, **module.METADATA})
        return {"providers": result}

    async def create(self, body, key, actor):
        self.service.live()
        key_check(key)
        body = Connection.model_validate(body).model_dump()
        principal = self.current(actor, "manage")
        digest = capabilities.parameter_digest(body)
        async with self.admission:
            previous = self.store.existing("source_connections", principal, key, digest)
            if previous:
                return self.view("source_connections", previous)
            module, installed = capabilities.provider(body["provider"])
            try:
                body["configuration"] = module.configuration(body["configuration"])
            except (ValueError, TypeError):
                raise Failure("source_configuration", "The source configuration does not match its installed provider.") from None
            if len(encoded(body)) > 131072:
                raise Failure("request_limit", "The connection configuration exceeds 128 KiB.", 413)
            if module.METADATA["kind"] == "local":
                if body["source"] is None or body["endpoint"] or body["read_secret"] or body["write_secret"]:
                    raise Failure("source_configuration", "Local providers require one registered local file and no network credentials.")
                root, reference = self.service.files.resolve(**body["source"], actor=actor)
                body["source"] = {"root_id": root["id"], "root_revision": root["revision"], "reference": reference}
                capabilities.local(self.service, body["source"], actor)
            elif body["source"] is not None or body["endpoint"] is None or body["read_secret"] is None:
                raise Failure("source_configuration", "Network sources require approved TLS identity, addresses and a read-account secret reference.")
            await capabilities.endpoint(body["endpoint"])
            if "write" in body["permissions"]:
                self.current(actor, "write")
                if not module.METADATA["write"] or not body["write_secret"] or body["write_secret"] == body["read_secret"]:
                    raise Failure("write_account", "Writes require a supported provider and a separate restricted write-account reference.")
            for role in ("read", "write"):
                _, body[role + "_secret_revision"] = capabilities.secret(self.service, body[role + "_secret"])
            principal = self.current(actor, "manage")
            value = {**body, **self.owner(principal), "installed": installed, "enabled": True, "revision": 1}
            self.store.insert("source_connections", value, key, digest)
            self.audit("source.create", value, actor, "approved")
            return self.view("source_connections", value)

    @staticmethod
    def owner(principal):
        return {"id": secrets.token_hex(16), "subject_id": principal.subject_id, "project_id": principal.project_id, "created_at": time.time()}

    def audit(self, action, value, actor, outcome):
        self.service.store.audit(action, value["id"], outcome, actor,
            subject_id=value["subject_id"], project_id=value["project_id"])

    def enabled(self, identity, body, actor):
        self.service.live()
        principal = self.current(actor, "manage")
        with self.service.store.lock, self.service.store.db:
            value = self.store.get("source_connections", identity)
            principal.require_record(value)
            if value["revision"] != body["revision"]:
                raise Failure("revision_conflict", "The source approval changed. Reload it before saving.", 409)
            value.update(enabled=body["enabled"], revision=value["revision"] + 1)
            self.store.save("source_connections", value)
        self.audit("source.approval", value, actor, "enabled" if value["enabled"] else "disabled")
        return self.view("source_connections", value)

    def register(self, identity, body, key, actor):
        self.service.live()
        principal = self.current(actor, "manage")
        connection = self.connection(identity, actor)
        body = RegisteredQuery.model_validate(body).model_dump()
        if body["mode"] == "write":
            self.connection(identity, actor, "write")
        module, _ = capabilities.provider(connection["provider"])
        try:
            body["specification"] = module.query(body["specification"], body["mode"])
        except (ValueError, TypeError):
            raise Failure("query_configuration", "The query does not match its provider contract.") from None
        if len(encoded(body)) > 65536:
            raise Failure("request_limit", "The registered query exceeds 64 KiB.", 413)
        key_check(key)
        digest = capabilities.parameter_digest({"connection_id": identity, "query": body})
        with self.service.store.lock, self.service.store.db:
            previous = self.store.existing("source_queries", principal, key, digest)
            if previous:
                return previous
            value = {**self.owner(principal), "connection_id": identity, "query": body, "template_digest": capabilities.parameter_digest(body)}
            self.store.insert("source_queries", value, key, digest)
        self.audit("source.query", value, actor, "registered")
        return value

    @staticmethod
    def parameters(query, values):
        values = dict(values)
        declared = query["parameters"]
        if set(values) != {item["name"] for item in declared} or len(encoded(values)) > 65536:
            raise Failure("query_parameters", "Supply exactly the registered query parameters within 64 KiB.")
        types = {"string": (str,), "integer": (int,), "number": (int, float), "boolean": (bool,)}
        for field in declared:
            value = values[field["name"]]
            if field["type"] == "integer" and isinstance(value, str) and len(value) <= 20 and value.removeprefix("-").isascii() and value.removeprefix("-").isdigit():
                value = values[field["name"]] = int(value)
            if value is None and field["nullable"]:
                continue
            if type(value) not in types[field["type"]] or isinstance(value, float) and not math.isfinite(value):
                raise Failure("query_parameters", "A parameter differs from its declared type.")
            if field["type"] == "integer" and not -(2**63) <= value <= 2**63 - 1:
                raise Failure("query_parameters", "Integer query parameters must fit signed 64-bit values.")
        return values

    async def inspect(self, identity, actor, action, request):
        connection = self.connection(identity, actor)
        packet = await capabilities.packet(self.service, connection, actor, action, request)
        result = {}

        async def receive(event):
            if event["kind"] == "schema":
                result["schema"] = DataSchema.model_validate(event["schema"]).model_dump()
            elif event["kind"] == "catalogue":
                if len(event["resources"]) > 100:
                    raise Failure("stream_limit", "The source catalogue exceeds its page limit.", 502)
                result.update(resources=event["resources"], next_cursor=event["next_cursor"])
            elif event["kind"] == "receipt":
                result["receipt"] = event
            else:
                raise Failure("stream_protocol", "The source returned unexpected catalogue data.", 502)
        async with self.workers:
            await source_runtime.execute(packet, self.limits(), lambda: self.connection(identity, actor), receive)
        return result

    async def preview(self, identity, values, actor):
        query, connection = self.query(identity, actor)
        if query["query"]["mode"] != "read":
            raise Failure("write_preview", "A write template cannot run as a read preview.", 403)
        values = self.parameters(query["query"], values)
        packet = await capabilities.packet(self.service, connection, actor, "query",
            {"specification": query["query"]["specification"], "parameters": values}, limit=101)
        result: dict = {"rows": [], "truncated": False}
        size = 0

        async def receive(event):
            nonlocal size
            if event["kind"] == "schema":
                result["schema"] = DataSchema.model_validate(event["schema"]).model_dump()
            elif event["kind"] == "rows":
                for row in event["rows"]:
                    length = len(encoded(row))
                    if len(result["rows"]) >= 100 or size + length > 131072:
                        result["truncated"] = True
                        break
                    result["rows"].append(row)
                    size += length
            elif event["kind"] == "bytes":
                data = base64.b64decode(event["data"], validate=True)
                result["preview_base64"] = base64.b64encode(data[:4096]).decode()
            elif event["kind"] == "receipt":
                result["receipt"] = event
            else:
                raise Failure("stream_protocol", "The source returned unexpected preview data.", 502)
        async with self.workers:
            await source_runtime.execute(packet, self.limits(), lambda: self.query(identity, actor), receive)
        return result

    async def submit(self, identity, body, key, actor):
        self.service.live()
        body = Run.model_validate(body).model_dump()
        key_check(key)
        query, connection = self.query(identity, actor, body["action"])
        principal = self.current(actor, body["action"])
        body["parameters"] = self.parameters(query["query"], body["parameters"])
        if query["query"]["mode"] != ("write" if body["action"] == "write" else "read"):
            raise Failure("query_mode", "The run action differs from the registered query mode.", 409)
        if body["action"] == "export" and not all(body.get(key) for key in ("destination", "filename", "dataset_name")):
            raise Failure("export_destination", "Select an output folder, filename and dataset name.")
        digest = capabilities.parameter_digest({"query_id": identity, **body})
        async with self.admission:
            previous = self.store.existing("source_runs", principal, key, digest)
            if previous:
                return self.view("source_runs", previous)
            if len(self.tasks) >= self.limits()["workers"]:
                raise Failure("capacity", "Wait for an active data operation to finish.", 429)
            value = {**self.owner(principal), "actor": actor, "query_id": identity, "connection_id": connection["id"],
                     "connection_revision": connection["revision"], "action": body["action"], "state": "queued", "rows": 0, "bytes": 0,
                     "parameter_digest": capabilities.parameter_digest(body["parameters"]), "template_digest": query["template_digest"],
                     "dataset_id": None, "manifest_digest": None, "error": None}
            self.store.insert("source_runs", value, key, digest)
            self.audit("source.run", value, actor, "queued")
            self.tasks[value["id"]] = asyncio.create_task(self.run(value, query, connection, body))
            return self.view("source_runs", value)

    async def run(self, value, query, connection, body):
        output, receipt, shape = None, None, None
        actor = value["actor"]

        def check():
            current = self.connection(connection["id"], actor, body["action"])
            if current["revision"] != value["connection_revision"]:
                raise Failure("source_changed", "The source approval changed during execution.", 409)

        async def receive(event):
            nonlocal receipt, shape
            kind = event["kind"]
            if kind == "schema":
                shape = DataSchema.model_validate(event["schema"]).model_dump()
            elif kind == "bytes" and output is not None:
                output.write(base64.b64decode(event["data"], validate=True))
                value["bytes"] = output.size
            elif kind == "committing" and body["action"] == "write":
                value["state"] = "committing"
                self.store.save("source_runs", value)
            elif kind == "receipt":
                receipt = event
                value["rows"] = event.get("rows", 0)
            else:
                raise Failure("stream_protocol", "The source returned an unexpected export frame.", 502)

        try:
            async with self.workers:
                check()
                if body["action"] == "write":
                    await self.service.audit_delivery.require("source.write", value["id"], self.current(actor, "write"))
                    check()
                packet = await capabilities.packet(self.service, connection, actor,
                    "write" if body["action"] == "write" else "query",
                    {"specification": query["query"]["specification"], "parameters": body["parameters"]},
                    write=body["action"] == "write", format=body["format"] if body["action"] == "export" else None)
                if body["action"] == "export":
                    def retain(staging):
                        value["staging"] = staging
                        self.store.save("source_runs", value)
                    output = Output(self.service, body["destination"], body["filename"], value["id"], actor, self.limits(), retain)
                value["state"] = "running"
                self.store.save("source_runs", value)
                await source_runtime.execute(packet, self.limits(), check, receive)
                if receipt is None:
                    raise Failure("source_interrupted", "The source did not return a completion receipt.", 502)
                check()
                value["receipt"] = receipt
                if output is not None:
                    if shape is None:
                        raise Failure("schema_missing", "The source did not declare an output schema.", 502)
                    value["state"] = "publishing"
                    self.store.save("source_runs", value)
                    source = output.publish()
                    value["published_file"] = source
                    self.store.save("source_runs", value)
                    dataset = await self.service.datasets.create({"name": body["dataset_name"], "format": body["format"] if body["format"] != "original" else "binary",
                        "schema": shape, "sources": [source], "provenance": {"description": "Verified source query export.", "input_dataset_ids": []}},
                        "source-run-" + value["id"], actor, origin={"kind": "query", "connection_id": connection["id"], "query_id": query["id"],
                        "template_digest": value["template_digest"], "parameter_digest": value["parameter_digest"], "provider": connection["installed"],
                        "run_id": value["id"], "receipt": receipt}, safety_sources=[connection["source"]] if connection.get("source") else [])
                    value.update(dataset_id=dataset["id"], manifest_digest=dataset["manifest_digest"])
                    if hasattr(self.service, "inspections"):
                        await self.service.inspections.publication(dataset, actor)
                value["state"] = "unknown" if receipt.get("outcome") == "unknown" else "completed"
        except BaseException as exc:
            uncertain = value["state"] in {"committing", "publishing"} or body["action"] == "write" and value["state"] == "running"
            value["state"] = "unknown" if uncertain else "cancelled" if isinstance(exc, asyncio.CancelledError) else "failed"
            value["error"] = {"code": exc.code, "message": exc.message} if isinstance(exc, Failure) else {
                "code": "source_interrupted", "message": "The source operation stopped before completion. Uncertain writes are never automatically replayed."}
        finally:
            if output is not None:
                try:
                    output.close()
                    value["staging"]["cleanup"] = "published_retained" if output.published else "partial_removed"
                except OSError:
                    value["cleanup_error"] = "The partial output cleanup failed. Cancel this retained operation to retry cleanup."
            value["finished_at"] = time.time()
            self.store.save("source_runs", value)
            self.audit("source.result", value, actor, value["state"])
            self.tasks.pop(value["id"], None)

    def status(self, identity, actor):
        value = self.store.get("source_runs", identity)
        self.current(actor).require_record(value)
        return self.view("source_runs", value)

    async def cancel(self, identity, actor):
        value = self.status(identity, actor)
        self.current(actor, value["action"])
        task = self.tasks.get(identity)
        if task:
            task.cancel()
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                if not task.cancelled():
                    raise
                # Cancellation before the coroutine's first instruction has no finally block.
                value = self.store.get("source_runs", identity)
                if value["state"] == "queued":
                    value.update(state="cancelled", finished_at=time.time())
                    self.store.save("source_runs", value)
                    if value.get("upload_id") and value.get("operation") == "begin":
                        upload = self.store.get("source_uploads", value["upload_id"])
                        upload["state"] = "aborted"
                        self.store.save("source_uploads", upload)
                    self.tasks.pop(identity, None)
        elif value["state"] not in TERMINAL:
            raise Failure("source_unknown", "The source outcome is not known and will not be replayed.", 409)
        retained = self.store.get("source_runs", identity)
        if retained.get("staging") and retained["staging"]["cleanup"] == "pending":
            self.service.live()
            try:
                cleanup(self.service, retained, actor)
                retained.pop("cleanup_error", None)
            except (Failure, OSError):
                retained["cleanup_error"] = "The partial output cleanup could not confirm its destination and identity. Cleanup remains pending."
                raise Failure("source_cleanup_failed", retained["cleanup_error"], 409) from None
            finally:
                self.store.save("source_runs", retained)
        return self.status(identity, actor)
