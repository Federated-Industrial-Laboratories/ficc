# SPDX-License-Identifier: Apache-2.0
"""Receiving clusters retain resource admission, model integrity and mutation ownership."""
import asyncio
import time

from ..errors import Failure
from ..execution.spec import digest as model_digest
from ..inference.stream import Stream
from ..models.schema import Manifest
from . import identity


def exact(body, names):
    if set(body) != set(names):
        raise Failure("federation_request", "The remote operation has missing or unknown fields.", 422)


def published_manifest(record):
    value = dict(record["manifest"])
    value["files"] = [{**item, "url": None} for item in value["files"]]
    return value


async def dispatch(manager, request, peer):
    auth = manager.authority
    grant, _ = auth.check(request.grant, peer, request.generation)
    if len(identity.encode(request.body)) > grant["spec"]["request_bytes"]:
        raise Failure("federation_limit", "The request exceeds this grant's allowance.", 413)
    def check(scope, resource=None):
        return auth.check(request.grant, peer, request.generation, scope, resource)[1]
    body, op = request.body, request.operation
    if op == "inference.prepare":
        exact(body, [])
        actor = check("inference:manage")
        models = []
        for model in grant["spec"]["models"] + grant.get("created_models", []):
            value = manager.service.models.view(manager.service.models.get(model, actor))
            models.append({"id": value["id"], "manifest": {key: value["manifest"][key] for key in ("name", "revision")},
                           "ready": value["ready"], "total_bytes": value["total_bytes"]})
        offers = manager.service.workloads.offers(actor)["offers"]
        return {"models": models, "offers": [offer for offer in offers
                if offer["snapshot"]["node_id"] in grant["spec"]["nodes"]]}, None
    if op == "inference.get":
        exact(body, ["service"])
        actor = check("inference:manage", ("services", body["service"]))
        value = manager.service.inference.get(body["service"], actor)
        return {key: value[key] for key in ("id", "spec", "state", "revision")}, None
    if op == "inference.preview":
        exact(body, ["spec"])
        actor = check("inference:manage")
        spec = deployment(body["spec"], grant)
        jobs = manager.service.inference.preview(spec, actor)
        return {"replicas": len(jobs), "download_bytes": 0,
                "reserved_bytes": sum(item.job.limits.storage_bytes for item in jobs)}, None
    if op == "discover":
        exact(body, [])
        actor = check("discover")
        services = []
        for service_id in grant["spec"]["services"] + grant["created_services"]:
            try:
                record = manager.service.inference.get(service_id, actor)
                view = manager.service.inference.view(record)
                services.append({"id": service_id, "alias": record["spec"]["alias"],
                    "state": record["state"], "generation": record["generation"], "revision": record["revision"],
                    "capabilities": view["capabilities"]})
            except Failure as error:
                if error.status != 404:
                    raise
        return {"services": services, "models": grant["spec"]["models"] + grant.get("created_models", []),
                "scopes": grant["spec"]["scopes"], "expires": grant["expires"]}, None
    if op == "inference.invoke":
        exact(body, ["service", "path", "body"])
        actor = check("inference:invoke", ("services", body["service"]))
        if not isinstance(body["body"], dict):
            raise Failure("federation_request", "The inference input must be an object.", 422)
        status, stream = await manager.service.inference.gateway.invoke(body["service"], body["path"], body["body"], actor)
        async def chunks():
            total = 0
            try:
                async for chunk in stream:
                    check("inference:invoke", ("services", body["service"]))
                    total += len(chunk)
                    if total > grant["spec"]["response_bytes"]:
                        raise Failure("federation_quota", "The inference response allowance is exhausted.", 429)
                    yield chunk
            finally:
                await stream.aclose()
        return {"stream": True, "status": status}, Stream(chunks(), stream.aclose)
    if op == "models.manifest":
        exact(body, ["model"])
        actor = check("models:read", ("models", body["model"]))
        record = manager.service.models.get(body["model"], actor)
        manifest = published_manifest(record)
        return {"model": body["model"], "manifest": manifest, "manifest_digest": identity.digest(manifest)}, None
    if op == "models.range":
        exact(body, ["model", "file", "offset", "length", "digest"])
        actor = check("models:transfer", ("models", body["model"]))
        record = manager.service.models.get(body["model"], actor)
        files = Manifest.model_validate(record["manifest"]).files
        index, offset, length = body["file"], body["offset"], body["length"]
        if (type(index) is not int or not 0 <= index < len(files)
                or type(offset) is not int or type(length) is not int):
            raise Failure("federation_range", "Select a valid model file and integer range.", 422)
        item = files[index]
        if offset < 0 or not 1 <= length <= 256*1024*1024 or offset+length > item.bytes or body["digest"] != item.digest:
            raise Failure("federation_range", "The requested immutable model range is invalid.", 422)
        cache = manager.service.models.cache_for(record)
        if not cache.status(item)["complete"]:
            raise Failure("model_missing", "This cluster has no complete verified copy of the selected model file.", 409)
        async def ranges():
            cursor = offset
            while cursor < offset+length:
                check("models:transfer", ("models", body["model"]))
                data = await asyncio.to_thread(cache.read, item, cursor, min(1024*1024, offset+length-cursor))
                if not data:
                    raise Failure("model_changed", "The model file ended before its declared range.", 409)
                auth.charge(request.grant, peer, request.generation, len(data))
                cursor += len(data)
                yield data
        return {"stream": True, "digest": item.digest, "offset": offset, "length": length}, ranges()
    if op == "resources":
        exact(body, [])
        actor = check("resources:read")
        result = []
        for node in grant["spec"]["nodes"]:
            manager.service.workloads.authority.node(actor.project_id, node)
            live = manager.service.workloads.runner.live.get(node)
            result.append({"id": node, "available": live[0].capacity.available.model_dump() if live else None})
        return {"nodes": result}, None
    if op in {"inference.create", "inference.control", "inference.replace", "models.create", "models.remove"}:
        return await mutate(manager, request, peer, check), None
    if op == "operation.status":
        exact(body, ["id"])
        value = manager.operations.get(body["id"])
        if value["grant"] != request.grant:
            raise Failure("not_found", "The operation was not found in this grant.", 404)
        return {k: value[k] for k in ("id", "state", "result", "error")}, None
    raise Failure("federation_operation", "The federation operation is unsupported.", 422)


def deployment(body, grant):
    from ..inference.schema import Specification
    spec = Specification.model_validate(body)
    if (spec.model_id not in grant["spec"]["models"] + grant.get("created_models", [])
            or any(p.node_id not in grant["spec"]["nodes"] for p in spec.placements)):
        raise Failure("federation_denied", "The deployment exceeds the granted model or machine selection.", 403)
    return spec


async def mutate(manager, request, peer, check):
    grant, actor = manager.authority.check(request.grant, peer, request.generation)
    fingerprint = identity.digest([request.operation, request.body, request.grant, request.generation])
    existing = manager.operations.find(request.id)
    if existing:
        if existing["digest"] != fingerprint or existing["grant"] != request.grant:
            raise Failure("operation_conflict", "The retained operation ID belongs to different arguments.", 409)
        if existing["state"] == "complete":
            return existing["result"]
        raise Failure("operation_uncertain", "This mutation has a retained outcome; inspect it before taking another action.", 409)
    body, op = request.body, request.operation
    spec = None
    if op in {"inference.create", "inference.replace"}:
        exact(body, ["spec"] if op.endswith("create") else ["service", "spec", "revision"])
        actor = check("inference:manage")
        spec = deployment(body["spec"], grant)
        manager.service.inference.preview(spec, actor)
    elif op == "inference.control":
        exact(body, ["service", "operation", "revision", *(["acknowledge_unknown"] if "acknowledge_unknown" in body else [])])
        if type(body.get("acknowledge_unknown", False)) is not bool:
            raise Failure("federation_request", "Unknown-outcome acknowledgement must be a boolean.", 422)
        actor = check("inference:manage", ("services", body["service"]))
    elif op == "models.create":
        exact(body, ["manifest"])
        actor = check("models:manage")
        manifest = Manifest.model_validate(body["manifest"])
        if any(item.url is not None for item in manifest.files):
            raise Failure("federation_source", "Remote model registration cannot initiate upstream downloads.", 403)
        for record in manager.service.models.records.all(actor.project_id):
            if record["manifest_digest"] == model_digest(manifest.model_dump()):
                check("models:manage", ("models", record["id"]))
    elif op == "models.remove":
        exact(body, ["model"])
        actor = check("models:manage", ("models", body["model"]))
    if op == "inference.replace":
        actor = check("inference:manage", ("services", body["service"]))
    created = {"inference.create": "created_services", "models.create": "created_models"}.get(op)
    pending = sum(record["grant"] == request.grant and record["operation"] == op
                  and record["state"] == "uncertain" for record in manager.operations.all(actor.project_id)) if created else 0
    if created and len(grant.get(created, [])) + pending >= 64:
        raise Failure("federation_capacity", "This grant has reached its 64 delegated resource limit; request a new grant.", 409)
    value = {"id": request.id, "project_id": actor.project_id, "grant": request.grant,
             "digest": fingerprint, "state": "uncertain", "operation": op,
             "result": None, "error": None, "created_at": time.time()}
    # Persist uncertainty before any effect. A crash never silently replays a launch.
    manager.operations.save(value)
    try:
        if op == "inference.create":
            result = await manager.service.inference.create(spec, actor)
            grant = manager.grants.get(request.grant)
            grant["created_services"].append(result["id"])
            manager.grants.save(grant)
        elif op == "inference.replace":
            result = await manager.service.inference.replace(body["service"], spec, body["revision"], actor)
        elif op == "inference.control":
            result = await manager.service.inference.control(body["service"], body["operation"], body["revision"], actor,
                acknowledge_unknown=body.get("acknowledge_unknown", False))
        elif op == "models.create":
            result = manager.service.models.create(body["manifest"], actor)
            if result["id"] not in grant["spec"]["models"] + grant.get("created_models", []):
                grant.setdefault("created_models", []).append(result["id"])
                manager.grants.save(grant)
        else:
            result = manager.service.models.remove(body["model"], actor)
            if body["model"] in grant.get("created_models", []):
                grant["created_models"].remove(body["model"])
                manager.grants.save(grant)
        value.update(state="complete", result=result)
        manager.operations.save(value)
        return result
    except Failure as error:
        value.update(state="failed", error={"code": error.code, "message": str(error)})
        manager.operations.save(value)
        raise
