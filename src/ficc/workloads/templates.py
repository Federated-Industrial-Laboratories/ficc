# SPDX-License-Identifier: Apache-2.0
"""Share immutable project recipes without credentials, inputs or node authority."""

import json
import secrets
import time
from typing import Annotated

from fastapi import Request
from pydantic import Field, model_validator

from ..errors import Failure
from ..execution.spec import Digest, Identity, Job, digest, encoded
from ..schema import Model
from ..workspace_schema import Name

KEY = "workload_templates"


class Share(Model):
    name: Name
    instructions: Annotated[str, Field(max_length=4096)] = ""
    job: Job


class Template(Share):
    id: Identity
    project_id: Identity
    subject_id: Identity
    version: Annotated[int, Field(ge=1, le=2**31 - 1)]
    created_at: Annotated[float, Field(ge=0, allow_inf_nan=False)]
    digest: Digest

    @model_validator(mode="after")
    def clean(self):
        if self.job.inputs or self.job.payload.environment or self.job.limits.gpu_devices:
            raise ValueError("Templates cannot contain input bindings, environment variables or GPU identities.")
        if self.digest != digest({"job": self.job.model_dump(), "instructions": self.instructions}):
            raise ValueError("The template content digest is invalid.")
        return self


def checked(values):
    if not isinstance(values, list) or len(values) > 128:
        raise ValueError("The workload template catalogue is invalid or full.")
    result = [Template.model_validate(value).model_dump() for value in values]
    if len({value["id"] for value in result}) != len(result) or len(encoded(result)) > 1048576:
        raise ValueError("The workload template catalogue is invalid or full.")
    return result


def validate_records(db):
    row = db.execute("SELECT value FROM settings WHERE key=:p0", (KEY,)).fetchone()
    if row:
        for value in checked(json.loads(row[0])):
            if not db.execute("SELECT 1 FROM projects WHERE id=:p0", (value["project_id"],)).fetchone():
                raise ValueError("The template project is unavailable.")


def install(app, service, principal):
    def actor(request, scope):
        return service.workloads.actor(principal(request, scope), scope)

    def values():
        try:
            return checked(service.store.get_setting(KEY, []))
        except ValueError:
            raise Failure("template_invalid", "The saved workload templates are unavailable.", 409) from None

    @app.get("/api/v1/workload-templates")
    async def all_templates(request: Request):
        current = actor(request, "jobs:read")
        return {"templates": [value for value in values() if value["project_id"] == current.project_id]}

    @app.post("/api/v1/workload-templates", status_code=201)
    async def share(body: Share, request: Request):
        service.live()
        current = actor(request, "jobs:execute")
        current.require("jobs:read")
        job = body.job.model_copy(deep=True)
        job.inputs, job.payload.environment, job.limits.gpu_devices = [], {}, []
        with service.store.lock, service.store.db:
            saved = values()
            version = 1 + max((item["version"] for item in saved if item["project_id"] == current.project_id
                               and item["name"] == body.name), default=0)
            value = Template(id=secrets.token_hex(16), project_id=current.project_id, subject_id=current.subject_id,
                name=body.name, instructions=body.instructions, job=job, version=version, created_at=time.time(),
                digest=digest({"job": job.model_dump(), "instructions": body.instructions})).model_dump()
            try:
                checked([*saved, value])
            except ValueError:
                raise Failure("capacity", "Remove an unused template version before sharing another.", 409) from None
            service.store.set_setting(KEY, [*saved, value])
            service.workloads.audit("workload.template.share", value["id"], current)
        return value

    @app.delete("/api/v1/workload-templates/{identity}")
    async def remove(identity: Identity, request: Request):
        service.live()
        current = actor(request, "jobs:execute")
        with service.store.lock, service.store.db:
            saved = values()
            value = next((item for item in saved if item["id"] == identity and item["project_id"] == current.project_id), None)
            if value is None:
                raise Failure("not_found", "The workload template was not found.", 404)
            service.store.set_setting(KEY, [item for item in saved if item["id"] != identity])
            service.workloads.audit("workload.template.remove", identity, current)
        return {"removed": True}
