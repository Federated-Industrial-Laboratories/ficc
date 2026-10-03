# SPDX-License-Identifier: Apache-2.0
"""Load an administrator-selected scheduler and validate its proposed job order."""

import importlib.metadata
import json

from ..execution.spec import Name
from ..schema import Model
from ..state_provider import read_private


class Configuration(Model):
    provider: Name
    configuration: dict


def load(state):
    path = state / "workload-provider.json"
    if not path.exists() and not path.is_symlink():
        return None
    configuration = Configuration.model_validate(json.loads(read_private(path)))
    matches = list(importlib.metadata.entry_points(group="ficc.scheduler", name=configuration.provider))
    if len(matches) != 1:
        raise ValueError("Install exactly one trusted provider for the configured workload scheduler.")
    provider = matches[0].load()
    if provider.API_VERSION != 1:
        raise ValueError("The workload scheduler interface is not supported.")
    return provider.create(configuration.configuration)


def select(provider, jobs, attempts):
    pending = [{"id": job.id, "project_id": job.project_id, "created_at": job.created_at}
               for job in jobs if job.state == "queued" and not job.cancelled]
    active = [{"id": attempt.id, "job_id": attempt.job_id, "project_id": attempt.plan.project_id}
              for attempt in attempts if attempt.state not in {"released", "abandoned"}]
    value = provider.select({"version": 1, "pending": pending, "active": active})
    identities = {job["id"] for job in pending}
    if (not isinstance(value, list) or len(value) > 64 or any(not isinstance(item, str) for item in value)
            or len(value) != len(set(value)) or set(value) - identities):
        raise ValueError("The scheduler returned invalid or duplicate workload identities.")
    return value
