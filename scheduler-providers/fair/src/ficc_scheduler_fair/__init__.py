# SPDX-License-Identifier: Apache-2.0
"""Select queued project jobs under explicit administrator-supplied concurrency limits."""

from collections import Counter, defaultdict, deque

API_VERSION = 1


class Scheduler:
    def __init__(self, global_active, project_active):
        self.global_active = global_active
        self.project_active = project_active
        self.last_project = None

    def select(self, request):
        if not isinstance(request, dict) or set(request) != {"version", "pending", "active"} or request["version"] != 1:
            raise ValueError("The scheduling request is invalid.")
        active = Counter(item["project_id"] for item in request["active"])
        capacity = min(64, max(0, self.global_active - len(request["active"])))
        queues: dict[str, deque[str]] = defaultdict(deque)
        for job in sorted(request["pending"], key=lambda job: (job["created_at"], job["id"])):
            queues[job["project_id"]].append(job["id"])
        projects = sorted(queues)
        if self.last_project is not None:
            projects = [project for project in projects if project > self.last_project] + [
                project for project in projects if project <= self.last_project]
        ready = deque(projects)
        chosen: list[str] = []
        while ready and len(chosen) < capacity:
            project = ready.popleft()
            if active[project] >= self.project_active:
                continue
            chosen.append(queues[project].popleft())
            active[project] += 1
            self.last_project = project
            if queues[project]:
                ready.append(project)
        return chosen

    def close(self):
        pass


def create(configuration):
    if not isinstance(configuration, dict) or set(configuration) != {"global_active", "project_active"}:
        raise ValueError("Set global_active and project_active for this scheduler.")
    if any(type(value) is not int or not 1 <= value <= 8192 for value in configuration.values()):
        raise ValueError("Scheduling concurrency must be an integer from one to 8192.")
    if configuration["project_active"] > configuration["global_active"]:
        raise ValueError("The project concurrency cannot exceed the global concurrency.")
    return Scheduler(**configuration)
