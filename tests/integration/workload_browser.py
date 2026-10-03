#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Serve the real controller API with explicitly synthetic executor receipts.
# Inputs: private fixture directory, count, loopback port. Output: readiness file. Exit: server status.
"""Provide distinct retained workloads for isolated browser contract checks."""

import argparse
import asyncio
import json
import secrets
import subprocess
import time
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi.testclient import TestClient
from policy_fixtures import activate, configure_policy, install_pack, signed_pack
from test_execution_ledger import plan as sample_plan
from workload_fixtures import contributor, placement, result
from workload_queue_fixtures import SyntheticExecutor, scheduler

from ficc.api import create_app
from ficc.execution.spec import Output
from ficc.execution.wire import Snapshot
from ficc.identity_store import LOCAL_PROJECT
from ficc.settings import Settings
from ficc.workloads.schema import Submission


class BrowserExecutor(SyntheticExecutor):
    def output(self, identity):
        return (f"Synthetic retained output for {self.plans[identity].job_id}\n" + "x" * 70000
                + '<img src=x onerror="window.injected=true">\n').encode()


def prepare(directory, count, port):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    state = directory / "state"
    configure_policy(state)
    key = directory / "policy-key"
    subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    material = {"public_key": key.with_suffix(".pub").read_text(), "managed": signed_pack(directory / "pack", key)}
    app = create_app(Settings(state_dir=state, port=port, control=False, poll_interval=3600, stale_after=7200))
    service = app.state.service
    destination = directory / "published"
    destination.mkdir()
    asyncio.run(service.files.register(str(destination), "Published workload outputs"))
    token, actor = service.auth.issue("token")
    client = TestClient(app, base_url=service.settings.origin, headers={"Authorization": f"Bearer {token}"})
    activate(client, install_pack(client, material))
    queue = service.workloads
    scheduler(queue)
    executors, jobs = {}, []
    for index in range(count):
        node = contributor(service, LOCAL_PROJECT, index)
        fake = BrowserExecutor(queue, node, 1)
        executors[node["id"]] = fake
        job = sample_plan(index).job.model_copy(deep=True)
        job.name = f"Retained computation {index + 1:02}"
        job.limits.gpu_devices = []
        job.outputs = [Output(name="result", path="result.bin")]
        request = Submission(job=job, node_ids=[node["id"]])
        record = queue.records.submit(request, secrets.token_hex(16), queue.authority.capture(actor, request))
        queue.authority.check(record, node["id"], enforcement=True)
        plan, lease = placement(record, node["id"])
        queue.records.reserve(plan, lease, fake.installation, fake.offer.limits,
                              ledger_id=fake.ledger_id, admission_version=1)
        state_name = "unknown" if index == count - 1 else "succeeded"
        receipt = result(plan, state=state_name)
        fake.plans[plan.attempt_id] = plan
        fake.attempts[plan.attempt_id] = {**receipt.model_dump(), "job_id": plan.job_id,
            "project_id": plan.project_id, "offer_revision": 1, "lease_sequence": 1,
            "lease_expires_at": lease.expires_at, "ready": True, "outcome": state_name}
        queue.records.observation(receipt, node["id"], fake.installation)
        snapshot = Snapshot.model_validate(fake.snapshot())
        queue.nodes.save(snapshot)
        queue.runner.live[node["id"]] = (snapshot, time.monotonic())
        queue.runner.reconciled[node["id"]] = (fake.session["id"], fake.installation, fake.ledger_id)
        jobs.append(record.id)

    def authenticate(fingerprint):
        return next(fake for fake in executors.values() if fake.fingerprint == fingerprint).authenticate(fingerprint)

    async def exchange(identity, message, check, **kwargs):
        return await executors[identity].request(identity, message, check, **kwargs)

    service.contributors.records.authenticate = authenticate
    queue.channel.request = exchange
    bootstrap, _ = service.auth.issue("bootstrap", lifetime=120)
    second_project = service.auth.identities.create("project", "Empty comparison project")
    metadata = {"origin": service.settings.origin, "bootstrap": bootstrap, "jobs": jobs,
                "nodes": list(executors), "other_project": second_project["id"]}
    ready = directory / "ready.json"
    ready.write_text(json.dumps(metadata))
    ready.chmod(0o600)

    async def pulse():
        while True:
            for identity, fake in executors.items():
                fake.pulse()
                snapshot, _seen = queue.runner.live[identity]
                queue.runner.live[identity] = (snapshot, time.monotonic())
            await asyncio.sleep(1)

    @asynccontextmanager
    async def lifespan(_app):
        task = asyncio.create_task(pulse())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            client.close()
            service.close()

    app.router.lifespan_context = lifespan
    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--count", type=int, choices=(1, 64), required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    uvicorn.run(prepare(args.directory, args.count, args.port), host="127.0.0.1", port=args.port,
                log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
