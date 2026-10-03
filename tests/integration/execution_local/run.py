# SPDX-License-Identifier: Apache-2.0
"""Qualify one installed executor attempt and preserve uncertain outcomes for inspection."""

import argparse
import asyncio
import base64
import json
import os
import secrets
import subprocess
import time
from pathlib import Path

from ficc.execution.client import Client
from ficc.execution.protocol import Admission, Collect, Control, Prepare, Read, Renew, Snapshot
from ficc.execution.spec import Fence, Plan, Renewal


class Run:
    def __init__(self, arguments):
        self.args = arguments
        self.client = Client(arguments.socket)
        self.plan = Plan.model_validate_json(arguments.plan.read_bytes())
        self.fence = Fence(attempt_id=self.plan.attempt_id, generation=self.plan.generation, plan_digest=self.plan.digest())
        self.output = arguments.output
        self.output.mkdir(mode=0o700)
        self.records = []

    def save(self, value):
        self.records.append({"observed_at": time.time(), **value})
        temporary = self.output / "result.tmp"
        temporary.write_text(json.dumps(self.records, indent=2) + "\n")
        os.replace(temporary, self.output / "result.json")

    async def call(self, kind, **kwargs):
        request = kind(version=1, id=secrets.token_hex(16), **kwargs)
        reply = await self.client.request(request)
        self.save({"action": request.action, "reply": reply})
        if not reply["ok"] or any(not item["ok"] for item in reply.get("results", [])):
            raise ValueError("The installed executor refused the qualification operation. Retained state is unchanged.")
        return reply

    def kernel(self, service):
        unit = "ficc-work-" + service.removeprefix("ficc-executor-").removesuffix(".service") + "-" + self.plan.attempt_id + ".service"
        group = Path("/sys/fs/cgroup/system.slice") / unit
        value = {}
        for name in ("cgroup.procs", "cgroup.events", "cpu.max", "cpu.stat", "memory.max", "memory.peak",
                     "memory.events", "memory.swap.max", "memory.oom.group", "pids.max", "pids.events", "pids.peak"):
            try:
                value[name] = (group / name).read_text()
            except FileNotFoundError:
                pass
        self.save({"kernel": value, "unit": unit})

    async def execute(self):
        before = (await self.call(Snapshot, action="snapshot", after=None))["snapshot"]
        if (before["deployment_id"], before["node_id"]) != (self.plan.deployment_id, self.plan.node_id):
            raise ValueError("The plan does not match the installed executor.")
        if before["offer"]["revision"] != self.plan.offer_revision:
            raise ValueError("The local offer changed before qualification.")
        maximum = before["maximum_lease_seconds"]
        service = "ficc-executor-" + before["installation_id"] + ".service"
        sequence = 1
        lease = Renewal(**self.fence.model_dump(), sequence=sequence, expires_at=time.time() + maximum - 1)
        await self.call(Prepare, action="prepare", attempts=[Admission(plan=self.plan, lease=lease)])
        renew_at = time.monotonic() + maximum / 3
        end = time.monotonic() + self.args.fixture_timeout
        started, fault = False, False
        current = None
        while time.monotonic() < end:
            try:
                reply = await self.call(Control, action="observe", attempts=[self.fence])
            except (OSError, TimeoutError, ValueError):
                if not fault or self.args.case not in {"restart", "watchdog"}:
                    raise
                await asyncio.sleep(0.2)
                continue
            current = reply["results"][0]["attempt"]
            self.kernel(service)
            if current["state"] not in {"prepared", "starting", "running"}:
                break
            if time.monotonic() >= renew_at and not fault:
                sequence += 1
                await self.call(Renew, action="renew", leases=[Renewal(**self.fence.model_dump(), sequence=sequence,
                    expires_at=time.time() + maximum - 1)])
                renew_at = time.monotonic() + maximum / 3
            if current["ready"] and not started:
                await self.call(Control, action="start", attempts=[self.fence])
                started = True
            if current["state"] == "running" and not fault and self.args.case != "complete":
                fault = True
                self.save({"fault": self.args.case, "service": service})
                if self.args.case == "stop":
                    await self.call(Control, action="stop", attempts=[self.fence])
                elif self.args.case in {"restart", "watchdog"}:
                    signum = "SIGKILL" if self.args.case == "restart" else "SIGSTOP"
                    subprocess.run(["/usr/bin/systemctl", "kill", "--kill-whom=main", "--signal=" + signum, service],
                                   check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            await asyncio.sleep(0.2)
        if current is None or current["state"] in {"prepared", "starting", "running"}:
            self.save({"status": "fixture_timeout", "cleanup": "retained"})
            raise ValueError("The fixture ended without a terminal observation. The lease will expire; retain its slot.")
        expected = {"complete": {"succeeded", "failed"}, "expire": {"expired"}, "stop": {"cancelled"},
                    "restart": {"unknown"}, "watchdog": {"unknown"}}[self.args.case]
        if self.args.expected:
            expected = {self.args.expected}
        if current["state"] not in expected or not current["cleanup_confirmed"]:
            raise ValueError("The observed outcome or cleanup differs. Keep the attempt for inspection.")
        for name in ["stdout", "stderr", *["output:" + item.name for item in self.plan.job.outputs]]:
            try:
                reply = await self.call(Collect, action="collect", reads=[Read(**self.fence.model_dump(), object=name,
                                                                              offset=0, length=65536)])
            except ValueError:
                if self.args.case == "complete":
                    raise
                continue
            data = base64.b64decode(reply["results"][0]["data"], validate=True)
            self.save({"object": name, "fixture_text": data.decode("utf-8", errors="replace")})
        self.save({"status": "observed", "state": current["state"], "cleanup_confirmed": True,
                   "released": False, "plan_digest": self.plan.digest()})
        print(json.dumps({"state": current["state"], "cleanup_confirmed": True, "retained": True}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=("complete", "expire", "stop", "restart", "watchdog"), default="complete")
    parser.add_argument("--fixture-timeout", type=int, default=120)
    parser.add_argument("--expected", choices=("succeeded", "failed", "unknown", "expired", "cancelled"))
    asyncio.run(Run(parser.parse_args()).execute())
