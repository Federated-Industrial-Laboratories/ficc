#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Exercise two installed controllers over their real HyperNet companions. Inputs: private HTTP credentials and public resource selections. Output: public results. Exit: workflow status.
"""Pair, manage, invoke, cancel, resume model acquisition and revoke two real clusters."""
import argparse
import hashlib
import json
import os
import secrets
import ssl
import stat
import subprocess
import time
from pathlib import Path

import httpx


class Controller:
    def __init__(self, path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384:
            raise ValueError("Use an owned private regular HTTP connection file.")
        value = json.loads(path.read_text())
        if not value["origin"].startswith("https://"):
            raise ValueError("The installed workflow requires HTTPS.")
        self.http = httpx.Client(base_url=value["origin"], verify=ssl.create_default_context(cafile=value["ca"]),
                                 headers={"Authorization": "Bearer " + value["credential"]}, timeout=180,
                                 trust_env=False, follow_redirects=False)

    def api(self, method, path, **kwargs):
        response = self.http.request(method, "/api/v1" + path, **kwargs)
        if response.status_code >= 400:
            raise ValueError(f"{path}: HTTP {response.status_code}: {response.text[:2000]}")
        return response.json()

    def remote(self, peer, operation, body=None, identity=None):
        return self.api("POST", f"/federation/peers/{peer}/request", json={
            "operation": operation, "body": body or {}, **({"id": identity} if identity else {})})

    def close(self):
        self.http.close()


def wait(check, seconds, description):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = check()
        if value:
            return value
        time.sleep(0.5)
    raise ValueError("Timed out waiting for " + description)


def run(args):
    plan = json.loads(args.plan.read_text())
    args.output.mkdir(mode=0o700)
    receipts = []
    def save(stage, **value):
        receipts.append({"stage": stage, "observed_at": time.time(), **value})
        (args.output / "result.json").write_text(json.dumps(receipts, indent=2) + "\n")
        print(json.dumps({"stage": stage}), flush=True)
    consumer, provider = Controller(args.consumer), Controller(args.provider)
    outgoing = incoming = grant = delegated = None
    try:
        identities = []
        for cluster, name in ((consumer, "consumer"), (provider, "provider")):
            value = cluster.api("PUT", "/federation/configuration", json={
                "agent_directory": plan[name + "_companion"], "label": "Integration " + name})
            identities.append(value["cluster"])
        assert identities[0]["network"] == identities[1]["network"]
        assert identities[0]["incarnation"] == identities[1]["incarnation"]
        save("companions", clusters=identities)
        scopes = ["discover", "inference:invoke", "inference:manage", "models:read", "models:manage"]
        models = list(plan["models"])
        if plan.get("transfer_model"):
            scopes.append("models:transfer")
            if plan["transfer_model"] not in models:
                models.append(plan["transfer_model"])
        offer = consumer.api("POST", "/federation/offers", json={"service": identities[1]["service"], "requested": scopes})
        accepted = provider.api("POST", f"/federation/offers/{offer['id']}/approve", json={"revision": 1, "grant": {
            "scopes": scopes, "models": models, "nodes": plan["nodes"], "services": plan.get("services", []),
            "lifetime": min(args.deadline + 600, 7200), "requests": 10000, "concurrent": 4,
            "transfer_bytes": plan.get("transfer_bytes", 0), "stop_on_revoke": True}})
        incoming, grant = accepted["peer"], accepted["receipt"]["payload"]["grant"]
        paired = consumer.api("POST", f"/federation/offers/{offer['id']}/finish")
        outgoing = paired["id"]
        assert paired["state"] == "paired"
        discovered = consumer.remote(outgoing, "discover")
        assert set(discovered["models"]) == set(models)
        denied = consumer.http.post(f"/api/v1/federation/peers/{outgoing}/request", json={
            "operation": "models.manifest", "body": {"model": "99" * 16}})
        assert denied.status_code == 403
        save("paired_and_scoped", peer=outgoing, receiving_peer=incoming, grant=grant)
        spec = {**plan["spec"], "alias": "federation-" + secrets.token_hex(4)}
        preview = consumer.remote(outgoing, "inference.preview", {"spec": spec})
        operation = secrets.token_hex(16)
        first = consumer.remote(outgoing, "inference.create", {"spec": spec}, operation)
        delegated = first["id"]
        repeated = consumer.remote(outgoing, "inference.create", {"spec": spec}, operation)
        assert repeated == first
        retained = consumer.remote(outgoing, "operation.status", {"id": operation})
        assert retained["state"] == "complete" and retained["result"]["id"] == delegated
        save("delegated_creation", service=delegated, preview=preview, operation=operation)
        def ready():
            value = provider.api("GET", "/inference/" + delegated)
            if value["state"] in {"failed", "unknown", "blocked"}:
                save("delegated_failure", service=value)
                raise ValueError("The delegated service failed before readiness.")
            return value if value["state"] == "ready" else None
        wait(ready, min(args.deadline, 1200), "delegated model readiness")
        path = f"/api/v1/federation/peers/{outgoing}/v1/chat/completions"
        body = {"model": delegated, "messages": [{"role": "user", "content": "Reply with one sentence about a cat. /no_think"}],
                "stream": True, "max_tokens": 128}
        with consumer.http.stream("POST", path, json=body) as response:
            response.raise_for_status()
            answer = b"".join(response.iter_bytes())
        assert b"data:" in answer and b"[DONE]" in answer
        content = "".join(choice.get("delta", {}).get("content", "") or ""
                          for line in answer.decode().splitlines()
                          if line.startswith("data:") and line[5:].strip() != "[DONE]"
                          for choice in json.loads(line[5:]).get("choices", []))
        assert content.strip(), "The remote engine must return actual generated text."
        body.update(max_tokens=4096, messages=[{"role": "user", "content": "Write a long story about a cat."}])
        with consumer.http.stream("POST", path, json=body) as response:
            response.raise_for_status()
            assert next(response.iter_bytes())
        wait(lambda: provider.api("GET", "/inference/" + delegated)["active_requests"] == 0, 15, "remote cancellation")
        save("inference_and_cancellation", answer=answer.decode(), sha256=hashlib.sha256(answer).hexdigest())
        if args.browser:
            env = dict(os.environ, FICC_TEST_FEDERATION_PEER_LABEL=identities[1]["label"],
                       FICC_TEST_FEDERATION_SERVICE_ALIAS=spec["alias"])
            browser = subprocess.run(["node", "web/node_modules/@playwright/test/cli.js", "test", "--config",
                                      "tests/browser/playwright.config.mjs", "federation.spec.mjs"],
                                     cwd=Path(__file__).resolve().parents[2], env=env, timeout=210)
            save("browser", exit=browser.returncode)
            browser.check_returncode()
        if plan.get("transfer_model"):
            remote_model = plan["transfer_model"]
            transfer = consumer.api("POST", f"/federation/peers/{outgoing}/models", json={"model": remote_model})
            def current():
                value = next(item for item in consumer.api("GET", "/federation")["transfers"] if item["id"] == transfer["id"])
                if value["state"] == "interrupted":
                    save("transfer_interrupted", transfer=value)
                    raise ValueError("The transfer was interrupted: " + str(value.get("error")))
                return value
            def progressed():
                value = current()
                return value if value["offset"] >= 32 * 1024 * 1024 else None
            partial = wait(progressed, args.deadline, "durable transfer progress")
            paused = consumer.api("POST", f"/federation/transfers/{transfer['id']}/pause")
            assert paused["state"] == "paused", "Use an uncached multi-GiB fixture for pause/resume."
            save("transfer_paused", transfer=paused, partial=partial["offset"])
            consumer.api("POST", f"/federation/peers/{outgoing}/models", json={"model": remote_model})
            def completed():
                value = current()
                return value if value["state"] == "complete" else None
            complete = wait(completed, args.deadline, "verified model publication")
            model = consumer.api("GET", "/models/" + complete["model"])
            assert model["ready"] and all(item["complete"] for item in model["files"])
            save("transfer_complete", model=model["id"], files=[{key: item[key] for key in ("name", "digest", "bytes", "complete")} for item in model["files"]])
        with consumer.http.stream("POST", path, json=body, timeout=30) as response:
            response.raise_for_status()
            chunks = response.iter_bytes()
            assert next(chunks)
            assert provider.api("GET", "/inference/" + delegated)["active_requests"] > 0
            revoked = time.monotonic()
            provider.api("DELETE", "/federation/grants/" + grant)
            try:
                for _ in chunks:
                    assert time.monotonic() - revoked < 15, "Revocation must close the live response."
            except httpx.RemoteProtocolError:
                pass
            assert time.monotonic() - revoked < 15
        save("active_revocation", seconds=round(time.monotonic() - revoked, 3))
        denied = consumer.http.post(f"/api/v1/federation/peers/{outgoing}/request", json={"operation": "discover", "body": {}})
        assert denied.status_code == 403
        def released():
            value = provider.api("GET", "/inference/" + delegated)
            return value if value["state"] == "stopped" else None
        stopped = wait(released, 90, "stop-on-revoke cleanup")
        assert all(not row["attempt"] or row["attempt"]["state"] == "released" for row in stopped["replicas"])
        save("revoked_and_released", service=stopped)
    finally:
        try:
            if grant:
                provider.api("DELETE", "/federation/grants/" + grant)
            if outgoing:
                consumer.api("DELETE", "/federation/peers/" + outgoing)
            if incoming:
                provider.api("DELETE", "/federation/peers/" + incoming)
        finally:
            consumer.close()
            provider.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consumer", type=Path, required=True, help="Private JSON with origin, ca and credential.")
    parser.add_argument("--provider", type=Path, required=True, help="Private JSON with origin, ca and credential.")
    parser.add_argument("--plan", type=Path, required=True, help="Public companion directories, selected models/nodes and a managed spec; optional transfer_model and transfer_bytes.")
    parser.add_argument("--output", type=Path, required=True, help="New result directory outside the source tree.")
    parser.add_argument("--deadline", type=int, default=1800, metavar="SECONDS")
    parser.add_argument("--browser", action="store_true", help="Run the installed console workflow before revoking its service; set the normal FICC browser environment.")
    arguments = parser.parse_args()
    if not 60 <= arguments.deadline <= 7200:
        parser.error("The phase deadline must be between 60 and 7200 seconds.")
    run(arguments)
