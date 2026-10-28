#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Qualify one real managed model through an isolated controller. Inputs: private paths and GPU UUIDs. Output: public receipts. Exit: qualification status.
"""Upload verified weights, deploy an offered runtime, prove GPU residency and stream/cancel/stop."""
import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path

import httpx

from ficc.cli import local_request
from ficc.local_client import client
from ficc.settings import SCOPES


def run(args):
    args.output.mkdir(mode=0o700)
    receipts = []
    def save(value):
        receipts.append({"observed_at": time.time(), **value})
        (args.output / "result.json").write_text(json.dumps(receipts, indent=2))
    grant = (json.loads(args.credential_file.read_text()) if args.credential_file else
             local_request(args.state, {"action": "token", "label": "Bounded inference integration", "lifetime": 3600, "scopes": sorted(SCOPES)}))
    def connection(timeout=60):
        if args.credential_file:
            import ssl
            return httpx.Client(base_url=grant["origin"], headers={"Authorization": "Bearer " + grant["credential"]},
                                verify=ssl.create_default_context(cafile=str(args.ca)), timeout=timeout, trust_env=False)
        return client(grant, args.state, timeout=timeout)
    identity = None
    success = False
    try:
        with connection() as http:
            def api(method, path, **kwargs):
                response = http.request(method, path, **kwargs)
                if response.status_code >= 400:
                    raise ValueError(f"{path}: HTTP {response.status_code}: {response.text[:2000]}")
                return response.json()
            manifest = json.loads(args.manifest.read_text())
            model = api("POST", "/api/v1/models", json=manifest)
            for index, item in enumerate(model["files"]):
                if item["complete"]:
                    continue
                source = args.directory / item["name"]
                with source.open("rb") as stream:
                    assert source.stat().st_size == item["bytes"]
                    assert "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest() == item["digest"]
                    offset = item["offset"]
                    stream.seek(offset)
                    while data := stream.read(16 * 1024 * 1024):
                        saved = api("POST", f"/api/v1/models/{model['id']}/files/{index}/bytes", params={"offset": offset},
                                    content=data, headers={"Content-Type": "application/octet-stream"}, timeout=600)
                        offset = saved["offset"]
            model = api("GET", "/api/v1/models/" + model["id"])
            assert model["ready"]
            save({"model": model})
            offers = api("GET", "/api/v1/workload-offers")["offers"]
            offered = next(row["snapshot"] for row in offers if row["available"] and row["snapshot"]["node_id"] == args.node)
            runtime = next(row for row in offered["offer"]["runtimes"] if row["image_digest"] == args.image)
            limits = {**offered["capacity"]["available"], "gpu_devices": args.gpu}
            assert set(args.gpu) <= set(offered["capacity"]["available"]["gpu_devices"])
            spec = {"alias": args.alias, "engine": args.engine, "model_id": model["id"], "runtime": runtime,
                    "executable": args.executable, "context": 2048, "concurrency": 1, "deadline_seconds": 120,
                    "placements": [{"node_id": args.node, "limits": limits}], "tensor_split": [1] * len(args.gpu) if len(args.gpu) > 1 else []}
            if args.spec:
                spec = json.loads(args.spec.read_text())
                assert spec["model_id"] == model["id"]
            save({"preview": api("POST", "/api/v1/inference/preview", json=spec)})
            value = api("POST", "/api/v1/inference", json=spec)
            identity = value["id"]
            save({"created": value})
            print(json.dumps({"service": identity, "state": value["state"]}), flush=True)
            end, previous = time.monotonic() + args.deadline, None
            while time.monotonic() < end:
                value = api("GET", "/api/v1/inference/" + identity)
                status = (value["state"], tuple((row["state"], row["reason"]) for row in value["replicas"]))
                if status != previous:
                    save({"service": value})
                    print(json.dumps({"state": value["state"], "replicas": status[1]}), flush=True)
                    previous = status
                if value["state"] == "ready":
                    break
                if value["state"] in {"failed", "unknown", "blocked"}:
                    raise ValueError("The managed model failed before readiness.")
                time.sleep(1)
            else:
                raise ValueError("The managed model exceeded its readiness deadline.")
            attempts = {row["attempt"]["id"] for row in value["replicas"]}
            probe = """import json,subprocess,pathlib
apps=subprocess.check_output(['nvidia-smi','--query-compute-apps=gpu_uuid,pid,used_gpu_memory','--format=csv,noheader'],text=True,timeout=5)
groups={}
for row in apps.splitlines():
 pid=row.split(',')[1].strip()
 try: groups[pid]=(pathlib.Path('/proc')/pid/'cgroup').read_text()
 except FileNotFoundError: pass
print(json.dumps({'apps':apps,'groups':groups}))
"""
            hosts = json.loads(args.gpu_hosts.read_text()) if args.gpu_hosts else {args.node: args.gpu_host}
            for placement in spec["placements"]:
                host = hosts[placement["node_id"]]
                command = ["ssh", "-oBatchMode=yes", "-oConnectTimeout=5", host, "python3", "-I", "-"] if host else ["python3", "-I", "-"]
                observed = json.loads(subprocess.check_output(command, input=probe, text=True, timeout=15))
                apps = observed["apps"]
                resident = set()
                for row in apps.splitlines():
                    gpu, pid, memory = [part.strip() for part in row.split(",")]
                    group = observed["groups"].get(pid, "")
                    if any(attempt in group for attempt in attempts) and int(memory.split()[0]) >= 64:
                        resident.add(gpu)
                save({"node": placement["node_id"], "gpu_processes": apps, "owned_gpu_devices": sorted(resident)})
                assert resident == set(placement["limits"]["gpu_devices"]), "Every selected GPU must have an owned resident engine."
            if args.ready_hold:
                print(json.dumps({"ready": identity, "hold_seconds": args.ready_hold}), flush=True)
                time.sleep(args.ready_hold)
                recovered = api("GET", "/api/v1/inference/" + identity)
                assert recovered["state"] == "ready"
                assert {row["attempt"]["id"] for row in recovered["replicas"]} == attempts
                save({"ready_after_hold": recovered})
            path = "/api/v1/inference/" + identity + "/v1/chat/completions"
            body = {"messages": [{"role": "user", "content": "Reply with one sentence about a cat. /no_think"}], "stream": True, "max_tokens": 128}
            with http.stream("POST", path, json=body, timeout=180) as response:
                response.raise_for_status()
                answer = b"".join(response.iter_bytes())
            assert b"data:" in answer and b"[DONE]" in answer
            body.update(max_tokens=1024, messages=[{"role": "user", "content": "Write a long story about a cat."}])
            with http.stream("POST", path, json=body, timeout=180) as response:
                response.raise_for_status()
                partial = next(response.iter_bytes())
                assert partial
            end = time.monotonic() + 10
            while api("GET", "/api/v1/inference/" + identity)["active_requests"] and time.monotonic() < end:
                time.sleep(0.1)
            assert api("GET", "/api/v1/inference/" + identity)["active_requests"] == 0
            save({"inference": {"stream_complete": True, "cancel_after_output": True, "answer": answer.decode()}})
            scoped = api("POST", "/api/v1/inference/" + identity + "/tokens", json={"lifetime": 300})
            try:
                headers = {"Authorization": "Bearer " + scoped["token"]}
                response = http.post(path, headers=headers, json={"messages": [{"role": "user", "content": "Reply with the word cat. /no_think"}], "stream": False, "max_tokens": 64}, timeout=180)
                response.raise_for_status()
                assert response.json()["choices"]
                denied = http.get("/api/v1/models", headers=headers)
                assert denied.status_code == 403
                other = next((row["id"] for row in api("GET", "/api/v1/inference")["services"] if row["id"] != identity), None)
                restricted = http.get("/api/v1/inference/" + other + "/v1/models", headers=headers) if other else None
                assert restricted is None or restricted.status_code == 404
                save({"scoped_client": {"answer": response.json(), "catalogue_refused": denied.status_code,
                                        "other_service_refused": restricted.status_code if restricted else None}})
            finally:
                response = http.delete("/api/v1/tokens/" + scoped["id"])
                response.raise_for_status()
            refused = http.get("/api/v1/inference/" + identity + "/v1/models", headers=headers)
            assert refused.status_code == 401
            save({"scoped_client_revoked": refused.status_code})
            success = True
    finally:
        try:
            if identity:
                with connection() as http:
                    value = http.get("/api/v1/inference/" + identity).json()
                    if args.retain_failure and not success:
                        for row in value["replicas"]:
                            if row["attempt"] and row["attempt"]["observed"] and row["attempt"]["observed"]["cleanup_confirmed"]:
                                continue
                            response = http.post("/api/v1/workloads/" + row["id"] + "/cancel", json={"revision": row["revision"]})
                            response.raise_for_status()
                        end = time.monotonic() + 60
                        while time.monotonic() < end:
                            value = http.get("/api/v1/inference/" + identity).json()
                            if all(not row["attempt"] or row["attempt"]["observed"] and row["attempt"]["observed"]["cleanup_confirmed"] for row in value["replicas"]):
                                break
                            time.sleep(1)
                        save({"retained_failure": value})
                        assert all(not row["attempt"] or row["attempt"]["observed"] and row["attempt"]["observed"]["cleanup_confirmed"] for row in value["replicas"])
                        raise RuntimeError("The stopped failed attempt is retained for administrator diagnosis and explicit release.")
                    response = http.post("/api/v1/inference/" + identity + "/control/stop", json={"revision": value["revision"]})
                    response.raise_for_status()
                    end = time.monotonic() + 60
                    while time.monotonic() < end:
                        value = http.get("/api/v1/inference/" + identity).json()
                        if value["state"] == "stopped":
                            break
                        time.sleep(1)
                    save({"stopped": value})
                    assert value["state"] == "stopped", "Do not reuse the slot until exact cleanup and release is proven."
        finally:
            if not args.credential_file:
                local_request(args.state, {"action": "revoke", "id": grant["id"]})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--credential-file", type=Path, help="Private temporary API grant; the caller must revoke it after this check.")
    parser.add_argument("--ca", type=Path, help="Verified controller CA for a remote grant.")
    parser.add_argument("--gpu-host", help="SSH inventory alias for the fixed read-only GPU/cgroup probe.")
    parser.add_argument("--gpu-hosts", type=Path, help="Public JSON mapping of selected node IDs to SSH inventory aliases for multi-node residency checks.")
    parser.add_argument("--spec", type=Path, help="Complete public service specification, including explicit replica placements.")
    parser.add_argument("--ready-hold", type=int, default=0, choices=range(601), help="Bounded seconds for client/UI or controller-recovery checks before proving the same attempts remain ready.")
    for name in ("manifest", "directory", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("node", "image", "alias"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--gpu", action="append", required=True)
    parser.add_argument("--engine", default="llama_cpp")
    parser.add_argument("--executable", default="/app/llama-server")
    parser.add_argument("--deadline", type=int, default=1200, choices=range(1, 3601))
    parser.add_argument("--retain-failure", action="store_true", help="Stop failed workloads but retain their reserved output for administrator diagnosis.")
    args = parser.parse_args()
    if bool(args.state) == bool(args.credential_file) or args.credential_file and not args.ca:
        parser.error("Select local --state, or a private --credential-file with --ca.")
    run(args)
