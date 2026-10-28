#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Run the maintained TLS lab for real inference integration. Inputs: private paths. Output: private readiness. Exit: teardown status.
"""Keep one isolated controller, real CA and production gateway available for bounded rack checks."""
import argparse
import base64
import json
import os
import runpy
import secrets
import signal
import ssl
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from contributor_tls.authority import authority, private, stop
from contributor_tls.gateway import Gateway
from contributor_tls.lab import Lab

from ficc.models.configure import configure
from ficc.settings import SCOPES
from ficc.state_provider import read_private


def resume(args):
    """Renew a stopped lab gateway/issuer without replacing controller identity or state."""
    directory = args.directory.absolute()
    state = directory / "controller"
    saved = json.loads(read_private(directory / "ready.json"))
    contributors = json.loads(read_private(state / "contributors.json"))
    remote = json.loads(read_private(state / "remote.json"))
    provider = contributors["issuer"]["configuration"]
    assert provider["installation_id"] == saved["deployment_id"]
    stopped = threading.Event()
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda *_args: stopped.set())
    root = Path(provider["root_file"])
    credentials = [read_private(Path(configuration["gateway_secret_file"])).decode().strip()
                   for configuration in (remote, contributors)]
    gateway = Gateway(directory, args.source.absolute(), Path(remote["socket"]), root,
                      urlsplit(saved["origin"]).port, urlsplit(saved["node_origin"]).port, credentials)
    with (directory / "authority.log").open("ab") as output:
        process = subprocess.Popen([os.environ["FICC_TEST_STEP_CA"], str(directory / "authority/config/ca.json"),
            "--password-file", str(directory / "authority-password")],
            env={**os.environ, "GOMAXPROCS": "2"}, stdout=output, stderr=output)
        try:
            with httpx.Client(verify=ssl.create_default_context(cafile=str(root)), trust_env=False, timeout=1) as client:
                for _ in range(100):
                    assert process.poll() is None, "The retained authority did not restart."
                    try:
                        if client.get(provider["ca_url"] + "/health").status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    time.sleep(0.05)
                else:
                    raise AssertionError("The retained authority did not become ready.")
            gateway.start()
            print(json.dumps({"resumed": str(directory), "origin": saved["origin"],
                              "server_ca": str(gateway.root), "deployment_preserved": True}), flush=True)
            stopped.wait(args.deadline)
        finally:
            gateway.close()
            stop(process)


def run(args):
    if args.resume:
        return resume(args)
    directory = args.directory.absolute()
    directory.mkdir(mode=0o700)
    stopped = threading.Event()
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda *_args: stopped.set())
    with authority(directory, secrets.token_hex(16)) as (provider, root):
        lab = Lab(directory, args.source.absolute(), provider, root)
        private(lab.state / "workload-provider.json", json.dumps({"provider": "fair", "configuration": {"global_active": 4, "project_active": 4}}))
        private(lab.state / "policy-provider.json", json.dumps({"provider": "opa", "configuration": {
            "binary": os.environ["FICC_TEST_OPA"], "sha256": "668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031"}}))
        if args.model_library:
            configure(lab.state, args.model_library, None)
        try:
            lab.start(scopes=sorted(SCOPES))
            key = directory / "policy-key"
            subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            archive = directory / "managed.zip"
            runpy.run_path(str(args.source / "tools/pack-policy.py"))["build"](args.source / "policy-packs/managed", "integration", key, archive)
            lab.api("PUT", "/api/v1/policy-publishers", json={"id": "integration", "public_key": key.with_suffix(".pub").read_text(), "enabled": True, "revision": 0})
            package = lab.api("POST", "/api/v1/policy-packages", json={"archive_base64": base64.b64encode(archive.read_bytes()).decode()})
            state = lab.api("GET", "/api/v1/policies")["state"]
            lab.api("POST", "/api/v1/policy-activation", json={"digest": package["digest"], "revision": state["revision"]})
            invitations = []
            for index in range(args.nodes):
                value = lab.api("POST", "/api/v1/contributor-invitations", json={"name": "Inference node " + str(index + 1), "mode": "managed"})
                destination = directory / ("invitation-" + str(index + 1) + ".json")
                private(destination, json.dumps(value))
                invitations.append({"node_id": value["node_id"], "invitation": str(destination)})
            metadata = {"state": str(lab.state), "origin": lab.browser_origin, "node_origin": lab.node_origin,
                        "server_ca": str(lab.gateway.root), "deployment_id": provider["installation_id"], "nodes": invitations}
            private(directory / "ready.json", json.dumps(metadata, indent=2))
            print(json.dumps({"ready": str(directory / "ready.json"), "origin": lab.browser_origin}), flush=True)
            stopped.wait(args.deadline)
        finally:
            lab.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--model-library", type=Path)
    parser.add_argument("--nodes", type=int, default=2, choices=range(3))
    parser.add_argument("--deadline", type=int, default=7200, choices=range(1, 10801))
    parser.add_argument("--resume", action="store_true", help="Restart retained issuer/gateway after stopping the earlier lab; copy the renewed server CA to isolated clients.")
    run(parser.parse_args())
