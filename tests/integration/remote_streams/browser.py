# SPDX-License-Identifier: Apache-2.0
"""Run remote browser checks with exact fixture TLS keys pinned for one launch."""

import argparse
import asyncio
import base64
import contextlib
import hashlib
import io
import json
import os
import secrets
import shutil
import subprocess
import zipfile
from pathlib import Path

from contributor_tls.authority import private
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .lab import SCOPES, laboratory
from .modules import install
from .workflows import download, request


async def seed(lab):
    lab.member(SCOPES + ["vm:read", "vm:console"] if lab.display else None)
    client, _ = await lab.login(0)
    async with contextlib.aclosing(client):
        workspace = await request(client, "POST", "/api/v1/workspaces", json={"name": "Remote operations"})
        manifest = {"format_version": 1, "id": "org.example.remote-notes", "display_name": "Remote notes",
            "version": "1.0.0", "category": "productivity", "contract_version": 1, "host_api": 1,
            "runtime": {"kind": "declarative", "language": "none"},
            "capabilities": ["workspace:read", "workspace:write"], "dependencies": [], "actions": [],
            "files": {}, "ui": {"type": "column", "children": [
                {"type": "editor", "id": "notes", "label": "Workspace notes"}]}}
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr("manifest.json", json.dumps(manifest))
        preview = lab.api("POST", "/api/v1/module-install-previews", content=archive.getvalue(),
                          headers={"Content-Type": "application/octet-stream"})
        installed = lab.api("POST", "/api/v1/modules", json={"preview_id": preview["preview_id"],
            "digest": preview["digest"], "accept_unverified": True})
        digest = installed["digest"]
        lab.api("POST", f"/api/v1/modules/{digest}/activation", json={"enabled": True,
            "grants": [{"capability": value, "target_ids": [workspace["id"]]}
                       for value in manifest["capabilities"]]})
        await request(client, "PUT", "/api/v1/workspaces/" + workspace["id"], json={
            "name": workspace["name"], "revision": workspace["revision"], "instances": [{
                "id": secrets.token_hex(16), "digest": digest, "title": "Remote notes", "targets": []}]})
        content = b"Remote browser verified file\n" * 20000
        (lab.files / "browser.bin").write_bytes(content)
        path, item = await download(client, lab.root["id"], "browser.bin")
        value = {"workspace": workspace["id"], "download": path, "sha256": item["sha256"],
                "size": len(content), "subject": lab.users[0]["user"]["id"]}
        if lab.display:
            vm = await request(client, "POST", "/api/v1/workspaces", json={"name": "Remote VM operations"})
            install(lab, vm)
            value["vm_workspace"] = vm["id"]
        return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser-source", type=Path, required=True)
    parser.add_argument("--node-modules", type=Path, required=True)
    parser.add_argument("--display", action="store_true")
    args = parser.parse_args()
    assert os.environ.get("DISPLAY"), "Run this check through the isolated display helper."
    with laboratory(display=args.display) as lab:
        value = asyncio.run(seed(lab))
        runner = lab.directory / "browser"
        files = runner / "tests/browser"
        files.mkdir(parents=True)
        shutil.copy2(args.browser_source, files / "remote-streams.spec.mjs")
        shutil.copy2(Path(__file__).with_name("playwright.config.mjs"), files / "playwright.config.mjs")
        (runner / "web").mkdir()
        (runner / "web/node_modules").symlink_to(args.node_modules.resolve(), target_is_directory=True)
        private(lab.directory / "browser.json", json.dumps(value))
        pins = []
        for path in (lab.gateway.certificate, lab.issuer.ca):
            certificate = x509.load_pem_x509_certificate(path.read_bytes())
            public = certificate.public_key().public_bytes(serialization.Encoding.DER,
                                                            serialization.PublicFormat.SubjectPublicKeyInfo)
            pins.append(base64.b64encode(hashlib.sha256(public).digest()).decode())
        environment = {**os.environ, "FICC_URL": lab.origin, "FICC_STREAM_DIRECTORY": str(lab.directory),
            "FICC_STREAM_SEED": str(lab.directory / "browser.json"), "FICC_STREAM_STATE": str(lab.state),
            "FICC_BROWSER_OUTPUT": str(lab.directory / "browser-results"), "FICC_BROWSER_SPKI": ",".join(pins)}
        command = ["/usr/bin/node", str(args.node_modules / "@playwright/test/cli.js"), "test",
                   "--config", str(files / "playwright.config.mjs"), "remote-streams.spec.mjs"]
        result = subprocess.run(command, cwd=runner, env=environment, timeout=180)
        captures = os.environ.get("FICC_STREAM_CAPTURES")
        if captures:
            destination = Path(captures)
            destination.mkdir(parents=True, exist_ok=True)
            for path in [*lab.directory.glob("browser-*.png"), *lab.directory.glob("browser-*.txt")]:
                shutil.copy2(path, destination / path.name)
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
