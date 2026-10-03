#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Exercise an installed artifact with isolated state; report checks without credentials.
# Inputs: command and payload paths. Exit: zero only when every check passes.
"""Verify the payload, local API, one-use login and terminal child after packaging."""

import argparse
import hashlib
import http.cookiejar
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_lib.modules import components as module_components  # noqa: E402
from release_lib.runtimes import verify_windows_sources  # noqa: E402

PROBE = '''import asyncio,io,json,pathlib,sys,zipfile
import importlib.metadata as metadata
import ficc_node
from ficc.ssh import archive
from ficc.terminal_pty import TerminalPTY
members={p.name:p.read_bytes() for p in pathlib.Path(ficc_node.__file__).parent.glob('*.py')}
with zipfile.ZipFile(io.BytesIO(archive())) as z:
 assert len(members)>20
 assert all(z.read('ficc_node/'+name)==data for name,data in members.items())
async def check():
 p=TerminalPTY(['/usr/bin/printf','ficc-package-pty'],80,24)
 try:
  output=await asyncio.wait_for(p.read(),5)
  assert output==b'ficc-package-pty',output
 finally: await p.close()
asyncio.run(check())
inventory=json.loads((pathlib.Path(sys.argv[1])/'runtime-packages/index.json').read_text())
assert inventory['version']==1 and inventory['packages']
providers=[]
for package in inventory['packages']:
 assert metadata.version(package['name'])==package['version']
 for group,items in package['entry_points'].items():
  if not group.startswith('ficc.'): continue
  for name in items:
   entries=list(metadata.entry_points(group=group,name=name))
   assert len(entries)==1,(group,name)
   assert entries[0].load().API_VERSION==1,(group,name)
   providers.append(group+':'+name)
print(json.dumps({'helper_modules':len(members),'pty':True,'runtime_packages':len(inventory['packages']),'providers':providers}))
'''


def qualify(command: Path, payload: Path, service_log: Path | None = None) -> dict:
    checks = []

    def check(name, condition):
        if not condition:
            raise ValueError("Package check failed: " + name)
        checks.append(name)

    manifest = json.loads((payload / "bundle.json").read_text())
    actual_files = {str(p.relative_to(payload)) for p in payload.rglob("*") if p.is_file() and not p.is_symlink()}
    actual_links = {str(p.relative_to(payload)) for p in payload.rglob("*") if p.is_symlink()}
    check("exact payload files", actual_files == set(manifest["files"]) | {"bundle.json"})
    check("exact payload links", actual_links == set(manifest["links"]))
    policy_files = {"tools/power-policy/README.md", "tools/power-policy/ficc-power.rules",
                    "tools/module-sandbox-policy/README.md"}
    check("optional policy instructions", policy_files <= actual_files)
    expected_modules = module_components(payload / "python/lib/python3.12/site-packages/ficc/module_packages")
    sbom = json.loads((payload / "sbom.cdx.json").read_text())
    actual_modules = [item for item in sbom["components"] if item.get("bom-ref", "").startswith("urn:ficc:module:")]
    check("supplied module inventory", sorted(actual_modules, key=lambda item: item["bom-ref"])
          == sorted(expected_modules, key=lambda item: item["bom-ref"]))
    if (payload / 'windows-runtime').exists():
        check("Windows helper source", verify_windows_sources(payload / 'windows-runtime', manifest['source']['files']) > 0)
    for name, checksum in manifest["files"].items():
        target = (payload / name).resolve()
        check("file: " + name, target.is_relative_to(payload.resolve()) and target.is_file()
              and hashlib.sha256(target.read_bytes()).hexdigest() == checksum)
    for name, target in manifest["links"].items():
        path = payload / name
        check("link: " + name, path.is_symlink() and os.readlink(path) == target
              and path.resolve().is_relative_to(payload.resolve()))
    env = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "PYTHONHOME", "APPDIR", "APPIMAGE"}}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("APPIMAGE_EXTRACT_AND_RUN", None)

    def cli(*args):
        return subprocess.check_output([str(command), *args], text=True, env=env, timeout=30).strip()

    check("version", cli("--version") == "FICC " + manifest["version"])
    native = json.loads(subprocess.check_output([str(payload / "python/bin/python3"), "-I", "-B", "-c", PROBE, str(payload)],
                                               env=env, text=True, timeout=20))
    check("helper archive", native["helper_modules"] > 20)
    check("terminal child", native["pty"] is True)
    check("installed runtime providers", native["runtime_packages"] > 0 and bool(native["providers"]))
    collector = subprocess.run([str(payload / "python/bin/ficc-audit-collector"), "--help"],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15, check=False)
    check("audit collector command", collector.returncode == 0)
    with tempfile.TemporaryDirectory(prefix="ficc-package-check-") as temporary:
        state = Path(temporary) / "state"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

        def request(path, data=None):
            value = json.dumps(data).encode() if data is not None else None
            req = urllib.request.Request(origin + path, value,
                                         {"Origin": origin, "Content-Type": "application/json"})
            try:
                with opener.open(req, timeout=3) as response:
                    return response.status, response.read(), response.headers
            except urllib.error.HTTPError as error:
                return error.code, error.read(), error.headers

        with (Path(temporary) / "service.log").open("wb") as log:
            process = subprocess.Popen([str(command), "serve", "--demo", "--state-dir", str(state),
                                        "--port", str(port)], env=env, stdout=log, stderr=log,
                                       start_new_session=True)
            try:
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise ValueError("Packaged service exited during startup")
                    try:
                        if request("/api/v1/health")[0] == 200 and (state / "control.sock").exists():
                            break
                    except (OSError, urllib.error.URLError):
                        pass
                    time.sleep(0.1)
                else:
                    raise ValueError("Packaged service did not become ready")
                check("unauthenticated inventory denied", request("/api/v1/nodes")[0] == 401)
                status, body, headers = request("/")
                check("console HTML", status == 200 and b"Cluster console" in body)
                check("content policy", "default-src 'self'" in headers.get("Content-Security-Policy", ""))
                for path in ("/static/mark.svg", "/static/vendor/xterm/xterm.mjs", "/static/vendor/xterm/LICENSE"):
                    status, body, _ = request(path)
                    check("asset " + path, status == 200 and len(body) > 20)
                url = urllib.parse.urlsplit(cli("open", "--print-url", "--state-dir", str(state)))
                check("one-use URL origin", f"{url.scheme}://{url.netloc}" == origin)
                credential = urllib.parse.parse_qs(url.fragment)["bootstrap"][0]
                status, body, headers = request("/api/v1/session", {"bootstrap": credential})
                check("owner login", status == 200 and json.loads(body)["mode"] == "demo")
                check("private cookie", "HttpOnly" in headers.get("Set-Cookie", "") and "SameSite=strict" in headers.get("Set-Cookie", ""))
                check("one-use credential consumed", request("/api/v1/session", {"bootstrap": credential})[0] in {401, 403})
                status, body, _ = request("/api/v1/nodes")
                check("authenticated inventory", status == 200 and len(json.loads(body)["nodes"]) > 0)
                check("CLI inventory", len(json.loads(cli("nodes", "--state-dir", str(state)))["nodes"]) > 0)
                check("private state", state.stat().st_mode & 0o777 == 0o700)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                if service_log:
                    shutil.copy2(Path(temporary) / "service.log", service_log)
        check("service exit", process.returncode in {0, -signal.SIGTERM, 128 + signal.SIGTERM})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if (not (state / "control.sock").exists()
                    and "Application shutdown complete." in (Path(temporary) / "service.log").read_text()):
                break
            time.sleep(0.05)
        check("control socket closed", not (state / "control.sock").exists())
        check("graceful shutdown", "Application shutdown complete." in (Path(temporary) / "service.log").read_text())
    return {"version": manifest["version"], "passed": len(checks), "failed": 0,
            "payload_files": len(manifest["files"]), "payload_links": len(manifest["links"]),
            "helper_modules": native["helper_modules"],
            "service_exit": process.returncode}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command", required=True, type=Path)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--service-log", type=Path, help="Retain the private qualification log outside the release")
    args = parser.parse_args()
    print(json.dumps(qualify(args.command.absolute(), args.payload.absolute(), args.service_log), indent=2))


if __name__ == "__main__":
    main()
