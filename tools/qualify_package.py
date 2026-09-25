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
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

PROBE = '''import asyncio,io,json,pathlib,zipfile
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
print(json.dumps({'helper_modules':len(members),'pty':True}))
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
    native = json.loads(subprocess.check_output([str(payload / "python/bin/python3"), "-I", "-B", "-c", PROBE],
                                               env=env, text=True, timeout=20))
    check("helper archive", native["helper_modules"] > 20)
    check("terminal child", native["pty"] is True)
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
        check("service exit", process.returncode in {0, -signal.SIGTERM, 128 + signal.SIGTERM})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if (not (state / "control.sock").exists()
                    and "Application shutdown complete." in (Path(temporary) / "service.log").read_text()):
                break
            time.sleep(0.05)
        if service_log:
            shutil.copy2(Path(temporary) / "service.log", service_log)
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
