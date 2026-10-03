# SPDX-License-Identifier: Apache-2.0
"""Download signed packages through real verified HTTPS without following redirects."""

import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from policy_fixtures import signed_pack

from ficc.policy_cli import package_bytes
from ficc.policy_packages import MAX_ARCHIVE, verify


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_verified_https_policy_sources_are_exact_and_bounded(tmp_path, monkeypatch, policy_material, count):
    key, cert = tmp_path / "tls.key", tmp_path / "tls.pem"
    subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-keyout", str(key), "-out", str(cert)], check=True, timeout=10,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    packages = {f"/package-{index}": signed_pack(tmp_path / f"signed-{index}", policy_material["key"],
                                               package_id=f"source-{index}") for index in range(count)}
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            if self.path == "/redirect":
                self.send_response(307)
                self.send_header("Location", "/must-not-follow")
                body = b""
            else:
                self.send_response(200)
                body = packages.get(self.path, b"x" * (MAX_ARCHIVE + 1))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"https://127.0.0.1:{server.server_port}"
    client = httpx.Client
    try:
        with pytest.raises(httpx.ConnectError):
            package_bytes(origin + "/package-0")
        assert seen == []
        verified = ssl.create_default_context(cafile=cert)
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: client(verify=verified, **kwargs))
        for path, expected in packages.items():
            raw = package_bytes(origin + path)
            assert raw == expected
            assert verify(raw, policy_material["public_key"])[0]["id"] == path[1:].replace("package-", "source-")
        with pytest.raises(ValueError, match="successful"):
            package_bytes(origin + "/redirect")
        with pytest.raises(ValueError, match="size limit"):
            package_bytes(origin + "/oversize")
        assert seen == [*packages, "/redirect", "/oversize"]
        for source in (origin.replace("https://", "http://") + "/package-0", origin + "/package-0#fragment",
                       origin.replace("https://", "https://secret@") + "/package-0"):
            with pytest.raises(ValueError):
                package_bytes(source)
        assert len(seen) == count + 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
