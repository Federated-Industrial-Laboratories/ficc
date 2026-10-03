# SPDX-License-Identifier: Apache-2.0
"""Serve a private HTTPS identity fixture with signed tokens and token rotation."""

import base64
import hashlib
import ipaddress
import json
import secrets
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote_plus

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from joserfc import jwk, jwt


def certificate(directory: Path, *, wrong_hostname: bool = False) -> tuple[Path, Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FICC identity fixture")])
    now = datetime.now(timezone.utc)
    names: list[x509.GeneralName] = ([x509.DNSName("mismatched.example")] if wrong_hostname else
                                    [x509.DNSName("localhost"),
                                     x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .sign(key, hashes.SHA256()))
    ca, keyfile, secret = (directory / name for name in ("ca.pem", "key.pem", "secret"))
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    secret.write_text("client:secret+value\n")
    for path in (ca, keyfile, secret):
        path.chmod(0o600)
    return ca, keyfile, secret


class Issuer:
    def __init__(self, directory: Path, *, wrong_hostname: bool = False):
        self.ca, self.keyfile, self.secret = certificate(directory, wrong_hostname=wrong_hostname)
        self.key = jwk.RSAKey.generate_key(2048, {"kid": "signing-1", "alg": "RS256", "use": "sig"})
        self.keys = [self.key.as_dict(private=False)]
        self.lock = threading.RLock()
        self.codes: dict[str, dict] = {}
        self.access: dict[str, dict] = {}
        self.refresh: dict[str, dict] = {}
        self.modes: dict[str, str] = {}
        self.subject_modes: dict[tuple[str, str], str] = {}
        self.counts: dict[str, int] = {}
        self.refresh_updates: dict[str, dict] = {}
        self.introspection_updates: dict[str, dict] = {}
        self.discovery_updates: dict = {}
        self.current_requests = 0
        self.max_requests = 0
        self.paused = threading.Event()
        self.release = threading.Event()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.dispatch(None)

            def do_POST(self):
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 <= size <= 64 * 1024:
                    self.send_error(413)
                    return
                form = {key: values[0] for key, values in
                        parse_qs(self.rfile.read(size).decode(), strict_parsing=True).items()}
                expected = base64.b64encode((quote_plus("ficc") + ":" +
                                            quote_plus("client:secret+value")).encode()).decode()
                if self.headers.get("Authorization") != "Basic " + expected:
                    self.send_error(401)
                    return
                self.dispatch(form)

            def dispatch(self, form):
                with fixture.lock:
                    fixture.current_requests += 1
                    fixture.max_requests = max(fixture.max_requests, fixture.current_requests)
                    fixture.counts[self.path] = fixture.counts.get(self.path, 0) + 1
                    subject = fixture.request_subject(self.path, form)
                    mode = fixture.subject_modes.get((self.path, subject), fixture.modes.get(self.path))
                try:
                    if mode == "pause":
                        fixture.paused.set()
                        fixture.release.wait(4)
                    if mode == "disconnect":
                        self.close_connection = True
                        return
                    if mode == "slow":
                        time.sleep(2.3)
                    status, result = fixture.respond(self.path, form)
                    if mode == "unavailable":
                        status, result = 503, {"error": "unavailable"}
                    if mode == "redirect":
                        status = 307
                    raw = json.dumps(result, separators=(",", ":")).encode()
                    if mode == "oversized":
                        raw = b" " * (256 * 1024 + 1)
                    if mode == "duplicate":
                        raw = b'{"active":false,"active":true}'
                    if mode == "nonfinite":
                        raw = b'{"active":true,"exp":NaN}'
                    if mode == "private-error":
                        status, raw = 400, b'{"error":"PRIVATE_RESPONSE_MUST_NOT_ESCAPE"}'
                    self.send_response(status)
                    self.send_header("Content-Type", "text/plain" if mode == "html" else "application/json")
                    if mode == "compressed":
                        self.send_header("Content-Encoding", "gzip")
                    if mode == "redirect":
                        self.send_header("Location", fixture.origin + "/never")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    if mode == "drip":
                        for byte in raw:
                            self.wfile.write(bytes([byte]))
                            self.wfile.flush()
                            time.sleep(0.04)
                    else:
                        self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass
                finally:
                    with fixture.lock:
                        fixture.current_requests -= 1

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(self.ca, self.keyfile)
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.origin = "https://127.0.0.1:" + str(self.server.server_address[1])
        self.issuer = self.origin + "/realm"
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.02),
                                       daemon=True)
        self.thread.start()

    def configuration(self) -> dict:
        return {"issuer": self.issuer, "client_id": "ficc", "client_secret_file": str(self.secret),
                "allowed_origins": [self.origin], "algorithms": ["RS256"], "required_acr": ["2"],
                "max_auth_age": 28800, "session_seconds": 28800, "ca_file": str(self.ca)}

    def request_subject(self, path: str, form: dict | None) -> str:
        if form is None:
            return ""
        if path == "/introspect":
            return self.access.get(form.get("token", ""), {}).get("sub", "")
        if path == "/revoke":
            record = self.refresh.get(form.get("token", ""), {})
        elif form.get("grant_type") == "authorization_code":
            record = self.codes.get(form.get("code", ""), {})
        else:
            record = self.refresh.get(form.get("refresh_token", ""), {})
        return record.get("claims", {}).get("sub", "")

    def code(self, index: int, *, claims: dict | None = None, header: dict | None = None,
             fields: dict | None = None, key=None) -> tuple[str, str, str]:
        now, code, nonce = int(time.time()), secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        value = {"iss": self.issuer, "sub": f"person-{index}", "aud": "ficc", "azp": "ficc",
                 "nonce": nonce, "iat": now, "exp": now + 300, "auth_time": now - index % 60,
                 "acr": "2", "amr": ["pwd", "otp"]}
        value.update(claims or {})
        self.codes[code] = {"claims": value, "header": header or {}, "fields": fields or {},
                            "verifier": verifier, "key": key}
        return code, verifier, nonce

    def tokens(self, record: dict, *, refresh: bool = False) -> dict:
        access, token = secrets.token_urlsafe(40), secrets.token_urlsafe(40)
        claims = dict(record["claims"])
        if refresh:
            claims.pop("at_hash", None)
            claims.update({"iat": int(time.time()), "exp": int(time.time()) + 300})
            claims.update(self.refresh_updates.get(claims["sub"], {}))
        header = {"alg": "RS256", "kid": "signing-1", "typ": "JWT", **record["header"]}
        header.setdefault("alg", "RS256")
        if "at_hash" not in claims:
            digest = hashlib.sha256(access.encode()).digest()[:16]
            claims["at_hash"] = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        encoded = jwt.encode(header, claims, record["key"] or self.key, algorithms=[header["alg"]])
        active = {"active": True, "sub": claims["sub"], "client_id": "ficc", "iss": self.issuer,
                  "exp": int(time.time()) + 300}
        self.access[access] = active
        self.refresh[token] = {**record, "claims": claims}
        return {"access_token": access, "refresh_token": token, "id_token": encoded,
                "expires_in": 300, "token_type": "Bearer", **record["fields"]}

    def respond(self, path: str, form: dict | None) -> tuple[int, dict]:
        with self.lock:
            if path == "/realm/.well-known/openid-configuration":
                return 200, {"issuer": self.issuer,
                    "authorization_endpoint": self.origin + "/authorize",
                    "token_endpoint": self.origin + "/token", "jwks_uri": self.origin + "/keys",
                    "introspection_endpoint": self.origin + "/introspect",
                    "revocation_endpoint": self.origin + "/revoke",
                    "response_types_supported": ["code"], "response_modes_supported": ["query"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "code_challenge_methods_supported": ["S256"],
                    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                    "introspection_endpoint_auth_methods_supported": ["client_secret_basic"],
                    "id_token_signing_alg_values_supported": ["RS256", "ES256"],
                    **self.discovery_updates}
            if path == "/keys":
                return 200, {"keys": self.keys}
            if path == "/token" and form is not None:
                grant = form.get("grant_type")
                self.counts[str(grant)] = self.counts.get(str(grant), 0) + 1
                if grant == "authorization_code":
                    record = self.codes.pop(form.get("code", ""), None)
                    if (not record or form.get("code_verifier") != record["verifier"]
                            or form.get("redirect_uri") != "https://controller.example/auth/callback"):
                        return 400, {"error": "invalid_grant"}
                    return 200, self.tokens(record)
                record = self.refresh.pop(form.get("refresh_token", ""), None)
                if not record:
                    return 400, {"error": "invalid_grant"}
                result = self.tokens(record, refresh=True)
                if self.modes.get("refresh") == "reuse":
                    result["refresh_token"] = form["refresh_token"]
                if self.modes.get("refresh") == "consume-drop":
                    return 503, {"error": "unavailable"}
                return 200, result
            if path == "/introspect" and form is not None:
                result = self.access.get(form.get("token", ""), {"active": False})
                return 200, {**result, **self.introspection_updates.get(result.get("sub", ""), {})}
            if path == "/revoke" and form is not None:
                self.refresh.pop(form.get("token", ""), None)
                return 200, {}
            return 404, {"error": "not_found"}

    def close(self) -> None:
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        for value in (self.codes, self.access, self.refresh):
            value.clear()
        for path in (self.ca, self.keyfile, self.secret):
            path.unlink(missing_ok=True)
