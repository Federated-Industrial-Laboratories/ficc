# SPDX-License-Identifier: Apache-2.0
"""Relay real CA mutations through controlled HTTPS response faults."""

import contextlib
import json
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from conftest import write_private
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def intermediate_key(authority):
    return serialization.load_pem_private_key(
        (authority.home / "secrets/intermediate_ca_key").read_bytes(),
        (authority.directory / "password").read_bytes())


def changed_certificate(pem, authority, fault):
    original = x509.load_pem_x509_certificate(pem.encode())
    key = original.public_key()
    subject = original.subject
    before, after = original.not_valid_before_utc, original.not_valid_after_utc
    if fault == "key":
        key = ec.generate_private_key(ec.SECP256R1()).public_key()
    if fault == "identity":
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "f" * 32)])
    if fault == "expired":
        before, after = datetime.now(UTC) - timedelta(hours=2), datetime.now(UTC) - timedelta(hours=1)
    if fault == "lifetime":
        after += timedelta(hours=1)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(original.issuer)
               .public_key(key).serial_number(original.serial_number).not_valid_before(before)
               .not_valid_after(after))
    for extension in original.extensions:
        value = extension.value
        if fault == "usage" and isinstance(value, x509.ExtendedKeyUsage):
            value = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        if fault == "ca" and isinstance(value, x509.BasicConstraints):
            value = x509.BasicConstraints(True, 0)
        builder = builder.add_extension(value, extension.critical)
    issuer = ec.generate_private_key(ec.SECP256R1()) if fault == "signature" \
        else intermediate_key(authority)
    return builder.sign(issuer, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


@contextlib.contextmanager
def faulty_authority(authority, directory):
    private_key = ec.generate_private_key(ec.SECP256R1())
    issuer = x509.load_pem_x509_certificate((authority.home / "certs/intermediate_ca.crt").read_bytes())
    now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])).issuer_name(issuer.subject)
        .public_key(private_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(intermediate_key(authority), hashes.SHA256()))
    cert, key = directory / "proxy.crt", directory / "proxy.key"
    write_private(cert, certificate.public_bytes(serialization.Encoding.PEM)
                  + issuer.public_bytes(serialization.Encoding.PEM))
    write_private(key, private_key.private_bytes(serialization.Encoding.PEM,
                  serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    state = {"mode": "good", "requests": [], "issued": [], "stopped": threading.Event(),
             "observed": threading.Event()}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            try:
                self.execute()
            except (OSError, ssl.SSLError):
                pass

        def execute(self):
            length = int(self.headers["content-length"])
            assert 0 < length < 16384
            body = json.loads(self.rfile.read(length))
            csr = x509.load_pem_x509_csr(body["csr"].encode()) if "csr" in body else None
            state["requests"].append(csr.subject.rfc4514_string() if csr else body["serial"])
            state["observed"].set()
            mode = state["mode"]
            if mode == "slow":
                state["stopped"].wait(2)
            upstream = authority.client.post(authority.config["ca_url"] + self.path, json=body)
            data = upstream.json()
            if self.path == "/sign" and upstream.status_code == 201:
                state["issued"].append(x509.load_pem_x509_certificate(data["crt"].encode()).serial_number)
            status = upstream.status_code
            headers = {"Content-Type": "application/json"}
            if mode in {"key", "identity", "expired", "lifetime", "usage", "ca", "signature"}:
                data["certChain"][0] = changed_certificate(data["certChain"][0], authority, mode)
            raw = json.dumps(data).encode()
            if mode == "oversize":
                raw = b"x" * 65537
            elif mode == "duplicate":
                raw = b'{"certChain": [], "certChain": []}'
            elif mode == "number":
                raw = b'{"number": NaN}'
            elif mode == "compressed":
                headers["Content-Encoding"] = "gzip"
            elif mode == "redirect":
                status, headers["Location"] = 307, "/redirected"
            elif mode == "html":
                headers["Content-Type"] = "text/html"
            elif mode == "private-error":
                status, raw = 500, b"PRIVATE_AUTHORITY_RESPONSE"
            elif mode == "disconnect":
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            elif mode == "wrong-duplicate":
                status, raw = 400, json.dumps({"status": 400, "message":
                    "The request could not be completed: certificate with serial number '7' "
                    "is already revoked."}).encode()
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            if mode == "drip":
                for byte in raw:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    if state["stopped"].wait(0.08):
                        break
            else:
                self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {**authority.config, "ca_url": f"https://localhost:{server.server_port}",
               "request_seconds": 1}, state
    finally:
        state["stopped"].set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
