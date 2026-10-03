# SPDX-License-Identifier: Apache-2.0
"""Serve one TLS append-only API; inputs are private paths and output is durable audit storage."""

import argparse
import hashlib
import hmac
import os
import re
import sqlite3
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from ficc import secret_io
from ficc.audit_sdk import MAX_BATCH, AuditError, batch, encoded
from ficc.settings import private_directory
from ficc.state_lock import StateLock


class Journal:
    def __init__(self, path):
        self.lock = StateLock(path)
        try:
            self.path = Path(path)
            database = self.path / "audit.sqlite3"
            if database.exists() or database.is_symlink():
                with secret_io.directory(self.path) as folder:
                    fd = os.open(database.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=folder)
                    try:
                        secret_io.checked(os.fstat(fd))
                    finally:
                        os.close(fd)
            else:
                fd = os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            self.db = sqlite3.connect(database, check_same_thread=False)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("CREATE TABLE IF NOT EXISTS batches (stream TEXT NOT NULL, sequence INTEGER NOT NULL, "
                            "digest TEXT NOT NULL, through INTEGER NOT NULL, body BLOB NOT NULL, PRIMARY KEY(stream,sequence))")
            self.db.commit()
            with secret_io.directory(self.path) as folder:
                os.fsync(folder)
        except BaseException:
            self.lock.close()
            raise

    def append(self, raw):
        value = batch(raw)
        digest = hashlib.sha256(raw).hexdigest()
        with self.db:
            previous = self.db.execute("SELECT digest FROM batches WHERE stream=? AND sequence=?",
                                       (value["stream_id"], value["sequence"])).fetchone()
            if previous:
                if not hmac.compare_digest(previous[0], digest):
                    raise AuditError("audit_acknowledgement")
            else:
                last = self.db.execute("SELECT sequence,through FROM batches WHERE stream=? ORDER BY sequence DESC LIMIT 1",
                                       (value["stream_id"],)).fetchone() or (0, 0)
                if (value["sequence"], value["after"]) != (last[0] + 1, last[1]):
                    raise AuditError("audit_acknowledgement")
                self.db.execute("INSERT INTO batches VALUES (?,?,?,?,?)",
                                (value["stream_id"], value["sequence"], digest, value["through"], raw))
        # Exiting the transaction precedes the acknowledgement, including duplicate replies.
        return {"version": 1, "stream_id": value["stream_id"], "sequence": value["sequence"], "sha256": digest, "durable": True}

    def close(self):
        try:
            self.db.close()
        finally:
            self.lock.close()


class Handler(BaseHTTPRequestHandler):
    server_version = "FICCAudit"
    sys_version = ""

    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            if self.path != "/v1/audit/append":
                self.send_error(404)
                return
            expected = "Bearer " + self.server.token  # type: ignore[attr-defined]
            received = self.headers.get_all("Authorization", [])
            if len(received) != 1 or not hmac.compare_digest(received[0], expected):
                self.send_error(401)
                return
            lengths = self.headers.get_all("Content-Length", [])
            if (len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,6}", lengths[0])
                    or not 0 < int(lengths[0]) <= MAX_BATCH or self.headers.get("Transfer-Encoding")):
                self.send_error(413)
                return
            raw = self.rfile.read(int(lengths[0]))
            if len(raw) != int(lengths[0]):
                raise AuditError()
            result = self.server.journal.append(raw)  # type: ignore[attr-defined]
            data = encoded(result)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (ValueError, OSError, sqlite3.Error):
            # No raw driver errors, credentials, URLs or event contents leave the endpoint.
            self.send_error(503, "Durable append unavailable")


class Server(HTTPServer):
    journal: Journal
    token: str
    context: ssl.SSLContext

    def get_request(self):
        stream, address = self.socket.accept()
        stream.settimeout(5)
        try:
            return self.context.wrap_socket(stream, server_side=True), address
        except BaseException:
            stream.close()
            raise


def server(address, journal, token, cert, key):
    if not re.fullmatch(rb"[A-Za-z0-9_-]{32,256}", token):
        raise ValueError("Use a private file containing one 32 to 256 character append token, without a newline.")
    secret_io.private_file(key, 32768)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    result = Server(address, Handler)
    try:
        result.context = context
        result.journal = journal
        result.token = token.decode("ascii")
        return result
    except BaseException:
        result.server_close()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description="Serve durable TLS audit appends under separate destination custody.")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--cert-file", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    private_directory(args.state_dir)
    journal = Journal(args.state_dir)
    try:
        collector = server((args.listen, args.port), journal, secret_io.private_file(args.token_file, 256), args.cert_file, args.key_file)
        try:
            collector.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            collector.server_close()
    finally:
        journal.close()


if __name__ == "__main__":
    main()
