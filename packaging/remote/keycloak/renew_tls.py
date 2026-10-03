#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Renew private backend TLS certificates and recover interrupted pair publication.
# Inputs: root-owned CA, backend pairs and CLI paths. Output: status. Exit: 0 success, 1 failure.
"""Renew RSA3072 backend leaf certificates without changing their private keys.

Run as root. Keycloak must enable automatic certificate reload; the supplied
profile uses KC_HTTPS_CERTIFICATES_RELOAD_PERIOD=60s. PostgreSQL receives a reload.
Routine renewal does not restart services or invalidate sessions. Private-key
rotation is a separate coordinated operation. Both backends retain their old
pair for recovery. A pending transaction is rolled back before a later renewal.
Custom directories need corresponding ReadWritePaths changes in the service unit.
"""

import argparse
import contextlib
import fcntl
import itertools
import json
import os
import pwd
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ROOT_UID = 0
MAX_FILE = 64 * 1024
DAY = 86400
LEAF_DAYS = 90
RENEW_DAYS = 30
TOTAL_SECONDS = 120
VERSION = re.compile(r"[0-9a-f]{32}")
EXTENSIONS = ("basicConstraints=critical,CA:FALSE\n"
              "keyUsage=critical,digitalSignature,keyEncipherment\n"
              "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")


def require_root() -> None:
    if os.geteuid() != 0:
        raise ValueError("Backend TLS renewal requires root.")


class Directory:
    """Pin a root-owned directory so a renamed ancestor cannot redirect writes."""

    def __init__(self, path: Path, *, group: int | None = None, mode: int | None = None):
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("TLS paths must be absolute and must not contain parent traversal.")
        self.fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in path.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                | os.O_CLOEXEC, dir_fd=self.fd)
                os.close(self.fd)
                self.fd = child
            info = os.fstat(self.fd)
            if info.st_uid != ROOT_UID or info.st_mode & 0o022:
                raise ValueError("A TLS directory is not owned and protected by root.")
            if group is not None:
                os.fchown(self.fd, ROOT_UID, group)
            if mode is not None:
                os.fchmod(self.fd, mode)
            self.path = Path(f"/proc/self/fd/{self.fd}")
        except BaseException:
            os.close(self.fd)
            raise

    def close(self) -> None:
        os.close(self.fd)


def read_file(path: Path, owner: int | tuple[int, ...], mode: int | None = None) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        owners = (owner,) if isinstance(owner, int) else owner
        if (not stat.S_ISREG(before.st_mode) or before.st_uid not in owners or before.st_nlink != 1
                or before.st_mode & 0o6022 or before.st_size > MAX_FILE
                or (mode is not None and stat.S_IMODE(before.st_mode) != mode)):
            raise ValueError("A TLS file has unsafe ownership, permissions or size.")
        data = source.read(MAX_FILE + 1)
        after = os.fstat(source.fileno())
        if (len(data) != before.st_size or any(getattr(before, key) != getattr(after, key)
                for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
            raise ValueError("A TLS file changed during its read.")
        return data


def write_file(path: Path, data: bytes, owner: int = ROOT_UID, group: int = 0,
               mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        os.fchmod(target.fileno(), mode)
        os.fchown(target.fileno(), owner, group)
        target.write(data)
        target.flush()
        os.fsync(target.fileno())


def command(arguments: list[str], deadline: float, descriptors: tuple[int, ...],
            *, accepted: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("The TLS renewal deadline expired.")
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=min(10, remaining),
                                pass_fds=descriptors, check=False,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                                     "OPENSSL_CONF": "/dev/null"})
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("A backend TLS command failed or timed out.") from None
    if result.returncode not in accepted or len(result.stdout) > MAX_FILE:
        raise ValueError("A backend TLS validation or service command failed.")
    return result


class Certificates:
    def __init__(self, work: Path, ca_cert: bytes, ca_key: bytes, descriptors: tuple[int, ...]):
        self.work, self.descriptors = work, descriptors
        self.deadline = time.monotonic() + TOTAL_SECONDS
        if ca_cert.count(b"-----BEGIN CERTIFICATE-----") != 1:
            raise ValueError("The TLS profile must contain exactly one root CA certificate.")
        self.ca, self.key = work / "ca.pem", work / "ca.key"
        write_file(self.ca, ca_cert, ROOT_UID, os.getgid())
        write_file(self.key, ca_key, ROOT_UID, os.getgid())
        self.run("verify", "-CAfile", self.ca, "-check_ss_sig", self.ca)
        details = self.run("x509", "-in", self.ca, "-noout", "-ext", "basicConstraints")
        names = self.run("x509", "-in", self.ca, "-noout", "-subject", "-issuer",
                         "-nameopt", "RFC2253").decode("ascii").splitlines()
        if (b"CA:TRUE" not in details or len(names) != 2
                or names[0].removeprefix("subject=") != names[1].removeprefix("issuer=")):
            raise ValueError("The configured certificate is not a self-signed root CA.")
        if self.public(self.key) != self.run("x509", "-in", self.ca, "-pubkey", "-noout"):
            raise ValueError("The root CA certificate and key do not match.")
        self.run("x509", "-in", self.ca, "-noout", "-checkend", (LEAF_DAYS + 1) * DAY)

    def run(self, *arguments: object) -> bytes:
        return command(["/usr/bin/openssl", *map(str, arguments)], self.deadline,
                       self.descriptors).stdout

    def public(self, key: Path) -> bytes:
        return self.run("pkey", "-in", key, "-passin", "pass:", "-pubout")

    def validate(self, cert: Path, key: Path, *, fresh: bool = False) -> bool:
        self.run("rsa", "-in", key, "-passin", "pass:", "-check", "-noout")
        public = self.public(key)
        public_file = self.work / ("public-" + secrets.token_hex(8))
        write_file(public_file, public, ROOT_UID, os.getgid())
        try:
            info = self.run("pkey", "-pubin", "-in", public_file, "-text_pub", "-noout")
        finally:
            public_file.unlink()
        if (not info.startswith(b"Public-Key: (3072 bit)")
                or public != self.run("x509", "-in", cert, "-pubkey", "-noout")):
            raise ValueError("A backend certificate does not match its RSA3072 key.")
        self.run("verify", "-CAfile", self.ca, "-purpose", "sslserver", "-no_check_time", cert)
        for option, expected in (("-checkhost", "localhost"), ("-checkip", "127.0.0.1")):
            self.run("x509", "-in", cert, "-noout", option, expected)
        san = self.run("x509", "-in", cert, "-noout", "-ext", "subjectAltName").decode("ascii")
        names = {part.strip() for part in san.splitlines()[-1].split(",")}
        if names != {"DNS:localhost", "IP Address:127.0.0.1"}:
            raise ValueError("A backend certificate has unexpected subject names.")
        if b"CA:TRUE" in self.run("x509", "-in", cert, "-noout", "-ext", "basicConstraints"):
            raise ValueError("A backend certificate must not be a CA.")
        eku = self.run("x509", "-in", cert, "-noout", "-ext", "extendedKeyUsage")
        if eku.decode("ascii").splitlines()[-1].strip() != "TLS Web Server Authentication":
            raise ValueError("A backend certificate must permit server authentication only.")
        start = self.run("x509", "-in", cert, "-noout", "-startdate").decode("ascii").strip()
        if ssl.cert_time_to_seconds(start.removeprefix("notBefore=")) > time.time():
            raise ValueError("A backend certificate is not yet valid.")
        result = command(["/usr/bin/openssl", "x509", "-in", str(cert), "-noout", "-checkend",
                          str((LEAF_DAYS - 1 if fresh else RENEW_DAYS) * DAY)],
                         self.deadline, self.descriptors, accepted=(0, 1))
        if fresh and result.returncode:
            raise ValueError("A renewed backend certificate has insufficient lifetime.")
        return result.returncode == 1

    def issue(self, cert: Path, key: Path) -> None:
        request, extensions = cert.parent / "request.pem", cert.parent / "extensions.cnf"
        write_file(extensions, EXTENSIONS.encode("ascii"), ROOT_UID, os.getgid())
        write_file(request, b"", ROOT_UID, os.getgid())
        try:
            self.run("req", "-new", "-sha256", "-key", key, "-passin", "pass:",
                     "-subj", "/CN=localhost", "-out", request)
            self.run("x509", "-req", "-in", request, "-CA", self.ca, "-CAkey", self.key,
                     "-passin", "pass:", "-set_serial", hex(secrets.randbits(159) | 1),
                     "-days", LEAF_DAYS, "-sha256", "-extfile", extensions, "-out", cert)
        finally:
            request.unlink(missing_ok=True)
            extensions.unlink(missing_ok=True)
        self.validate(cert, key, fresh=True)


@dataclass
class Backend:
    name: str
    directory: Directory
    uid: int
    gid: int
    old: str | None = None
    new: str | None = None
    renew: bool = False

    @property
    def path(self) -> Path:
        return self.directory.path

    def version(self, name: str) -> Path:
        if not VERSION.fullmatch(name):
            raise ValueError("The backend certificate version is invalid.")
        path = self.path / "versions" / name
        for directory in (path.parent, path):
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID
                    or stat.S_IMODE(info.st_mode) != 0o750 or info.st_gid != self.gid):
                raise ValueError("The backend certificate directory is unsafe.")
        return path

    def pointer(self, name: str) -> str | None:
        path = self.path / name
        if not os.path.lexists(path):
            return None
        info = path.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != ROOT_UID:
            raise ValueError("A backend version pointer is unsafe.")
        target = os.readlink(path)
        if not target.startswith("versions/") or not VERSION.fullmatch(target[9:]):
            raise ValueError("A backend version pointer is invalid.")
        self.version(target[9:])
        return target[9:]

    def link(self, name: str, target: str) -> None:
        temporary = self.path / (".link-" + secrets.token_hex(8))
        try:
            os.symlink(target, temporary)
            os.replace(temporary, self.path / name)
            os.fsync(self.directory.fd)
        finally:
            temporary.unlink(missing_ok=True)

    def data(self) -> tuple[bytes, bytes]:
        current = self.pointer("current")
        values = []
        for name, owner, mode in (("server.pem", (ROOT_UID, self.uid), None),
                                  ("server.key", self.uid, 0o600)):
            path = self.path / name
            if path.is_symlink():
                if path.lstat().st_uid != ROOT_UID or os.readlink(path) != "current/" + name or not current:
                    raise ValueError("A backend certificate link is invalid.")
                path = self.version(current) / name
            values.append(read_file(path, owner, mode))
        return values[0], values[1]

    def save(self, cert: bytes, key: bytes) -> str:
        directory = self.path / "versions"
        if not os.path.lexists(directory):
            directory.mkdir(mode=0o700)
            directory.chmod(0o750)
            os.chown(directory, ROOT_UID, self.gid)
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID
                or info.st_gid != self.gid or stat.S_IMODE(info.st_mode) != 0o750):
            raise ValueError("The backend version directory is unsafe.")
        name = secrets.token_hex(16)
        path = directory / name
        path.mkdir(mode=0o700)
        path.chmod(0o750)
        os.chown(path, ROOT_UID, self.gid)
        self.version(name)
        write_file(path / "server.pem", cert, ROOT_UID, self.gid, 0o644)
        write_file(path / "server.key", key, self.uid, self.gid)
        with directory_fd(path) as descriptor:
            os.fsync(descriptor)
        with directory_fd(directory) as descriptor:
            os.fsync(descriptor)
        return name

    def journal(self) -> dict | None:
        path = self.path / "pending.json"
        if not os.path.lexists(path):
            return None
        result = json.loads(read_file(path, ROOT_UID, 0o600))
        if (not isinstance(result, dict) or set(result) != {"old", "new"}
                or any(not isinstance(value, str) or not VERSION.fullmatch(value)
                       for value in result.values())):
            raise ValueError("The TLS recovery record is invalid.")
        return result

    def publish(self) -> None:
        assert self.old and self.new
        path = self.path / (".pending-" + secrets.token_hex(8))
        write_file(path, json.dumps({"old": self.old, "new": self.new}).encode(), ROOT_UID, self.gid)
        os.replace(path, self.path / "pending.json")
        os.fsync(self.directory.fd)
        if self.pointer("current") is None:
            self.link("current", "versions/" + self.old)
        for name in ("server.pem", "server.key"):
            self.link(name, "current/" + name)
        self.link("previous", "versions/" + self.old)
        self.link("current", "versions/" + self.new)

    def restore(self, pending: dict) -> None:
        self.link("current", "versions/" + pending["old"])
        for name in ("server.pem", "server.key"):
            self.link(name, "current/" + name)

    def finish(self) -> None:
        (self.path / "pending.json").unlink(missing_ok=True)
        os.fsync(self.directory.fd)

    def prune(self) -> None:
        versions = self.path / "versions"
        if not os.path.lexists(versions):
            return
        info = versions.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID
                or info.st_gid != self.gid or stat.S_IMODE(info.st_mode) != 0o750):
            raise ValueError("The backend version directory is unsafe.")
        keep = {self.pointer("current"), self.pointer("previous")}
        paths = list(itertools.islice(versions.iterdir(), 17))
        if len(paths) > 16:
            raise ValueError("The backend certificate history exceeds its limit.")
        for path in paths:
            if path.name not in keep:
                self.version(path.name)
                shutil.rmtree(path)
        with directory_fd(versions) as descriptor:
            os.fsync(descriptor)


@contextlib.contextmanager
def directory_fd(path: Path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def execute(args: argparse.Namespace) -> list[str]:
    require_root()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_@.:-]*\.service", args.postgresql_service):
        raise ValueError("The PostgreSQL service name is invalid.")
    with contextlib.ExitStack() as stack:
        def directory(path: Path, **options) -> Directory:
            result = Directory(path, **options)
            stack.callback(result.close)
            return result

        lockdir = directory(args.lock_file.parent)
        lock = os.open(lockdir.path / args.lock_file.name,
                       os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        stack.callback(os.close, lock)
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_nlink != 1:
            raise ValueError("The TLS renewal lock is unsafe.")
        os.fchmod(lock, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another TLS renewal is active.") from None
        ca_dir, key_dir = directory(args.ca_cert.parent), directory(args.ca_key.parent)
        ca = read_file(ca_dir.path / args.ca_cert.name, ROOT_UID)
        key = read_file(key_dir.path / args.ca_key.name, ROOT_UID, 0o600)
        backends = []
        for name, path, account in (("identity", args.identity_dir, args.identity_user),
                                    ("database", args.database_dir, args.database_user)):
            user = pwd.getpwnam(account)
            backends.append(Backend(name, directory(path, group=user.pw_gid, mode=0o750),
                                    user.pw_uid, user.pw_gid))
        identities = {(os.fstat(backend.directory.fd).st_dev, os.fstat(backend.directory.fd).st_ino)
                      for backend in backends}
        if len(identities) != len(backends):
            raise ValueError("Backend TLS directories must be distinct.")
        descriptors = tuple({lockdir.fd, ca_dir.fd, key_dir.fd,
                             *(backend.directory.fd for backend in backends)})
        temporary = stack.enter_context(tempfile.TemporaryDirectory(prefix="renew-", dir=lockdir.path))
        work = Path(temporary)
        work.chmod(0o700)
        certificates = Certificates(work, ca, key, descriptors)

        def reload_database() -> None:
            command(["/usr/bin/systemctl", "reload", args.postgresql_service],
                    time.monotonic() + 10, descriptors)

        pending = [(backend, backend.journal()) for backend in backends]
        recover = [(backend, value) for backend, value in pending if value]
        if recover:
            for backend, value in recover:
                old = backend.version(value["old"])
                read_file(old / "server.pem", ROOT_UID)
                read_file(old / "server.key", backend.uid, 0o600)
                certificates.validate(old / "server.pem", old / "server.key")
            for backend, value in recover:
                backend.restore(value)
            if any(backend.name == "database" for backend, _ in recover):
                reload_database()
            for backend, _ in recover:
                backend.finish()
                backend.prune()
            return ["Interrupted backend TLS renewal was rolled back."]

        for backend in backends:
            cert, private = backend.data()
            staging = work / backend.name
            staging.mkdir(mode=0o700)
            staging.chmod(0o700)
            write_file(staging / "server.pem", cert, ROOT_UID, os.getgid())
            write_file(staging / "server.key", private, ROOT_UID, os.getgid())
            backend.renew = certificates.validate(staging / "server.pem", staging / "server.key")
        changed = [backend for backend in backends if backend.renew]
        if not changed:
            return ["Backend TLS certificates do not need renewal."]
        for backend in changed:
            backend.prune()
            staging = work / backend.name
            old_cert, old_key = (staging / "server.pem").read_bytes(), (staging / "server.key").read_bytes()
            backend.old = backend.pointer("current") or backend.save(old_cert, old_key)
            certificates.issue(staging / "server.pem", staging / "server.key")
            if backend.data() != (old_cert, old_key):
                raise ValueError("The active backend pair changed before publication.")
            backend.new = backend.save((staging / "server.pem").read_bytes(), old_key)
        if time.monotonic() > certificates.deadline - 30:
            raise ValueError("Insufficient time remains to publish backend certificates safely.")
        try:
            for backend in changed:
                backend.publish()
            if any(backend.name == "database" for backend in changed):
                reload_database()
        except BaseException:
            for backend in changed:
                recovery = backend.journal()
                if recovery:
                    backend.restore(recovery)
            if any(backend.name == "database" and backend.journal() for backend in changed):
                reload_database()
            for backend in changed:
                backend.finish()
            raise
        for backend in changed:
            backend.finish()
            backend.prune()
        return ["Backend TLS certificate renewed: " + backend.name for backend in changed]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--ca-cert", type=Path, default=Path("/etc/ficc-identity/tls/ca.pem"))
    result.add_argument("--ca-key", type=Path, default=Path("/etc/ficc-identity/tls/ca.key"))
    result.add_argument("--identity-dir", type=Path, default=Path("/etc/ficc-identity/tls"))
    result.add_argument("--database-dir", type=Path, default=Path("/etc/postgresql/18/main/ficc-tls"))
    result.add_argument("--identity-user", default="ficc-identity")
    result.add_argument("--database-user", default="postgres")
    result.add_argument("--postgresql-service", default="postgresql@18-main.service")
    result.add_argument("--lock-file", type=Path, default=Path("/run/ficc-identity-tls/renew.lock"))
    return result


def main() -> int:
    try:
        for message in execute(parser().parse_args()):
            print(message)
        return 0
    except Exception:
        print("Backend TLS renewal failed; check the private certificate profile and service state.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
