# SPDX-License-Identifier: Apache-2.0
"""Check real OpenSSL backend renewal, pair publication and recovery in private files."""

import hashlib
import importlib.util
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "packaging/remote/keycloak/renew_tls.py"
SPEC = importlib.util.spec_from_file_location("ficc_backend_tls", SCRIPT)
assert SPEC and SPEC.loader
TLS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TLS
SPEC.loader.exec_module(TLS)


def openssl(*arguments):
    result = subprocess.run(["/usr/bin/openssl", *map(str, arguments)], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15,
                            env={"PATH": "/usr/bin", "OPENSSL_CONF": "/dev/null"})
    return result.stdout


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    path = tmp_path_factory.mktemp("identity-tls-keys")
    path.chmod(0o700)
    for name in ("ca", "identity", "database", "wrong"):
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072",
                "-out", path / (name + ".key"))
        (path / (name + ".key")).chmod(0o600)
    openssl("req", "-new", "-x509", "-key", path / "ca.key", "-subj", "/CN=Backend test CA",
            "-days", "3650", "-sha256", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", path / "ca.pem")
    (path / "ca.pem").chmod(0o600)
    (path / "extensions.cnf").write_text(TLS.EXTENSIONS)
    for name in ("identity", "database"):
        openssl("req", "-new", "-key", path / (name + ".key"), "-subj", "/CN=localhost",
                "-out", path / (name + ".csr"))
        openssl("x509", "-req", "-in", path / (name + ".csr"), "-CA", path / "ca.pem",
                "-CAkey", path / "ca.key", "-days", "5", "-sha256", "-set_serial",
                "1" if name == "identity" else "2", "-extfile", path / "extensions.cnf",
                "-out", path / (name + ".pem"))
        (path / (name + ".pem")).chmod(0o600)
    try:
        yield path
    finally:
        shutil.rmtree(path)


@pytest.fixture
def profile_factory(tmp_path, certificates, monkeypatch):
    # Local tests simulate root ownership without sudo or production service access.
    monkeypatch.setattr(TLS, "ROOT_UID", os.getuid())
    monkeypatch.setattr(TLS, "require_root", lambda: None)
    user = pwd.getpwuid(os.getuid()).pw_name
    original, destinations = TLS.command, {}

    def command(arguments, deadline, descriptors, **kwargs):
        if arguments[0] == "/usr/bin/systemctl":
            assert arguments[:2] == ["/usr/bin/systemctl", "reload"]
            assert arguments[2] in destinations
            destinations[arguments[2]].append(arguments)
            return subprocess.CompletedProcess(arguments, 0, b"")
        return original(arguments, deadline, descriptors, **kwargs)

    monkeypatch.setattr(TLS, "command", command)

    def create(index=0, *, distinct=False):
        path = tmp_path / f"profile-{index}"
        path.mkdir(mode=0o700)
        for directory in ("ca", "identity", "database", "run"):
            (path / directory).mkdir(mode=0o700)
        for name in ("ca.pem", "ca.key"):
            shutil.copyfile(certificates / name, path / "ca" / name)
            (path / "ca" / name).chmod(0o600)
        for name in ("identity", "database"):
            for suffix in ("pem", "key"):
                shutil.copyfile(certificates / (name + "." + suffix), path / name / ("server." + suffix))
                (path / name / ("server." + suffix)).chmod(0o600)
        if distinct:
            openssl("req", "-new", "-x509", "-key", path / "ca/ca.key",
                    "-subj", f"/CN=Backend test CA {index}", "-days", "3650", "-sha256",
                    "-set_serial", 10000 + index, "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", path / "ca/ca.pem")
            for offset, name in enumerate(("identity", "database")):
                days = 90 if name == "identity" and index % 2 else 5
                openssl("x509", "-req", "-in", certificates / (name + ".csr"),
                        "-CA", path / "ca/ca.pem", "-CAkey", path / "ca/ca.key", "-days", days,
                        "-set_serial", 20000 + index * 2 + offset, "-sha256",
                        "-extfile", certificates / "extensions.cnf", "-out", path / name / "server.pem")
        service = f"test-postgres-{index}.service"
        calls = destinations[service] = []
        args = TLS.parser().parse_args([
            "--ca-cert", str(path / "ca/ca.pem"), "--ca-key", str(path / "ca/ca.key"),
            "--identity-dir", str(path / "identity"), "--database-dir", str(path / "database"),
            "--identity-user", user, "--database-user", user, "--postgresql-service", service,
            "--lock-file", str(path / "run/renew.lock"),
        ])
        return args, path, calls

    try:
        yield create
    finally:
        for path in tmp_path.glob("profile-*"):
            shutil.rmtree(path)


@pytest.fixture
def profile(profile_factory):
    return profile_factory()


def recovery_profiles(factory, count):
    profiles = [factory(index, distinct=True) for index in range(count)]
    for relative in ("ca/ca.pem", "identity/server.pem", "database/server.pem"):
        assert len({hashlib.sha256((path / relative).read_bytes()).digest()
                    for _args, path, _calls in profiles}) == count
    assert len({args.postgresql_service for args, _path, _calls in profiles}) == count
    return profiles


def profile_states(profiles):
    return [{(name, suffix): (path / name / suffix).read_bytes()
             if (path / name / suffix).exists() else None
             for name in ("identity", "database")
             for suffix in ("server.pem", "server.key", "pending.json")}
            for _args, path, _calls in profiles]


def expected_renewal(index):
    names = ("database",) if index % 2 else ("identity", "database")
    return ["Backend TLS certificate renewed: " + name for name in names]


def check_pair(path, ca, key):
    assert hashlib.sha256((path / "server.key").read_bytes()).digest() == hashlib.sha256(key).digest()
    openssl("verify", "-CAfile", ca, "-purpose", "sslserver", path / "server.pem")
    assert openssl("pkey", "-in", path / "server.key", "-pubout") == openssl(
        "x509", "-in", path / "server.pem", "-pubkey", "-noout")
    assert stat.S_IMODE((path / "server.key").stat().st_mode) == 0o600
    assert (path / "server.key").stat().st_uid == os.getuid()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_renewal_retains_keys_and_prior_pairs(profile, certificates, count):
    args, path, calls = profile
    keys = {name: (path / name / "server.key").read_bytes() for name in ("identity", "database")}
    assert hashlib.sha256(keys["identity"]).digest() != hashlib.sha256(keys["database"]).digest()
    for index in range(count):
        before = {}
        for offset, name in enumerate(("identity", "database")):
            destination = path / name / "server.pem"
            openssl("x509", "-req", "-in", certificates / (name + ".csr"), "-CA", args.ca_cert,
                    "-CAkey", args.ca_key, "-days", "5", "-set_serial", 1000 + index * 2 + offset,
                    "-extfile", certificates / "extensions.cnf", "-out", destination)
            before[name] = destination.read_bytes()
        result = TLS.execute(args)
        assert result == ["Backend TLS certificate renewed: identity", "Backend TLS certificate renewed: database"]
        assert len(calls) == index + 1
        for name in ("identity", "database"):
            directory = path / name
            assert os.readlink(directory / "server.pem") == "current/server.pem"
            assert os.readlink(directory / "server.key") == "current/server.key"
            assert (directory / "previous/server.pem").read_bytes() == before[name]
            assert (directory / "server.pem").read_bytes() != before[name]
            check_pair(directory, args.ca_cert, keys[name])
            assert len(list((directory / "versions").iterdir())) == 2
            assert stat.S_IMODE(directory.stat().st_mode) == 0o750
            assert not (directory / "pending.json").exists()
        assert stat.S_IMODE(args.ca_key.stat().st_mode) == 0o600
    assert list((path / "run").iterdir()) == [path / "run/renew.lock"]


def test_noop_does_not_reload_or_create_versions(profile):
    args, path, calls = profile
    TLS.execute(args)
    calls.clear()
    before = {name: (path / name / "server.pem").read_bytes() for name in ("identity", "database")}
    assert TLS.execute(args) == ["Backend TLS certificates do not need renewal."]
    assert not calls
    assert all((path / name / "server.pem").read_bytes() == data for name, data in before.items())


@pytest.mark.parametrize("fault", ["ca-pair", "ca-life", "leaf-pair", "leaf-name", "leaf-ca",
                                   "ca-permission", "leaf-permission", "ca-link", "version-link"])
def test_invalid_profile_does_not_publish(profile, certificates, fault):
    args, path, calls = profile
    if fault in ("ca-pair", "leaf-pair"):
        target = args.ca_key if fault == "ca-pair" else path / "database/server.key"
        target.write_bytes((certificates / "wrong.key").read_bytes())
    elif fault == "ca-life":
        openssl("req", "-new", "-x509", "-key", args.ca_key, "-subj", "/CN=Backend test CA",
                "-days", "30", "-addext", "basicConstraints=critical,CA:TRUE", "-out", args.ca_cert)
    elif fault in ("leaf-name", "leaf-ca"):
        extensions = path / "bad.cnf"
        extensions.write_text(TLS.EXTENSIONS.replace("DNS:localhost", "DNS:other.example")
                              if fault == "leaf-name" else TLS.EXTENSIONS.replace("CA:FALSE", "CA:TRUE"))
        openssl("x509", "-req", "-in", certificates / "database.csr", "-CA", args.ca_cert, "-CAkey", args.ca_key,
                "-days", "5", "-set_serial", "87", "-extfile", extensions,
                "-out", path / "database/server.pem")
    elif fault in ("ca-permission", "leaf-permission"):
        (args.ca_key if fault == "ca-permission" else path / "database/server.key").chmod(0o644)
    elif fault == "ca-link":
        original = path / "ca/original.key"
        args.ca_key.rename(original)
        args.ca_key.symlink_to(original)
    else:
        target = path / "unrelated"
        target.mkdir(mode=0o700)
        (path / "database/versions").symlink_to(target, target_is_directory=True)
    with pytest.raises((ValueError, OSError)):
        TLS.execute(args)
    assert not calls
    assert not (path / "identity/current").exists()
    assert not (path / "database/current").exists()
    if fault == "version-link":
        assert not list((path / "unrelated").iterdir())


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_reload_failure_restores_both_prior_pairs(profile_factory, monkeypatch, count):
    profiles = recovery_profiles(profile_factory, count)
    expected = profile_states(profiles)
    original, failed = TLS.command, set()

    def command(arguments, deadline, descriptors, **kwargs):
        if arguments[0] == "/usr/bin/systemctl" and arguments[2] not in failed:
            failed.add(arguments[2])
            raise ValueError("Injected reload failure")
        return original(arguments, deadline, descriptors, **kwargs)

    monkeypatch.setattr(TLS, "command", command)
    for index, (args, path, calls) in enumerate(profiles):
        with pytest.raises(ValueError, match="Injected reload failure"):
            TLS.execute(args)
        assert profile_states(profiles) == expected
        assert len(calls) == 1
        assert TLS.execute(args) == expected_renewal(index)
        assert len(calls) == 2
        for name in ("identity", "database"):
            check_pair(path / name, args.ca_cert, expected[index][name, "server.key"])
            assert not (path / name / "pending.json").exists()
        expected[index] = profile_states([profiles[index]])[0]
        assert profile_states(profiles) == expected
    assert len(failed) == count


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_interrupted_publication_recovers_before_new_renewal(profile_factory, count):
    profiles = recovery_profiles(profile_factory, count)
    old = profile_states(profiles)
    for index, (args, path, calls) in enumerate(profiles):
        assert TLS.execute(args) == expected_renewal(index)
        for name in ("identity", "database"):
            directory = path / name
            if not (directory / "previous").exists():
                continue
            pending = {"old": os.readlink(directory / "previous").split("/")[1],
                       "new": os.readlink(directory / "current").split("/")[1]}
            (directory / "pending.json").write_text(json.dumps(pending))
            (directory / "pending.json").chmod(0o600)
        calls.clear()
    expected = profile_states(profiles)
    for index, (args, path, calls) in enumerate(profiles):
        assert TLS.execute(args) == ["Interrupted backend TLS renewal was rolled back."]
        assert len(calls) == 1
        expected[index] = old[index]
        assert profile_states(profiles) == expected
        for name in ("identity", "database"):
            check_pair(path / name, args.ca_cert, old[index][name, "server.key"])
        assert list((path / "run").iterdir()) == [path / "run/renew.lock"]


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_failed_rollback_reload_keeps_recovery_records(profile_factory, monkeypatch, count):
    profiles = recovery_profiles(profile_factory, count)
    old = profile_states(profiles)
    expected = list(old)
    original = TLS.command

    def unavailable(arguments, deadline, descriptors, **kwargs):
        if arguments[0] == "/usr/bin/systemctl":
            raise ValueError("Injected unavailable service")
        return original(arguments, deadline, descriptors, **kwargs)

    monkeypatch.setattr(TLS, "command", unavailable)
    for index, (args, path, calls) in enumerate(profiles):
        with pytest.raises(ValueError, match="unavailable service"):
            TLS.execute(args)
        current = profile_states([profiles[index]])[0]
        for name in ("identity", "database"):
            assert current[name, "server.pem"] == old[index][name, "server.pem"]
            assert current[name, "server.key"] == old[index][name, "server.key"]
            assert bool(current[name, "pending.json"]) == (name == "database" or index % 2 == 0)
        expected[index] = current
        assert profile_states(profiles) == expected
        assert not calls
    monkeypatch.setattr(TLS, "command", original)
    for index, (args, _path, calls) in enumerate(profiles):
        assert TLS.execute(args) == ["Interrupted backend TLS renewal was rolled back."]
        expected[index] = old[index]
        assert profile_states(profiles) == expected
        assert len(calls) == 1


def test_migration_always_exposes_a_matching_pair(profile, monkeypatch):
    args, path, _calls = profile
    keys = {name: (path / name / "server.key").read_bytes() for name in ("identity", "database")}
    original, observations = TLS.Backend.link, []

    def observe(backend, name, target):
        original(backend, name, target)
        check_pair(path / backend.name, args.ca_cert, keys[backend.name])
        observations.append((backend.name, name))

    monkeypatch.setattr(TLS.Backend, "link", observe)
    TLS.execute(args)
    assert len(observations) == 10


def test_explicit_modes_work_under_restrictive_umask(profile):
    args, path, _calls = profile
    previous = os.umask(0o777)
    try:
        TLS.execute(args)
    finally:
        os.umask(previous)
    for name in ("identity", "database"):
        assert stat.S_IMODE((path / name / "versions").stat().st_mode) == 0o750
        assert stat.S_IMODE((path / name / "current").stat().st_mode) == 0o750
        assert stat.S_IMODE((path / name / "server.key").stat().st_mode) == 0o600
    assert stat.S_IMODE(args.ca_key.stat().st_mode) == 0o600


def test_nonroot_cli_fails_before_profile_access(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("The CLI refusal requires an unprivileged test process")
    with pytest.raises(ValueError, match="requires root"):
        TLS.require_root()
    result = subprocess.run([sys.executable, str(SCRIPT), "--ca-cert", str(tmp_path / "missing.pem")],
                            capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 1
    assert result.stdout == "Backend TLS renewal failed; check the private certificate profile and service state.\n"
    assert not result.stderr
    assert not list(tmp_path.iterdir())


def test_subprocess_timeout_and_service_name_are_bounded(profile, monkeypatch):
    args, _path, calls = profile
    args.postgresql_service = "name.service;unexpected"
    with pytest.raises(ValueError, match="service name"):
        TLS.execute(args)
    assert not calls
    with pytest.raises(ValueError, match="deadline"):
        TLS.command(["/usr/bin/openssl", "version"], time.monotonic() - 1, ())


def test_backend_directories_cannot_alias(profile):
    args, _path, calls = profile
    args.database_dir = args.identity_dir
    with pytest.raises(ValueError, match="distinct"):
        TLS.execute(args)
    assert not calls


def test_private_contents_do_not_enter_failure_output(profile, monkeypatch, capsys):
    args, _path, calls = profile
    args.ca_key.write_bytes(b"PRIVATE_CA_KEY_MARKER_DO_NOT_LOG")
    monkeypatch.setattr(TLS, "parser", lambda: SimpleNamespace(parse_args=lambda: args))
    assert TLS.main() == 1
    captured = capsys.readouterr()
    assert "PRIVATE_CA_KEY_MARKER" not in captured.out + captured.err
    assert not captured.err and not calls
