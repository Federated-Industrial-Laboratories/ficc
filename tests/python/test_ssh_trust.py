# SPDX-License-Identifier: Apache-2.0
"""Check distinct SSH certificate bindings, current revocation and bounded lifetime."""

import asyncio
import base64
import json
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_ssh_trust_support import fixture, krl, save, signed

from ficc.errors import Failure
from ficc.settings import Settings
from ficc.ssh import SSH
from ficc.ssh_trust import TRUST_ERRORS, snapshot
from ficc.ssh_trust_command import verify
from ficc.ssh_trust_connection import Arguments, Connection, completed, prepare


def handshake(connection, path):
    kind, key = path.read_text().split()[:2]
    return verify(connection.directory, "HOSTNAME", kind, key)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_distinct_revoked_certificates_keep_other_connections(tmp_path, count):
    state, _, revoked, _, rows = fixture(tmp_path, count)
    connections = [prepare(state, row["node"], row["config"])[0] for row in rows]
    try:
        for row, connection in zip(rows, connections, strict=True):
            authority = handshake(connection, row["host_certificate"])
            assert authority.startswith("@cert-authority " + row["node"]["host_principal"] + " ")
            connection.check()
        assert len({value.checked_host for value in connections}) == count
        for selected in reversed(range(count)):
            krl(revoked, rows[selected]["host_certificate"])
            for index, connection in enumerate(connections):
                if index == selected:
                    with pytest.raises(Failure) as refused:
                        connection.check()
                    assert refused.value.code == "ssh_trust_revoked"
                else:
                    connection.check()
                    assert connection.checked_host == rows[index]["host_certificate"].read_bytes()
        assert all(len(list(connection.directory.glob("krl-*"))) <= 2 for connection in connections)
    finally:
        for connection in connections:
            connection.close()
            connection.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("fault", ["authority", "principal", "expired", "signature", "future"])
def test_distinct_bad_handshakes_do_not_create_proofs(tmp_path, count, fault):
    state, ca, _, _, rows = fixture(tmp_path, count)
    bad_ca = Ed25519PrivateKey.generate()
    for index, row in enumerate(rows):
        bad = signed(row["host"], bad_ca if fault == "authority" else ca,
                     f"substituted-{index}.example" if fault == "principal" else row["node"]["host_principal"],
                     index + 5000, before=int(time.time()) - 1 if fault == "expired" else None,
                     after=int(time.time()) + 60 if fault == "future" else None)
        if fault == "signature":
            kind, encoded = bad.split()
            raw = bytearray(base64.b64decode(encoded))
            raw[-1] ^= 1
            bad = kind + b" " + base64.b64encode(raw)
        connection, _ = prepare(state, row["node"], row["config"])
        try:
            with pytest.raises(TRUST_ERRORS):
                verify(connection.directory, "HOSTNAME", *bad.decode().split())
            assert not connection.proof.exists()
            handshake(connection, row["host_certificate"])
            completed(Arguments([], connection))
        finally:
            connection.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("fault", ["principal", "expired", "revoked"])
def test_distinct_user_certificate_refusals_and_retained_controls(tmp_path, count, fault):
    state, ca, revoked, _, rows = fixture(tmp_path, count)
    for index, row in enumerate(rows):
        original = row["user_certificate"].read_bytes()
        if fault == "revoked":
            krl(revoked, row["user_certificate"])
        else:
            save(row["user_certificate"], signed(
                row["client"], ca, "other" if fault == "principal" else row["node"]["account"],
                index + 9000, user=True, before=int(time.time()) - 1 if fault == "expired" else None))
        with pytest.raises(Failure) as failure:
            prepare(state, row["node"], row["config"])
        assert failure.value.code == "ssh_trust_revoked"
        if count > 1:
            control = rows[(index + 1) % count]
            connection, _ = prepare(state, control["node"], control["config"])
            handshake(connection, control["host_certificate"])
            connection.check()
            connection.close()
        save(row["user_certificate"], original)
        krl(revoked)
        connection, _ = prepare(state, row["node"], row["config"])
        connection.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_removed_profile_never_reverts_to_key_trust(tmp_path, count):
    state, _, _, profiles, rows = fixture(tmp_path, count)
    connections = [prepare(state, row["node"], row["config"])[0] for row in rows]
    try:
        for row, connection in zip(rows, connections, strict=True):
            handshake(connection, row["host_certificate"])
            connection.check()
        for selected in reversed(range(count)):
            remaining = {key: value for key, value in profiles.items() if key != rows[selected]["node"]["profile"]}
            save(state / "ssh-trust.json", json.dumps({"version": 1, "profiles": remaining}).encode())
            with pytest.raises(Failure):
                connections[selected].check()
            with pytest.raises(Failure):
                prepare(state, rows[selected]["node"], rows[selected]["config"])
            for index, connection in enumerate(connections):
                if index != selected:
                    connection.check()
        (state / "ssh-trust.json").unlink()
        for connection in connections:
            with pytest.raises(Failure):
                connection.check()
    finally:
        for connection in connections:
            connection.close()


def test_private_files_and_exact_identity_are_required(tmp_path):
    state, _, _, _, rows = fixture(tmp_path, 1)
    row = rows[0]
    selected = snapshot(state, row["node"]["profile"])
    assert selected
    config = state / "ssh-trust.json"
    config.chmod(0o644)
    with pytest.raises(ValueError):
        snapshot(state, row["node"]["profile"])
    config.chmod(0o600)
    for field, changed in (("certificatefiles", [str(row["user_certificate"])]),
                           ("identityfiles", ["/tmp/other"]), ("hostkeyalgorithms", "ssh-ed25519")):
        with pytest.raises(Failure):
            prepare(state, row["node"], {**row["config"], field: changed})
    connection = Connection(state, row["node"]["profile"], selected)
    connection.deadline = time.monotonic() - 1
    with pytest.raises(Failure):
        connection.check()
    connection.close()


def test_bound_expiry_cannot_extend_when_clock_moves_back(tmp_path, monkeypatch):
    state, _, _, _, rows = fixture(tmp_path, 1)
    connection, _ = prepare(state, rows[0]["node"], rows[0]["config"])
    try:
        handshake(connection, rows[0]["host_certificate"])
        connection.check()
        connection.valid_until = time.monotonic() - 1
        with pytest.raises(Failure):
            connection.check()
    finally:
        connection.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("user", [False, True])
def test_distinct_expiry_cohorts_retain_unexpired_connections(tmp_path, monkeypatch, count, user):
    state, ca, _, _, rows = fixture(tmp_path, count)
    base = int(time.time())
    connections = []
    try:
        for index, row in enumerate(rows):
            save(row["user_certificate" if user else "host_certificate"], signed(
                row["client" if user else "host"], ca,
                row["node"]["account" if user else "host_principal"], index + 12000,
                user=user, before=base + 120 + index))
            connection, _ = prepare(state, row["node"], row["config"])
            connections.append(connection)
            handshake(connection, row["host_certificate"])
            connection.check()
        for selected in range(count):
            monkeypatch.setattr("ficc.ssh_trust_connection.time", SimpleNamespace(
                time=lambda: base + 120 + selected, monotonic=time.monotonic))
            for index, connection in enumerate(connections):
                if index <= selected:
                    with pytest.raises(Failure):
                        connection.check()
                else:
                    connection.check()
    finally:
        for connection in connections:
            connection.close()


async def test_guarded_command_cancels_revoked_work_and_closes_lease(tmp_path, monkeypatch):
    state, _, _, _, rows = fixture(tmp_path, 1)
    transport = SSH(Settings(state_dir=state))
    row = rows[0]
    stopped = asyncio.Event()

    async def config(profile):
        return row["config"]

    async def run(args, *unused, **kwargs):
        connection = next(iter(transport.certificates))
        handshake(connection, row["host_certificate"])
        (state / "ssh-trust.json").unlink()
        try:
            await asyncio.sleep(60)
        finally:
            stopped.set()

    monkeypatch.setattr(transport, "config", config)
    monkeypatch.setattr("ficc.ssh.run", run)
    with pytest.raises(Failure):
        await asyncio.wait_for(transport.command(row["node"], "fixed", b""), 3)
    assert stopped.is_set()
    assert all(value.closed and not value.directory.exists() for value in transport.certificates)
    await transport.close()
