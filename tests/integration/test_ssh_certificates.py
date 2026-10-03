# SPDX-License-Identifier: Apache-2.0
"""Qualify certificate-only helper and terminal operations through real OpenSSH."""

import asyncio
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_ssh_certificates_support import material, server

from ficc.errors import Failure
from ficc.settings import Settings
from ficc.ssh import SSH, transport_failure
from ficc.terminal_pty import TerminalPTY
from ficc.terminal_stream import bridge


class Socket:
    def __init__(self):
        self.received = bytearray()
        self.frames = asyncio.Queue()

    async def send_bytes(self, data):
        self.received.extend(data)

    async def receive(self):
        return await self.frames.get()

    async def wait(self, value: bytes):
        async with asyncio.timeout(5):
            while value not in self.received:
                await asyncio.sleep(.01)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_real_certificate_helper_terminal_and_live_revocation(tmp_path, count):
    state, _, revoked, _, rows = material.fixture(tmp_path, count)
    transport = SSH(Settings(state_dir=state, ssh_config=tmp_path / "ssh_config", control=False))
    seen = set()
    try:
        for index, row in enumerate(rows):
            with server(tmp_path, row) as home:
                preview = await transport.preview(row["node"]["profile"], row["node"]["name"])
                assert preview["trust"] == "trusted" and preview["host_principal"] == row["node"]["host_principal"]
                assert preview["helper_install_required"]
                await transport.install(preview)
                node = {**preview, "id": row["node"]["id"]}
                sample = await transport.probe(node)
                assert sample["resources"]["cpu_count"] > 0
                assert (home / ".local/lib/ficc/node.pyz").is_file()
                master = transport.masters.current[node["id"]]
                assert master.args.trust.checked_host == row["host_certificate"].read_bytes()
                await transport.probe(node)
                assert transport.masters.current[node["id"]] is master
                args = await transport.arguments(node, terminal=True)
                pty = TerminalPTY(args + [f"printf 'READY-%s\\n' {index + 1000}; exec /bin/sh"], 100, 30)
                socket = Socket()
                task = asyncio.create_task(bridge(socket, pty, transport.connection_check(args)))
                try:
                    await socket.wait(f"READY-{index + 1000}".encode())
                    await socket.frames.put({"type": "websocket.receive", "bytes":
                        f"printf 'RESULT-%s\\n' $(({index}+7000))\n".encode()})
                    await socket.wait(f"RESULT-{index + 7000}".encode())
                    seen.add(args.trust.checked_host)
                    material.krl(revoked, row["host_certificate"])
                    with pytest.raises(Failure) as stopped:
                        await asyncio.wait_for(task, 3)
                    assert stopped.value.code == "ssh_trust_revoked"
                    async with asyncio.timeout(3):
                        while master.alive():
                            await asyncio.sleep(.02)
                    await master.watcher
                    assert master.process.returncode is not None
                    code, _, stderr = await transport.command(node, "true", b"")
                    assert code and transport_failure(stderr).code in {"host_key_changed", "unreachable", "ssh_trust_revoked"}
                finally:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    await pty.close()
                    transport.release(args)
                    transport.reset(node["id"])
                material.krl(revoked)
        assert len(seen) == count
    finally:
        await transport.close()
    assert not transport.certificates and not transport.masters.watchers


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_real_wrong_expired_and_substituted_certificates(tmp_path, count):
    state, ca, revoked, _, rows = material.fixture(tmp_path, count)
    bad_ca = Ed25519PrivateKey.generate()
    transport = SSH(Settings(state_dir=state, ssh_config=tmp_path / "ssh_config", control=False))
    failures = []
    try:
        for index, row in enumerate(rows):
            for fault in ("authority", "principal", "expired", "revoked", "substituted"):
                key = Ed25519PrivateKey.generate() if fault == "substituted" else row["host"]
                bad = material.signed(key, bad_ca if fault == "authority" else ca,
                    "other.example" if fault == "principal" else row["node"]["host_principal"],
                    index + 2000, before=int(time.time()) - 1 if fault == "expired" else None)
                certificate = material.save(tmp_path / "invalid-cert.pub", bad)
                if fault == "revoked":
                    material.krl(revoked, certificate)
                with server(tmp_path, row, certificate=certificate):
                    with pytest.raises(Failure) as refused:
                        await transport.preview(row["node"]["profile"], "Refused certificate")
                    assert refused.value.code in {"host_key_changed", "unreachable", "ssh_trust_revoked"}
                    failures.append((index, fault))
                material.krl(revoked)
            with server(tmp_path, row):
                valid = await transport.preview(row["node"]["profile"], "Valid certificate")
                assert valid["trust"] == "trusted"
    finally:
        await transport.close()
    assert len(set(failures)) == count * 5


@pytest.mark.parametrize("fault", ["host_expiry", "user_expiry", "host_krl", "user_krl"])
async def test_live_certificate_failure_preserves_other_peer(tmp_path, fault):
    state, ca, revoked, _, rows = material.fixture(tmp_path, 2)
    target = rows[1]
    if fault.endswith("expiry"):
        user = fault == "user_expiry"
        material.save(target["user_certificate" if user else "host_certificate"], material.signed(
            target["client" if user else "host"], ca,
            target["node"]["account" if user else "host_principal"], 701,
            user=user, before=int(time.time()) + 10))
    transport = SSH(Settings(state_dir=state, ssh_config=tmp_path / "ssh_config", control=False))
    attachments = []
    try:
        with server(tmp_path, rows[0]), server(tmp_path, target):
            nodes = []
            for index, row in enumerate(rows):
                preview = await transport.preview(row["node"]["profile"], "Certificate control")
                await transport.install(preview)
                node = {**preview, "id": row["node"]["id"]}
                await transport.probe(node)
                nodes.append(node)
                args = await transport.arguments(node, terminal=True)
                pty = TerminalPTY(args + [f"printf 'CONNECTED-%s\\n' {index}; exec /bin/sh"], 80, 24)
                socket = Socket()
                task = asyncio.create_task(bridge(socket, pty, transport.connection_check(args)))
                attachments.append((args, pty, socket, task))
                await socket.wait(f"CONNECTED-{index}".encode())
            selected_master = transport.masters.current[nodes[1]["id"]]
            control_master = transport.masters.current[nodes[0]["id"]]
            if fault.endswith("krl"):
                material.krl(revoked, target["user_certificate" if fault == "user_krl" else "host_certificate"])
            with pytest.raises(Failure) as failure:
                await asyncio.wait_for(attachments[1][3], 12)
            assert failure.value.code == "ssh_trust_revoked"
            await asyncio.wait_for(selected_master.watcher, 3)
            assert not selected_master.alive()
            assert control_master.alive() and not attachments[0][3].done()
            await attachments[0][2].frames.put({"type": "websocket.receive", "bytes":
                b"printf 'UNTOUCHED-%s\\n' $((4321+1234))\n"})
            await attachments[0][2].wait(b"UNTOUCHED-5555")
            sample = await transport.probe(nodes[0])
            assert sample["resources"]["cpu_count"] > 0
            assert transport.masters.current[nodes[0]["id"]] is control_master
    finally:
        for args, pty, _, task in attachments:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await pty.close()
            transport.release(args)
        await transport.close()
