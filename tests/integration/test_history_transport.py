# SPDX-License-Identifier: Apache-2.0
"""Exercise owner archive preview, publication and retries through real OpenSSH."""

import hashlib
import json
import secrets
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from ficc_node import file_state, job_state, job_system, terminals
from test_ssh import ssh_fixture as ssh_fixture

from ficc.errors import Failure
from ficc.service import Service
from ficc.settings import Settings
from ficc.ssh import PROBE


def invoke(state, output, config, confirm=False):
    args = [sys.executable, "-m", "ficc.cli", "archive-history", "--state-dir", str(state),
            "--output", str(output), "--ssh-config", str(config)]
    result = subprocess.run(args + (["--confirm"] if confirm else []), capture_output=True, timeout=120)
    assert result.returncode == 0, result.stderr.decode()
    return json.loads(result.stdout)


@pytest.mark.parametrize("count", [0, 1, 64])
async def test_complete_cli_archive_real_ssh_and_systemd_inspection(ssh_fixture, monkeypatch, count):
    transport, home, temporary = ssh_fixture
    node = await transport.preview("fixture-node", "Archive fixture")
    await transport.install(node)
    sample = await transport.probe(node)
    assert sample["capabilities"]["history_archive"] is True
    node.update(id=secrets.token_hex(16), capabilities=sample["capabilities"], state="ready")
    state = transport.settings.state_dir
    service = Service(Settings(state_dir=state, control=False))
    service.store.save_node(node)
    controller = service.store.get_setting("controller_id", None)
    terminal = service.store.get_setting("terminal_controller", None)
    credential, _ = service.auth.issue("token")
    original = {}
    identities = [secrets.token_hex(16) for _ in range(count)]
    with monkeypatch.context() as patch:
        patch.setenv("HOME", str(home))
        jobs = job_state.root()
        files = job_state.directory(file_state.state_root() / controller)
        terms = terminals.base(terminal)
        if count:
            job_state.write(jobs / "controller.json", {"id": controller})
        for index, identity in enumerate(identities):
            unit = f"ficc-{controller}-{identity}.service"
            # The read is real and the random unit must not exist before or after archival.
            assert job_system.properties(unit)["LoadState"] == "not-found"
            folder = job_state.directory(jobs / identity)
            job_state.write(folder / "request.json", {"controller_id": controller, "job_id": identity,
                            "digest": f"digest-{index}", "unit": unit,
                            "description": f"FICC:{controller}:{identity}:digest-{index}"})
            job_state.write(folder / "result.json", {"state": "succeeded", "result": {"exit_code": 0}})
            data = bytes(range(256)) + f"different-record-{index}\n".encode()
            (folder / "stdout").write_bytes(data)
            (folder / "stdout").chmod(0o600)
            job_state.write(files / (identity + ".json"), {"id": identity, "state": "succeeded"})
            job_state.write(terms / (identity + ".json"), {"id": identity, "state": "stopped"})
            for kind, base in (("jobs", jobs), ("files", files), ("terminals", terms)):
                for path in base.rglob("*"):
                    if path.is_file() and path.name != "controller.json":
                        original[kind + "/" + path.relative_to(base).as_posix()] = path.read_bytes()
            service.jobs.store.insert({"id": identity, "actor": "fixture", "key": "archive-" + identity,
                                       "digest": f"digest-{index}", "targets": [{"node_id": node["id"], "job_id": identity, "state": "succeeded"}]})
    service.close()
    await transport.close()
    output = temporary / "archive"
    config = temporary / "ssh_config"
    preview = invoke(state, output, config)
    assert preview["preview"]["counts"]["operations"] == count
    assert preview["preview"]["nodes"][0]["fingerprint"] == node["fingerprint"]
    assert not output.exists() and not (state / "archive.pending.json").exists()
    result = invoke(state, output, config, True)
    assert result["archived"]
    assert invoke(state, output, config, True) == result
    archive = result["node_archives"][node["id"]]
    folder = Path(archive["path"])
    assert folder == home / ".local/state/ficc/history" / result["archive_id"]
    assert hashlib.sha256((folder / "manifest.json").read_bytes()).hexdigest() == archive["manifest_sha256"]
    manifest = json.loads((folder / "manifest.json").read_bytes())
    assert set(manifest["members"]) == set(original)
    for name, data in original.items():
        assert (folder / name).read_bytes() == data
        assert manifest["members"][name] == {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    assert all(path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600) for path in folder.rglob("*"))
    assert not (state / "archive.pending.json").exists()
    assert not any(credential.encode() in path.read_bytes() for path in output.rglob("*") if path.is_file())
    with sqlite3.connect(output / "controller/state.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM operations").fetchone()[0] == count
    current = Service(Settings(state_dir=state, control=False))
    try:
        assert current.store.get_setting("controller_id", None) == archive["next_controller_id"]
        assert current.store.db.execute("SELECT count(*) FROM operations").fetchone()[0] == 0
        with pytest.raises(Failure):
            current.auth.resolve(credential)
    finally:
        current.close()
    # An earlier controller cannot archive again under a different identity and seize the namespace.
    request = {**manifest["request"], "archive_id": secrets.token_hex(16), "next_controller_id": secrets.token_hex(16)}
    code, raw, _ = await transport.command(node, PROBE, json.dumps(request).encode() + b"\n")
    assert code != 0 and b"another controller" in raw
    await transport.close()
