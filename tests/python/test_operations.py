# SPDX-License-Identifier: Apache-2.0
"""Check diagnostic redaction, audit continuity and real backup/restore receipts."""

import hashlib
import json

from conftest import node

from ficc.backup import export, restore
from ficc.operations import receipt
from ficc.service import Service
from ficc.settings import Settings


def test_reports_redact_configuration_and_exports_require_owner_authority(console):
    client, service = console
    marker = "private-source-password-and-query"
    service.store.set_setting("unrelated-private-setting", marker)
    machine = node()
    machine.update(name=marker, host=marker, error={"code": "fixture", "message": marker})
    service.store.save_node(machine)
    response = client.get("/api/v1/operational-status/diagnostics")
    assert response.status_code == 200
    value = response.json()
    assert marker not in response.text
    assert value["backup"]["state"] == "not_recorded"
    assert value["external_data_backup"] == "not_observed"
    assert value["connections"]["stale"] == 1
    service.store.audit("fixture.export", "resource-1")
    exported = client.get("/api/v1/operational-status/audit")
    assert exported.status_code == 200
    records = [json.loads(line) for line in exported.text.splitlines()]
    assert records[0]["format"] == "ficc-audit-v1"
    assert any(row.get("target") == "resource-1" for row in records[1:-1])
    assert records[-1]["complete"]
    with service.store.lock, service.store.db:
        service.store.db.execute("DELETE FROM audit WHERE id<:p0", (records[-1]["last_id"],))
    assert json.loads(client.get("/api/v1/operational-status/audit").text.splitlines()[0])["retention_gap"]
    for scopes, nodes in ((["nodes:read"], None), (["audit:read"], [machine["id"]])):
        token, _ = service.auth.issue("token", scopes=scopes, node_ids=nodes)
        for path in ("", "/diagnostics", "/audit"):
            assert client.get("/api/v1/operational-status" + path,
                              headers={"Authorization": "Bearer " + token}).status_code == 403


def test_real_backup_and_isolated_restore_record_only_completed_operations(tmp_path):
    state, bundle, destination = (tmp_path / name for name in ("state", "backup", "restored"))
    service = Service(Settings(state_dir=state, control=False))
    service.close()
    export(state, bundle)
    observed = receipt(state, "backup")
    assert observed["state"] == "recorded"
    assert observed["manifest_sha256"] == hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest()
    assert not (bundle / "operations-backup.json").exists()
    restore(bundle, destination, True)
    recovered = Service(Settings(state_dir=destination, control=False))
    try:
        assert receipt(destination, "restore")["manifest_sha256"] == observed["manifest_sha256"]
        assert receipt(destination, "backup")["state"] == "not_recorded"
        assert recovered.store.db.execute("SELECT count(*) FROM credentials").fetchone()[0] == 0
    finally:
        recovered.close()
    export(destination, tmp_path / "restored-backup")
