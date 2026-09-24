# SPDX-License-Identifier: Apache-2.0
"""Verify CLI recovery records cannot leak credentials or hide uncertain submissions."""

import hashlib
import json

import pytest
from test_backup import populated

from ficc.backup import export, restore


def receipts(path, service, count):
    folder = path / "cli-requests"
    folder.mkdir(mode=0o700)
    lock = folder / "requests.lock"
    lock.touch(mode=0o600)
    saved = []
    for index in range(count):
        key = f"qualified-request-{index:04}"
        operation = service.jobs.store.get(f"job-{index}")
        operation["key"] = key
        with service.store.db:
            service.store.db.execute("UPDATE operations SET key=?,value=? WHERE id=?", (
                key, json.dumps(operation), operation["id"]))
        value = {"key": key, "digest": operation["digest"],
                 "grant": {"id": "fixture", "credential": f"retired-private-cli-credential-{index:04}"},
                 "operation_id": operation["id"] if index % 2 == 0 else None}
        file = folder / (hashlib.sha256(key.encode()).hexdigest() + ".json")
        file.write_text(json.dumps(value))
        file.chmod(0o600)
        saved.append((file, value))
    return saved


@pytest.mark.parametrize("count", [1, 64])
def test_closed_cli_receipts_reconcile_without_exporting_credentials(tmp_path, count):
    state, bundle, target = (tmp_path / name for name in ("state", "bundle", "restored"))
    service, _, _ = populated(state, count)
    saved = receipts(state, service, count)
    service.close()
    original = {file.name: file.read_bytes() for file, _ in saved}
    export(state, bundle)
    restore(bundle, target, True)
    for directory in (bundle, target):
        assert not (directory / "cli-requests").exists()
        raw = b"".join(p.read_bytes() for p in directory.rglob("*") if p.is_file())
        assert all(value["grant"]["credential"].encode() not in raw for _, value in saved)
    assert {file.name: file.read_bytes() for file, _ in saved} == original


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("fault", ["unresolved", "different_digest", "different_operation", "wrong_name", "link"])
def test_last_cli_receipt_blocks_incomplete_or_mismatched_backup(tmp_path, count, fault):
    state = tmp_path / "state"
    service, _, _ = populated(state, count)
    saved = receipts(state, service, count)
    file, value = saved[-1]
    if fault == "unresolved":
        with service.store.db:
            service.store.db.execute("DELETE FROM operations WHERE id=?", (f"job-{count-1}",))
    elif fault == "different_digest":
        value["digest"] = "different"
    elif fault == "different_operation":
        value["operation_id"] = "different"
    file.write_text(json.dumps(value))
    if fault == "wrong_name":
        file.rename(file.with_name("a" * 64 + ".json"))
    if fault == "link":
        other = tmp_path / "external-receipt"
        file.rename(other)
        file.symlink_to(other)
    service.close()
    with pytest.raises((ValueError, OSError)):
        export(state, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()
