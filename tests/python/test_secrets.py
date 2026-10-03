# SPDX-License-Identifier: Apache-2.0
"""Protect encrypted secret lifecycle, source migration, custody and backup exclusion."""

import base64
import hmac
import json
import os
import shutil
from types import SimpleNamespace

import pytest

from ficc import secret_io
from ficc.backup import export, restore
from ficc.cli import main
from ficc.errors import Failure
from ficc.secret_cli import initialize
from ficc.secret_sdk import SecretError
from ficc.secrets import PRIVATE, Secrets
from ficc.source_capabilities import secret
from ficc.store import Store

VALUE = b'{"username":"reader","password":"synthetic-secret-not-for-output"}\n'


@pytest.fixture
def vault(tmp_path):
    state, key = tmp_path / "state", tmp_path / "controller.key"
    initialize(state, key)
    return state, key, Secrets(state)


def test_cli_private_input_rotation_conflict_and_delete(vault, tmp_path, capsys):
    state, _key, host = vault
    source = tmp_path / "credential"
    source.write_bytes(VALUE)
    source.chmod(0o600)
    args = ["--state-dir", str(state), "--reference", "reader"]
    assert main(["secret-put", *args, "--input", str(source)]) == 0
    first = json.loads(capsys.readouterr().out)
    assert set(first) == {"reference", "revision"}
    assert host.resolve("reader").value == VALUE
    assert b"synthetic-secret" not in repr(host.resolve("reader")).encode()
    assert main(["secret-put", *args, "--input", str(source)]) == 1
    assert "already exists" in capsys.readouterr().err
    assert main(["secret-put", *args, "--input", str(source), "--revision", first["revision"]]) == 0
    second = json.loads(capsys.readouterr().out)
    assert first["revision"] != second["revision"]
    assert main(["secret-delete", *args, "--revision", first["revision"]]) == 1
    assert "already exists" in capsys.readouterr().err
    assert main(["secret-status", *args]) == 0
    assert json.loads(capsys.readouterr().out) == second
    assert main(["secret-delete", *args, "--revision", second["revision"]]) == 0
    assert json.loads(capsys.readouterr().out) == {"reference": "reader", "deleted": True}
    with pytest.raises(SecretError) as refused:
        host.resolve("reader")
    assert refused.value.code == "secret_missing"
    assert source.read_bytes() == VALUE


def test_authenticated_records_reject_tamper_and_reference_substitution(vault):
    state, _key, host = vault
    host.put("reader", VALUE)
    records = state / PRIVATE / "records"
    selected = records / "reader.json"
    original = selected.read_bytes()
    assert VALUE not in original and b"synthetic-secret" not in original
    for field, replacement in (("revision", "0" * 64), ("store", "0" * 32),
                               ("reference", "another"), ("nonce", base64.b64encode(b"x" * 12).decode()),
                               ("ciphertext", base64.b64encode(b"x" * (len(VALUE) + 16)).decode())):
        modified = json.loads(original)
        modified[field] = replacement
        selected.write_text(json.dumps(modified))
        with pytest.raises(SecretError):
            host.resolve("reader")
    selected.write_bytes(original)
    selected.rename(records / "another.json")
    with pytest.raises(SecretError):
        host.resolve("another")


def test_unavailable_wrong_or_insecure_key_fails_without_cached_plaintext(vault):
    state, key, host = vault
    host.put("reader", VALUE)
    original = key.read_bytes()
    key.unlink()
    with pytest.raises(SecretError):
        host.resolve("reader")
    key.write_bytes(b"x" * 32)
    key.chmod(0o600)
    with pytest.raises(SecretError):
        host.status()
    key.write_bytes(original)
    key.chmod(0o644)
    with pytest.raises(SecretError):
        host.resolve("reader")
    key.chmod(0o600)
    assert host.resolve("reader").value == VALUE
    key.unlink()
    target = key.parent / "original-key"
    target.write_bytes(original)
    target.chmod(0o600)
    key.symlink_to(target)
    with pytest.raises(SecretError):
        host.resolve("reader")
    assert all(path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
               for path in (state / PRIVATE).rglob("*"))


def test_provider_unavailable_key_custody_and_safe_error(vault, tmp_path, monkeypatch):
    _state, _key, host = vault
    import ficc.secrets as module
    monkeypatch.setattr(module.importlib.metadata, "entry_points", lambda **kwargs: [])
    with pytest.raises(SecretError) as missing:
        host.status()
    assert missing.value.code == "secret_provider_unavailable"
    monkeypatch.undo()
    with pytest.raises(SecretError) as unsafe:
        initialize(tmp_path / "unsafe", tmp_path / "unsafe" / "key")
    assert unsafe.value.code == "secret_key_location"


def test_atomic_update_failure_preserves_current_record_and_redacts_exception(vault, monkeypatch):
    state, _key, host = vault
    initial = host.put("reader", VALUE)
    original = (state / PRIVATE / "records" / "reader.json").read_bytes()

    def refused(*args, **kwargs):
        raise OSError("synthetic-secret-not-for-output")

    monkeypatch.setattr(secret_io.os, "replace", refused)
    with pytest.raises(SecretError) as failed:
        host.put("reader", b"new value", initial["revision"])
    assert "synthetic-secret" not in str(failed.value)
    assert host.status("reader") == initial
    assert (state / PRIVATE / "records" / "reader.json").read_bytes() == original
    assert not list((state / PRIVATE / "records").glob(".pending-*"))


def test_explicit_source_migration_retains_revision_and_reports_plaintext(vault, capsys):
    state, _key, host = vault
    key = os.urandom(32)
    store = Store(state / "state.sqlite3")
    store.set_setting("file_reference_key", key.hex())
    store.close()
    legacy = state / "data-secrets"
    legacy.mkdir(mode=0o700)
    path = legacy / "reader"
    path.write_bytes(VALUE)
    path.chmod(0o600)
    service = SimpleNamespace(settings=SimpleNamespace(state_dir=state))
    with pytest.raises(Failure) as unavailable:
        secret(service, "reader")
    assert unavailable.value.code == "secret_unavailable"
    args = ["secret-migrate-source", "--state-dir", str(state), "--reference", "reader"]
    assert main(args) == 0
    migrated = json.loads(capsys.readouterr().out)
    expected = hmac.digest(key, b"ficc-source-secret\0" + VALUE, "sha256").hex()
    assert migrated == {"reference": "reader", "revision": expected, "migrated": True, "plaintext_retained": True}
    assert path.read_bytes() == VALUE
    assert secret(service, "reader") == (json.loads(VALUE), expected)
    assert main([*args, "--remove-plaintext"]) == 0
    assert json.loads(capsys.readouterr().out)["plaintext_retained"] is False
    assert not path.exists() and host.resolve("reader").revision == expected
    changed = host.put("reader", VALUE, expected)
    assert secret(service, "reader")[1] == changed["revision"] != expected


def test_state_backup_excludes_keys_ciphertexts_and_plaintext_and_restores_closed(tmp_path):
    state, key = tmp_path / "state", tmp_path / "controller.key"
    store = Store(state / "state.sqlite3")
    store.set_setting("controller_id", "b" * 32)
    store.close()
    initialize(state, key)
    saved = Secrets(state).put("reader", VALUE)
    legacy = state / "data-secrets"
    legacy.mkdir(mode=0o700)
    selected = legacy / "reader"
    selected.write_bytes(VALUE)
    selected.chmod(0o600)
    bundle, restored = tmp_path / "backup", tmp_path / "restored"
    export(state, bundle)
    assert not (bundle / PRIVATE).exists() and not (bundle / "data-secrets").exists()
    for member in bundle.rglob("*"):
        if member.is_file():
            raw = member.read_bytes()
            assert VALUE not in raw and key.read_bytes() not in raw and b"synthetic-secret" not in raw
    restore(bundle, restored, True)
    with pytest.raises(SecretError):
        Secrets(restored).resolve("reader")
    shutil.copytree(state / PRIVATE, restored / PRIVATE)
    assert Secrets(restored).resolve("reader").value == VALUE
    (restored / PRIVATE / "provider.json").unlink()
    initialize(restored, key, existing_key=True)
    assert Secrets(restored).status("reader") == saved
