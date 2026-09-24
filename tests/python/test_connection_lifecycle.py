# SPDX-License-Identifier: Apache-2.0
"""Verify public ownership changes invalidate observation connections."""

import sqlite3

import pytest
from conftest import node

from ficc.errors import Failure
from ficc.service import Service
from ficc.settings import Settings


def test_token_revocation_logout_and_node_removal_reset_connections(console, monkeypatch):
    client, service = console
    invalidations = []
    monkeypatch.setattr(service.ssh, "reset", lambda node_id=None: invalidations.append(node_id))
    _, token = service.auth.issue("token", scopes=["nodes:read"])
    assert client.delete("/api/v1/tokens/" + token.id).status_code == 200
    assert invalidations == [None]
    service.store.save_node(node())
    assert client.delete("/api/v1/nodes/node-0").status_code == 200
    assert invalidations == [None, "node-0"]
    assert client.delete("/api/v1/session").status_code == 200
    assert invalidations == [None, "node-0", None]
    assert client.get("/api/v1/nodes").status_code == 401


def test_local_revocation_invalidates_before_failed_audit(console, monkeypatch):
    _, service = console
    invalidations = []
    monkeypatch.setattr(service.ssh, "reset", lambda node_id=None: invalidations.append(node_id))
    token, actor = service.auth.issue("token")
    def failed_audit(*args, **kwargs):
        raise sqlite3.OperationalError("Synthetic full database")
    monkeypatch.setattr(service.store, "audit", failed_audit)
    with pytest.raises(sqlite3.OperationalError):
        service.auth.revoke(actor.id)
    assert invalidations == [None]
    with pytest.raises(Failure, match="Sign in"):
        service.auth.resolve(token)


def test_pending_archival_blocks_service_before_database_access(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "archive.pending.json").write_text("{}")
    def forbidden(*args):
        pytest.fail("An incomplete archive must block all database access")
    monkeypatch.setattr("ficc.service.Store", forbidden)
    with pytest.raises(ValueError, match="Resume archive-history"):
        Service(Settings(state_dir=state, control=False))
    assert not (state / "state.sqlite3").exists()
