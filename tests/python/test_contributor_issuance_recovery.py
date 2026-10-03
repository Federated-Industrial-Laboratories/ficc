# SPDX-License-Identifier: Apache-2.0
"""Recover an interrupted certificate save without retaining an in-memory owner."""

import sqlite3

import pytest
from contributor_fixtures import csr


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("failure", ["storage_methods", "sqlite_readonly"])
async def test_failed_save_and_cleanup_release_the_request(contributor_console, monkeypatch, count, failure):
    f = contributor_console
    if failure == "sqlite_readonly" and not isinstance(f.service.store.db, sqlite3.Connection):
        pytest.skip("The read-only engine check requires SQLite.")
    nodes = f.service.contributors
    requests = []
    for index in range(max(2, count)):
        invite = nodes.invite(f"Recovery identity {index}", "managed", f.actor)
        pem, key = csr(f.settings, invite["node_id"])
        claim = nodes.claim(invite["secret"], pem, invite["node_id"])
        requests.append((claim["request_id"], key))
    identity, key = requests[-1]
    issue = f.authority.issue

    def unavailable(*_args, **_kwargs):
        raise OSError("Temporary certificate storage failure")

    def readonly(request):
        result = issue(request)
        with f.service.store.lock:
            f.service.store.db.execute("PRAGMA query_only=ON")
        return result

    try:
        with monkeypatch.context() as patch:
            if failure == "sqlite_readonly":
                patch.setattr(f.authority, "issue", readonly)
            else:
                patch.setattr(nodes.records, "issued", unavailable)
                patch.setattr(nodes.records, "failed", unavailable)
            with pytest.raises(sqlite3.OperationalError if failure == "sqlite_readonly" else OSError):
                await nodes.issue(identity, key, 1, f.actor)
        assert not nodes.issuing
        assert not nodes.slots.locked()
    finally:
        if failure == "sqlite_readonly":
            with f.service.store.lock:
                f.service.store.db.execute("PRAGMA query_only=OFF")

    current = nodes.records.get("contributor_requests", identity)
    assert current["status"] == "issuing"
    assert nodes.records.rows("contributor_certificates") == []
    assert len(f.authority.calls) == 1
    for peer, public_key in requests[:-1]:
        result = await nodes.issue(peer, public_key, 1, f.actor)
        assert result["status"] == "issued"
    result = await nodes.issue(identity, key, current["revision"], f.actor)
    assert result["id"] == identity and result["status"] == "issued"
    assert len(f.authority.calls) == len(requests) + 1
    assert len(nodes.records.rows("contributor_certificates")) == len(requests)
    assert not nodes.issuing
