# SPDX-License-Identifier: Apache-2.0
"""Verify CLI recovery after a lost acknowledgement without a new job identity."""

import argparse
import json
import time

import httpx
import pytest

from ficc.job_cli_state import submit_saved


def test_lost_ack_reuses_credential_preview_and_key(tmp_path, monkeypatch, capsys):
    import ficc.cli

    args = argparse.Namespace(state_dir=tmp_path, idempotency_key="distinct-request-0001")
    grants, posts = [], []
    secret = "private-credential-never-printed"

    def local(state, request):
        grants.append(request["action"])
        return {"id": "actor-1", "credential": secret, "origin": "http://127.0.0.1:8170",
                "expires_at": time.time() + 3600}

    def post(client, route, **kwargs):
        posts.append((route, client.headers["Authorization"], kwargs))
        if route.endswith("operation-previews"):
            return httpx.Response(200, json={"preview_id": "preview-1"})
        if len(posts) == 2:
            raise httpx.ReadTimeout("Acknowledgement lost")
        return httpx.Response(202, json={"id": "operation-1", "targets": [{"state": "running"}]})

    monkeypatch.setattr(ficc.cli, "local_request", local)
    monkeypatch.setattr(httpx.Client, "post", post)
    request = {"action": "job.submit", "node_ids": ["node-1"]}
    with pytest.raises(httpx.ReadTimeout):
        submit_saved(args, request)
    result = submit_saved(args, request)
    assert result["operation"]["id"] == "operation-1"
    assert grants == ["job-credential", "revoke"]
    assert len(posts) == 3 and posts[1] == posts[2]
    files = list((tmp_path / "cli-requests").glob("*.json"))
    assert len(files) == 1 and files[0].stat().st_mode & 0o777 == 0o600
    receipt = json.loads(files[0].read_text())
    assert receipt["operation_id"] == "operation-1" and "credential" not in receipt["grant"]
    assert secret not in capsys.readouterr().err

    monkeypatch.setattr(httpx.Client, "get", lambda *a, **k: httpx.Response(200, json=result["operation"]))
    assert submit_saved(args, request)["operation"]["id"] == "operation-1"
    assert len(posts) == 3
    with pytest.raises(ValueError, match="different request"):
        submit_saved(args, {**request, "node_ids": ["node-2"]})


def test_expired_ambiguous_receipt_cannot_create_new_credential(tmp_path, monkeypatch):
    import ficc.cli

    grants = []

    def local(state, request):
        grants.append(request["action"])
        return {"id": "expired-actor", "credential": "secret", "origin": "http://127.0.0.1:8170",
                "expires_at": time.time() - 1}

    monkeypatch.setattr(ficc.cli, "local_request", local)
    args = argparse.Namespace(state_dir=tmp_path, idempotency_key="distinct-request-0002")
    for _ in range(2):
        with pytest.raises(ValueError, match="expired"):
            submit_saved(args, {"action": "job.submit"})
    assert grants == ["job-credential"]


def test_rejected_preview_does_not_reach_submission(tmp_path, monkeypatch):
    import ficc.cli

    monkeypatch.setattr(ficc.cli, "local_request", lambda *a: {
        "id": "actor", "credential": "secret", "origin": "http://127.0.0.1:8170",
        "expires_at": time.time() + 3600})
    routes = []

    def post(client, route, **kwargs):
        routes.append(route)
        return httpx.Response(403, json={"error": {"message": "Access denied"}})

    monkeypatch.setattr(httpx.Client, "post", post)
    args = argparse.Namespace(state_dir=tmp_path, idempotency_key="distinct-request-0003")
    with pytest.raises(ValueError, match="Access denied"):
        submit_saved(args, {})
    assert routes == ["/api/v1/operation-previews"]


def test_cancel_keeps_authority_until_terminal_result(tmp_path, monkeypatch):
    import ficc.cli
    from ficc.job_cli import execute

    actions = []

    def local(state, request):
        actions.append(request["action"])
        return {"id": "cancel-actor", "credential": "secret", "origin": "http://127.0.0.1:8170",
                "expires_at": time.time() + 3600}

    monkeypatch.setattr(ficc.cli, "local_request", local)
    monkeypatch.setattr(httpx.Client, "post", lambda *a, **k: httpx.Response(202, json={
        "targets": [{"node_id": "node", "state": "cancel_requested"}]}))

    def get(*args, **kwargs):
        assert actions == ["job-credential"]
        return httpx.Response(200, json={"targets": [{"node_id": "node", "state": "cancelled"}]})

    monkeypatch.setattr(httpx.Client, "get", get)
    args = ficc.cli.parser().parse_args(["job-cancel", "operation", "--node", "node"])
    execute(args)
    assert actions == ["job-credential", "revoke"]
