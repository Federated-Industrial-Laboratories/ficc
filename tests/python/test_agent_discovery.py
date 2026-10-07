# SPDX-License-Identifier: Apache-2.0
"""Discover actual node commands and register them without launching agents."""

import asyncio
from pathlib import Path

import pytest
from conftest import node
from ficc_node import agents

from ficc.errors import Failure


def installed(command="codex", **extra):
    return {"command": command, "name": "Codex", "adapter": "codex", "argv": ["/opt/agents/" + command],
            "workspace": "/work", "version": "codex-cli 0.156.1", "delivery_method": "direct", **extra}


@pytest.fixture
def discovery(console, monkeypatch):
    client, service = console
    calls, inventories = [], {}
    async def remote(node_id, action, body, check=None):
        if check:
            check()
        calls.append((node_id, action))
        if action == "probe":
            return {**body["profile"], "version": "codex-cli 0.156.1", "delivery_method": "direct"}
        assert action == "discover", "Discovery must not launch an agent."
        result = inventories[node_id]
        if isinstance(result, Exception):
            raise result
        return result
    monkeypatch.setattr(service.agents, "remote", remote)
    def add(index=0):
        machine = node(index)
        machine.update(helper_version="3", capabilities={"agents": True, "agent_discovery": True})
        service.store.save_node(machine)
        inventories[machine["id"]] = {"profiles": [installed()], "errors": []}
        return machine
    def refresh(headers=None):
        service.agents.discovery.due.clear()
        service.agents.discovery.last_attempt.clear()
        return client.post("/api/v1/agent-profiles/refresh", json={}, headers=headers)
    return client, service, calls, inventories, add, refresh


def test_node_discovers_installed_codex_without_a_manual_profile(tmp_path, monkeypatch):
    command = tmp_path / ".local/bin/codex"
    command.parent.mkdir(parents=True)
    command.write_text("#!/bin/sh\nprintf 'codex-cli 0.156.1\\n'\n")
    command.chmod(0o755)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("PATH", str(command.parent))
    result = agents.dispatch({"version": "3", "action": "agent.discover"})
    codex = next(item for item in result["profiles"] if item["command"] == "codex")
    assert codex["argv"][-1] == str(command)
    assert codex["workspace"] == str(tmp_path)
    assert codex["version"] == "codex-cli 0.156.1"
    assert codex["delivery_method"] == "direct"


def test_node_absent_and_broken_commands_do_not_become_launch_choices(tmp_path, monkeypatch):
    from ficc_node import agent_discovery
    folder = tmp_path / "bin"
    folder.mkdir()
    command = folder / "codex"
    command.write_text("#!/bin/sh\nexit 1\n")
    command.chmod(0o755)
    (folder / "claude").symlink_to(folder / "missing")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(agent_discovery, "search_path", lambda: str(folder))
    result = agents.dispatch({"version": "3", "action": "agent.discover"})
    assert result["profiles"] == []
    assert [error["command"] for error in result["errors"]] == ["codex"]


def test_node_discovers_mise_latest_outside_ssh_path(tmp_path, monkeypatch):
    root = tmp_path / ".local/share/mise/installs/codex"
    command = root / "0.156.1/bin/codex"
    command.parent.mkdir(parents=True)
    command.write_text("#!/bin/sh\nprintf 'codex-cli 0.156.1\\n'\n")
    command.chmod(0o755)
    (root / "latest").symlink_to(command.parent.parent)
    wrapper = tmp_path / ".local/bin/codex"
    wrapper.parent.mkdir(parents=True)
    marker = tmp_path / "installer-ran"
    wrapper.write_text(f"#!/bin/sh\ntouch '{marker}'\nmise use -g codex\n")
    wrapper.chmod(0o755)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    result = agents.dispatch({"version": "3", "action": "agent.discover"})
    assert next(p for p in result["profiles"] if p["command"] == "codex")["argv"][-1] == str(command)
    assert not marker.exists()


def test_node_retains_env_interpreter_and_isolates_empty_version(tmp_path, monkeypatch):
    from ficc_node import agent_discovery
    folder = tmp_path / "tools"
    folder.mkdir()
    for name, contents in {
        "bun": "#!/bin/sh\nprintf 'omp/18.1.12\\n'\n",
        "omp": "#!/usr/bin/env bun\n",
        "codex": "#!/bin/sh\nexit 0\n",
    }.items():
        command = folder / name
        command.write_text(contents)
        command.chmod(0o755)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(agent_discovery, "search_path", lambda: str(folder))
    result = agent_discovery.discover()
    assert [profile["command"] for profile in result["profiles"]] == ["omp"]
    assert result["profiles"][0]["version"] == "omp/18.1.12"
    assert [error["command"] for error in result["errors"]] == ["codex"]


def test_other_installed_clis_use_the_existing_generic_adapter(tmp_path, monkeypatch):
    from ficc_node import agent_discovery

    from ficc.agent_schema import DiscoveryResult
    marker = tmp_path / "unexpected-command-execution"
    for name in ("claude", "pi"):
        command = tmp_path / name
        command.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        command.chmod(0o755)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(agent_discovery, "search_path", lambda: str(tmp_path))
    result = DiscoveryResult.model_validate(agent_discovery.discover()).model_dump()
    assert {profile["command"] for profile in result["profiles"]} == {"claude", "pi"}
    assert all(profile["adapter"] == "generic" and profile["version"] == "unversioned"
               and profile["delivery_method"] == "inbox" for profile in result["profiles"])
    assert not result["errors"] and not marker.exists()


@pytest.mark.parametrize("exists", [False, True])
def test_generic_command_rejects_missing_or_nonexecutable_absolute_interpreter(tmp_path, monkeypatch, exists):
    from ficc_node import agent_discovery
    interpreter = tmp_path / "python"
    if exists:
        interpreter.write_text("not executable")
        interpreter.chmod(0o644)
    command = tmp_path / "claude"
    command.write_text(f"#!{interpreter}\n")
    command.chmod(0o755)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(agent_discovery, "search_path", lambda: str(tmp_path))
    result = agent_discovery.discover()
    assert result["profiles"] == []
    assert [error["command"] for error in result["errors"]] == ["claude"]


@pytest.mark.parametrize("count", [1, 64])
def test_refresh_registers_each_machine_once_and_reuses_identity(discovery, count):
    client, _, calls, _, add, refresh = discovery
    for index in range(count):
        add(index)
    first = refresh()
    assert first.status_code == 200, first.text
    profiles = first.json()["profiles"]
    assert len(profiles) == count
    assert {p["node_id"] for p in profiles} == {f"node-{i}" for i in range(count)}
    assert all(p["source"] == "discovered" and p["availability"] == "available" for p in profiles)
    second = refresh().json()["profiles"]
    assert [p["id"] for p in second] == [p["id"] for p in profiles]
    assert all(action == "discover" for _, action in calls)
    assert client.get("/api/v1/agents").json()["agents"] == []


def test_discovery_preserves_exact_manual_workspace_registration(discovery):
    _, service, _, _, add, refresh = discovery
    machine = add()
    manual = asyncio.run(service.agents.register({"node_id": machine["id"], "name": "My Codex", "adapter": "codex",
                                                  "argv": ["/opt/agents/codex"], "workspace": "/custom/project"}))
    profiles = refresh().json()["profiles"]
    assert len(profiles) == 1
    assert profiles[0]["id"] == manual["id"]
    assert profiles[0]["workspace"] == "/custom/project"
    assert "source" not in profiles[0]


def test_missing_agent_becomes_unavailable_and_reinstallation_reuses_identity(discovery):
    _, _, _, inventories, add, refresh = discovery
    machine = add()
    profile = refresh().json()["profiles"][0]
    inventories[machine["id"]] = {"profiles": [], "errors": []}
    missing = refresh().json()["profiles"][0]
    assert missing["id"] == profile["id"] and missing["availability"] == "unavailable"
    inventories[machine["id"]] = {"profiles": [installed()], "errors": []}
    returned = refresh().json()["profiles"][0]
    assert returned["id"] == profile["id"] and returned["availability"] == "available"


def test_failed_scan_preserves_inventory_and_reports_the_machine(discovery):
    _, _, _, inventories, add, refresh = discovery
    machine = add()
    profile = refresh().json()["profiles"][0]
    inventories[machine["id"]] = Failure("unreachable", "Machine unavailable", 502)
    result = refresh().json()
    assert result["profiles"][0]["id"] == profile["id"]
    assert result["profiles"][0]["availability"] == "available"
    assert result["discovery"][0]["state"] == "error"
    assert result["discovery"][0]["node"]["name"] == machine["name"]


def test_scoped_refresh_polls_and_exposes_only_permitted_nodes(discovery):
    _, service, calls, _, add, refresh = discovery
    first, _ = add(0), add(1)
    token, _ = service.auth.issue("token", scopes=["agents:read"], node_ids=[first["id"]])
    response = refresh({"Authorization": "Bearer " + token})
    assert response.status_code == 200, response.text
    assert calls == [(first["id"], "discover")]
    assert [p["node_id"] for p in response.json()["profiles"]] == [first["id"]]
    assert [s["node_id"] for s in response.json()["discovery"]] == [first["id"]]


def test_inventory_obeys_machine_policy_beyond_credential_ceiling(discovery, monkeypatch):
    client, service, _, _, add, refresh = discovery
    first, _ = add(0), add(1)
    refresh()
    token, _ = service.auth.issue("token", scopes=["agents:read"])
    headers = {"Authorization": "Bearer " + token}
    def policy(principal, scope, node_id=None, root_id=None):
        if node_id is not None and node_id != first["id"]:
            raise Failure("denied", "Machine policy denied access.", 403)
    monkeypatch.setattr(service.auth, "policy_check", policy)
    for response in (client.get("/api/v1/agent-profiles", headers=headers), refresh(headers)):
        assert response.status_code == 200, response.text
        assert [p["node_id"] for p in response.json()["profiles"]] == [first["id"]]
        assert [s["node_id"] for s in response.json()["discovery"]] == [first["id"]]


async def test_slow_scan_does_not_block_refresh_and_concurrent_requests_share_it(discovery, monkeypatch):
    _, service, _, _, add, _ = discovery
    add()
    gate, started = asyncio.Event(), asyncio.Event()
    calls = []
    async def slow(*args, **kwargs):
        calls.append(args)
        started.set()
        await gate.wait()
        return {"profiles": [installed()], "errors": []}
    monkeypatch.setattr(service.agents, "remote", slow)
    scanner = service.agents.discovery
    first = asyncio.create_task(scanner.refresh())
    await started.wait()
    second = asyncio.create_task(scanner.refresh())
    async with asyncio.timeout(3):
        results = await asyncio.gather(first, second)
    assert all(result[0]["state"] == "scanning" for result in results)
    assert len(calls) == 1
    gate.set()
    await asyncio.gather(*scanner.tasks.values())
    assert len(service.agents.store.all("agent_profiles")) == 1
    assert scanner.status["node-0"]["state"] == "ready"


def test_unused_automatic_registrations_do_not_prevent_forgetting_machine(discovery):
    client, service, _, _, add, refresh = discovery
    add()
    refresh()
    response = client.delete("/api/v1/nodes/node-0")
    assert response.status_code == 200, response.text
    assert service.agents.store.all("agent_profiles") == []
    assert "node-0" not in service.agents.discovery.status


@pytest.mark.parametrize("kind", ["manual", "agent"])
def test_forget_keeps_agent_and_manual_registration_history(discovery, kind):
    client, service, _, _, add, refresh = discovery
    add()
    refresh()
    profile = service.agents.store.all("agent_profiles")[0]
    if kind == "manual":
        profile.pop("source")
        service.agents.store.save("agent_profiles", profile)
    else:
        value = service.agents.store.new("agents", "local-owner", "retained-agent", {}, node_id="node-0", state="stopped")
        service.agents.store.save("agents", value)
    response = client.delete("/api/v1/nodes/node-0")
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "history_retained"


def test_changed_discovery_invalidates_preview_before_launch(discovery):
    client, _, calls, inventories, add, refresh = discovery
    machine = add()
    profile = refresh().json()["profiles"][0]
    run = client.post("/api/v1/bus/runs", json={"name": "discovery", "idempotency_key": "discovery-run-0001"}).json()
    preview = client.post("/api/v1/agent-previews", json={"profile_id": profile["id"], "label": "Codex", "run_id": run["id"]})
    assert preview.status_code == 200, preview.text
    inventories[machine["id"]] = {"profiles": [installed(version="codex-cli 0.999.0", delivery_method="inbox")], "errors": []}
    updated = refresh().json()["profiles"][0]
    assert updated["id"] == profile["id"]
    response = client.post("/api/v1/agents", json={"preview_id": preview.json()["preview_id"],
                           "idempotency_key": "discovery-launch-0001", "confirm_execution": True})
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "profile_changed"
    assert not any(action == "launch" for _, action in calls)


async def test_background_poll_registers_without_a_browser_refresh(discovery):
    _, service, calls, _, add, _ = discovery
    machine = add()
    task = asyncio.create_task(service.agents.discovery.poll())
    try:
        async with asyncio.timeout(2):
            while not service.agents.store.all("agent_profiles"):
                await asyncio.sleep(0.01)
        assert calls == [(machine["id"], "discover")]
        assert service.agents.store.all("agent_profiles")[0]["source"] == "discovered"
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


def test_discovery_rechecks_permission_before_saving(discovery, monkeypatch):
    _, service, _, _, add, refresh = discovery
    machine = add()
    token, principal = service.auth.issue("token", scopes=["agents:read"], node_ids=[machine["id"]])
    async def revoked(*args, **kwargs):
        service.auth.revoke(principal.id)
        return {"profiles": [installed()], "errors": []}
    monkeypatch.setattr(service.agents, "remote", revoked)
    response = refresh({"Authorization": "Bearer " + token})
    assert response.status_code in {401, 403}
    assert service.agents.store.all("agent_profiles") == []


async def test_revoked_initiator_does_not_invalidate_other_refresh_callers(discovery, monkeypatch):
    _, service, _, _, add, _ = discovery
    add()
    _, first = service.auth.issue("token", scopes=["agents:read"])
    _, second = service.auth.issue("token", scopes=["agents:read"])
    started, release = asyncio.Event(), asyncio.Event()
    async def revoked(*args, **kwargs):
        started.set()
        await release.wait()
        service.auth.revoke(first.id)
        return {"profiles": [installed()], "errors": []}
    monkeypatch.setattr(service.agents, "remote", revoked)
    scanner = service.agents.discovery
    initiating = asyncio.create_task(scanner.refresh(first.id))
    await started.wait()
    shared = asyncio.create_task(scanner.refresh(second.id))
    await asyncio.sleep(0)
    release.set()
    failed, authorized = await asyncio.gather(initiating, shared, return_exceptions=True)
    assert isinstance(failed, Failure) and failed.status == 401
    assert isinstance(authorized, list) and authorized[0]["state"] == "pending"
    assert service.agents.store.all("agent_profiles") == []
    retried = await scanner.refresh(second.id)
    assert retried[0]["state"] == "ready"
    assert len(service.agents.store.all("agent_profiles")) == 1


@pytest.mark.parametrize("failure", ["identity", "duplicate", "invalid"])
def test_invalid_discovery_cannot_replace_saved_profiles(discovery, monkeypatch, failure):
    _, service, _, inventories, add, refresh = discovery
    machine = add()
    original = refresh().json()["profiles"][0]
    if failure == "identity":
        async def changed(*args, **kwargs):
            service.store.save_node({**machine, "fingerprint": "SHA256:changed"})
            return {"profiles": [installed(argv=["/changed/codex"])], "errors": []}
        monkeypatch.setattr(service.agents, "remote", changed)
    else:
        inventories[machine["id"]] = {"profiles": [installed(), installed()] if failure == "duplicate" else [installed(argv=["relative"])], "errors": []}
    result = refresh().json()
    assert result["profiles"][0] == original
    assert result["discovery"][0]["state"] == "error"
