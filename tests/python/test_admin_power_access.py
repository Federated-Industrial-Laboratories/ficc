# SPDX-License-Identifier: Apache-2.0
"""Verify power authority at read, preview and dispatch without issuing shutdown."""

import pytest
from ficc_node import admin_spec as spec
from ficc_node import admin_systemd
from test_admin_provider import provider
from test_module_admin import DIGEST, inventory, setup

from ficc.errors import Failure
from ficc.providers.admin import description


@pytest.mark.parametrize("permission", ["no", "challenge", "na", "unavailable", None])
@pytest.mark.parametrize("action", ["reboot", "poweroff"])
def test_power_permission_rechecked_before_dispatch(monkeypatch, permission, action):
    value = provider()
    pointer = value.pointer("system", "system")
    frozen = {"resource": pointer, "state": "running", "revision": "d" * 64, "definition": "e" * 64,
              "boot_id": "f" * 32, "invocation": ""}
    current = {**frozen, "power": {action: permission}} if permission else frozen
    monkeypatch.setattr(value, "status_batch", lambda _: {"results": [{"resource": pointer, "data": current}]})
    monkeypatch.setattr(admin_systemd, "run", lambda *a, **kw: pytest.fail("power action dispatched"))
    result = value.apply_batch(action, [frozen])[0]
    assert result["state"] == "refused" and result["error"]["code"] == "admin_power_denied"


@pytest.mark.parametrize("response,code,expected", [
    ({"type": "s", "data": ["yes"]}, 0, "yes"),
    ({"type": "s", "data": ["challenge"]}, 0, "challenge"),
    ({"type": "s", "data": ["yes"]}, 1, "unavailable"),
    ({"type": "s", "data": ["yes", "yes"]}, 0, "unavailable"),
    ({"type": "s", "data": [True]}, 0, "unavailable"),
    ({"type": "s", "data": [{}]}, 0, "unavailable"),
])
def test_power_probe_is_bounded_read_only(monkeypatch, response, code, expected):
    calls = []

    def run(command, **limits):
        calls.append((command, limits))
        return code, spec.encode(response), False

    monkeypatch.setattr(admin_systemd, "run", run)
    assert provider().power_access() == dict.fromkeys(spec.POWER, expected)
    assert [command[-1] for command, _ in calls] == ["CanReboot", "CanPowerOff"]
    assert all(command[1:4] == ["--system", "--json=short", "--timeout=1"] for command, _ in calls)
    assert all(limits == {"timeout": 2, "maximum": 4096} for _, limits in calls)
    value = provider()
    value.manager = "user"
    assert value.power_access() == dict.fromkeys(spec.POWER, "na") and len(calls) == 2


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("permission", ["challenge", "no", "unavailable", None])
async def test_preview_denial_keeps_all_targets_unchanged(tmp_path, monkeypatch, count, permission):
    host, source, _, nodes = await setup(tmp_path, monkeypatch, count=count)
    profiles = host.records.profiles()
    for index, profile in enumerate(profiles):
        profile.update(manager="system", system_id=f"{index:064x}", binding=f"{index:064x}")
        host.records.save_profile(profile)
    row = next(iter(source.rows.values()))
    row["resource"].update(kind="system", name="system")
    row["state"] = "running"
    if permission:
        row["power"] = dict.fromkeys(spec.POWER, permission)
    await inventory(host, nodes)
    ids = [spec.resource(profile["id"], row["resource"]) for profile in profiles]
    for action in spec.POWER:
        with pytest.raises(Failure) as error:
            await host.preview("owner", DIGEST, "instance", list(nodes),
                               {"action": action, "resource_ids": ids}, lambda: None)
        assert error.value.code == "admin_power_denied"
    assert not source.calls and not host.previews and not host.records.all()


@pytest.mark.parametrize("power", [{"reboot": "yes"}, {"reboot": True, "poweroff": "yes"},
                                  {"reboot": "yes", "poweroff": "always"}])
def test_invalid_power_response_is_rejected(power):
    value = {"resource": {"kind": "system", "name": "system", "id": "a" * 64}, "state": "running",
             "revision": "b" * 64, "definition": "c" * 64, "boot_id": "d" * 32,
             "invocation": "", "detail": "", "metrics": None, "power": power}
    with pytest.raises(ValueError):
        description(value)
