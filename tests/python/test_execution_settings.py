# SPDX-License-Identifier: Apache-2.0
"""Refuse confused executor identities and replaceable administrator inputs."""

import copy
import os

import pytest
from test_execution_ledger import INSTALLATION, identity, offer, plan

from ficc.execution.settings import Settings, read_owned


def settings():
    initial = offer(1)
    return {"version": 1, "installation_id": INSTALLATION, "deployment_id": identity(1),
        "node_id": identity(2), "mode": "voluntary", "transport_uid": 997,
        "local_owner_uids": [1000], "maximum_lease_seconds": 30,
        "service": "ficc-executor-" + INSTALLATION + ".service",
        "state": "/var/lib/ficc-executor/state", "sockets": "/run/ficc-executor",
        "ceiling": initial.model_dump(exclude={"mode", "control", "revision"}),
        "initial_offer": initial.model_dump(),
        "slots": [{"id": "slot-a", "generation": 1, "mount": "/var/lib/ficc-executor/slots/a",
            "filesystem_uuid": "11111111-2222-3333-4444-555555555555", "account": "ficc-work-a",
            "uid": 994, "gid": 994, "storage_bytes": 268435456, "storage_inodes": 16384}],
        "providers": [{"id": "example", "package_digest": "sha256:" + "a" * 64, "configuration": {}}]}


@pytest.mark.parametrize("change", ["transport_workload", "owner_workload", "owner_transport", "managed_owner",
                                    "state_under_slot", "socket_under_state", "duplicate_account", "duplicate_group",
                                    "wrong_package", "offer_expansion", "wrong_service", "relative_path", "parent_path"])
def test_installation_rejects_overlapping_authority_and_paths(change):
    value = settings()
    if change == "transport_workload":
        value["transport_uid"] = 994
    elif change == "owner_workload":
        value["local_owner_uids"] = [994]
    elif change == "owner_transport":
        value["local_owner_uids"] = [997]
    elif change == "managed_owner":
        value["mode"] = value["initial_offer"]["mode"] = "managed"
    elif change == "state_under_slot":
        value["state"] = value["slots"][0]["mount"] + "/state"
    elif change == "socket_under_state":
        value["sockets"] = value["state"] + "/sockets"
    elif change in {"duplicate_account", "duplicate_group"}:
        other = copy.deepcopy(value["slots"][0])
        other.update(id="slot-b", mount="/var/lib/ficc-executor/slots/b", uid=993)
        other.update({"gid": 993} if change == "duplicate_account" else {"account": "ficc-work-b"})
        value["slots"].append(other)
    elif change == "wrong_package":
        value["providers"][0]["package_digest"] = "sha256:" + "b" * 64
    elif change == "offer_expansion":
        value["initial_offer"]["limits"]["memory_bytes"] += 1
    elif change == "wrong_service":
        value["service"] = "ficc-executor-" + "b" * 32 + ".service"
    else:
        value["state"] = {"relative_path": "state", "parent_path": "/var/../state"}[change]
    with pytest.raises(ValueError):
        Settings.model_validate(value)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_configured_identity_accepts_distinct_jobs_and_refuses_other_deployments(count):
    configured = Settings.model_validate(settings())
    for index in range(count):
        item = plan(index)
        configured.check_identity(item)
        for field in ("deployment_id", "node_id"):
            with pytest.raises(ValueError, match="another deployment or contributor"):
                configured.check_identity(item.model_copy(update={field: identity(50 + index)}))


@pytest.mark.parametrize("change", ["link", "parent_link", "hard_link", "shared", "large", "fifo"])
def test_configuration_opens_only_private_regular_owned_inputs(tmp_path, change):
    tmp_path.chmod(0o700)
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    path = directory / "settings.json"
    path.write_text('{"fixture": true}')
    path.chmod(0o600)
    assert read_owned(path, owner=os.getuid()) == path.read_bytes()
    if change == "link":
        candidate = directory / "link.json"
        candidate.symlink_to(path)
        path = candidate
    elif change == "parent_link":
        candidate = tmp_path / "alias"
        candidate.symlink_to(directory, target_is_directory=True)
        path = candidate / path.name
    elif change == "hard_link":
        os.link(path, directory / "duplicate.json")
    elif change == "shared":
        path.chmod(0o640)
    elif change == "large":
        path.write_bytes(b"x" * 33)
    else:
        path.unlink()
        os.mkfifo(path, 0o600)
    with pytest.raises((ValueError, OSError)):
        read_owned(path, maximum=32, owner=os.getuid())
