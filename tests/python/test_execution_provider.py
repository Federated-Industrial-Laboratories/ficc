# SPDX-License-Identifier: Apache-2.0
"""Exercise installed-provider arguments and immutable CDI decisions without privileged execution."""

import copy
import errno
import importlib
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROVIDER = Path(__file__).resolve().parents[2] / "executor-providers/podman/src"
sys.path.insert(0, str(PROVIDER))
runner = importlib.import_module("ficc_executor_podman.runner")
devices = importlib.import_module("ficc_executor_podman.devices")
prepare = importlib.import_module("ficc_executor_podman.prepare")


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_payload_arguments_cannot_change_engine_flags_or_host_environment(tmp_path, count):
    for index in range(count):
        root = tmp_path / f"attempt-{index}"
        request = {"context": {"directory": str(root), "cgroup": "/system.slice/fixed",
            "plan": {"attempt_id": f"{index:032x}", "job": {"payload": {
                "argv": ["/payload", "--privileged", "--volume=/etc:/host"],
                "environment": {"LD_PRELOAD": "/work/value", "CONTAINERS_CONF": "/work/false"}}}}},
            "barrier": "/root-approved/barrier", "image_digest": "sha256:" + "a" * 64,
            "containers_config": str(root / "containers.conf"), "gpu": {"cdi_name": None}}
        args = runner.arguments(request)
        boundary = args.index(request["image_digest"])
        assert args[boundary:] == [request["image_digest"], "--", "/payload", "--privileged", "--volume=/etc:/host"]
        assert "--network=none" in args[:boundary] and "--read-only-tmpfs=false" in args[:boundary]
        assert not any(item == "--dns" or item.startswith("--dns=") for item in args[:boundary])
        assert "--no-hosts" in args[:boundary]
        assert "--volume=" + str(root / "resolv.conf") + ":/etc/resolv.conf:ro,nosuid,nodev" in args[:boundary]
        assert "--privileged" not in args[:boundary]
        assert "--security-opt=no-new-privileges" in args[:boundary]
        assert "--http-proxy=false" in args[:boundary] and "--log-driver=none" in args[:boundary]
        assert "--cap-drop=ALL" in args[:boundary] and "--pull=never" in args[:boundary]
        values = runner.environment(root, request)
        assert "LD_PRELOAD" not in values and values["CONTAINERS_CONF"] == str(root / "containers.conf")
        assert set(values) == {"PATH", "LANG", "LC_ALL", "HOME", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME",
                               "XDG_DATA_HOME", "TMPDIR", "CONTAINERS_STORAGE_CONF", "CONTAINERS_CONF"}


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_no_network_resolver_is_empty_read_only_and_bound_to_the_attempt(tmp_path, count):
    mask = os.umask(0o077)
    try:
        for index in range(count):
            root = tmp_path / f"attempt-{index}"
            root.mkdir()
            mounted = prepare.resolver(root)
            source = root / "resolv.conf"
            assert source.read_bytes() == b""
            assert stat.S_IMODE(source.stat().st_mode) == 0o444
            assert source.stat().st_uid == root.stat().st_uid
            assert mounted["source"] == str(source) and mounted["target"] == "/etc/resolv.conf"
            assert mounted["read_only"] and mounted["identity"]["inode"] == source.stat().st_ino
            assert mounted["identity"]["bytes"] == 0
    finally:
        os.umask(mask)


def mapped(monkeypatch):
    uuid = ["GPU-" + f"{index:08x}-0000-0000-0000-000000000000" for index in (1, 2)]
    obj = devices.Devices(None)
    obj.mapping = {value: {"path": "/dev/nvidia" + str(index), "major": 195, "minor": index}
                   for index, value in enumerate(uuid)}
    obj.shared = {name: {"major": 195 if name.endswith("ctl") else 511, "minor": 255 if name.endswith("ctl") else index}
                  for index, name in enumerate(devices.SHARED)}
    obj.libraries = []
    monkeypatch.setattr(devices, "inventory", lambda: {value: index for index, value in enumerate(uuid)})
    monkeypatch.setattr(Path, "exists", lambda _path: True)
    def node(path, expected=None):
        return {"source": path, "identity": {"device": 1, "inode": 4, "mode": stat.S_IFCHR | 0o666,
                                             "rdev": expected or os.makedev(10, 229)}}
    monkeypatch.setattr(devices, "character", node)
    return obj, uuid


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_uuid_selection_emits_only_selected_character_devices_and_no_hooks(monkeypatch, count):
    obj, uuids = mapped(monkeypatch)
    for index in range(count):
        selected, denied = index % 2, 1 - index % 2
        result = obj.select([uuids[selected]])
        assert result["negative"] == ["/dev/nvidia" + str(denied)]
        assert result["positive"] == ["/dev/nvidia" + str(selected), *devices.SHARED]
        assert [row["source"] for row in result["devices"]] == ["/dev/fuse", *result["positive"]]
        edits = result["cdi"]["devices"][0]["containerEdits"]
        assert set(edits) == {"deviceNodes", "mounts"}
        assert all(row["permissions"] == "rw" and row["type"] == "c" for row in edits["deviceNodes"])
        assert "NVIDIA_VISIBLE_DEVICES" not in str(result)
    empty = obj.select([])
    assert empty["positive"] == [] and empty["cdi"] is None
    assert empty["negative"] == ["/dev/nvidia0", "/dev/nvidia1"]
    with pytest.raises(ValueError, match="physical GPU"):
        obj.select(["GPU-00000003-0000-0000-0000-000000000000"])
    monkeypatch.setattr(devices, "inventory", lambda: {uuids[0]: 1, uuids[1]: 0})
    with pytest.raises(ValueError, match="mapping changed"):
        obj.select([uuids[0]])


def test_actual_character_guard_rejects_regular_file_and_wrong_device(tmp_path):
    path = tmp_path / "node"
    path.write_bytes(b"foreign")
    with pytest.raises(ValueError):
        devices.character(str(path))
    with pytest.raises(ValueError):
        devices.character("/dev/null", os.makedev(195, 0))
    accepted = devices.character("/dev/null", os.makedev(1, 3))
    assert accepted["identity"]["rdev"] == os.makedev(1, 3)


@pytest.mark.parametrize("operation", ["start", "prepare"])
def test_changed_input_and_stronger_isolation_never_reach_launch(tmp_path, operation):
    from ficc_executor_podman import Driver

    from ficc.execution.files import identity
    image = tmp_path / "approved.oci"
    image.write_bytes(b"original")
    driver = object.__new__(Driver)
    driver.images = {"sha256:" + "a" * 64: object()}
    driver.identities = {str(image): identity(image.lstat())}
    driver.devices = SimpleNamespace(select=lambda _rows: None)
    ctx = {"plan": {"job": {"runtime": {"image_digest": next(iter(driver.images)), "network": "none",
                                       "isolation": "hardware-vm"}, "limits": {"gpu_devices": []}}}}
    with pytest.raises(ValueError, match="only shared-kernel"):
        getattr(driver, operation)([ctx])
    ctx["plan"]["job"]["runtime"]["isolation"] = "shared-kernel"
    image.write_bytes(b"substituted")
    with pytest.raises(ValueError, match="changed after"):
        getattr(driver, operation)([ctx])


def test_device_probe_records_real_errors_without_substituting_environment(monkeypatch):
    calls = []
    def opened(path, _flags):
        calls.append(path)
        raise OSError(errno.EPERM, "denied")
    monkeypatch.setattr(runner.os, "open", opened)
    request = {"gpu": {"positive": [], "negative": ["/dev/nvidia0", "/dev/nvidia1"]}}
    assert runner.device_probe(copy.deepcopy(request)) == [
        {"path": path, "errno": errno.EPERM, "expected": errno.EPERM} for path in calls]
    assert calls == request["gpu"]["negative"]
