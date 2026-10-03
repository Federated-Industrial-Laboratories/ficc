# SPDX-License-Identifier: Apache-2.0
"""Keep every repeated device property and reject ambiguous scalar properties."""

from pathlib import Path

import pytest

from ficc.execution import envelope, process


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("change", ["exact", "missing", "extra", "permissions", "duplicate", "substituted"])
def test_repeated_system_manager_devices_keep_exact_ancestor_allow_list(tmp_path, monkeypatch, count, change):
    monkeypatch.setattr(envelope, "Path", lambda value: tmp_path if value == "/sys/fs/cgroup" else Path(value))
    for index in range(count):
        unit = f"attempt-{index}.service"
        ctx = {"unit": unit, "description": f"FICC attempt {index}", "cgroup": "/system.slice/" + unit,
               "supervisor": f"supervisor-{index}.service", "plan": {"job": {"limits": {
                   "cpu_millis": 500, "memory_bytes": 134217728, "swap_bytes": 0, "processes": 64}}}}
        group = tmp_path / ctx["cgroup"].lstrip("/")
        group.mkdir(parents=True)
        for name, value in {"cpu.max": "50000 100000", "memory.max": "134217728", "memory.high": "134217728",
                            "memory.swap.max": "0", "memory.oom.group": "1", "pids.max": "64"}.items():
            (group / name).write_text(value + "\n")
        selected = f"/dev/nvidia{index}"
        devices = [selected + " rw", "/dev/fuse rw"]
        if change == "missing":
            devices.pop(0)
        elif change == "extra":
            devices.append(f"/dev/nvidia{index + 100} rw")
        elif change == "permissions":
            devices[0] = selected + " rwm"
        elif change == "duplicate":
            devices.append(devices[0])
        elif change == "substituted":
            devices[0] = f"/dev/nvidia{index + 100} rw"
        fields = {"Description": ctx["description"], "ControlGroup": ctx["cgroup"], "DevicePolicy": "closed",
                  "BindsTo": ctx["supervisor"], "After": ctx["supervisor"], "KillMode": "control-group",
                  "OOMPolicy": "kill", "RuntimeMaxUSec": "infinity", "LimitCORE": "0", "LimitCORESoft": "0"}
        # This prefix uses the actual repeated-key format from the system manager.
        output = "LoadState=loaded\nActiveState=active\n"
        output += "".join("DeviceAllow=" + value + "\n" for value in devices)
        output += "".join(name + "=" + value + "\n" for name, value in fields.items())

        def command(argv):
            assert argv == ["/usr/bin/systemctl", "show", unit, "--no-pager",
                            "--property=" + ",".join(envelope.FIELDS)]
            return {"exit": 0, "stdout": output, "stderr": ""}

        monkeypatch.setattr(process, "command", command)
        prepared = {"devices": [{"source": "/dev/fuse"}, {"source": selected}]}
        if change == "exact":
            result = envelope.Envelope().controls(ctx, prepared)
            assert result["unit"]["DeviceAllow"].split() == [selected, "rw", "/dev/fuse", "rw"]
            assert result["limits"]["cpu.max"] == "50000 100000"
        else:
            with pytest.raises(ValueError, match="device allow-list"):
                envelope.Envelope().controls(ctx, prepared)


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_repeated_scalar_properties_are_not_silently_replaced(monkeypatch, count):
    for index in range(count):
        for name, before, after in (("LoadState", "loaded", "loaded"), ("DevicePolicy", "closed", "auto"),
                                    ("MainPID", str(index + 10), str(index + 100)), ("After", "one", "two")):
            output = f"{name}={before}\n{name}={after}\n"
            monkeypatch.setattr(process, "command", lambda _argv: {"exit": 0, "stdout": output, "stderr": ""})
            with pytest.raises(ValueError, match="scalar property"):
                process.properties(f"attempt-{index}.service", (name,))
