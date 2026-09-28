# SPDX-License-Identifier: Apache-2.0
"""Check fixed administration commands, state identity and bounded protocol input."""

import copy

import pytest
from ficc_node import admin_spec as spec
from ficc_node import admin_systemd


def provider():
    value = admin_systemd.Systemd.__new__(admin_systemd.Systemd)
    value.manager = "system"
    value.binding, value.boot, value.version = "b" * 64, "c" * 32, "259"
    value.command = ["/usr/bin/systemctl", "--system", "--no-pager", "--no-ask-password"]
    return value


def test_dependency_order_does_not_change_frozen_definition():
    value = provider()
    pointer = value.pointer("service", "fixture.service")
    props = {"Id": "fixture.service", "LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "InvocationID": "",
             "After": "b.target a.target", "ExecStart": "opaque saved command"}
    before = value.describe(pointer, props)
    props["After"] = "a.target b.target"
    assert value.describe(pointer, props) == before
    props["ExecStart"] = "changed saved command"
    assert value.describe(pointer, props)["definition"] != before["definition"]


@pytest.mark.parametrize("action", ["start", "stop", "restart", "reboot", "poweroff"])
def test_only_fixed_noninteractive_program_arguments(monkeypatch, action):
    value = provider()
    pointer = value.pointer("system", "system") if action in spec.POWER else value.pointer("service", "fixture.service")
    frozen = {"resource": pointer, "state": "active", "revision": "d" * 64, "definition": "e" * 64,
              "boot_id": "f" * 32, "invocation": ""}
    monkeypatch.setattr(value, "status_batch", lambda _: {"results": [{"resource": pointer, "data": copy.deepcopy(frozen)}]})
    calls = []
    monkeypatch.setattr(admin_systemd, "run", lambda args, **kw: calls.append(args) or (0, b"", False))
    assert value.apply_batch(action, [frozen]) == [{"resource": pointer, "state": "accepted"}]
    args = calls[0]
    assert args[:4] == value.command and "--no-block" in args
    assert not any(item in {"--force", "sudo", "--ignore-inhibitors"} for item in args)
    if action in spec.POWER:
        assert "--check-inhibitors=yes" in args and args[-1] == action
    else:
        assert args[-3:] == [action, "--", "fixture.service"]
    frozen["boot_id"] = "a" * 32
    monkeypatch.setattr(value, "status_batch", lambda _: {"results": [{"resource": pointer, "data": {**frozen, "boot_id": "f" * 32}}]})
    assert value.apply_batch(action, [frozen])[0]["error"]["code"] == "admin_stale"
    assert len(calls) == 1


@pytest.mark.parametrize("bad", ["--force", "../a.service", "a@.service", "a.service\n", "x" * 300 + ".service"])
def test_service_names_reject_paths_options_templates_and_controls(bad):
    with pytest.raises(ValueError):
        spec.unit(bad)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'[' * 34 + b'0' + b']' * 34, b' ' * (spec.MAX_MESSAGE + 1)])
def test_json_bounds_and_duplicate_fields(raw):
    with pytest.raises(ValueError):
        spec.decode(raw)


@pytest.mark.parametrize("mode", ["output", "timeout", "orphan"])
def test_bounded_process_output_deadline_and_descendant_cleanup(tmp_path, monkeypatch, mode):
    import os
    import subprocess
    import sys
    import time
    from pathlib import Path

    from ficc_node import admin_process

    real = subprocess.Popen
    pid_file = tmp_path / "pid"
    if mode == "output":
        source = "import os,time;os.write(1,b'x'*65536);time.sleep(30)"
    elif mode == "timeout":
        source = "import time;time.sleep(30)"
    else:
        source = ("import os,time;from pathlib import Path;child=os.fork();"
                  f"Path({str(pid_file)!r}).write_text(str(child)) if child else None;"
                  "os._exit(0) if child else time.sleep(30)")
    children = []
    def launch(arguments, **options):
        assert arguments == ["/usr/bin/systemctl", "--version"]
        assert options["env"]["SYSTEMCTL_SKIP_AUTO_KEXEC"] == "1"
        assert options["env"]["SYSTEMCTL_SKIP_AUTO_SOFT_REBOOT"] == "1"
        child = real([sys.executable, "-c", source], **options)
        children.append(child)
        return child
    monkeypatch.setattr(admin_process.subprocess, "Popen", launch)
    start = time.monotonic()
    with pytest.raises(spec.ProviderError):
        admin_process.run(["/usr/bin/systemctl", "--version"], timeout=0.3, maximum=1024)
    assert time.monotonic() - start < 3 and children[0].poll() is not None
    if mode == "orphan":
        child = int(pid_file.read_text())
        for _ in range(50):
            try:
                state = (Path(f"/proc/{child}/stat").read_text().split(") ", 1)[1]).split()[0]
            except FileNotFoundError:
                break
            if state == "Z":
                break
            time.sleep(0.01)
        else:
            os.kill(child, 9)
            raise AssertionError("The bounded command left an active descendant.")


@pytest.mark.parametrize("count", [1, 64])
def test_fixed_batch_keeps_order_and_excludes_stale_targets(monkeypatch, count):
    value = provider()
    expected = [{"resource": value.pointer("service", f"fixture-{i}.service"), "state": "inactive", "revision": "d" * 64,
                 "definition": "e" * 64, "boot_id": "f" * 32, "invocation": ""} for i in range(count)]
    current = copy.deepcopy(expected)
    current[-1]["definition"] = "a" * 64
    monkeypatch.setattr(value, "status_batch", lambda _: {"results": [{"resource": item["resource"], "data": item} for item in current]})
    calls = []
    monkeypatch.setattr(admin_systemd, "run", lambda arguments, **kwargs: calls.append(arguments) or (0, b"", False))
    result = value.apply_batch("start", expected)
    assert [item["resource"] for item in result] == [item["resource"] for item in expected]
    assert result[-1]["state"] == "refused" and result[-1]["error"]["code"] == "admin_stale"
    assert all(item["state"] == "accepted" for item in result[:-1])
    assert len(calls) == (1 if count > 1 else 0)
    if calls:
        marker = calls[0].index("--")
        assert calls[0][marker + 1:] == [item["resource"]["name"] for item in expected[:-1]]
