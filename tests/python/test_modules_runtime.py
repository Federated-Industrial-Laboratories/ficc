# SPDX-License-Identifier: Apache-2.0
"""Exercise process supervision separately from platform sandbox qualification."""

import asyncio
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest
import test_modules_registry
from test_modules_packages import bundle, package
from test_modules_protocol import reply

from ficc.errors import Failure
from ficc.modules import inspect_archive, protocol
from ficc.modules.runtime import Runtime
from ficc.modules.sandbox import SandboxStatus

registry = test_modules_registry.registry


def executable(registry, capabilities=None):
    capabilities = capabilities or []
    manifest, files = package({"main.py": b"pass"},
        runtime={"kind": "python", "language": "python", "platform": "linux",
                 "architecture": "any", "entry": "main.py"}, capabilities=capabilities,
        actions=[{"id": "read", "parameters": {}, "capabilities": capabilities}])
    inspection = inspect_archive(bundle(manifest, files))
    registry.install(inspection, inspection.digest)
    registry.set_enabled(inspection.digest, True,
                         [{"capability": cap, "target_ids": ["a"]} for cap in capabilities],
                         sandbox_ready=True)
    return inspection.digest


@pytest.mark.parametrize("count", [1, 64])
async def test_runtime_batches_check_current_authority(registry, monkeypatch, count):
    import ficc.modules.runtime as module

    digest = executable(registry)
    runtime = Runtime(registry)
    checked = []

    async def probe():
        return SandboxStatus(True, "Test transport")

    async def execute(_package, _command, payload, guard):
        guard()
        request = protocol.frames(payload)[1]
        return reply(request["id"], [{"target": target, "data": target}
                                     for target in request["targets"]])

    monkeypatch.setattr(runtime.sandbox, "probe", probe)
    monkeypatch.setattr(module, "execute", execute)
    targets = [f"workspace-{i}" for i in range(count)]
    result = await runtime.invoke(digest, "read", targets, {}, lambda: checked.append(True))
    assert [item["data"] for item in result["results"]] == targets
    assert len(checked) >= 4 and not runtime.active and not registry._leases


async def test_runtime_rejects_capability_calls_before_launch(registry, monkeypatch):
    digest = executable(registry, ["workspace:read"])
    runtime = Runtime(registry)

    async def forbidden():
        pytest.fail("Capability invocation reached process launch")

    monkeypatch.setattr(runtime.sandbox, "probe", forbidden)
    with pytest.raises(Failure) as error:
        await runtime.invoke(digest, "read", ["a"], {}, lambda: None)
    assert error.value.code == "module_capability_unavailable"


async def test_runtime_fails_closed_when_probe_unavailable(registry, monkeypatch):
    digest = executable(registry)
    runtime = Runtime(registry)

    async def probe():
        return SandboxStatus(False, "Missing sandbox")

    monkeypatch.setattr(runtime.sandbox, "probe", probe)
    with pytest.raises(Failure) as error:
        await runtime.invoke(digest, "read", ["a"], {}, lambda: None)
    assert error.value.code == "module_sandbox_unavailable"
    assert not registry._leases


async def test_probe_capacity_and_stop_wait_for_task_cleanup(registry, monkeypatch):
    digest = executable(registry)
    runtime = Runtime(registry)
    entered, cleaned = asyncio.Event(), []

    async def probe():
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.append(True)

    monkeypatch.setattr(runtime.sandbox, "probe", probe)
    tasks = [asyncio.create_task(runtime.invoke(digest, "read", ["a"], {}, lambda: None))
             for _ in range(4)]
    await entered.wait()
    await asyncio.sleep(0)
    with pytest.raises(Failure) as error:
        await runtime.invoke(digest, "read", ["a"], {}, lambda: None)
    assert error.value.code == "capacity"
    registry.revoke(digest)
    await runtime.stop(digest)
    assert len(cleaned) == 4 and not runtime.active and not registry._leases
    assert all(isinstance(result, asyncio.CancelledError)
               for result in await asyncio.gather(*tasks, return_exceptions=True))


@pytest.mark.parametrize("case", ["stdout", "stderr", "timeout", "revoked", "cancel"])
async def test_supervision_bounds_and_kills_owned_processes(tmp_path, monkeypatch, case):
    import ficc.modules.sandbox as module

    # Substitute only platform enforcement. This exercises the actual bounded
    # pipes and cleanup; it does not qualify bwrap or kernel isolation.
    processes, stopped = [], []
    real_popen = subprocess.Popen
    source = "import sys,time; sys.stdin.buffer.read(); time.sleep(60)"
    if case in ("stdout", "stderr"):
        source = "import sys; sys.stdin.buffer.read(); sys.%s.buffer.write(b'x'*3000000)" % case

    def spawn(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process

    async def controls(_unit):
        return None

    async def management(*args):
        stopped.append(args)
        return 0, b""

    monkeypatch.setattr(module, "command", lambda *args: [sys.executable, "-c", source])
    monkeypatch.setattr(module.subprocess, "Popen", spawn)
    monkeypatch.setattr(module, "enforcement", controls)
    monkeypatch.setattr(module, "management", management)
    monkeypatch.setattr(module, "MAX_SECONDS", 0.15)
    checks = 0

    def guard():
        nonlocal checks
        checks += 1
        if case == "revoked" and checks > 1:
            raise Failure("module_revoked", "Revoked", 403)

    task = asyncio.create_task(module.execute(tmp_path, [], b"request", guard))
    if case == "cancel":
        await asyncio.sleep(0.03)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(Failure) as error:
            await task
        assert error.value.code == {"stdout": "module_output_limit", "stderr": "module_output_limit",
                                    "timeout": "module_timeout", "revoked": "module_revoked"}[case]
    assert stopped and stopped[-1][0] == "stop"
    assert processes and all(process.returncode is not None for process in processes)
    for process in processes:
        with pytest.raises(ProcessLookupError):
            os.kill(process.pid, 0)


def test_controller_watcher_stops_child_when_owner_dies(tmp_path):
    import ficc.modules.watcher as module

    owner = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    child_file = tmp_path / "child.pid"
    child_code = "import os,time,pathlib; pathlib.Path(%r).write_text(str(os.getpid())); time.sleep(60)" % str(child_file)
    watcher = subprocess.Popen([sys.executable, "-I", module.__file__, str(owner.pid),
                                module.identity(owner.pid), "--", sys.executable, "-c", child_code])
    try:
        import time
        deadline = time.monotonic() + 3
        while not child_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert child_file.exists()
        child_pid = int(child_file.read_text())
        owner.kill()
        owner.wait(timeout=3)
        assert watcher.wait(timeout=3) == 125
        with pytest.raises(ProcessLookupError):
            os.kill(child_pid, 0)
    finally:
        for process in (owner, watcher):
            if process.poll() is None:
                process.send_signal(signal.SIGKILL)
            process.wait(timeout=3)


def test_command_uses_private_namespaces_explicit_mounts_and_no_inherited_secrets(tmp_path, monkeypatch):
    import ficc.modules.sandbox as module

    monkeypatch.setenv("MODULE_TEST_SECRET", "do not inherit")
    monkeypatch.setattr(module.os, "access", lambda *args: True)
    command = module.command(tmp_path, ["/usr/bin/python3", "-I", "/module/main.py"], "ficc-module-test.service")
    assert "--unshare-all" in command and "--clearenv" in command and "--new-session" in command
    assert "--property=MemoryMax=134217728" in command
    assert "--property=KillMode=control-group" in command
    assert "--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK" in command
    assert "--share-net" not in command and str(Path.home()) not in command
    assert "MODULE_TEST_SECRET" not in module.environment()


async def test_repeated_cancellation_waits_for_cleanup():
    from ficc.modules.sandbox import finish_cleanup

    started, finish = asyncio.Event(), asyncio.Event()
    completed = []

    async def cleanup():
        started.set()
        await finish.wait()
        completed.append(True)

    task = asyncio.create_task(finish_cleanup(cleanup()))
    await started.wait()
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done() and not completed
    finish.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert completed == [True]


async def test_cleanup_confirms_cgroup_empty_even_when_bus_stop_fails(tmp_path, monkeypatch):
    import ficc.modules.sandbox as module

    group = tmp_path / "service"
    group.mkdir()
    (group / "cgroup.events").write_text("populated 1\nfrozen 0\n")

    async def management(*args):
        raise TimeoutError

    monkeypatch.setattr(module, "management", management)
    task = asyncio.create_task(module.stop_service("test.service", group))
    await asyncio.sleep(0.02)
    assert not task.done()
    (group / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    await asyncio.wait_for(task, 1)
