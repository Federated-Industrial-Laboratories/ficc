# SPDX-License-Identifier: Apache-2.0
"""Qualify actual module isolation with disposable files, services and processes."""

import asyncio
import hashlib
import io
import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from ficc.errors import Failure
from ficc.modules import Registry, initialize, inspect_archive, watcher
from ficc.modules.runtime import Runtime
from ficc.modules.sandbox import (
    MAX_SECONDS,
    MEMORY_BYTES,
    Sandbox,
    environment,
    management,
    stop_service,
)

ROOT = Path(__file__).resolve().parents[2]
OPT_IN = os.environ.get("FICC_MODULE_HOST_TESTS") == "1"
REQUIRED = os.environ.get("FICC_MODULE_HOST_REQUIRED") == "1"
pytestmark = pytest.mark.skipif(not OPT_IN, reason="Set FICC_MODULE_HOST_TESTS=1 for real host tests")
EVENTS = []


def record(name, **values):
    EVENTS.append({"name": name, **values})


def unavailable(reason):
    if REQUIRED:
        pytest.fail(reason)
    pytest.skip(reason)


@pytest.fixture(scope="module", autouse=True)
def evidence():
    yield
    target = os.environ.get("FICC_MODULE_HOST_EVIDENCE")
    if target:
        Path(target).write_text(json.dumps({"events": EVENTS}, indent=2) + "\n")


async def units(owner, package=None):
    code, data = await management("list-units", "ficc-module-*", "--all", "--output=json")
    assert code == 0
    found = []
    for unit in json.loads(data):
        name = unit["unit"]
        code, output = await management("show", name, "--property=MainPID", "--property=ControlGroup")
        if code:
            continue
        values = dict(line.split("=", 1) for line in output.decode().splitlines() if "=" in line)
        pid = int(values.get("MainPID", "0"))
        try:
            args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        except FileNotFoundError:
            continue
        marker = str(Path(watcher.__file__)).encode()
        if marker not in args:
            continue
        index = args.index(marker)
        if args[index + 1] != str(owner).encode() or (package and str(package).encode() not in args):
            continue
        group = Path("/sys/fs/cgroup") / values["ControlGroup"].lstrip("/")
        found.append((name, group))
    return found


async def started(task, package, owner=None):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if task is not None and task.done():
            await task
            pytest.fail("The test process exited before observation")
        found = await units(owner or os.getpid(), package)
        if found:
            name, group = found[0]
            limits = {key: (group / key).read_text().strip() for key in
                      ("memory.max", "memory.swap.max", "pids.max", "cpu.max")}
            assert limits["memory.max"] == str(MEMORY_BYTES)
            assert limits["memory.swap.max"] == "0" and limits["pids.max"] == "32"
            quota, period = map(int, limits["cpu.max"].split())
            assert quota * 2 <= period
            record("kernel_limits", unit=name, limits=limits)
            return name, group
        await asyncio.sleep(0.02)
    pytest.fail("The owned test service did not become visible")


async def empty(group):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if not group.exists() or "populated 0" in (group / "cgroup.events").read_text().splitlines():
            return
        await asyncio.sleep(0.02)
    pytest.fail("An owned test service still has live processes")


def module_processes(group):
    found = []
    for pid in (group / "cgroup.procs").read_text().split():
        try:
            args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        except FileNotFoundError:
            continue
        if args[:3] == [b"/usr/bin/python3", b"-I", b"/module/main.py"]:
            found.append(int(pid))
    return found


@pytest.fixture
async def host(tmp_path):
    for binary in ("/usr/bin/python3", "/usr/bin/node", "/usr/bin/bwrap", "/usr/bin/systemd-run"):
        if not os.access(binary, os.X_OK):
            unavailable(f"Required host executable is absent: {binary}")
    status = await Sandbox().probe()
    if not status.available:
        unavailable(status.reason)
    db = sqlite3.connect(":memory:", check_same_thread=False)
    initialize(db)
    registry = Registry(SimpleNamespace(db=db, lock=threading.RLock()), tmp_path / "modules")
    runtime = Runtime(registry)
    yield registry, runtime
    await runtime.stop()
    leftovers = await units(os.getpid())
    for unit, group in leftovers:
        await stop_service(unit, group)
    for entry in registry.list():
        registry.uninstall(entry["digest"])
    db.close()
    assert not leftovers, "A test left an owned module service active"


async def enable(registry, archive, grants=None):
    inspection = inspect_archive(archive)
    registry.install(inspection, inspection.digest)
    status = await Sandbox().probe()
    assert status.available, status.reason
    registry.set_enabled(inspection.digest, True, grants or [], sandbox_ready=status.available)
    return inspection.digest


async def script(host, body, capabilities=None):
    registry, _ = host
    source = "\n".join((
        "import runpy", "from pathlib import Path",
        "serve=runpy.run_path(str(Path(__file__).with_name('ficc_module.py')))['serve']",
        "def action(request):", *["    " + line for line in body.splitlines()],
        "raise SystemExit(serve(action))", ""))
    files = {"main.py": source.encode(), "ficc_module.py": (ROOT / "sdk/python/ficc_module.py").read_bytes()}
    manifest = json.loads((ROOT / "sdk/examples/python/manifest.json").read_text())
    manifest["id"] = "org.example.host-test"
    manifest["capabilities"] = capabilities or []
    manifest["actions"][0]["parameters"] = {}
    manifest["ui"] = {"type": "column", "children": []}
    manifest["files"] = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, data in files.items():
            archive.writestr(name, data)
    grants = [{"capability": cap, "target_ids": ["target"]} for cap in capabilities or []]
    return await enable(registry, output.getvalue(), grants)


def results(expression):
    return "return [{'target':target,'data':" + expression + "} for target in request['targets']]"


@pytest.mark.parametrize("language", ["c", "cpp", "rust", "python", "javascript", "typescript"])
@pytest.mark.parametrize("count", [1, 64])
async def test_installed_sdk_runtime_batches_and_disable(host, language, count):
    folder = Path(os.environ.get("FICC_MODULE_HOST_PACKAGES", ROOT / "dist/module-examples"))
    archive = folder / f"org.example.echo.{language}-1.0.0.ficc-module.zip"
    if not archive.is_file():
        unavailable("Build the SDK examples and set FICC_MODULE_HOST_PACKAGES")
    registry, runtime = host
    digest = await enable(registry, archive.read_bytes())
    targets = [f"target-{index}" for index in range(count)]
    message = 'Escapes: " \\ \n Unicode: lambda \u03bb heart \u2665 rocket \U0001f680'
    result = await runtime.invoke(digest, "echo", targets, {"message": message}, lambda: None)
    assert result["results"] == [{"target": target, "data": {"message": message, "index": index}}
                                 for index, target in enumerate(targets)]
    with pytest.raises(Failure) as denied:
        await runtime.invoke(digest, "not-declared", targets, {}, lambda: None)
    assert denied.value.code == "module_action_unavailable"
    registry.revoke(digest)
    with pytest.raises(Failure) as disabled:
        await runtime.invoke(digest, "echo", targets, {"message": message}, lambda: None)
    assert disabled.value.code == "module_disabled"
    assert not runtime.active and not registry._leases
    record("sdk_runtime", language=language, count=count, digest=digest, result="passed")


@pytest.mark.parametrize("count", [1, 64])
async def test_real_mixed_results_and_order(host, count):
    digest = await script(host, "return list(reversed([{'target':t,'data':i} if i%2==0 else "
                        "{'target':t,'error':{'code':'unavailable','message':'Unavailable'}} "
                        "for i,t in enumerate(request['targets'])]))")
    targets = [f"target-{i}" for i in range(count)]
    result = await host[1].invoke(digest, "echo", targets, {}, lambda: None)
    assert [item["target"] for item in result["results"]] == targets
    for index, item in enumerate(result["results"]):
        if index % 2 == 0:
            assert item["data"] == index
        else:
            assert item["error"]["code"] == "unavailable"
    record("mixed_results", count=count, result="passed")


async def test_host_files_sockets_environment_fds_and_scratch_are_isolated(host, tmp_path, monkeypatch):
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("Disposable test sentinel")
    socket_path = str(tmp_path / "host.sock")
    abstract = "\0ficc-test-" + uuid.uuid4().hex
    scratch = "/tmp/ficc-test-" + uuid.uuid4().hex
    servers = [socket.socket(socket.AF_UNIX), socket.socket(socket.AF_UNIX), socket.socket()]
    fd = os.open(sentinel, os.O_RDONLY)
    os.set_inheritable(fd, True)
    monkeypatch.setenv("FICC_TEST_SENTINEL", "must-not-enter-module")
    try:
        servers[0].bind(socket_path)
        servers[1].bind(abstract)
        servers[2].bind(("127.0.0.1", 0))
        for server in servers:
            server.listen(1)
            server.setblocking(False)
        body = f"""import os,socket
from pathlib import Path
def denied(f):
    try: f()
    except OSError: return True
    return False
def unix_connect(address):
    with socket.socket(socket.AF_UNIX) as sock: sock.connect(address)
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
mounts=[line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
seen=[]
for fd in Path('/proc/self/fd').iterdir():
    try: seen.append(os.readlink(fd))
    except OSError: pass
data={{'file_absent':not Path({str(sentinel)!r}).exists(),
      'socket_absent':denied(lambda:unix_connect({socket_path!r})),
      'abstract_denied':denied(lambda:unix_connect({abstract!r})),
      'network_denied':denied(lambda:socket.socket(socket.AF_INET)),
      'read_only':denied(lambda:Path('/module/main.py').write_text('changed')),
      'chmod_denied':denied(lambda:os.chmod('/module/main.py',0o600)),
      'mount_read_only':any(row[4]=='/module' and 'ro' in row[5].split(',') for row in mounts),
      'fd_absent':{str(sentinel)!r} not in seen,
      'env':dict(os.environ),'seccomp':status['Seccomp'].strip(),
      'nnp':status['NoNewPrivs'].strip(),'caps':status['CapEff'].strip(),
      'scratch_absent':not Path({scratch!r}).exists()}}
Path({scratch!r}).write_text('private scratch')
data['scratch_writable']=Path({scratch!r}).read_text()=='private scratch'
{results('data')}"""
        digest = await script(host, body)
        for _ in range(2):
            result = await host[1].invoke(digest, "echo", ["target"], {}, lambda: None)
            data = result["results"][0]["data"]
            for key in ("file_absent", "socket_absent", "abstract_denied", "network_denied",
                        "read_only", "chmod_denied", "mount_read_only", "fd_absent",
                        "scratch_absent", "scratch_writable"):
                assert data[key], key
            assert data["env"] == {"PATH": "/usr/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent",
                                   "TMPDIR": "/tmp", "PWD": "/module"}
            assert data["seccomp"] == "2" and data["nnp"] == "1" and int(data["caps"], 16) == 0
            assert not Path(scratch).exists()
        host[0].verify(digest)
        assert sentinel.read_text() == "Disposable test sentinel"
        record("isolation", result="passed", checks=data)
    finally:
        os.close(fd)
        for server in servers:
            server.close()


async def test_live_grant_revocation_stops_the_owned_service(host):
    registry, runtime = host
    digest = await script(host, "import time\ntime.sleep(30)\n" + results("True"), ["workspace:read"])
    def check():
        registry.require(digest, "workspace:read", ["target"])
    task = asyncio.create_task(runtime.invoke(digest, "echo", ["target"], {}, check))
    unit, group = await started(task, registry.root / digest)
    before = time.monotonic()
    registry.revoke(digest)
    with pytest.raises(Failure) as denied:
        await asyncio.wait_for(task, 3)
    assert denied.value.code in {"module_disabled", "module_revoked"}
    await empty(group)
    assert not runtime.active and not registry._leases
    record("live_revocation", result="passed", seconds=time.monotonic() - before, unit=unit)


@pytest.mark.parametrize("stream,amount", [("stdout", 2200000), ("stderr", 70000)])
async def test_actual_output_limits(host, stream, amount):
    registry, runtime = host
    digest = await script(host, f"import os\nos.write({1 if stream == 'stdout' else 2},b'x'*{amount})\n"
                          "import time\ntime.sleep(2)\n" + results("True"))
    with pytest.raises(Failure) as error:
        await runtime.invoke(digest, "echo", ["target"], {}, lambda: None)
    assert error.value.code == "module_output_limit"
    assert not runtime.active and not registry._leases
    record("output_limit", stream=stream, amount=amount, result="passed")


async def test_actual_timeout_and_descendant_cleanup(host):
    registry, runtime = host
    digest = await script(host, "import os,signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                          "if os.fork()==0:\n    os.setsid()\n    time.sleep(30)\n    os._exit(0)\n"
                          "time.sleep(30)\n" + results("True"))
    before = time.monotonic()
    task = asyncio.create_task(runtime.invoke(digest, "echo", ["target"], {}, lambda: None))
    unit, group = await started(task, registry.root / digest)
    await asyncio.sleep(0.2)
    assert len(module_processes(group)) >= 2
    with pytest.raises(Failure) as error:
        await task
    assert error.value.code == "module_timeout"
    elapsed = time.monotonic() - before
    assert MAX_SECONDS <= elapsed < MAX_SECONDS + 5
    await empty(group)
    record("timeout_cleanup", result="passed", seconds=elapsed, unit=unit)


async def test_actual_fork_limit_and_detached_child_cleanup(host):
    registry, runtime = host
    digest = await script(host, """import errno,os,time
children=[]
failure=0
for _ in range(64):
    try: pid=os.fork()
    except OSError as error:
        failure=error.errno
        break
    if pid==0:
        os.setsid()
        time.sleep(5)
        os._exit(0)
    children.append(pid)
time.sleep(0.5)
""" + results("{'children':len(children),'denied':failure==errno.EAGAIN}"))
    task = asyncio.create_task(runtime.invoke(digest, "echo", ["target"], {}, lambda: None))
    unit, group = await started(task, registry.root / digest)
    data = (await task)["results"][0]["data"]
    assert data["denied"] and 1 <= data["children"] < 32
    await empty(group)
    record("fork_limit", result="passed", unit=unit, **data)


async def test_actual_cpu_quota(host):
    digest = await script(host, """import time
start=time.monotonic()
cpu=time.process_time()
while time.monotonic()-start<2: pass
data={'wall':time.monotonic()-start,'cpu':time.process_time()-cpu}
""" + results("data"))
    task = asyncio.create_task(host[1].invoke(digest, "echo", ["target"], {}, lambda: None))
    _, group = await started(task, host[0].root / digest)
    data = (await task)["results"][0]["data"]
    assert data["wall"] >= 2 and 0 < data["cpu"] < data["wall"] * 0.8
    await empty(group)
    record("cpu_quota", result="passed", **data)


async def test_actual_memory_limit(host):
    registry, runtime = host
    digest = await script(host, """import time
blocks=[]
time.sleep(0.2)
for _ in range(192):
    block=bytearray(1024*1024)
    for offset in range(0,len(block),4096): block[offset]=1
    blocks.append(block)
    time.sleep(0.02)
""" + results("'allocation-completed'"))
    task = asyncio.create_task(runtime.invoke(digest, "echo", ["target"], {}, lambda: None))
    unit, group = await started(task, registry.root / digest)
    peak, events = 0, {}
    while not task.done():
        try:
            peak = max(peak, int((group / "memory.peak").read_text()))
            current = dict(line.split() for line in (group / "memory.events").read_text().splitlines())
            events = {key: max(events.get(key, 0), int(value)) for key, value in current.items()}
        except FileNotFoundError:
            pass
        await asyncio.sleep(0.005)
    with pytest.raises(Failure) as error:
        await task
    assert error.value.code == "module_failed"
    # Systemd can remove the cgroup before the final counter read.
    journal_kill = False
    if not events.get("oom_kill", 0):
        for _ in range(10):
            result = subprocess.run(
                ["/usr/bin/journalctl", "--user", "--boot", "--unit=" + unit,
                 "--output=json", "--output-fields=USER_UNIT,UNIT_RESULT,SYSLOG_IDENTIFIER",
                 "--lines=20", "--no-pager", "--quiet"],
                capture_output=True, env=environment(), timeout=3, check=True)
            journal_kill = any(
                entry.get("USER_UNIT") == unit and entry.get("UNIT_RESULT") == "oom-kill"
                and entry.get("SYSLOG_IDENTIFIER") == "systemd"
                for entry in (json.loads(line) for line in result.stdout.splitlines()))
            if journal_kill:
                break
            await asyncio.sleep(0.05)
    assert peak >= 100 * 1024 * 1024 and (events.get("oom_kill", 0) > 0 or journal_kill), (peak, events)
    await empty(group)
    record("memory_limit", result="passed", unit=unit, peak=peak, events=events,
           journal_oom_kill=journal_kill)


async def test_controller_death_kills_owned_service_and_children(host, tmp_path):
    registry, _ = host
    digest = await script(host, "import os,time\nif os.fork()==0:\n    os.setsid()\n"
                          "    time.sleep(30)\n    os._exit(0)\ntime.sleep(30)\n" + results("True"))
    package = registry.root / digest
    source = "\n".join(("import asyncio", "from pathlib import Path",
                        "from ficc.modules import protocol", "from ficc.modules.sandbox import execute",
                        "_,payload=protocol.request('echo',['target'],{})",
                        f"asyncio.run(execute(Path({str(package)!r}),"
                        "['/usr/bin/python3','-I','/module/main.py'],payload,lambda:None))"))
    controller_file = tmp_path / "controller.py"
    controller_file.write_text(source)
    controller = subprocess.Popen([sys.executable, str(controller_file)], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  env={**environment(), "PYTHONPATH": str(ROOT / "src")},
                                  start_new_session=True)
    unit, group = None, None
    try:
        unit, group = await started(None, package, controller.pid)
        await asyncio.sleep(0.2)
        assert len(module_processes(group)) >= 2
        before = time.monotonic()
        controller.kill()
        controller.wait(timeout=3)
        await empty(group)
        record("controller_death", result="passed", seconds=time.monotonic() - before, unit=unit)
    finally:
        if controller.poll() is None:
            controller.kill()
            controller.wait(timeout=3)
        if unit:
            await stop_service(unit, group)
