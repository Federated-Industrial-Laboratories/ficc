# SPDX-License-Identifier: Apache-2.0
"""Support explicit, isolated libvirt qualification without general remote commands."""

import importlib.util
import json
import os
import secrets
import selectors
import shlex
import signal
import subprocess
import time
from functools import partial
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ficc.api import create_app
from ficc.settings import Settings

ROOT = Path(__file__).resolve().parents[2]
PROFILE = "ficc-linux-fixture"
FIXTURES = {"ficc-vm-a", "ficc-vm-b"}
DEFINITIONS = """import fcntl,json,os,pathlib,re,signal,sys,uuid,libvirt
signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(90)
v=json.load(sys.stdin)
assert set(v)=={'prefix','action'} and re.fullmatch(r'ficc-qual-[0-9a-f]{8}',v['prefix'])
assert v['action'] in {'create','cleanup'}
base=pathlib.Path.home()/'.local/state/ficc'
base.mkdir(mode=0o700,parents=True,exist_ok=True)
assert not base.is_symlink() and base.stat().st_uid==os.getuid() and not base.stat().st_mode&0o077
lock=os.open(base/'vm-qualification.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
info=os.fstat(lock)
assert info.st_uid==os.getuid() and info.st_nlink==1 and not info.st_mode&0o077
fcntl.flock(lock,fcntl.LOCK_EX)
c=libvirt.open('qemu:///system')
names=[v['prefix']+'-'+str(i).zfill(2) for i in range(64)]
ids={name:str(uuid.uuid5(uuid.NAMESPACE_OID,name)) for name in names}
try:
 if v['action']=='create':
  assert not any(d.name() in names for d in c.listAllDomains(0))
  for name in names:
   xml='<domain type="qemu"><name>'+name+'</name><uuid>'+ids[name]+'</uuid><memory unit="KiB">65536</memory><vcpu>1</vcpu><os><type arch="x86_64">hvm</type></os><devices/></domain>'
   d=c.defineXML(xml)
   assert not d.isActive() and d.UUIDString()==ids[name]
 else:
  for d in c.listAllDomains(0):
   if d.name() in names:
    assert not d.isActive() and d.UUIDString()==ids[d.name()]
    d.undefine()
 print(json.dumps({'count':sum(d.name() in names for d in c.listAllDomains(0)),
                   'active':sum(bool(d.isActive()) for d in c.listAllDomains(0))}))
finally:c.close();os.close(lock)
"""
BOOT = """import json,os,pathlib,stat,sys,xml.etree.ElementTree as E,libvirt
v=json.load(sys.stdin)
assert set(v)=={'offset'} and (v['offset'] is None or type(v['offset']) is int and 0<=v['offset']<=16777216)
c=libvirt.openReadOnly('qemu:///system')
d=c.lookupByName('ficc-vm-b')
assert d.UUIDString()=='953546e6-bb95-4563-8ce7-b979a877e43b'
x=E.fromstring(d.XMLDesc(0))
p=x.find('./devices/serial[@type="file"]/source').attrib['path']
assert p=='/var/log/libvirt/qemu/ficc-vm-b-console.log'
f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
try:
 s=os.fstat(f)
 assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=16777216
 offset=v['offset']
 if offset is None:print(json.dumps({'offset':s.st_size}))
 else:
  assert offset<=s.st_size and s.st_size-offset<=1048576
  os.lseek(f,offset,os.SEEK_SET)
  content=os.read(f,1048576)
  print(json.dumps({'ready':b'ficc-vm-b FICC-FIXTURE-READY' in content}))
finally:os.close(f);c.close()
"""


def checked(response, status=200):
    assert response.status_code == status, response.text[:2048]
    return response.json()


class Live:
    def __init__(self, client, service, node, digest, context, grants, actor):
        self.client, self.service, self.node, self.digest = client, service, node, digest
        self.context, self.grants, self.actor = context, grants, actor

    def invoke(self, action, parameters=None, status=200):
        return checked(self.client.post("/api/v1/module-invocations", json={**self.context,
            "targets": [self.node["id"]], "action": action, "parameters": parameters or {}}), status)

    def inventory(self, offset=0):
        result = self.invoke("load", {"offset": offset})
        return result["results"][0]["data"]

    def activate(self, grants):
        return checked(self.client.post(f"/api/v1/modules/{self.digest}/activation",
                                       json={"enabled": True, "grants": grants}))

    def fixture_rows(self):
        result = self.inventory()
        assert not result["notice"], result["notice"]
        rows = {row["values"]["name"]: row for row in result["rows"]}
        assert set(rows) == FIXTURES, "The disposable guest inventory differs from its fixture contract."
        return rows

    def preview(self, action, vm_id):
        result = self.invoke("preview-" + action, {"vm_ids": [vm_id]})
        preview = result["results"][0]["data"]
        assert len(preview["vms"]) == 1 and preview["vms"][0]["vm_id"] == vm_id
        return checked(self.client.post("/api/v1/module-vms/preview",
                        json={**self.context, "preview_id": preview["preview_id"]}))

    def commit(self, preview, key=None, status=200):
        return checked(self.client.post("/api/v1/module-vms/commit", json={**self.context,
            "preview_id": preview["preview_id"], "confirm": True},
            headers={"Idempotency-Key": key or secrets.token_hex(16)}), status)

    def wait_operation(self, operation_id, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = checked(self.client.post("/api/v1/module-vms/operation",
                             json={**self.context, "operation_id": operation_id}))
            states = {target["state"] for target in result["targets"]}
            if states <= {"observed", "refused", "resolved"}:
                return result
            assert states <= {"accepted"}, result
            time.sleep(1)
        pytest.fail("The disposable VM did not reach its requested state before the deadline.")

    def definitions(self, prefix, action):
        result = self.client.portal.call(partial(self.service.ssh.command, self.node,
            "exec python3 -c " + shlex.quote(DEFINITIONS), json.dumps({"prefix": prefix, "action": action}).encode(), timeout=95))
        assert result[0] == 0, result[2].decode(errors="replace")[:2048]
        return json.loads(result[1])

    def boot_marker(self, offset=None):
        result = self.client.portal.call(self.service.ssh.command, self.node,
            "exec sudo -n python3 -c " + shlex.quote(BOOT), json.dumps({"offset": offset}).encode())
        assert result[0] == 0, result[2].decode(errors="replace")[:2048]
        return json.loads(result[1])

    def wait_boot(self, offset, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.boot_marker(offset)["ready"]:
                return
            time.sleep(3)
        pytest.fail("The disposable VM did not reach its current-boot marker before the deadline.")


@pytest.fixture
def live_vm(tmp_path):
    config = os.environ.get("FICC_LIBVIRT_TEST_CONFIG")
    if not config or os.environ.get("FICC_REAL_MODULE_SANDBOX") != "1":
        pytest.skip("Explicit disposable fixture SSH configuration and real sandbox required.")
    app = create_app(Settings(state_dir=tmp_path / "state", ssh_config=Path(config), profiles=(PROFILE,),
                              control=False, poll_interval=3600, stale_after=7200))
    service = app.state.service
    with TestClient(app, base_url="http://127.0.0.1:8170") as client:
        token, _ = service.auth.issue("bootstrap", lifetime=120)
        session = checked(client.post("/api/v1/session", json={"bootstrap": token},
                                      headers={"Origin": "http://127.0.0.1:8170"}))
        client.headers.update({"Origin": "http://127.0.0.1:8170", "X-CSRF-Token": session["csrf"]})
        preview = checked(client.post("/api/v1/node-previews", json={"profile": PROFILE, "name": "Disposable libvirt fixture"}))
        assert preview["trust"] == "trusted"
        view = checked(client.post("/api/v1/nodes", json={"preview_id": preview["preview_id"],
            "expected_fingerprint": preview["fingerprint"], "install_helper": True}))
        node = service.store.node(view["id"])
        client.portal.call(service.ssh.install, node)
        checked(client.put(f"/api/v1/nodes/{node['id']}/vm-profile", json={"connection": "system"}))
        spec = importlib.util.spec_from_file_location("vm_live_pack", ROOT / "tools/build-modules.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        manifest, files = builder.read_source(ROOT / "modules/libvirt")
        files["ficc_module.py"] = (ROOT / "sdk/python/ficc_module.py").read_bytes()
        data = builder.build_archive(manifest, files)
        inspection = checked(client.post("/api/v1/module-install-previews", content=data,
                                         headers={"Content-Type": "application/octet-stream"}))
        package = checked(client.post("/api/v1/modules", json={"preview_id": inspection["preview_id"],
            "digest": inspection["digest"], "accept_unverified": True}), 201)
        space = checked(client.post("/api/v1/workspaces", json={"name": "Disposable VMs"}), 201)
        digest = package["digest"]
        context = {"workspace_id": space["id"], "instance_id": secrets.token_hex(16)}
        grants = [{"capability": "workspace:read", "target_ids": [space["id"]]},
                  {"capability": "vm:read", "target_ids": [node["id"]]}]
        checked(client.post(f"/api/v1/modules/{digest}/activation", json={"enabled": True, "grants": grants}))
        checked(client.put(f"/api/v1/workspaces/{space['id']}", json={"revision": space["revision"],
            "name": space["name"], "instances": [{"id": context["instance_id"], "digest": digest,
                                                   "title": "VMs", "targets": [node["id"]]}]}))
        yield Live(client, service, node, digest, context, grants, session["principal"]["id"])


def rfb_handshake(arguments, header):
    process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
    received = bytearray()
    try:
        process.stdin.write(header)
        deadline = time.monotonic() + 8
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline and len(received) < 256:
                if not selector.select(max(0, deadline - time.monotonic())):
                    break
                data = os.read(process.stdout.fileno(), 256 - len(received))
                if not data:
                    break
                received.extend(data)
                if b"\nRFB " in received and received.endswith(b"\n"):
                    break
        ready, _, banner = bytes(received).partition(b"\n")
        assert json.loads(ready) == {"version": 1, "ready": True}, bytes(received)
        assert banner.startswith(b"RFB 003.") and len(banner) == 12, banner
        return banner.decode().strip()
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        process.stdout.close()
        process.stderr.close()
