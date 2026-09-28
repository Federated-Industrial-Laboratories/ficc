# SPDX-License-Identifier: Apache-2.0
"""Support opt-in Proxmox qualification on the dedicated disposable fixture."""

import importlib.util
import json
import os
import secrets
import shlex
import time
from functools import partial
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_module_vm_live_support import Live as Common
from test_module_vm_live_support import checked

from ficc.api import create_app
from ficc.settings import Settings

ROOT = Path(__file__).resolve().parents[2]
PROFILE = "ficc-proxmox-fixture"
CAPTURE = r'''
import json,os,pathlib,socket,struct,sys,time
nonce=sys.argv[1];base=pathlib.Path('/root/ficc-lab/ficc-pve-a')
path=base/('test-boot-'+nonce+'.log');fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
stream=socket.socket(socket.AF_UNIX);stream.settimeout(1);deadline=time.monotonic()+570
while time.monotonic()<deadline:
 try:stream.connect('/var/run/qemu-server/9101.serial0');break
 except (FileNotFoundError,ConnectionRefusedError):time.sleep(.1)
pid,uid,_=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
assert uid==0 and pid==int(pathlib.Path('/var/run/qemu-server/9101.pid').read_text())
ready=False;size=0;tail=b''
with os.fdopen(fd,'wb') as output:
 while time.monotonic()<deadline and size<1048576:
  try:data=stream.recv(min(65536,1048576-size))
  except socket.timeout:continue
  if not data:break
  output.write(data);output.flush();size+=len(data);tail=(tail+data)[-4096:]
  if b'ficc-pve-a FICC-FIXTURE-READY' in tail:ready=True;break
 output.flush();os.fsync(output.fileno())
stream.close();(base/('test-boot-'+nonce+'.json')).write_text(json.dumps({'ready':ready,'pid':pid,'bytes':size}))
'''
BOOT = r'''
import json,os,pathlib,re,subprocess,sys
value=json.load(sys.stdin);assert set(value)=={'action','nonce'}
assert value['action'] in {'arm','read'} and re.fullmatch('[0-9a-f]{32}',value['nonce'])
assert os.getuid()==0 and pathlib.Path('/sys/class/dmi/id/product_uuid').read_text().strip()=='610bec8c-7be0-42ca-a64f-e627bf66894e'
conf=pathlib.Path('/etc/pve/qemu-server/9101.conf').read_text().splitlines()
assert 'name: ficc-pve-a' in conf and 'smbios1: uuid=a00173d1-c259-4e55-b203-c62286bf09a9' in conf
assert 'vmgenid: 373f8e3c-f7cd-4ad0-a5ae-81c1344fe0ba' in conf
base=pathlib.Path('/root/ficc-lab/ficc-pve-a');assert not base.is_symlink() and not base.stat().st_mode&0o077
if value['action']=='arm':
 subprocess.run(['systemd-run','--quiet','--collect','--unit=ficc-lab-test-serial-'+value['nonce'],
  '--property=RuntimeMaxSec=600','--property=MemoryMax=64M','--property=TasksMax=8','--property=CPUQuota=25%',
  '--property=NoNewPrivileges=yes','--property=UMask=0077','--property=StandardOutput=null','--property=StandardError=journal',
  '--','python3','-c',CAPTURE,value['nonce']],check=True,timeout=10)
 print(json.dumps({'armed':True}))
else:
 path=base/('test-boot-'+value['nonce']+'.json')
 print(path.read_text() if path.exists() else json.dumps({'ready':False}))
'''.replace('CAPTURE', repr(CAPTURE))


class Live(Common):
    def fixture_rows(self):
        result = self.inventory()
        assert not result["notice"], result["notice"]
        rows = {item["values"]["name"]: item for item in result["rows"]}
        assert set(rows) == {"ficc-pve-a", "ficc-pve-b"}
        return rows

    def capture(self, action, nonce):
        result = self.client.portal.call(partial(self.service.ssh.command, self.node,
            "exec python3 -c " + shlex.quote(BOOT), json.dumps({"action": action, "nonce": nonce}).encode(), timeout=15))
        assert result[0] == 0, result[2].decode(errors="replace")[:2048]
        return json.loads(result[1])

    def wait_ready(self, nonce):
        deadline = time.monotonic() + 580
        while time.monotonic() < deadline:
            if self.capture("read", nonce)["ready"]:
                return
            time.sleep(3)
        pytest.fail("The current boot did not produce its fixture readiness marker.")

    def forget(self, operation):
        return checked(self.client.post("/api/v1/module-vms/forget",
            json={**self.context, "operation_id": operation["id"], "confirm": True}))


@pytest.fixture
def live_pve(tmp_path):
    config = os.environ.get("FICC_PROXMOX_TEST_CONFIG")
    if not config or os.environ.get("FICC_REAL_MODULE_SANDBOX") != "1":
        pytest.skip("Explicit Proxmox fixture SSH configuration and real sandbox required.")
    runtime = os.environ.get("FICC_VIEWER_RUNTIME")
    settings = Settings(state_dir=tmp_path / "state", ssh_config=Path(config), profiles=(PROFILE,),
        viewer_runtime=Path(runtime) if runtime else None, control=False, poll_interval=3600, stale_after=7200)
    app = create_app(settings)
    service = app.state.service
    with TestClient(app, base_url="http://127.0.0.1:8170") as client:
        token, _ = service.auth.issue("bootstrap", lifetime=120)
        session = checked(client.post("/api/v1/session", json={"bootstrap": token},
                                     headers={"Origin": "http://127.0.0.1:8170"}))
        client.headers.update({"Origin": "http://127.0.0.1:8170", "X-CSRF-Token": session["csrf"]})
        preview = checked(client.post("/api/v1/node-previews", json={"profile": PROFILE, "name": "Disposable Proxmox fixture"}))
        assert preview["trust"] == "trusted"
        view = checked(client.post("/api/v1/nodes", json={"preview_id": preview["preview_id"],
            "expected_fingerprint": preview["fingerprint"], "install_helper": True}))
        node = service.store.node(view["id"])
        client.portal.call(service.ssh.install, node)
        checked(client.put(f"/api/v1/nodes/{node['id']}/proxmox-profile", json={"enabled": True}))
        spec = importlib.util.spec_from_file_location("pve_live_pack", ROOT / "tools/build-modules.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        manifest, files = builder.read_source(ROOT / "modules/proxmox")
        files["ficc_module.py"] = (ROOT / "sdk/python/ficc_module.py").read_bytes()
        data = builder.build_archive(manifest, files)
        inspected = checked(client.post("/api/v1/module-install-previews", content=data,
            headers={"Content-Type": "application/octet-stream"}))
        package = checked(client.post("/api/v1/modules", json={"preview_id": inspected["preview_id"],
            "digest": inspected["digest"], "accept_unverified": True}), 201)
        space = checked(client.post("/api/v1/workspaces", json={"name": "Disposable Proxmox"}), 201)
        digest = package["digest"]
        context = {"workspace_id": space["id"], "instance_id": secrets.token_hex(16)}
        grants = [{"capability": "workspace:read", "target_ids": [space["id"]]},
                  {"capability": "vm:read", "target_ids": [node["id"]]}]
        checked(client.post(f"/api/v1/modules/{digest}/activation", json={"enabled": True, "grants": grants}))
        checked(client.put(f"/api/v1/workspaces/{space['id']}", json={"revision": space["revision"],
            "name": space["name"], "instances": [{"id": context["instance_id"], "digest": digest,
                "title": "Proxmox", "targets": [node["id"]]}]}))
        yield Live(client, service, node, digest, context, grants, session["principal"]["id"])
