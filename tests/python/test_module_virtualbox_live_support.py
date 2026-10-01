# SPDX-License-Identifier: Apache-2.0
"""Support opt-in qualification on the dedicated VirtualBox account."""

import importlib.util
import json
import os
import re
import secrets
import shlex
import stat
import time
from functools import partial
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_module_vm_live_support import Live as Common
from test_module_vm_live_support import checked

from ficc.api import create_app
from ficc.modules.validation import fields, loads
from ficc.settings import Settings

ROOT = Path(__file__).resolve().parents[2]
BOOT = r'''
import json,os,pathlib,re,stat,subprocess,sys
v=json.load(sys.stdin)
assert set(v)=={'action','nonce','fixture'} and v['action'] in {'inspect','arm','read'} and re.fullmatch('[0-9a-f]{32}',v['nonce'])
fixture=v['fixture']
assert set(fixture)=={'outer_id','account_uid','vm_id','vm_birth','vm_name','batch_prefix','profile','transport_socket'}
assert type(fixture['account_uid']) is int and os.getuid()==fixture['account_uid']
marker=pathlib.Path('/etc/ficc-lab-virtualbox-public.json')
assert marker.stat().st_uid==0 and not marker.stat().st_mode&0o022
assert json.loads(marker.read_text())=={'format':1,'id':fixture['outer_id'],'role':'virtualbox'}
identity=fixture['vm_id']
def box(*args):return subprocess.check_output(['VBoxManage',*args],text=True,timeout=10)
values={}
for line in box('showvminfo',identity,'--machinereadable').splitlines():
 key,_,value=line.partition('=')
 if key in {'UUID','VMState','CfgFile'}:values[key]=json.loads(value)
base=pathlib.Path.home()/'fixtures'/fixture['vm_name']
assert values['UUID']==identity and values['CfgFile']==str(base/(fixture['vm_name']+'.vbox'))
assert box('getextradata',identity,'FICC/Birth').strip()=='Value: '+fixture['vm_birth']
assert base.resolve()==base and base.stat().st_uid==os.getuid() and not base.stat().st_mode&0o077
if v['action']=='inspect':
 print(json.dumps({'identity_checked':True}))
 raise SystemExit(0)
path=base/('console-'+v['nonce']+'.log')
if v['action']=='arm':
 assert values['VMState']=='poweroff'
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
 box('modifyvm',identity,'--uart1','0x3f8','4','--uartmode1','file',str(path))
 print(json.dumps({'armed':True}))
else:
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd);assert stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and info.st_size<=1048576
  data=os.read(fd,1048576)
  print(json.dumps({'ready':(fixture['vm_name']+' login:').encode() in data,'bytes':len(data)}))
 finally:os.close(fd)
'''


def qualification(path):
    """Require an explicit private fixture identity before any remote admission."""
    location = Path(path)
    if location.resolve() != location.absolute():
        raise ValueError("The qualification input must not contain a path link.")
    fd = os.open(location, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or info.st_mode & 0o077 or info.st_size > 8192):
            raise ValueError("The qualification input must be a private owned regular file.")
        value = fields(loads(stream.read(8193), 8192),
            {"outer_id", "account_uid", "vm_id", "vm_birth", "vm_name", "batch_prefix", "profile", "transport_socket"})
    for field in ("outer_id", "vm_id"):
        if not isinstance(value[field], str) or re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", value[field]) is None:
            raise ValueError("The qualification VM identity must be a canonical UUID.")
    if (type(value["account_uid"]) is not int or not 1 <= value["account_uid"] < 2**31
            or not isinstance(value["vm_birth"], str) or re.fullmatch(r"[0-9a-f]{64}", value["vm_birth"]) is None
            or value["vm_birth"] == "0" * 64):
        raise ValueError("The qualification account or birth identity is invalid.")
    for field in ("vm_name", "batch_prefix", "profile"):
        if not isinstance(value[field], str) or re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", value[field]) is None:
            raise ValueError("The qualification name must be an explicit bounded identifier.")
    socket_path = value["transport_socket"]
    if (not isinstance(socket_path, str) or len(socket_path) > 240 or not socket_path.startswith("/")
            or any(part in {"", ".", ".."} for part in socket_path.split("/")[1:])):
        raise ValueError("The qualification provider socket must be an absolute direct path.")
    return value


class Live(Common):
    def invoke(self, action, parameters=None, status=200):
        values = dict(parameters or {})
        if action != "profiles":
            values["profile_id"] = self.profile["id"]
        return super().invoke(action, values, status)

    def fixture_rows(self):
        result = self.inventory()
        rows = {item["values"]["name"]: item for item in result["rows"]}
        assert self.fixture["vm_name"] in rows
        allowed = {self.fixture["vm_name"]} | {self.fixture["batch_prefix"] + "-" + str(index).zfill(2) for index in range(64)}
        assert set(rows) <= allowed
        return rows

    def forget(self, operation):
        return checked(self.client.post("/api/v1/module-vms/forget",
            json={**self.context, "operation_id": operation["id"], "confirm": True}))

    def boot(self, action, nonce):
        result = self.client.portal.call(partial(self.service.ssh.command, self.node,
            "exec python3 -B -c " + shlex.quote(BOOT),
            json.dumps({"action": action, "nonce": nonce, "fixture": self.fixture}).encode(), timeout=30))
        assert result[0] == 0, result[2].decode(errors="replace")[:1024]
        return json.loads(result[1])

    def wait_boot(self, nonce):
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            if self.boot("read", nonce)["ready"]:
                return
            time.sleep(3)
        pytest.fail("The current disposable guest boot did not reach its serial login marker.")


def install(client, data):
    inspected = checked(client.post("/api/v1/module-install-previews", content=data,
        headers={"Content-Type": "application/octet-stream"}))
    return checked(client.post("/api/v1/modules", json={"preview_id": inspected["preview_id"],
        "digest": inspected["digest"], "accept_unverified": True}), 201)


@pytest.fixture
def live_vbox(tmp_path):
    config, archive = os.environ.get("FICC_VBOX_TEST_CONFIG"), os.environ.get("FICC_VBOX_ADAPTER_ARCHIVE")
    fixture_path = os.environ.get("FICC_VBOX_QUALIFICATION")
    if not config or not archive or not fixture_path or os.environ.get("FICC_REAL_MODULE_SANDBOX") != "1":
        pytest.skip("Explicit disposable VirtualBox SSH configuration, private qualification JSON, archive and real sandbox required.")
    fixture = qualification(fixture_path)
    runtime = os.environ.get("FICC_VIEWER_RUNTIME")
    app = create_app(Settings(state_dir=tmp_path / "state", ssh_config=Path(config), profiles=(fixture["profile"],),
        viewer_runtime=Path(runtime) if runtime else None, control=False, poll_interval=3600, stale_after=7200))
    service = app.state.service
    with TestClient(app, base_url="http://127.0.0.1:8170") as client:
        token, _ = service.auth.issue("bootstrap", lifetime=120)
        session = checked(client.post("/api/v1/session", json={"bootstrap": token},
            headers={"Origin": "http://127.0.0.1:8170"}))
        client.headers.update({"Origin": "http://127.0.0.1:8170", "X-CSRF-Token": session["csrf"]})
        preview = checked(client.post("/api/v1/node-previews", json={"profile": fixture["profile"], "name": "Disposable VirtualBox"}))
        assert preview["trust"] == "trusted"
        view = checked(client.post("/api/v1/nodes", json={"preview_id": preview["preview_id"],
            "expected_fingerprint": preview["fingerprint"], "install_helper": False}))
        node = service.store.node(view["id"])
        result = client.portal.call(partial(service.ssh.command, node, "exec python3 -B -c " + shlex.quote(BOOT),
            json.dumps({"action": "inspect", "nonce": secrets.token_hex(16), "fixture": fixture}).encode(), timeout=30))
        assert result[0] == 0, result[2].decode(errors="replace")[:1024]
        assert json.loads(result[1]) == {"identity_checked": True}
        client.portal.call(service.ssh.install, node)
        adapter = install(client, Path(archive).read_bytes())
        binding = checked(client.post("/api/v1/adapter-bindings", json={"endpoint_kind": "linux-ssh",
            "endpoint_id": node["id"], "socket_path": fixture["transport_socket"]}), 201)
        profile = checked(client.post("/api/v1/adapter-profiles", json={"digest": adapter["digest"],
            "endpoint_kind": "linux-ssh", "endpoint_id": node["id"], "transport_binding_id": binding["id"]}), 201)
        assert not profile["enabled"] and not profile["admin_granted"]
        checked(client.post(f"/api/v1/adapter-profiles/{profile['id']}/grant",
            json={"expected_revision": profile["revision"], "confirm": False}), 422)
        profile = checked(client.post(f"/api/v1/adapter-profiles/{profile['id']}/grant",
            json={"expected_revision": profile["revision"], "confirm": True}))
        assert profile["ready"] and profile["consistency"] == "checked-before-dispatch"
        spec = importlib.util.spec_from_file_location("vbox_live_pack", ROOT / "tools/build-modules.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        manifest, files = builder.read_source(ROOT / "modules/virtualbox")
        files["ficc_module.py"] = (ROOT / "sdk/python/ficc_module.py").read_bytes()
        package = install(client, builder.build_archive(manifest, files))
        space = checked(client.post("/api/v1/workspaces", json={"name": "Disposable VirtualBox"}), 201)
        digest = package["digest"]
        context = {"workspace_id": space["id"], "instance_id": secrets.token_hex(16)}
        grants = [{"capability": "workspace:read", "target_ids": [space["id"]]},
                  {"capability": "vm:read", "target_ids": [node["id"]]}]
        checked(client.post(f"/api/v1/modules/{digest}/activation", json={"enabled": True, "grants": grants}))
        checked(client.put(f"/api/v1/workspaces/{space['id']}", json={"revision": space["revision"],
            "name": space["name"], "instances": [{"id": context["instance_id"], "digest": digest,
                "title": "VirtualBox", "targets": [node["id"]]}]}))
        live = Live(client, service, node, digest, context, grants, session["principal"]["id"])
        live.fixture = fixture
        live.profile = profile
        yield live
