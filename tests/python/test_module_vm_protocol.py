# SPDX-License-Identifier: Apache-2.0
"""Exercise provider APIs and reject forged or oversized VM protocol results."""

import copy
import os
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from ficc_node import vm_spec, vm_state
from ficc_node.vm_libvirt import Libvirt, ProviderError

from ficc.providers.libvirt import validate


def request(action="status", size=1):
    parameters = {"uuids": [f"{index:032x}" for index in range(size)]}
    if action == "list":
        parameters = {"offset": 0, "limit": 64}
    return {"version": 1, "action": action, "connection": "system",
            "profile": "b" * 32, "parameters": parameters}


@pytest.mark.parametrize("size", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_exact_batch_identity_and_duplicate_refusal(size):
    value = request(size=size)
    assert vm_spec.request(value) == value
    response = {"results": [{"uuid": item, "error": {"code": "vm_unavailable", "message": "Unavailable."}}
                            for item in value["parameters"]["uuids"]]}
    assert validate(response, value) == response
    response["results"][-1]["uuid"] = "f" * 32
    with pytest.raises(ValueError):
        validate(response, value)


@pytest.mark.parametrize("mutation", ["uri", "version", "extra", "duplicate", "oversized", "path", "action"])
def test_hostile_requests_rejected(mutation):
    value = request()
    if mutation == "uri":
        value["connection"] = "qemu+ssh://attacker/system?command=sh"
    elif mutation == "version":
        value["version"] = True
    elif mutation == "extra":
        value["parameters"]["command"] = "reboot"
    elif mutation == "duplicate":
        value["parameters"]["uuids"] *= 2
    elif mutation == "oversized":
        value["parameters"]["uuids"] = [f"{index:032x}" for index in range(65)]
    elif mutation == "path":
        value["parameters"]["uuids"] = ["../../etc/passwd"]
    else:
        value["action"] = "destroy"
    with pytest.raises(ValueError):
        vm_spec.request(value)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"value":NaN}', b"x" * (1024 * 1024 + 1)])
def test_bounded_duplicate_free_json(raw):
    with pytest.raises(ValueError):
        vm_spec.decode(raw)


def test_provider_uses_fixed_connection_uuid_and_graphics_fd(monkeypatch):
    class Domain:
        state = 5
        created = 0
        stopped = 0
        opened = []
        xml = '<domain><devices><graphics type="spice"/><graphics type="vnc" passwd="secret"/></devices></domain>'

        def info(self):
            return [self.state, 1024, 512, 1, 0]

        def name(self):
            return "VM"

        def UUIDString(self):
            return "00000000-0000-0000-0000-000000000000"

        def isPersistent(self):
            return True

        def isActive(self):
            return self.state == 1

        def XMLDesc(self, flags):
            return self.xml

        def create(self):
            self.created += 1
            self.state = 1

        def shutdown(self):
            self.stopped += 1

        def openGraphicsFD(self, index, flags):
            self.opened.append((index, flags))
            return 123

    domain = Domain()
    calls = []

    class Connection:
        def lookupByUUIDString(self, value):
            assert value == domain.UUIDString()
            return domain

        def listAllDomains(self, flags):
            return [domain]

        def close(self):
            pass

    def connect(uri):
        calls.append(uri)
        return Connection()

    monkeypatch.setitem(sys.modules, "libvirt", SimpleNamespace(open=connect, openReadOnly=connect,
        registerErrorHandler=lambda *args: None, VIR_DOMAIN_XML_INACTIVE=2, libvirtError=RuntimeError))
    provider = Libvirt("system", writable=True)
    assert calls == ["qemu:///system"]
    described = provider.status(["0" * 32])["results"][0]["data"]
    assert "secret" not in str(described)
    expected = {key: described[key] for key in ("uuid", "state", "definition")}
    assert provider.apply("start", expected) == {"state": "accepted"}
    assert provider.apply("start", expected)["state"] == "refused"
    descriptor, fd = provider.console("0" * 32, open_fd=True)
    assert fd == 123 and domain.opened == [(1, 0)]
    assert descriptor["audio"] is False and "secret" not in str(descriptor)
    expected["state"] = "running"
    assert provider.apply("shutdown", expected) == {"state": "accepted"}
    assert domain.stopped == 1 and domain.created == 1
    domain.xml = '<domain><devices><graphics type="spice"/></devices></domain>'
    with pytest.raises(ProviderError, match="no supported VNC"):
        provider.console("0" * 32)


def test_receipt_link_and_unknown_recovery(tmp_path, monkeypatch):
    monkeypatch.setattr(vm_state, "root", lambda: tmp_path)
    value = request("apply")
    value["parameters"] = {"controller": "c" * 32, "operation": "d" * 32,
                           "intent": {"action": "start", "expected": [
                               {"uuid": "0" * 32, "state": "off", "definition": "e" * 64}]}}
    path = tmp_path / ("c" * 32 + "-" + "d" * 32 + ".json")
    path.symlink_to(tmp_path / "missing")
    with pytest.raises(OSError):
        vm_state.receipt(None, value)
    path.unlink()
    identity = {key: value[key] for key in ("connection", "profile")}
    identity["intent"] = value["parameters"]["intent"]
    vm_state.write(path, {"digest": vm_spec.digest(identity), "results": [{"uuid": "0" * 32, "state": "dispatching"}]})
    result = vm_state.receipt(None, value)
    assert result["results"][0]["state"] == "unknown"


@pytest.mark.parametrize("mutation", ["missing", "extra", "type", "count", "order", "pagination"])
def test_host_rejects_malformed_provider_results(mutation):
    payload = request("list")
    value = {"results": [{"uuid": "0" * 32, "error": {"code": "unavailable", "message": "Unavailable."}}],
             "total": 1, "next_offset": None, "truncated": False, "inventory_digest": "b" * 64}
    if mutation == "missing":
        value.pop("total")
    elif mutation == "extra":
        value["password"] = "hidden"
    elif mutation == "type":
        value["truncated"] = 0
    elif mutation == "count":
        value["total"] = 2
    elif mutation == "order":
        value["results"].append(copy.deepcopy(value["results"][0]))
        value["total"] = 2
    else:
        value["truncated"] = True
        value["next_offset"] = 1
    with pytest.raises(ValueError):
        validate(value, payload)


def test_helper_deadline_terminates_blocked_provider():
    started = time.monotonic()
    code = ("from ficc_node import vm_rpc;import time;"
            "vm_rpc.dispatch=lambda value: time.sleep(30);vm_rpc.main()")
    result = subprocess.run([sys.executable, "-c", code], input=b"{}", capture_output=True,
                            env=os.environ.copy(), timeout=9)
    assert result.returncode == -signal.SIGALRM
    assert time.monotonic() - started < 9


@pytest.mark.parametrize("parent", [".local", ".local/state"])
def test_group_writable_receipt_ancestor_fails_with_actionable_error(tmp_path, monkeypatch, parent):
    from pathlib import Path
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    unsafe = tmp_path / parent
    unsafe.mkdir(mode=0o700, parents=True)
    unsafe.chmod(0o775)
    with pytest.raises(ProviderError) as error:
        vm_state.root()
    assert error.value.code == "vm_receipt_unavailable"
    assert "group/world write" in error.value.message
    assert unsafe.stat().st_mode & 0o777 == 0o775
