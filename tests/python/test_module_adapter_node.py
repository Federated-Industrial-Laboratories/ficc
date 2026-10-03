# SPDX-License-Identifier: Apache-2.0
"""Detect node package, socket identity and no-replay journal failures."""

import copy
import hashlib
import io
import socket

import pytest
from ficc_node import adapter_binding as binding
from ficc_node import adapter_journal as journal
from ficc_node import adapter_store as store
from test_module_adapter_manifest import adapter_package
from test_module_adapter_protocol import bindings

from ficc.errors import Failure
from ficc.modules.adapter_protocol import Conversation
from ficc.modules.sandbox import command


def test_socket_registration_pins_inode_and_process_and_refuses_replacement(tmp_path):
    location = tmp_path / "provider.sock"
    first = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        first.bind(str(location))
        location.chmod(0o600)
        first.listen(16)
        selected = binding.register(tmp_path, {"socket_path": str(location)})
        with binding.selected(tmp_path, selected["id"]) as pinned:
            assert pinned.stat().st_ino == location.stat().st_ino
            args = command(tmp_path, ["/usr/bin/true"], "ficc-module-test", provider_socket=pinned)
            assert args[args.index(str(pinned)) + 1] == "/provider/socket"
            assert "--unshare-all" in args and "--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK" in args
        location.unlink()
        second.bind(str(location))
        location.chmod(0o600)
        second.listen(16)
        with pytest.raises(Failure, match="changed"):
            with binding.selected(tmp_path, selected["id"]):
                pytest.fail("A replaced socket was admitted")
        assert binding.listing(tmp_path)["bindings"][0]["available"] is False
        fresh = binding.register(tmp_path, {"socket_path": str(location)})
        assert fresh["id"] != selected["id"]
    finally:
        first.close()
        second.close()


@pytest.mark.parametrize("kind", ["link", "public", "file"])
def test_socket_registration_refuses_untrusted_path(tmp_path, kind):
    location = tmp_path / "socket"
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if kind == "file":
            location.write_text("not a socket")
        else:
            peer.bind(str(location))
            location.chmod(0o666 if kind == "public" else 0o600)
            peer.listen()
        if kind == "link":
            alias = tmp_path / "alias"
            alias.symlink_to(location)
            location = alias
        with pytest.raises(Failure):
            binding.register(tmp_path, {"socket_path": str(location)})
    finally:
        peer.close()


def transfer():
    manifest, files = adapter_package()
    manifest["files"] = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    members = [{"path": name, "size": len(data), "sha256": manifest["files"][name]} for name, data in files.items()]
    return {"digest": "a" * 64, "manifest": manifest, "members": members}, b"".join(files.values())


def test_private_atomic_install_and_content_verification(tmp_path):
    parameters, data = transfer()
    assert store.install(tmp_path, parameters, io.BytesIO(data)) == {"installed": True}
    path, manifest = store.verify(tmp_path, parameters["digest"])
    assert path.stat().st_mode & 0o777 == 0o500
    target = path / manifest["runtime"]["entry"]
    assert target.stat().st_mode & 0o777 == 0o400
    assert store.install(tmp_path, parameters, io.BytesIO(data)) == {"installed": True}
    target.chmod(0o600)
    target.write_bytes(b"changed")
    with pytest.raises(Failure, match="content changed"):
        store.verify(tmp_path, parameters["digest"])


@pytest.mark.parametrize("mutation", ["extra", "digest", "duplicate", "traversal", "oversize"])
def test_package_transfer_refuses_changed_members_without_publish(tmp_path, mutation):
    parameters, data = transfer()
    if mutation == "extra":
        data += b"extra"
    elif mutation == "digest":
        data = b"x" * len(data)
    elif mutation == "duplicate":
        parameters["members"].append(copy.deepcopy(parameters["members"][0]))
    elif mutation == "traversal":
        parameters["members"][0]["path"] = "../escape"
    else:
        parameters["members"][0]["size"] = 16 * 1024 * 1024 + 1
    with pytest.raises(Failure):
        store.install(tmp_path, parameters, io.BytesIO(data))
    assert not (tmp_path / "packages" / parameters["digest"]).exists()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_node_journal_repeated_apply_never_reexecutes_and_cleanup_is_exact(tmp_path, count):
    selected = bindings()[0]
    selected["resources"] = [{"id": f"{index + 1:032x}", "key": str(index), "birth": "b" * 64,
        "revision": "c" * 64, "state": "off"} for index in range(count)]
    selected["intent"] = {"controller": "1" * 32, "operation": "2" * 32, "digest": "d" * 64,
        "targets": [{"id": item["id"], "intent": {"action": "start"}} for item in selected["resources"]]}
    path, saved, previous = journal.prepare(tmp_path, "a" * 64, selected, "apply")
    assert previous is None and len(saved["results"]) == count
    again = journal.prepare(tmp_path, "a" * 64, selected, "apply")[2]
    assert all(item["receipt"]["state"] == "unknown" for item in again["results"])
    changed = copy.deepcopy(selected)
    changed["resources"][0]["birth"] = "f" * 64
    with pytest.raises(Failure, match="changed"):
        journal.prepare(tmp_path, "a" * 64, changed, "apply")
    params = {"profile_id": selected["id"], "digest": "a" * 64, "intent": selected["intent"],
              "outcomes": [{"id": item["id"], "state": "observed"} for item in selected["resources"]]}
    with pytest.raises(Failure, match="terminal proof"):
        journal.forget(tmp_path, params)
    for item in params["outcomes"]:
        item["state"] = "resolved"
    assert journal.forget(tmp_path, params) == {"removed": True}
    assert not path.exists()
    assert journal.forget(tmp_path, params) == {"removed": True}


def test_received_adapter_request_keeps_original_id_without_mutable_aliases():
    original = Conversation("a" * 64, "probe", "probe", bindings(), lambda: None)
    value = original.request
    received = Conversation.received(value, lambda: None)
    value["bindings"][0]["parameters"]["changed"] = True
    assert received.id == original.id and received.payload == original.payload
    assert received.request == original.request


def test_trusted_node_support_has_only_standard_library_imports(tmp_path):
    import subprocess

    from ficc.ssh import archive

    target = tmp_path / "node.pyz"
    target.write_bytes(archive())
    script = "import sys;sys.path.insert(0,sys.argv[1]);import ficc_node.adapter_rpc;print('adapter-import-ok')"
    result = subprocess.run(["/usr/bin/python3", "-I", "-S", "-c", script, str(target)],
                            capture_output=True, check=True, timeout=5)
    assert result.stdout.strip() == b"adapter-import-ok"
    assert len(target.read_bytes()) <= 1024 * 1024
