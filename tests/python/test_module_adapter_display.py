# SPDX-License-Identifier: Apache-2.0
"""Reject changed Unix display processes, inodes and private path boundaries."""

import os
import socket

import pytest
from ficc_node import adapter_display as display

from ficc.errors import Failure


@pytest.mark.parametrize("count", [1, 64])
def test_display_attests_real_peer_and_rejects_replaced_inodes(tmp_path, count):
    peers = []
    try:
        for index in range(count):
            path = tmp_path / f"v{index}.sock"
            peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            peers.append(peer)
            peer.bind(str(path))
            path.chmod(0o600)
            peer.listen(4)
            value = display.describe({"pid": os.getpid(), "socket_path": str(path)})
            assert value["pid"] == os.getpid() and value["uid"] == os.getuid()
            with display.connect(value) as stream:
                assert stream.getpeername()
            display.check(value)
            changed = dict(value, start=str(int(value["start"]) + 1))
            with pytest.raises(Failure, match="changed"):
                display.check(changed)
            path.unlink()
            replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            peers.append(replacement)
            replacement.bind(str(path))
            path.chmod(0o600)
            replacement.listen(2)
            with pytest.raises(Failure, match="changed"):
                with display.connect(value):
                    pytest.fail("A different display inode was admitted")
    finally:
        for peer in peers:
            peer.close()


@pytest.mark.parametrize("fault", ["pid", "symlink", "public", "file"])
def test_display_refuses_wrong_process_and_untrusted_resource(tmp_path, fault):
    path = tmp_path / "view.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        if fault == "file":
            path.write_text("Not a socket")
        else:
            peer.bind(str(path))
            path.chmod(0o666 if fault == "public" else 0o600)
            peer.listen(2)
        if fault == "symlink":
            alias = tmp_path / "alias.sock"
            alias.symlink_to(path)
            path = alias
        with pytest.raises(Failure):
            display.describe({"pid": os.getpid() + (1 if fault == "pid" else 0), "socket_path": str(path)})


def test_display_descriptor_has_no_network_destination_or_credentials():
    with pytest.raises(Failure):
        display.descriptor({"pid": os.getpid(), "port": 5900, "password": "secret"})
