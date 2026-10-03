# SPDX-License-Identifier: Apache-2.0
"""Require certificate identity and disable unrelated display capabilities."""

import pytest
from test_viewer_configuration import rdp_config

from ficc.viewer.connection import settings

VNC = {"hostname", "port", "read-only", "disable-copy", "disable-paste", "color-depth", "force-lossless",
       "autoretry", "password"}
RDP = VNC - {"autoretry"} | {"security", "preconnection-blob", "username", "domain",
       "cert-fingerprints", "ignore-cert", "cert-tofu", "disable-auth", "disable-audio",
       "enable-audio-input", "enable-printing", "enable-drive"}


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_daemon_config_binds_each_vm_and_certificate(count):
    for index in range(count):
        private = rdp_config(index)
        value = settings(private, 2000 + index, RDP)
        assert value["hostname"] == "127.0.0.1" and value["port"] == str(2000 + index)
        assert value["preconnection-blob"] == private["vm_id"] and value["security"] == "vmconnect"
        assert value["cert-fingerprints"] == "sha256:" + private["certificate_sha256"]
        for key in ("username", "password", "domain"):
            assert value[key] == private[key]
        for key in ("ignore-cert", "cert-tofu", "disable-auth", "enable-drive", "enable-printing",
                    "enable-audio-input", "enable-sftp", "wol-send-packet", "create-recording-path"):
            assert value[key] == "false"
        for key in ("disable-audio", "disable-copy", "disable-paste", "force-lossless", "disable-download", "disable-upload"):
            assert value[key] == "true"
        for key in ("remote-app", "initial-program", "gateway-hostname", "drive-path", "recording-path", "static-channels"):
            assert value.get(key, "") == ""


@pytest.mark.parametrize("argument", sorted(RDP))
def test_rdp_missing_security_control_refuses(argument):
    with pytest.raises(ValueError, match="required controls"):
        settings(rdp_config(), 2000, RDP - {argument})


@pytest.mark.parametrize("argument", sorted(VNC))
def test_vnc_missing_security_control_refuses(argument):
    with pytest.raises(ValueError, match="required controls"):
        settings({"protocol": "vnc", "password": "Test1234"}, 2000, VNC - {argument})


def test_optional_ssh_settings_do_not_require_an_ssh_build():
    value = settings({"protocol": "vnc", "password": "Test1234"}, 2000, VNC)
    assert value["enable-sftp"] == value["enable-audio"] == "false"
    assert value["autoretry"] == "0" and value["password"] == "Test1234"
