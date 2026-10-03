# SPDX-License-Identifier: Apache-2.0
"""Keep attach credentials private, exact and bound to the declared authentication."""

import json
import sys

import pytest

from ficc.viewer import configuration
from ficc.viewer_stream import ProviderStream


@pytest.mark.parametrize("authentication", ["none", "rfb", "rfb-password"])
async def test_ready_envelope_preserves_following_rfb_and_cleans_up(authentication):
    value = {"version": 1, "ready": True}
    if authentication == "rfb-password":
        value["password"] = "Test1234"
    data = json.dumps(value).encode() + b"\nRFB 003.008\n"
    source = "import sys,time;sys.stdin.buffer.readline();sys.stdout.buffer.write(" + repr(data) + ");sys.stdout.flush();time.sleep(60)"
    provider = ProviderStream([sys.executable, "-I", "-c", source])
    try:
        assert await provider.start(b"{}\n", authentication) == value.get("password")
        assert await provider.read() == b"RFB 003.008\n"
    finally:
        await provider.close()
    assert provider.process.poll() is not None


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_ready_checks_bound_chunks_and_rechecks_buffered_authority(count):
    from ficc.errors import Failure

    for index in range(count):
        calls, allowed = [], [True]

        def check():
            calls.append(None)
            if not allowed[0]:
                raise Failure("denied", "Display access was revoked.", 403)

        password = f"{index:08x}"
        payload = b"RFB 003.008\n" + index.to_bytes(4, "big")
        data = json.dumps({"version": 1, "ready": True, "password": password}).encode() + b"\n" + payload
        source = ("import os,sys,time;sys.stdin.buffer.readline();os.write(1," + repr(data)
                  + ");time.sleep(60)")
        provider = ProviderStream([sys.executable, "-I", "-c", source], check)
        try:
            assert await provider.start(b"{}\n", "rfb-password") == password
            assert len(calls) <= 8
            assert await provider.read(4) == payload[:4]
            allowed[0] = False
            with pytest.raises(Failure, match="Display access was revoked"):
                await provider.read()
        finally:
            await provider.close()
        assert provider.process.poll() is not None


async def test_split_ready_and_oversized_response_keep_the_stream_bound():
    data = b'{"version":1,"ready":true}\nRFB 003.008\n'
    source = ("import os,sys,time;sys.stdin.buffer.readline();os.write(1," + repr(data[:9])
              + ");time.sleep(.05);os.write(1," + repr(data[9:]) + ");time.sleep(60)")
    provider = ProviderStream([sys.executable, "-I", "-c", source])
    try:
        assert await provider.start(b"{}\n") is None
        assert await provider.read() == b"RFB 003.008\n"
    finally:
        await provider.close()
    source = "import os,sys,time;sys.stdin.buffer.readline();os.write(1,b' '*1024+b'\\n');time.sleep(60)"
    provider = ProviderStream([sys.executable, "-I", "-c", source])
    try:
        with pytest.raises(ValueError, match="exceeds its limit"):
            await provider.start(b"{}\n")
    finally:
        await provider.close()


@pytest.mark.parametrize("data,authentication", [
    (b'{"version":1,"ready":true,"password":"Test1234"}', "none"),
    (b'{"version":1,"ready":true,"password":"Test1234"}', "rfb"),
    (b'{"version":1,"ready":true}', "rfb-password"),
    (b'{"version":1,"ready":true}', "unknown"),
    (b'{"version":1,"ready":true,"ready":false}', "none"),
    (b'{"version":true,"ready":true}', "none"),
    (b'{"version":1,"ready":1}', "none"),
    (b'{"version":1,"ready":true,"url":"private"}', "none"),
    (b' ' * 1025, "none"),
])
def test_invalid_private_ready_refused(data, authentication):
    with pytest.raises(ValueError):
        configuration.ready(data, authentication)


@pytest.mark.parametrize("password", [None, True, 12345678, "", "short", "Test12345", "Test123\n", "T\u00e9st1234"])
def test_credentials_fail_without_value_in_diagnostics(password):
    for callback, document in [
        (lambda data: configuration.ready(data, "rfb-password"), {"version": 1, "ready": True}),
        (configuration.settings, {"version": 1, "protocol": "vnc"}),
    ]:
        with pytest.raises(ValueError, match="^Invalid private display credential.$"):
            callback(json.dumps({**document, "password": password}))


def test_private_native_vnc_config_supports_only_password():
    assert configuration.settings(b'{"version":1,"protocol":"vnc"}') == {"protocol": "vnc"}
    assert configuration.settings(b'{"version":1,"protocol":"vnc","password":"Test1234"}') == {"protocol": "vnc", "password": "Test1234"}
    for value in ({"version": 1, "protocol": "rdp"}, {"version": 1, "protocol": "vnc", "hostname": "other"}):
        with pytest.raises(ValueError):
            configuration.settings(json.dumps(value))


def rdp_config(index=0):
    return {"version": 1, "protocol": "rdp", "transport": "vmconnect",
            "vm_id": f"12345678-1234-1234-1234-{index:012x}", "username": f"user-{index}",
            "password": f"Secret-{index}-\u00e9;4.name,1.a;", "domain": "LAB", "certificate_sha256": f"{index:064x}"}


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_private_vmconnect_config_keeps_exact_identity_and_unicode(count):
    from ficc.viewer.wire import instruction, parse

    for index in range(count):
        value = rdp_config(index)
        actual = configuration.settings(json.dumps(value).encode())
        assert actual == {key: item for key, item in value.items() if key != "version"}
        assert parse(instruction(actual["username"], actual["password"]).decode()) == [value["username"], value["password"]]


@pytest.mark.parametrize("key,value", [
    ("version", True), ("protocol", "vnc"), ("transport", "rdp"), ("host", "other.example"),
    ("ignore-cert", True), ("username", ""), ("username", "x" * 129), ("password", ""),
    ("password", "x" * 257), ("domain", "x" * 254), ("password", "value\x00"),
    ("username", "value\n"), ("domain", "value\x7f"), ("password", "value\x85"),
    ("username", "value\ud800"), ("vm_id", "../other"), ("vm_id", True),
    ("certificate_sha256", "a" * 63), ("certificate_sha256", "A" * 64), ("certificate_sha256", None),
])
def test_vmconnect_configuration_refuses_override_and_invalid_credentials(key, value):
    document = {**rdp_config(), key: value}
    with pytest.raises(ValueError) as error:
        configuration.settings(json.dumps(document))
    assert "Secret" not in str(error.value)


def test_vmconnect_configuration_refuses_missing_duplicate_or_large_data():
    value = rdp_config()
    for key in value:
        with pytest.raises(ValueError):
            configuration.settings(json.dumps({name: item for name, item in value.items() if name != key}))
    duplicate = json.dumps(value)[:-1] + ',"password":"SecondSecret"}'
    for data in (duplicate, b" " * 4097, b"\xff", None, []):
        with pytest.raises(ValueError) as error:
            configuration.settings(data)
        assert "Secret" not in str(error.value)
