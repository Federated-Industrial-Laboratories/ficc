# SPDX-License-Identifier: Apache-2.0
"""Check package source boundaries, pinned resolution and bounded HTTP responses."""

import hashlib
import ipaddress
import socket

import httpx
import pytest

from ficc.errors import Failure
from ficc.module_fetch import MAXIMUM, fetch_package, permitted

PRIVATE_A = str(ipaddress.IPv4Address(bytes((10, 2, 3, 4))))
PRIVATE_B = str(ipaddress.IPv4Address(bytes((192, 168, 1, 2))))


@pytest.mark.parametrize("address,private,accepted", [
    ("8.8.8.8", False, True), ("2001:4860:4860::8888", False, True),
    (PRIVATE_A, False, False), (PRIVATE_A, True, True),
    (PRIVATE_B, True, True), ("fd00::1", True, True),
    ("127.0.0.1", True, False), ("::1", True, False),
    ("169.254.169.254", True, False), ("fe80::1", True, False),
    ("224.0.0.1", True, False), ("0.0.0.0", True, False),
])
def test_address_classes(address, private, accepted):
    assert permitted(address, private) is accepted


def transport(monkeypatch, respond, addresses=("8.8.8.8",)):
    import ficc.module_fetch as module
    resolved, requests, options = [], [], []

    def lookup(host, port, *args):
        resolved.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port)) for address in addresses]

    def handle(request):
        requests.append(request)
        response = respond(request)
        if response.is_stream_consumed:
            return httpx.Response(response.status_code, headers=response.headers,
                                  stream=httpx.ByteStream(response.content))
        return response

    original = httpx.AsyncClient

    def client(**kwargs):
        options.append(kwargs)
        return original(transport=httpx.MockTransport(handle), **kwargs)

    monkeypatch.setattr(module.socket, "getaddrinfo", lookup)
    monkeypatch.setattr(module.httpx, "AsyncClient", client)
    return resolved, requests, options


async def test_connects_to_one_validated_address_with_original_tls_name(monkeypatch):
    resolved, requests, options = transport(monkeypatch, lambda _: httpx.Response(200, content=b"package"))
    result = await fetch_package("https://packages.example:8443/module.zip", hashlib.sha256(b"package").hexdigest())
    assert result == b"package" and resolved == [("packages.example", 8443)]
    assert len(requests) == 1
    assert requests[0].url == "https://8.8.8.8:8443/module.zip"
    assert requests[0].headers["host"] == "packages.example:8443"
    assert requests[0].extensions["sni_hostname"] == "packages.example"
    assert options[0]["trust_env"] is False and options[0]["follow_redirects"] is False


@pytest.mark.parametrize("address", ["http://packages.example/file", "https://user:secret@packages.example/file",
                                   "https://packages.example/file#fragment", "file:///etc/passwd"])
async def test_source_refusal_precedes_resolution(monkeypatch, address):
    resolved, requests, _ = transport(monkeypatch, lambda _: httpx.Response(200))
    with pytest.raises(Failure):
        await fetch_package(address, None)
    assert not resolved and not requests


async def test_mixed_public_and_forbidden_resolution_never_connects(monkeypatch):
    _, requests, _ = transport(monkeypatch, lambda _: httpx.Response(200), ("8.8.8.8", "127.0.0.1"))
    with pytest.raises(Failure) as caught:
        await fetch_package("https://packages.example/file", None, True)
    assert caught.value.code == "source_denied" and not requests


@pytest.mark.parametrize("status,headers,content,expected", [
    (302, {"Location": "http://127.0.0.1/private"}, b"", "source_failed"),
    (200, {"Content-Encoding": "gzip"}, b"", "source_failed"),
    (200, {"Content-Length": str(MAXIMUM + 1)}, b"", "package_limit"),
    (200, {}, b"different", "digest_mismatch"),
])
async def test_response_boundaries(monkeypatch, status, headers, content, expected):
    _, requests, _ = transport(monkeypatch, lambda _: httpx.Response(status, headers=headers, content=content))
    with pytest.raises(Failure) as caught:
        await fetch_package("https://packages.example/file", "0" * 64)
    assert caught.value.code == expected and len(requests) == 1


async def test_approved_private_http_still_requires_matching_digest(monkeypatch):
    resolved, requests, _ = transport(monkeypatch, lambda _: httpx.Response(200, content=b"package"), (PRIVATE_A,))
    assert await fetch_package("http://packages.example/file", hashlib.sha256(b"package").hexdigest(), True, True) == b"package"
    assert resolved == [("packages.example", 80)] and requests[0].url.host == PRIVATE_A


async def test_stream_without_length_cannot_exceed_budget(monkeypatch):
    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(17):
                yield b"x" * 1024**2
    transport(monkeypatch, lambda _: httpx.Response(200, stream=Body()))
    with pytest.raises(Failure) as caught:
        await fetch_package("https://packages.example/file", None)
    assert caught.value.code == "package_limit"
