# SPDX-License-Identifier: Apache-2.0
"""Fetch one approved package address with pinned resolution and bounded content."""

import asyncio
import hashlib
import ipaddress
import socket

import httpx

from .errors import Failure

MAXIMUM = 16 * 1024 * 1024


def permitted(address: str, allow_private: bool) -> bool:
    ip = ipaddress.ip_address(address)
    if ip.is_global:
        return not ip.is_multicast
    # RFC 1918 private prefixes and the IPv6 unique-local prefix.
    networks = (ipaddress.IPv4Network((10 << 24, 8)),
                ipaddress.IPv4Network(((172 << 24) | (16 << 16), 12)),
                ipaddress.IPv4Network(((192 << 24) | (168 << 16), 16)),
                ipaddress.IPv6Network("fc00::/7"))
    return allow_private and any(ip in network for network in networks)


async def fetch_package(address: str, expected_digest: str | None,
                        allow_private: bool = False, allow_http: bool = False) -> bytes:
    try:
        url = httpx.URL(address)
    except (httpx.InvalidURL, ValueError) as exc:
        raise Failure("invalid_source", "Enter a complete package URL.") from exc
    if (url.scheme not in {"https", "http"} or not url.host or url.userinfo or url.fragment
            or (url.scheme == "http" and (not allow_http or not expected_digest))):
        raise Failure("invalid_source", "Use HTTPS. HTTP requires explicit approval and an expected SHA-256 digest.")
    try:
        async with asyncio.timeout(30):
            resolved = await asyncio.to_thread(socket.getaddrinfo, url.host, url.port or
                                               (443 if url.scheme == "https" else 80),
                                               0, socket.SOCK_STREAM)
            addresses = sorted({str(record[4][0]) for record in resolved})
            if not addresses or any(not permitted(item, allow_private) for item in addresses):
                raise Failure("source_denied", "This source address is not allowed. Approve private network access if required.", 403)
            # Connect to the checked address; retain the original Host and TLS name.
            pinned = url.copy_with(host=addresses[0])
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=10) as client:
                async with client.stream("GET", pinned, headers={"Host": url.netloc.decode("ascii"),
                                         "Accept-Encoding": "identity"},
                                         extensions={"sni_hostname": url.host}) as response:
                    if response.status_code != 200:
                        raise Failure("source_failed", "The package source did not return a file. Redirects are not followed.", 502)
                    if response.headers.get("content-encoding", "identity") != "identity":
                        raise Failure("source_failed", "The package source uses an unsupported content encoding.", 502)
                    size = response.headers.get("content-length")
                    if size is not None and (not size.isdigit() or int(size) > MAXIMUM):
                        raise Failure("package_limit", "The package exceeds the 16 MiB download limit.", 413)
                    data = bytearray()
                    async for chunk in response.aiter_raw():
                        if len(data) + len(chunk) > MAXIMUM:
                            raise Failure("package_limit", "The package exceeds the 16 MiB download limit.", 413)
                        data.extend(chunk)
    except (TimeoutError, httpx.HTTPError, OSError) as exc:
        raise Failure("source_unavailable", "The package source could not be reached or verified.", 502) from exc
    if expected_digest and hashlib.sha256(data).hexdigest() != expected_digest:
        raise Failure("digest_mismatch", "The package does not match the expected SHA-256 digest.", 409)
    return bytes(data)
