# SPDX-License-Identifier: Apache-2.0
"""Validate private contributor authority and deployment limits."""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .remote_settings import https_url
from .state_provider import read_private

CONFIG = "contributors.json"
IDENTITY = re.compile(r"[0-9a-f]{32}\Z")
FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class ContributorSettings:
    deployment_id: str
    origin: str
    ca: bytes = field(repr=False)
    secret: str = field(repr=False)
    issuer: dict = field(repr=False)
    certificate_seconds: int
    invitation_seconds: int
    lease_seconds: int
    heartbeat_seconds: int
    max_nodes: int

    def uri(self, node_id):
        if not isinstance(node_id, str) or not IDENTITY.fullmatch(node_id):
            raise ValueError("The contributor identity is invalid.")
        return f"urn:ficc:node:{self.deployment_id}:{node_id}"


def configuration(state):
    path = Path(state) / CONFIG
    if not path.exists() and not path.is_symlink():
        return None
    value = json.loads(read_private(path))
    fields = {"deployment_id", "origin", "ca_file", "gateway_secret_file", "issuer", "limits"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("The contributor configuration is invalid.")
    if not isinstance(value["deployment_id"], str) or not IDENTITY.fullmatch(value["deployment_id"]):
        raise ValueError("Use an immutable contributor deployment identifier.")
    https_url(value["origin"], origin=True)
    if any(not isinstance(value[key], str) or not Path(value[key]).is_absolute()
           for key in ("ca_file", "gateway_secret_file")):
        raise ValueError("Use absolute private authority file paths.")
    secret = read_private(Path(value["gateway_secret_file"]), 256).decode("ascii").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", secret):
        raise ValueError("Use a separate random node gateway credential.")
    ca = read_private(Path(value["ca_file"]), 16384)
    from cryptography import x509
    roots = x509.load_pem_x509_certificates(ca)
    if not 1 <= len(roots) <= 4:
        raise ValueError("Select a bounded public contributor authority bundle.")
    issuer = value["issuer"]
    if (not isinstance(issuer, dict) or set(issuer) != {"provider", "configuration"}
            or not isinstance(issuer["provider"], str)
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", issuer["provider"])
            or not isinstance(issuer["configuration"], dict)):
        raise ValueError("Select an installed trusted certificate provider.")
    limits = value["limits"]
    bounds = {"certificate_seconds": (60, 86400), "invitation_seconds": (60, 3600),
              "lease_seconds": (5, 30), "heartbeat_seconds": (1, 10), "max_nodes": (1, 64)}
    if (not isinstance(limits, dict) or set(limits) != set(bounds)
            or any(type(limits[key]) is not int or not lower <= limits[key] <= upper
                   for key, (lower, upper) in bounds.items())
            or limits["heartbeat_seconds"] * 2 > limits["lease_seconds"]):
        raise ValueError("The contributor limits exceed the supported security bounds.")
    return ContributorSettings(value["deployment_id"], value["origin"], ca, secret, issuer, **limits)
