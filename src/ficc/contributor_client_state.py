# SPDX-License-Identifier: Apache-2.0
"""Keep node keys, enrollment receipts and recoverable rotations private."""

import json
import os
import secrets
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from .contributor_certificates import certificate, key_fingerprint
from .contributor_settings import IDENTITY
from .launcher_config import write_file
from .remote_settings import https_url
from .settings import private_directory
from .state_provider import read_private


def default_state():
    return Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "ficc-contributor"


class NodeState:
    def __init__(self, path):
        self.path = Path(path).absolute()
        private_directory(self.path)

    def load(self):
        value = json.loads(read_private(self.path / "node.json", 65536))
        for key in ("controller", "node_origin"):
            https_url(value[key], origin=True)
        if not all(IDENTITY.fullmatch(value[key]) for key in ("node_id", "deployment_id")):
            raise ValueError("The saved node identity is invalid.")
        return value

    def save(self, value):
        write_file(self.path / "node.json", json.dumps(value, indent=2, allow_nan=False) + "\n")

    def file(self, name):
        if not isinstance(name, str) or not name or Path(name).name != name or name in {".", ".."}:
            raise ValueError("The private node filename is invalid.")
        return self.path / name

    def key(self, value):
        key = ed25519.Ed25519PrivateKey.generate()
        uri = f"urn:ficc:node:{value['deployment_id']}:{value['node_id']}"
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value["node_id"])]))
               .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=False)
               .sign(key, None))
        name = "key-" + secrets.token_hex(16) + ".pem"
        write_file(self.file(name), key.private_bytes(serialization.Encoding.PEM,
                   serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode("ascii"))
        return {"key_file": name, "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                "public_key": key_fingerprint(key.public_key())}

    def tls(self, value, material=None):
        ca = value.get("server_ca_file")
        context = ssl.create_default_context(cadata=read_private(self.file(ca), 65536).decode("ascii") if ca else None)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        if material:
            key, cert = self.file(material["key_file"]), self.file(material["certificate_file"])
            read_private(key, 8192)
            read_private(cert, 16384)
            context.load_cert_chain(cert, key)
        return context

    def accept_certificate(self, value, material, pem):
        uri = f"urn:ficc:node:{value['deployment_id']}:{value['node_id']}"
        checked = certificate(pem, material["csr_pem"], uri, value["node_id"],
                              value["node_ca_pem"].encode("ascii"), 86400)
        name = material["key_file"].replace("key-", "certificate-")
        write_file(self.file(name), pem)
        material.update(certificate_file=name, fingerprint=checked["fingerprint"],
                        expires_at=checked["expires_at"], not_before=checked["not_before"])

    def promote(self, value):
        previous = value.get("current")
        value["current"] = value.pop("pending")
        value["stage"] = "active"
        value.pop("receipt", None)
        self.save(value)
        if previous:
            for field in ("key_file", "certificate_file"):
                self.file(previous[field]).unlink(missing_ok=True)

    def report(self, **values):
        write_file(self.path / "connection.json", json.dumps(values, allow_nan=False) + "\n")
