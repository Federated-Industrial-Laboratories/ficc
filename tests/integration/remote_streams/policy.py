# SPDX-License-Identifier: Apache-2.0
"""Use the installed evaluator and a privately signed copy of the managed policy."""

import runpy
import subprocess


class Policy:
    def __init__(self, lab):
        self.lab = lab
        self.helpers = runpy.run_path(str(lab.host / "tests/python/policy_fixtures.py"))
        self.helpers["configure_policy"](lab.state)

    def start(self):
        key = self.lab.directory / "policy-signing-key"
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                        "disposable policy", "-f", str(key)], check=True, capture_output=True, timeout=10)
        package = self.helpers["signed_pack"](self.lab.directory / "policy-package", key)
        digest = self.helpers["install_pack"](self.lab.admin,
            {"public_key": key.with_suffix(".pub").read_text(), "managed": package})
        self.helpers["activate"](self.lab.admin, digest)

    def member(self, user):
        self.lab.api("PUT", f"/api/v1/projects/{self.lab.project['id']}/policy-roles/{user['id']}",
                     json={"roles": ["operator", "vm-operator"], "revision": 0})
