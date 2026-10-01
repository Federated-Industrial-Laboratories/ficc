# SPDX-License-Identifier: Apache-2.0
"""Check that the optional system policy cannot grant force or unrelated actions."""

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_optional_power_policy_has_no_inhibitor_or_service_authority():
    node = shutil.which("node")
    assert node, "Node.js is required for policy validation."
    code = r"""
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
let rule;
const polkit = {Result: {YES: 'yes'}, addRule: value => {rule = value;}};
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), {polkit}, {timeout: 1000});
const member = {isInGroup: group => group === 'ficc-power'};
const outsider = {isInGroup: () => false};
for (const action of ['power-off', 'reboot']) {
  for (const suffix of ['', '-multiple-sessions']) {
    const request = {id: 'org.freedesktop.login1.' + action + suffix};
    assert.equal(rule(request, member), 'yes');
    assert.equal(rule(request, outsider), undefined);
  }
  assert.equal(rule({id: 'org.freedesktop.login1.' + action + '-ignore-inhibit'}, member), undefined);
}
for (const id of ['org.freedesktop.systemd1.manage-units', 'org.freedesktop.policykit.exec',
                 'org.freedesktop.login1.suspend', 'org.freedesktop.login1.halt']) {
  assert.equal(rule({id}, member), undefined);
}
"""
    subprocess.run([node, "-e", code, str(ROOT / "tools/power-policy/ficc-power.rules")],
                   check=True, timeout=5, capture_output=True)
