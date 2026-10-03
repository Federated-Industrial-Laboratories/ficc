# SPDX-License-Identifier: Apache-2.0
"""Feed actual module protocol output through the host JavaScript bindings."""

import json
import os
import runpy
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("provider,prefix", [("proxmox", "proxmox"), ("libvirt", "libvirt")])
@pytest.mark.parametrize("size", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("errors", [False, True])
@pytest.mark.parametrize("per_node", [1, 4])
def test_actual_module_result_matches_host_table_binding(tmp_path, size, errors, per_node, provider, prefix):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the actual host component binding check.")
    protocol = runpy.run_path(str(ROOT / "sdk/broker_conformance.py"))
    main = tmp_path / "main.py"
    shutil.copy2(ROOT / "modules" / provider / "payload/main.py", main)
    shutil.copy2(ROOT / "sdk/python/ficc_module.py", tmp_path / "ficc_module.py")
    process = subprocess.Popen([sys.executable, str(main)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True, cwd=tmp_path)
    identity, targets = "a" * 32, [f"system-{index}" for index in range(size)]
    deadline, received = time.monotonic() + 5, [0]
    try:
        process.stdin.write(protocol["frame"]({"version": 2, "type": "hello", "host_api": 1}))
        process.stdin.write(protocol["frame"]({"version": 2, "type": "invoke", "id": identity,
            "action": "load", "targets": targets, "parameters": {}}))
        process.stdin.flush()
        assert protocol["read"](process, deadline, received) == {"version": 2, "type": "hello", "protocol": 2}
        request = protocol["read"](process, deadline, received)
        assert request["primitive"] == f"vm.{provider}.list" and request["targets"] == targets
        assert request["parameters"] == {"offset": 0, "limit": min(64, 128 // size)}
        selected = min(per_node, request["parameters"]["limit"])
        values = []
        for index, target in enumerate(targets):
            rows = []
            for row_index in range(selected):
                vm = f"{prefix}-{'b' * 32}-{index * 4 + row_index + 100:08x}{'c' * 24}"
                row = {"vm_id": vm, "uuid": vm[-32:], "data": {"name": f"VM {index}", "state": "off",
                    "vcpus": 1, "memory_kib": 0}}
                if errors and index == size - 1:
                    row.pop("data")
                    row["error"] = {"code": "vm_unavailable", "message": "The VM cannot be read."}
                rows.append(row)
            values.append({"target": target, "data": {"results": rows, "truncated": selected < per_node,
                "total": per_node, "next_offset": selected if selected < per_node else None, "inventory_digest": "f" * 64}})
        process.stdin.write(protocol["frame"]({"version": 2, "type": "broker-result", "id": request["id"],
            "invocation_id": identity, "results": values}))
        process.stdin.close()
        result = protocol["read"](process, deadline, received)
        assert process.wait(timeout=5) == 0 and result["type"] == "result"
        assert [item["target"] for item in result["results"]] == targets
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()

    for name in ("ui-components.js", "ui-table.js", "components.js"):
        shutil.copy2(ROOT / "web/static" / name, tmp_path / name)
    (tmp_path / "package.json").write_text('{"type":"module"}')
    manifest = json.loads((ROOT / "modules" / provider / "manifest.json").read_text())
    script = r'''
import fs from 'node:fs';
import {boundedData,pathValue,validateData} from './ui-components.js';
const {manifest,result,count}=JSON.parse(fs.readFileSync(0,'utf8'));
const output=boundedData(result);
let rows=0;
function visit(component) {
 const bound={...component};
 for(const [name,binding] of Object.entries(component.bind||{})) bound[name]=pathValue(output,binding.path);
 validateData(bound);
 if(bound.type==='table') {
  rows+=bound.rows.length;
  const invalid=structuredClone(bound);
  invalid.rows[0].values.undeclaredProvider='proxmox';
  let rejected=false;
  try {validateData(invalid);} catch {rejected=true;}
  if(!rejected) throw Error('The detector accepted an undeclared table cell.');
 }
 for(const child of component.children||[]) visit(child);
}
visit(manifest.ui);
if(rows!==count) throw Error('The actual output binding lost rows.');
console.log(JSON.stringify({rows}));
'''
    checked = subprocess.run([node, "--input-type=module", "-e", script],
        input=json.dumps({"manifest": manifest, "result": result, "count": size * selected}), text=True,
        capture_output=True, cwd=tmp_path, timeout=10)
    assert checked.returncode == 0, checked.stderr
    assert json.loads(checked.stdout) == {"rows": size * selected}
