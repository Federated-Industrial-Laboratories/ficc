# SPDX-License-Identifier: Apache-2.0
"""Check output polling through the packaged helper and controller."""

from test_jobs import manual_poll as manual_poll
from test_jobs import prepare, submit


def test_queued_output_uses_packaged_helper_and_controller_response_validation(console, monkeypatch, tmp_path):
    import base64
    import json
    import sys

    from ficc.process import run
    from ficc.ssh import SSH, archive

    client, service, remote, actor = prepare(console, monkeypatch)
    operation, _ = submit(client)
    assert operation["targets"][0]["state"] == "queued"
    home = tmp_path / "remote-home"
    home.mkdir(mode=0o700)
    helper = tmp_path / "node.pyz"
    helper.write_bytes(archive())
    wrapper = "import os,runpy,sys;os.environ['HOME']=sys.argv[1];sys.argv=sys.argv[2:];runpy.run_path(sys.argv[0],run_name='__main__')"

    async def command(node, fixed_command, payload, check=None):
        if check:
            check()
        return await run([sys.executable, "-c", wrapper, str(home), str(helper)], payload)

    monkeypatch.setattr(service.ssh, "command", command)
    monkeypatch.setattr(service.ssh, "job", SSH.job.__get__(service.ssh, SSH))
    path = f'/api/v1/operations/{operation["id"]}/logs/node-0'
    first = client.get(path + "?stream=stdout&offset=0&limit=32")
    assert first.status_code == 200, first.text
    assert first.json() == {"data_base64": "", "next_offset": 0, "total_bytes": 0,
                            "dropped_bytes": None, "complete": False}
    stderr = client.get(path + "?stream=stderr&offset=7&limit=32")
    assert stderr.status_code == 200 and stderr.json()["next_offset"] == 7
    job = home / ".local/state/ficc/jobs" / operation["targets"][0]["job_id"]
    assert not job.exists()
    job.mkdir(mode=0o700)
    for name, value in (("request.json", {"controller_id": service.jobs.controller}),
                        ("result.json", {"state": "succeeded", "result": {"dropped_bytes": 0}})):
        file = job / name
        file.write_text(json.dumps(value))
        file.chmod(0o600)
    output = job / "stdout"
    output.write_bytes(b"ready after dispatch\n")
    output.chmod(0o600)
    later = client.get(path + "?stream=stdout&offset=0&limit=32")
    assert later.status_code == 200, later.text
    assert base64.b64decode(later.json()["data_base64"]) == output.read_bytes()
    assert later.json()["complete"] and later.json()["dropped_bytes"] == 0
