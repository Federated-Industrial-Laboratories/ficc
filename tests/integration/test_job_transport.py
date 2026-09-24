# SPDX-License-Identifier: Apache-2.0
"""Verify the packaged job protocol and refusal over an isolated SSH server."""

import pytest
from test_ssh import ssh_fixture as ssh_fixture

from ficc.errors import Failure


async def test_packaged_job_capability_and_invalid_request(ssh_fixture):
    transport, home, _ = ssh_fixture
    preview = await transport.preview("fixture-node", "Test machine")
    await transport.install(preview)
    sample = await transport.probe(preview)
    assert sample["version"] == "1" and sample["helper_version"] == "3"
    capability = await transport.job(preview, {"action": "job.capabilities"})
    assert type(capability["jobs"]) is bool
    assert type(capability["logout_persistent"]) is bool
    with pytest.raises(Failure) as error:
        await transport.job(preview, {"action": "job.submit", "controller_id": "a" * 32,
                                     "job_id": "b" * 32, "node_id": "node-0", "job": {}})
    assert error.value.code == "job_refused"
    assert not (home / ".local/state/ficc/jobs" / ("b" * 32) / "request.json").exists()
