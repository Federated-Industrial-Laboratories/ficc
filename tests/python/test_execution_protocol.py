# SPDX-License-Identifier: Apache-2.0
"""Bind executor messages to exact plans and actual socket peer authority."""

import copy

import pytest
from test_execution_ledger import NOW, fence, identity, plan
from test_execution_settings import settings

from ficc.execution.protocol import authorize, decode
from ficc.execution.settings import Settings
from ficc.execution.spec import Output, encoded


def request(action, **fields):
    return {"version": 1, "id": identity(99999), "action": action, **fields}


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_distinct_initial_leases_bind_every_command_and_output(count):
    attempts = []
    for index in range(count):
        item = plan(index)
        item.job.outputs = [Output(name="result", path=f"results/item-{index}.json")]
        attempts.append({"plan": item.model_dump(), "lease": {**fence(item).model_dump(),
            "sequence": 1, "expires_at": NOW + 30}})
    message = request("prepare", installation_id=identity(90001), ledger_id=identity(90002), admission_version=1, attempts=attempts)
    parsed = decode(encoded(message))
    assert len(parsed.attempts) == count
    for field, changed in (("generation", 2), ("attempt_id", identity(77777)), ("plan_digest", "sha256:" + "f" * 64)):
        altered = copy.deepcopy(message)
        altered["attempts"][-1]["lease"][field] = changed
        with pytest.raises(ValueError):
            decode(encoded(altered))
    changed = copy.deepcopy(message)
    changed["attempts"][-1]["plan"]["job"]["outputs"][0]["path"] = "different.json"
    with pytest.raises(ValueError, match="does not bind"):
        decode(encoded(changed))
    duplicate = copy.deepcopy(message)
    duplicate["attempts"] = [attempts[0], attempts[0]]
    with pytest.raises(ValueError, match="distinct"):
        decode(encoded(duplicate))


@pytest.mark.parametrize("mode", ["managed", "voluntary"])
def test_transport_cannot_change_consent_or_claim_another_socket_identity(mode):
    value = settings()
    value["mode"] = value["initial_offer"]["mode"] = mode
    if mode == "managed":
        value["local_owner_uids"] = []
    config = Settings.model_validate(value)
    change = decode(encoded(request("set_offer", expected_revision=1,
        settings=config.initial_offer.model_dump(exclude={"mode", "revision", "control"}), control="stopped")))
    start = decode(encoded(request("start", attempts=[fence(plan(0)).model_dump()])))
    snapshot = decode(encoded(request("snapshot", after=None)))
    authorize(start, config.transport_uid, config)
    authorize(snapshot, config.transport_uid, config)
    authorize(change, 0, config)
    with pytest.raises(ValueError):
        authorize(change, config.transport_uid, config)
    if mode == "voluntary":
        authorize(change, 1000, config)
        authorize(snapshot, 1000, config)
    else:
        with pytest.raises(ValueError):
            authorize(change, 1000, config)
    for peer in (994, 1000, 7777):
        with pytest.raises(ValueError):
            authorize(start, peer, config)
    forged = request("snapshot", after=None, peer_uid=0)
    with pytest.raises(ValueError):
        decode(encoded(forged))


@pytest.mark.parametrize("path", ["/etc/passwd", "../secret", "a/../../secret", "a//b", ".", "a/./b", "a\0b", "a\nb"])
def test_output_names_cannot_select_paths_outside_the_job(path):
    with pytest.raises(ValueError):
        Output(name="result", path=path)


def test_chunk_limits_do_not_set_a_total_output_size():
    item = {**fence(plan(0)).model_dump(), "object": "output:result", "offset": 40 * 1024**3, "length": 1024 * 1024}
    parsed = decode(encoded(request("collect", reads=[item])))
    assert parsed.reads[0].offset == 40 * 1024**3
    with pytest.raises(ValueError, match="at most 1 MiB"):
        decode(encoded(request("collect", reads=[item, {**item, "offset": item["offset"] + item["length"]}])))
    with pytest.raises(ValueError):
        decode(encoded(request("collect", reads=[{**item, "object": "/etc/shadow"}])))
