# SPDX-License-Identifier: Apache-2.0
"""Reject profile substitution, malformed phases and mutable transport authority."""

import copy
from dataclasses import FrozenInstanceError

import pytest

from ficc.errors import Failure
from ficc.modules.adapter_protocol import Conversation, binding, request


def bindings(count=1):
    return [{"id": f"{index + 1:032x}", "endpoint_id": f"{index + 100:032x}", "endpoint_revision": 1,
        "machine_identity": "b" * 64, "consistency": "provider-lock", "resources": [],
        "parameters": {"offset": 0, "limit": 1}} for index in range(count)]


def transport_frame(conversation, index=0, request_id="f" * 32):
    return {"version": 1, "type": "adapter-transport", "id": request_id,
        "invocation_id": conversation.id, "profile_id": conversation.profile_ids[index],
        "commands": [{"command": "Get-FiccVm", "parameters": {"Ids": ["machine"]}}]}


@pytest.mark.parametrize("count", [1, 64])
def test_frozen_profile_batch_and_complete_ordered_result(count):
    supplied = bindings(count)
    conversation = Conversation("a" * 64, "inventory", "inventory", supplied, lambda: None)
    supplied[0]["endpoint_id"] = "c" * 32
    assert conversation.request["bindings"][0]["endpoint_id"] == f"{100:032x}"
    copy_out = conversation.request
    copy_out["bindings"][0]["endpoint_revision"] = 500
    assert conversation.request["bindings"][0]["endpoint_revision"] == 1
    result = {"version": 1, "type": "adapter-result", "id": conversation.id,
        "results": [{"profile_id": value, "data": {"resources": []}} for value in conversation.profile_ids]}
    assert conversation.result(result) == result
    result["results"][-1]["profile_id"] = "d" * 32
    with pytest.raises(Failure):
        conversation.result(result)


@pytest.mark.parametrize("count", [1, 64])
def test_transport_call_retains_exact_profile_and_copies_commands(count):
    conversation = Conversation("a" * 64, "inventory", "inventory", bindings(count), lambda: None)
    value = transport_frame(conversation, count - 1)
    call = conversation.call(value)
    value["commands"][0]["parameters"]["Ids"].append("outside")
    assert call.commands == [{"command": "Get-FiccVm", "parameters": {"Ids": ["machine"]}}]
    call.commands[0]["parameters"]["Ids"].clear()
    assert call.commands[0]["parameters"]["Ids"] == ["machine"]
    assert call.profile_id == conversation.profile_ids[-1]
    with pytest.raises(FrozenInstanceError):
        call.profile_id = "e" * 32
    with pytest.raises(Failure):
        conversation.call(value)


@pytest.mark.parametrize("field,value", [
    ("version", True), ("version", 2), ("type", "broker"), ("invocation_id", "b" * 32),
    ("profile_id", "b" * 32), ("id", "short"), ("commands", []),
    ("commands", [{"command": "Get-FiccVm", "parameters": {}, "url": "https://outside/"}]),
    ("commands", [{"command": "Get-FiccVm", "parameters": {"value": "x" * 65536}}]),
])
def test_transport_refuses_unsupported_identity_shape_and_size(field, value):
    conversation = Conversation("a" * 64, "inventory", "inventory", bindings(), lambda: None)
    frame = transport_frame(conversation)
    frame[field] = value
    with pytest.raises(Failure):
        conversation.call(frame)


def test_seventeenth_transport_call_is_refused():
    conversation = Conversation("a" * 64, "inventory", "inventory", bindings(), lambda: None)
    for index in range(16):
        conversation.call(transport_frame(conversation, request_id=f"{index:032x}"))
    with pytest.raises(Failure):
        conversation.call(transport_frame(conversation, request_id="f" * 32))


@pytest.mark.parametrize("field,value", [("phase", "shell"), ("phase", []), ("action", []),
    ("action", "start"), ("version", True), ("bindings", []), ("digest", "bad")])
def test_invalid_phase_or_identity_refuses_before_dispatch(field, value):
    conversation = Conversation("a" * 64, "inventory", "inventory", bindings(), lambda: None)
    raw = conversation.request
    raw[field] = value
    with pytest.raises(Failure):
        request(raw)


@pytest.mark.parametrize("count", [1, 64])
def test_mutation_requires_frozen_complete_resources_and_private_intent(count):
    values = bindings(count)
    for index, value in enumerate(values):
        value["resources"] = [{"id": f"{index:032x}", "key": f"vm-{index}", "birth": "a" * 64,
            "revision": "c" * 64, "state": "off"}]
        value["intent"] = {"selected": [f"vm-{index}"]}
    conversation = Conversation("a" * 64, "apply", "start", values, lambda: None)
    assert len(conversation.request["bindings"]) == count
    values[0].pop("intent")
    with pytest.raises(Failure):
        Conversation("a" * 64, "apply", "start", values, lambda: None)
    values[0]["receipt"] = {}
    with pytest.raises(Failure):
        Conversation("a" * 64, "status", "status", values, lambda: None)


def test_unknown_private_binding_fields_and_duplicate_resources_refuse():
    value = bindings()[0]
    value["socket"] = "/tmp/provider.sock"
    with pytest.raises(Failure):
        binding(value)
    value.pop("socket")
    selected = {"id": "a" * 32, "key": "key", "birth": "b" * 64,
                "revision": "c" * 64, "state": "off"}
    value["resources"] = [selected, copy.deepcopy(selected)]
    with pytest.raises(Failure):
        binding(value)
