# SPDX-License-Identifier: Apache-2.0
"""Detect malformed broker traffic and preserve protocol-one byte contracts."""

import copy
from unittest.mock import patch

import pytest
from test_modules_packages import package

from ficc.errors import Failure
from ficc.modules import protocol
from ficc.modules.broker_protocol import Conversation
from ficc.modules.manifest import parameter_schema, validate_manifest, validate_parameters


def conversation():
    return Conversation('a' * 64, 'read', ['a', 'b'], {}, ['test:read'], lambda: None, None)


def call(value, **changes):
    return {'version': 2, 'type': 'broker', 'id': 'b' * 32, 'invocation_id': value.id,
            'primitive': 'resource.read.v1', 'targets': ['a'], 'parameters': {}, **changes}


def test_protocol_one_bytes_and_default_manifest_are_unchanged():
    with patch.object(protocol.secrets, 'token_hex', return_value='a' * 32):
        identifier, data = protocol.request('read', ['a'], {})
    expected = (protocol.frame({'version': 1, 'type': 'hello', 'host_api': 1})
                + protocol.frame({'version': 1, 'type': 'invoke', 'id': 'a' * 32,
                                  'action': 'read', 'targets': ['a'], 'parameters': {}}))
    assert identifier == 'a' * 32 and data == expected
    assert protocol.response(protocol.frame({'version': 1, 'type': 'hello', 'protocol': 1})
        + protocol.frame({'version': 1, 'type': 'result', 'id': identifier,
                          'results': [{'target': 'a', 'data': 7}]}), identifier, ['a']) == {
                              'version': 1, 'id': identifier, 'results': [{'target': 'a', 'data': 7}]}


@pytest.mark.parametrize('version', [None, 1, 2, 0, 3, True, '2'])
def test_manifest_process_protocol_is_explicit_and_closed(version):
    runtime = {'kind': 'python', 'language': 'python', 'entry': 'main.py',
               'platform': 'linux', 'architecture': 'any'}
    if version is not None:
        runtime['protocol'] = version
    manifest, _ = package({'main.py': b'pass'}, runtime=runtime)
    if version is None or type(version) is int and version in (1, 2):
        assert validate_manifest(manifest)['runtime'] == runtime
    else:
        with pytest.raises(Failure):
            validate_manifest(manifest)
    declarative, _ = package(runtime={'kind': 'declarative', 'language': 'none', 'protocol': 2})
    with pytest.raises(Failure):
        validate_manifest(declarative)


@pytest.mark.parametrize('changes', [
    {'version': 1}, {'version': True}, {'type': 'invoke'}, {'id': 'wrong'},
    {'invocation_id': '0' * 32}, {'package_digest': 'f' * 64}, {'targets': ['outside']},
    {'targets': ['a', 'a']}, {'targets': []}, {'targets': ['a', 1]},
    {'parameters': []}, {'parameters': {'large': 'x' * 65536}},
    {'primitive': '/bin/sh'}, {'primitive': 'https://localhost'},
])
def test_broker_refuses_spoofed_unknown_or_unbounded_fields(changes):
    value = conversation()
    with pytest.raises(Failure):
        value.call(call(value, **changes))


def test_broker_count_and_request_ids_are_unique_and_parameters_are_detached():
    value = conversation()
    parameters = {'nested': {'items': ['one']}}
    request = value.call(call(value, parameters=parameters))
    parameters['nested']['items'].append('two')
    assert request.parameters == {'nested': {'items': ['one']}}
    assert request.target_ids == ('a',) and request.action_capabilities == ('test:read',)
    with pytest.raises(Failure):
        value.call(call(value))
    with pytest.raises(Failure):
        value.call(call(value, id=value.id))
    for index in range(15):
        value.call(call(value, id=f'{index:032x}'))
    with pytest.raises(Failure):
        value.call(call(value, id='c' * 32))


@pytest.mark.parametrize('count', [1, pytest.param(64, marks=pytest.mark.scale)])
def test_string_list_accepts_unique_bounded_batches(count):
    schema = {'selected': {'type': 'string-list', 'required': True}}
    parameter_schema(schema)
    values = {'selected': [f'row-{index}' for index in range(count)]}
    assert validate_parameters(schema, values) == values


@pytest.mark.parametrize('value', [['a', 'a'], ['x' * 129], ['a', 1], 'a', [str(i) for i in range(65)], ['']])
def test_string_list_refuses_duplicates_types_and_default_bounds(value):
    with pytest.raises(Failure):
        validate_parameters({'selected': {'type': 'string-list'}}, {'selected': value})


@pytest.mark.parametrize('spec', [
    {'type': 'string-list', 'max_items': 0}, {'type': 'string-list', 'max_items': 129},
    {'type': 'string-list', 'max_items': True}, {'type': 'string', 'max_items': 2},
    {'type': 'string-list', 'max_length': 8193}, {'type': 'string-list', 'min': 1},
])
def test_string_list_schema_rejects_incompatible_or_unbounded_options(spec):
    with pytest.raises(Failure):
        parameter_schema({'selected': spec})


def test_string_list_custom_count_length_and_choices_are_enforced():
    schema = {'selected': {'type': 'string-list', 'max_items': 2, 'max_length': 3, 'choices': ['one', 'two']}}
    parameter_schema(schema)
    assert validate_parameters(schema, {'selected': ['one', 'two']})
    for values in (['other'], ['one', 'two', 'six'], ['six']):
        with pytest.raises(Failure):
            validate_parameters(schema, {'selected': values})
    larger = copy.deepcopy(schema)
    larger['selected'] = {'type': 'string-list', 'max_items': 128, 'max_length': 8192}
    parameter_schema(larger)
    assert validate_parameters(larger, {'selected': [str(i) for i in range(128)]})
