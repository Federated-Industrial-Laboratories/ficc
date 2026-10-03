# SPDX-License-Identifier: Apache-2.0
"""Check Windows endpoint revisions, secret-free backup records and JEA bounds."""

import copy
import json

import pytest

from ficc import module_windows_spec as spec
from ficc import module_windows_store as store
from ficc.errors import Failure
from ficc.store import Store


def endpoint(index=0):
    return {'id': f'{index:032x}', 'name': f'Windows {index}', 'host': f'windows-{index}.invalid',
            'port': 5986, 'configuration': 'FICC.HyperV',
            'commands': [{'name': 'Get-FICCEndpointIdentity', 'parameters': []},
                         {'name': 'Invoke-FICCHyperV', 'parameters': ['Request']}],
            'certificate_sha256': f'{index + 1:064x}', 'trust_ref': f'2{index:031x}',
            'credential_ref': f'3{index:031x}', 'vmconnect': None,
            'enabled': True, 'revision': 1, 'machine_identity': f'{index + 2:064x}', 'probe_at': 1700000000}


@pytest.fixture
def records(tmp_path):
    backend = Store(tmp_path / 'state.sqlite3')
    yield store.Records(backend)
    backend.close()


@pytest.mark.parametrize('count', [1, pytest.param(64, marks=pytest.mark.scale)])
def test_distinct_windows_endpoints_restore_disabled_and_revision_bound(records, count):
    for index in range(count):
        records.save(endpoint(index))
    assert [item['name'] for item in records.all()] == [f'Windows {index}' for index in range(count)]
    store.validate_records(records.store.db)
    with records.store.db:
        store.disable_restored(records.store.db)
    for index in range(count):
        value = records.get(f'{index:032x}')
        assert value['enabled'] is False and value['revision'] == 2
        assert value['credential_ref'] == endpoint(index)['credential_ref']
        with pytest.raises(Failure, match='revision changed'):
            records.save({**value, 'name': 'Stale change', 'revision': 2}, 1)
        assert records.get(value['id'])['name'] == f'Windows {index}'
    store.validate_records(records.store.db)


def test_endpoint_capacity_and_remove_revision(records):
    for index in range(64):
        records.save(endpoint(index))
    with pytest.raises(Failure, match='limit'):
        records.save(endpoint(64))
    with pytest.raises(Failure, match='revision'):
        records.remove(endpoint()['id'], 2)
    with pytest.raises(ValueError, match='integer'):
        records.remove(endpoint()['id'], True)
    records.remove(endpoint()['id'], 1)
    records.save(endpoint(64))
    assert len(records.all()) == 64


@pytest.mark.parametrize('change', ['password', 'reference', 'identity', 'host', 'unprobed', 'command', 'parameters'])
def test_invalid_windows_records_refuse_backup(records, change):
    value = endpoint()
    if change == 'password':
        value['password'] = 'Not a durable record field'
    elif change == 'reference':
        value['trust_ref'] = value['credential_ref']
    elif change == 'identity':
        value['id'] = 'different'
    elif change == 'host':
        value['host'] = 'https://windows.invalid/wsman'
    elif change == 'unprobed':
        value['machine_identity'] = None
    elif change == 'command':
        value['commands'][1]['name'] = 'Invoke-FICCHyperV;Start-Process'
    else:
        value['commands'][1]['parameters'] = ['Request', 'request']
    records.store.db.execute('INSERT INTO module_windows_endpoints VALUES (?,?)', (endpoint()['id'], json.dumps(value)))
    with pytest.raises(ValueError):
        store.validate_records(records.store.db)


def test_windows_backup_cannot_alias_other_endpoint_credentials(records):
    first, second = endpoint(0), endpoint(1)
    second['credential_ref'] = first['credential_ref']
    records.save(first)
    records.save(second)
    with pytest.raises(ValueError, match='separate'):
        store.validate_records(records.store.db)


@pytest.mark.parametrize('count', [1, pytest.param(64, marks=pytest.mark.scale)])
def test_jea_batch_preserves_literals_and_order(count):
    commands = [{'command': 'Invoke-FICCHyperV', 'parameters': {'Request': json.dumps({'index': index, 'name': 'VM\u03b1'})}}
                for index in range(count)]
    assert spec.batch(commands, endpoint()['commands']) == commands
    assert spec.decode(spec.encode(commands)) == commands
    assert [json.loads(item['parameters']['Request'])['index'] for item in commands] == list(range(count))


@pytest.mark.parametrize('bad', [[], [{}] * 65, [{'command': 'AddScript', 'parameters': {}}],
                                [{'command': [], 'parameters': {}}],
                                [{'command': 'Invoke-FICCHyperV', 'parameters': {'ComputerName': 'another'}}]])
def test_unregistered_jea_invocation_refused(bad):
    with pytest.raises(ValueError):
        spec.batch(bad, endpoint()['commands'])


@pytest.mark.parametrize('bad', [b'{"a":1,"a":2}', b'{"__proto__":{}}', b'NaN', b'Infinity',
                                b'1' + b'0' * 1000, b'"' + b'x' * 262145 + b'"', b'[' * 18 + b'0' + b']' * 18])
def test_unbounded_or_ambiguous_windows_json_refused(bad):
    with pytest.raises(ValueError):
        spec.decode(bad)


def test_disabled_unprobed_endpoint_is_explicit(records):
    value = copy.deepcopy(endpoint())
    value.update(enabled=False, machine_identity=None, probe_at=0)
    records.save(value)
    assert records.get(value['id'])['enabled'] is False
    with pytest.raises(ValueError, match='checked identity'):
        store.endpoint({**value, 'enabled': True})


def test_windows_runtime_cli_and_explicit_implicit_discovery(monkeypatch, tmp_path):
    from ficc import settings
    from ficc.cli import parser
    args = parser().parse_args(['serve', '--windows-runtime', str(tmp_path)])
    assert args.windows_runtime == tmp_path
    monkeypatch.setattr(settings, 'discover_windows', lambda path=None: path)
    assert settings.Settings(state_dir=tmp_path, windows_runtime=tmp_path).windows_runtime == tmp_path
    def invalid(path=None):
        raise ValueError('Invalid runtime fixture')
    monkeypatch.setattr(settings, 'discover_windows', invalid)
    implicit = settings.Settings(state_dir=tmp_path)
    assert implicit.windows_runtime is None and implicit.windows_runtime_error
    with pytest.raises(ValueError, match='Invalid runtime'):
        settings.Settings(state_dir=tmp_path, windows_runtime=tmp_path)
