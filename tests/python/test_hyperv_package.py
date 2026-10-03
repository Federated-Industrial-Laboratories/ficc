# SPDX-License-Identifier: Apache-2.0
"""Check the installed provider's batch identity and acknowledgement rules."""

import copy
import importlib.util
import json
import os
import uuid
from pathlib import Path

import pytest

from ficc.modules.adapter_vm_protocol import result as validate_result

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('hyperv_package', ROOT / 'modules/hyperv-adapter/payload/hyperv.py')
assert SPEC and SPEC.loader
provider = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provider)


class Endpoint:
    def __init__(self, count):
        self.rows = [{"key": str(uuid.UUID(int=i + 1)), "birth": f'{i + 1:064x}',
                      "revision": 'b' * 64, "name": f'VM {i}', "state": 3,
                      "memory_bytes": 33554432, "vcpus": 1, "console": True} for i in range(count)]
        self.calls = []
        self.ack = True
        self.async_job = False
        self.job_state = 4
        self.job_error = 0

    def __call__(self, profile, commands):
        self.calls.append(copy.deepcopy(commands))
        assert len(commands) == 1
        command = commands[0]
        name = command['command']
        value = json.loads(command['parameters']['Request']) if command['parameters'] else None
        if name == 'Get-FICCHyperVVersion':
            return [{'version': '10.0.26100', 'backend': 1}]
        if name == 'Get-FICCHyperVSnapshot':
            selected = [item for item in self.rows if not value['ids'] or item['key'] in value['ids']]
            return [{'rows': copy.deepcopy(selected), 'next_offset': None}]
        if name == 'Invoke-FICCHyperVPower':
            results = []
            for item in value['targets']:
                resource = item['resource']
                raw = next(row for row in self.rows if row['key'] == resource['key'])
                safe = provider.row(raw)['resource'] == resource
                if safe:
                    raw['state'] = 2 if item['action'] == 'start' else 3
                results.append({'key': resource['key'], 'birth': resource['birth'], 'dispatched': safe,
                                'return_value': 4096 if self.async_job else 0,
                                'job': str(uuid.UUID(int=len(results) + 1024)) if self.async_job else None})
            if not self.ack:
                raise OSError('The acknowledgement was lost.')
            return [{'results': results}]
        if name == 'Get-FICCHyperVTasks':
            return [{'results': [{'id': key, 'state': self.job_state, 'error': self.job_error} for key in value['ids']]}]
        raise AssertionError(name)


def request(endpoint, phase, action=None):
    return {'version': 1, 'type': 'adapter-invoke', 'id': 'a' * 32, 'digest': 'b' * 64,
            'phase': phase, 'action': action or phase, 'bindings': [{
                'id': 'c' * 32, 'endpoint_id': 'd' * 32, 'endpoint_revision': 1,
                'machine_identity': 'e' * 64, 'consistency': 'checked-before-dispatch',
                'resources': [] if phase in {'inventory', 'probe'} else [provider.row(raw)['resource'] for raw in endpoint.rows],
                'parameters': {}}]}


def run(endpoint, value):
    output = provider.handle(value, endpoint)
    assert len(output) == 1 and 'data' in output[0], output
    data = output[0]['data']
    validate_result(data, value['phase'], value['action'], value['bindings'][0])
    return data


def prepared(endpoint, action='start'):
    value = request(endpoint, 'prepare', action)
    data = run(endpoint, value)
    value['phase'] = 'apply'
    value['bindings'][0]['intent'] = {'controller': 'f' * 32, 'operation': '1' * 32,
        'digest': value['digest'], 'targets': [{'id': row['id'], 'intent': row['intent']} for row in data['results']]}
    return value


@pytest.mark.parametrize('count', [1, pytest.param(64, marks=pytest.mark.scale)])
def test_inventory_status_prepare_acknowledgement_and_observation(count):
    endpoint = Endpoint(count)
    assert len(run(endpoint, request(endpoint, 'inventory'))['resources']) == count
    assert run(endpoint, request(endpoint, 'probe'))['provider']['name'] == 'Microsoft Hyper-V'
    assert len(run(endpoint, request(endpoint, 'status'))['results']) == count
    value = prepared(endpoint)
    data = run(endpoint, value)
    assert all(row['receipt']['state'] == 'accepted' and row['receipt']['task_state'] == 'none' for row in data['results'])
    value['phase'] = 'observe'
    value['bindings'][0]['receipt'] = {'targets': [{'id': row['id'], 'receipt': row['receipt']} for row in data['results']]}
    data = run(endpoint, value)
    assert [row['id'] for row in data['results']] == [row['id'] for row in value['bindings'][0]['resources']]
    assert all(row['receipt']['state'] == 'observed' for row in data['results'])
    assert sum(call[0]['command'] == 'Invoke-FICCHyperVPower' for call in endpoint.calls) == 1


@pytest.mark.parametrize('count', [1, pytest.param(64, marks=pytest.mark.scale)])
def test_lost_acknowledgement_stays_unknown_despite_desired_state(count):
    endpoint = Endpoint(count)
    value = prepared(endpoint)
    endpoint.ack = False
    with pytest.raises(OSError):
        provider.handle(value, endpoint)
    value['phase'] = 'observe'
    value['bindings'][0]['receipt'] = {'targets': [{'id': row['id'], 'receipt': None} for row in value['bindings'][0]['resources']]}
    data = run(endpoint, value)
    assert all(row['observed_state'] == 'running' and row['receipt']['state'] == 'unknown' for row in data['results'])
    assert sum(call[0]['command'] == 'Invoke-FICCHyperVPower' for call in endpoint.calls) == 1


@pytest.mark.parametrize('count', [1, pytest.param(64, marks=pytest.mark.scale)])
def test_async_job_retained_until_exact_successful_completion(count):
    endpoint = Endpoint(count)
    value = prepared(endpoint)
    endpoint.async_job = True
    data = run(endpoint, value)
    value['phase'] = 'observe'
    value['bindings'][0]['receipt'] = {'targets': [{'id': row['id'], 'receipt': row['receipt']} for row in data['results']]}
    data = run(endpoint, value)
    assert all(row['receipt']['state'] == 'accepted' and row['receipt']['task_state'] == 'active' for row in data['results'])
    endpoint.job_state = 0
    assert all(row['receipt']['task_state'] == 'unknown' for row in run(endpoint, value)['results'])
    endpoint.job_state = 7
    assert all(row['receipt']['state'] == 'observed' for row in run(endpoint, value)['results'])
    endpoint.job_error = 5
    assert all(row['receipt']['state'] == 'failed' for row in run(endpoint, value)['results'])


@pytest.mark.parametrize('count', [1, pytest.param(64, marks=pytest.mark.scale)])
def test_shutdown_acknowledgement_needs_same_birth_off_state(count):
    endpoint = Endpoint(count)
    for item in endpoint.rows:
        item['state'] = 2
    value = prepared(endpoint, 'shutdown')
    data = run(endpoint, value)
    value['phase'] = 'observe'
    value['bindings'][0]['receipt'] = {'targets': [{'id': row['id'], 'receipt': row['receipt']} for row in data['results']]}
    original = endpoint.rows[0]['birth']
    endpoint.rows[0]['birth'] = 'f' * 64
    data = run(endpoint, value)
    assert data['results'][0]['receipt']['state'] == 'accepted'
    assert 'observed_state' not in data['results'][0]
    endpoint.rows[0]['birth'] = original
    assert all(row['receipt']['state'] == 'observed' for row in run(endpoint, value)['results'])


@pytest.mark.parametrize('field', ['birth', 'revision', 'state'])
def test_changed_preview_is_refused_without_dispatch(field):
    endpoint = Endpoint(1)
    value = prepared(endpoint)
    endpoint.rows[0][field] = 2 if field == 'state' else 'f' * 64
    result = run(endpoint, value)['results'][0]
    assert result['receipt']['state'] == 'refused'


def test_console_freezes_same_resource_and_endpoint_without_address_or_credentials():
    endpoint = Endpoint(1)
    value = request(endpoint, 'console')
    result = run(endpoint, value)
    assert result == {'resource': value['bindings'][0]['resources'][0], 'kind': 'vmconnect',
                      'binding_id': 'd' * 32, 'parameters': {'vm_id': endpoint.rows[0]['key']}}
    endpoint.rows[0]['revision'] = 'f' * 64
    assert 'error' in provider.handle(value, endpoint)[0]


def test_malformed_or_duplicate_inventory_and_foreign_receipt_are_refused():
    endpoint = Endpoint(1)
    endpoint.rows.append(copy.deepcopy(endpoint.rows[0]))
    assert 'error' in provider.handle(request(endpoint, 'inventory'), endpoint)[0]
    endpoint.rows.pop()
    value = prepared(endpoint)
    data = run(endpoint, value)
    data['results'][0]['receipt']['token']['birth'] = 'f' * 64
    value['phase'] = 'observe'
    value['bindings'][0]['receipt'] = {'targets': [{'id': row['id'], 'receipt': row['receipt']} for row in data['results']]}
    assert 'error' in provider.handle(value, endpoint)[0]


@pytest.mark.skipif(os.environ.get('FICC_REAL_MODULE_SANDBOX') != '1',
                    reason='Set FICC_REAL_MODULE_SANDBOX=1 for actual host isolation')
@pytest.mark.parametrize('count', [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_installed_hyperv_package_uses_real_sandbox_and_fixed_batch_transport(tmp_path, count):
    from test_modules_packages import bundle

    from ficc.modules import inspect_archive
    from ficc.modules.adapter_protocol import Conversation
    from ficc.modules.adapter_runtime import ControllerRuntime
    from ficc.modules.archive import publish

    source = ROOT / 'modules/hyperv-adapter'
    manifest = json.loads((source / 'manifest.json').read_text())
    files = {path.relative_to(source / 'payload').as_posix(): path.read_bytes()
             for path in (source / 'payload').rglob('*') if path.is_file() and '__pycache__' not in path.parts}
    for name in ('ficc_module.py', 'ficc_adapter.py'):
        files[name] = (ROOT / 'sdk/python' / name).read_bytes()
    import hashlib
    manifest['files'] = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    package = inspect_archive(bundle(manifest, files))
    installed = publish(tmp_path, package)
    endpoint = Endpoint(count)
    binding = request(endpoint, 'status')['bindings'][0]
    checked = []
    def check():
        checked.append(True)
    async def transport(call):
        call.check()
        return endpoint(call.profile_id, call.commands)
    conversation = Conversation(package.digest, 'status', 'status', [binding], check, transport)
    output = await ControllerRuntime().execute(installed, manifest, conversation)
    data = output['results'][0]['data']
    validate_result(data, 'status', 'status', binding)
    assert [item['id'] for item in data['results']] == [item['id'] for item in binding['resources']]
    assert len(checked) >= 4 and len(endpoint.calls) == 1


def test_asynchronous_acknowledgement_without_job_is_unknown_not_failed():
    endpoint = Endpoint(1)
    value = prepared(endpoint)
    endpoint.async_job = True
    def missing_job(profile, commands):
        data = endpoint(profile, commands)
        if commands[0]['command'] == 'Invoke-FICCHyperVPower':
            data[0]['results'][0]['job'] = None
        return data
    result = provider.handle(value, missing_job)[0]['data']
    validate_result(result, 'apply', 'start', value['bindings'][0])
    assert result['results'][0]['receipt']['state'] == 'unknown'
    assert result['results'][0]['receipt']['task_state'] == 'unknown'


def test_completed_job_proof_survives_provider_job_expiry():
    endpoint = Endpoint(1)
    value = prepared(endpoint)
    endpoint.async_job = True
    data = run(endpoint, value)
    value['phase'] = 'observe'
    value['bindings'][0]['receipt'] = {'targets': [{'id': row['id'], 'receipt': row['receipt']} for row in data['results']]}
    endpoint.job_state = 7
    data = run(endpoint, value)
    value['bindings'][0]['receipt'] = {'targets': [{'id': row['id'], 'receipt': row['receipt']} for row in data['results']]}
    endpoint.job_state = 0
    before = sum(call[0]['command'] == 'Get-FICCHyperVTasks' for call in endpoint.calls)
    assert run(endpoint, value)['results'][0]['receipt']['state'] == 'observed'
    assert sum(call[0]['command'] == 'Get-FICCHyperVTasks' for call in endpoint.calls) == before
