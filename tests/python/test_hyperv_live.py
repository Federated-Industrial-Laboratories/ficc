# SPDX-License-Identifier: Apache-2.0
"""Qualify an installed Hyper-V module through the real isolated HTTP service."""

import json
import os
import re
import secrets
import stat
import time
from pathlib import Path

import httpx
import pytest

BOOTABLE = 'ficc-hyperv-linux03'
DISKLESS = {count: {f'ficc-hyperv-{count}-{index:02d}' for index in range(count)} for count in (1, 64)}


def checked(response, status=200):
    if response.status_code != status:
        pytest.fail(f'HTTP {response.status_code}: {response.text[:2048]}')
    return response.json()


class Live:
    def __init__(self, client, record, evidence):
        self.client, self.record, self.evidence = client, record, evidence
        self.context = record['context']

    def retain(self, name, value):
        path = self.evidence / name
        with path.open('x', encoding='utf-8') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')

    def invoke(self, action, parameters):
        response = checked(self.client.post('/api/v1/module-invocations', json={**self.context,
            'targets': [self.record['endpoint']['id']], 'action': action,
            'parameters': {'profile_id': self.record['profile']['id'], **parameters}}))
        assert len(response['results']) == 1 and 'data' in response['results'][0], response
        return response['results'][0]['data']

    def rows(self):
        rows = []
        for offset in (0, 64):
            page = self.invoke('load', {'offset': offset})
            assert all(not row['values']['error'] for row in page['rows']), page
            assert len(page['rows']) == (64 if offset == 0 else 2), page
            rows.extend(page['rows'])
        assert len({row['id'] for row in rows}) == 66
        result = {row['values']['name']: row for row in rows}
        assert set(result) == DISKLESS[1] | DISKLESS[64] | {BOOTABLE}
        return result

    def preview(self, action, rows, name):
        ids = [row['id'] for row in rows]
        preview = self.invoke('preview-' + action, {'vm_ids': ids})
        assert {item['vm_id'] for item in preview['vms']} == set(ids)
        result = checked(self.client.post('/api/v1/module-vms/preview', json={
            **self.context, 'preview_id': preview['preview_id']}))
        assert {item['name'] for item in result['vms']} == {row['values']['name'] for row in rows}
        self.retain(name + '-preview.json', result)
        return result

    def commit(self, preview, name):
        key = secrets.token_hex(16)
        self.retain(name + '-intent.json', {'preview_id': preview['preview_id'], 'key': key})
        start = time.monotonic()
        response = self.client.post('/api/v1/module-vms/commit', json={**self.context,
            'preview_id': preview['preview_id'], 'confirm': True}, headers={'Idempotency-Key': key})
        result = checked(response)
        self.retain(name + '-commit.json', {'seconds': round(time.monotonic() - start, 3), 'operation': result})
        return result

    def observe(self, operation, expected, name):
        deadline = time.monotonic() + 180
        sample = 0
        while time.monotonic() < deadline:
            value = checked(self.client.post('/api/v1/module-vms/operation', json={
                **self.context, 'operation_id': operation['id']}))
            self.retain(name + f'-observation-{sample:02d}.json', value)
            sample += 1
            states = {item['state'] for item in value['targets']}
            if states == {'observed'}:
                assert all(item['observed_state'] == expected for item in value['targets']), value
                history = checked(self.client.post('/api/v1/module-vms/history', json=self.context))
                assert any(item['id'] == value['id'] for item in history['operations'])
                self.retain(name + '-history.json', history)
                return value
            assert states <= {'accepted', 'observed'}, value
            time.sleep(2)
        pytest.fail('The same VM identities did not reach the requested state before the deadline.')

    def power(self):
        if os.environ.get('FICC_HYPERV_TEST_POWER') != '1':
            pytest.skip('Explicit disposable VM power permission is required.')


@pytest.fixture(scope='module')
def live_hyperv(tmp_path_factory):
    value = os.environ.get('FICC_HYPERV_HTTP_CONTEXT')
    if not value or os.environ.get('FICC_REAL_MODULE_SANDBOX') != '1':
        pytest.skip('An explicit isolated Hyper-V HTTP context and real module sandbox are required.')
    path = Path(value)
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077
    assert info.st_size < 262144
    record = json.loads(path.read_text())
    assert record['grant']['origin'] == 'http://127.0.0.1:18274'
    expected_endpoint = record['endpoint']
    expected_identity = expected_endpoint['machine_identity']
    assert isinstance(expected_identity, str) and re.fullmatch('[0-9a-f]{64}', expected_identity)
    assert expected_endpoint['host'] in {'localhost', '127.0.0.1'}
    assert type(expected_endpoint['port']) is int and 1024 <= expected_endpoint['port'] <= 65535
    evidence = tmp_path_factory.mktemp('hyperv-live')
    with httpx.Client(base_url=record['grant']['origin'], timeout=90, trust_env=False,
                      headers={'Authorization': 'Bearer ' + record['grant']['credential']}) as client:
        assert client.get('/').status_code == 200, 'Build the application assets before starting the fixture.'
        endpoints = checked(client.get('/api/v1/windows-endpoints'))['endpoints']
        endpoint = next(item for item in endpoints if item['id'] == record['endpoint']['id'])
        assert endpoint['machine_identity'] == expected_identity and endpoint['enabled']
        assert endpoint['configuration'] == 'FICC.HyperV'
        assert all(endpoint[field] == expected_endpoint[field] for field in ('host', 'port'))
        profiles = checked(client.get('/api/v1/adapter-profiles'))['profiles']
        profile = next(item for item in profiles if item['id'] == record['profile']['id'])
        assert profile['enabled'] and profile['digest'] == record['hyperv-adapter']['digest']
        assert profile['endpoint_id'] == endpoint['id'] and profile['machine_identity'] == expected_identity
        yield Live(client, record, evidence)


@pytest.fixture(scope='module')
def inventory(live_hyperv):
    rows = live_hyperv.rows()
    live_hyperv.retain('inventory.json', rows)
    return rows


@pytest.mark.parametrize('count', [1, 64])
def test_real_installed_hyperv_inventory(live_hyperv, inventory, count):
    selected = [inventory[name] for name in sorted(DISKLESS[count])]
    assert len(selected) == count
    assert all(row['values']['memory'] == 32768 and row['values']['vcpus'] == 1 for row in selected)
    assert all(row['id'].startswith('vm-' + live_hyperv.record['profile']['id'] + '-') for row in selected)


@pytest.mark.parametrize('count', [1, 64])
def test_real_installed_hyperv_diskless_start(live_hyperv, inventory, count):
    live_hyperv.power()
    selected = [inventory[name] for name in sorted(DISKLESS[count])]
    assert all(row['values']['state'] == 'off' for row in selected), 'Reconcile prior actions before this test.'
    name = f'start-{count}'
    preview = live_hyperv.preview('start', selected, name)
    operation = live_hyperv.commit(preview, name)
    assert len(operation['targets']) == count
    live_hyperv.observe(operation, 'running', name)


def test_real_installed_hyperv_graceful_guest_shutdown(live_hyperv):
    live_hyperv.power()
    rows = live_hyperv.rows()
    selected = rows[BOOTABLE]
    assert selected['values']['state'] == 'running', 'Complete console qualification before guest shutdown.'
    preview = live_hyperv.preview('shutdown', [selected], 'guest-shutdown')
    operation = live_hyperv.commit(preview, 'guest-shutdown')
    result = live_hyperv.observe(operation, 'off', 'guest-shutdown')
    assert result['targets'][0]['vm_id'] == selected['id']
