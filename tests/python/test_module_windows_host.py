# SPDX-License-Identifier: Apache-2.0
"""Check endpoint custody, scoped access, identity rechecks and disabled transport."""

import copy
import json
import subprocess
from types import SimpleNamespace

import pytest

from ficc.auth import Auth
from ficc.errors import Failure
from ficc.module_adapter_store import initialize
from ficc.module_windows import WindowsEndpoints
from ficc.module_windows_store import validate_records
from ficc.settings import Settings
from ficc.store import Store


class Runner:
    def __init__(self):
        self.calls = []
        self.identity = 'e' * 64
        self.closed = False
        self.before_return = lambda: None

    def ready(self):
        return not self.closed

    async def run(self, request, *, check, timeout):
        check()
        assert 0 < timeout <= 30
        self.calls.append(copy.deepcopy(request))
        self.before_return()
        check()
        if request.get('expected_machine_identity', self.identity) != self.identity:
            raise Failure('windows_identity_changed', 'The Windows machine identity changed.', 409)
        return [{'machine_identity': self.identity} if command['command'] == 'Get-FICCEndpointIdentity'
                else {'index': command['parameters']['Index']} for command in request['commands']]

    async def close(self):
        self.closed = True


@pytest.fixture
def host(tmp_path):
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    store = Store(state / 'state.sqlite3')
    with store.db:
        initialize(store.db)
    auth = Auth(store)
    _, owner = auth.issue('session')
    service = SimpleNamespace(store=store, auth=auth, settings=Settings(state_dir=state), live=lambda: None,
        authorize=lambda actor, scope, identity=None: auth.current(actor).require(scope, identity))
    runner = Runner()
    manager = WindowsEndpoints(service, runner)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=localhost', '-keyout', str(tmp_path / 'key'), '-out', str(tmp_path / 'cert')],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    value = {'name': 'Windows fixture', 'host': 'localhost', 'port': 5986, 'configuration': 'FICC.Test',
             'commands': [{'name': 'Get-FICCEndpointIdentity', 'parameters': []},
                          {'name': 'Get-FICCFixture', 'parameters': ['Index']}],
             'certificate_sha256': 'a' * 64, 'ca_pem': (tmp_path / 'cert').read_text(),
             'credentials': {'username': 'fixture', 'password': 'Fixture account secret', 'domain': ''},
             'vmconnect': {'port': 2179, 'certificate_sha256': 'b' * 64,
                          'credentials': {'username': 'display', 'password': 'Separate display secret', 'domain': ''}},
             'enabled': True}
    yield manager, owner.id, value, runner
    store.close()


@pytest.mark.parametrize('count', [1, 64])
@pytest.mark.parametrize('timeout', [10, 30])
async def test_endpoint_secret_custody_and_literal_batch(host, count, timeout):
    manager, actor, value, runner = host
    saved = await manager.set_endpoint(actor, None, value, None)
    assert saved['credentials_ready'] and saved['helper_ready'] and saved['display_credentials_ready']
    assert 'secret' not in json.dumps(saved).lower()
    raw = manager.service.store.db.execute('SELECT value FROM module_windows_endpoints').fetchone()[0]
    assert 'secret' not in raw.lower() and 'BEGIN CERTIFICATE' not in raw
    assert saved['credential_ref'] != saved['vmconnect']['credential_ref']
    result = await manager.execute(saved['id'], 1, saved['machine_identity'],
        [{'command': 'Get-FICCFixture', 'parameters': {'Index': index}} for index in range(count)],
        check=lambda: manager.authorize(actor, 'nodes:read', saved['id']), timeout=timeout)
    assert result == [{'index': index} for index in range(count)]
    assert len(runner.calls[-1]['commands']) == count
    assert len(runner.calls) == 2
    assert runner.calls[-1]['expected_machine_identity'] == saved['machine_identity']
    validate_records(manager.service.store.db)


async def test_endpoint_rename_preserves_two_accounts_and_requires_revision(host):
    manager, actor, value, runner = host
    saved = await manager.set_endpoint(actor, None, value, None)
    update = {key: item for key, item in value.items() if key not in {'credentials', 'ca_pem'}}
    update['vmconnect'] = {key: item for key, item in value['vmconnect'].items() if key != 'credentials'}
    update['name'] = 'Renamed endpoint'
    renamed = await manager.set_endpoint(actor, saved['id'], update, 1)
    assert renamed['credential_ref'] == saved['credential_ref']
    assert renamed['trust_ref'] == saved['trust_ref']
    assert renamed['vmconnect']['credential_ref'] == saved['vmconnect']['credential_ref']
    assert len(list(manager.private.path.iterdir())) == 3
    before = len(runner.calls)
    with pytest.raises(Failure, match='revision changed'):
        await manager.set_endpoint(actor, saved['id'], update, 1)
    assert len(runner.calls) == before


async def test_endpoint_disable_without_network_and_identity_change_refused(host):
    manager, actor, value, runner = host
    saved = await manager.set_endpoint(actor, None, value, None)
    before = len(runner.calls)
    disabled = await manager.set_enabled(actor, saved['id'], False, 1)
    assert not disabled['enabled'] and len(runner.calls) == before
    with pytest.raises(Failure, match='disabled or changed'):
        await manager.execute(saved['id'], 1, saved['machine_identity'], [], check=lambda: None, timeout=10)
    runner.identity = 'f' * 64
    with pytest.raises(Failure, match='machine identity changed'):
        await manager.set_enabled(actor, saved['id'], True, 2)
    assert not manager.endpoint(saved['id'])['enabled']


async def test_revoked_actor_cannot_complete_probe_or_dispatch(host):
    manager, actor, value, runner = host
    saved = await manager.set_endpoint(actor, None, value, None)
    runner.before_return = lambda: manager.service.auth.revoke(actor)
    with pytest.raises(Failure, match='Sign in'):
        await manager.execute(saved['id'], 1, saved['machine_identity'],
            [{'command': 'Get-FICCFixture', 'parameters': {'Index': 1}}],
            check=lambda: manager.authorize(actor, 'nodes:read', saved['id']), timeout=10)
    assert runner.calls[-1]['expected_machine_identity'] == saved['machine_identity']


async def test_endpoint_remove_and_private_files_require_current_revision(host):
    manager, actor, value, _ = host
    saved = await manager.set_endpoint(actor, None, value, None)
    with pytest.raises(Failure, match='revision changed'):
        await manager.remove_endpoint(actor, saved['id'], 2)
    assert len(list(manager.private.path.iterdir())) == 3
    assert await manager.remove_endpoint(actor, saved['id'], 1) == {'removed': saved['id']}
    assert list(manager.private.path.iterdir()) == []


async def test_endpoint_private_file_link_and_missing_records_are_unavailable(host, tmp_path):
    manager, actor, value, _ = host
    saved = await manager.set_endpoint(actor, None, value, None)
    private = manager.private.path / saved['credential_ref']
    private.rename(tmp_path / 'record')
    private.symlink_to(tmp_path / 'record')
    assert not manager.endpoints(actor)[0]['credentials_ready']
    with pytest.raises(Failure, match='account and trust records'):
        await manager.execute(saved['id'], 1, saved['machine_identity'],
            [{'command': 'Get-FICCFixture', 'parameters': {'Index': 1}}], check=lambda: None, timeout=10)


async def test_bound_adapter_prevents_endpoint_replacement_but_allows_disable(host):
    from ficc.module_adapter_store import Records as AdapterRecords
    manager, actor, value, _ = host
    saved = await manager.set_endpoint(actor, None, value, None)
    adapters = AdapterRecords(manager.service.store)
    adapters.save_profile({'id': '8' * 32, 'endpoint_kind': 'windows', 'endpoint_id': saved['id'],
        'endpoint_revision': 1, 'machine_identity': saved['machine_identity'],
        'transport_binding_id': '9' * 32, 'consistency': 'checked-before-dispatch',
        'digest': 'a' * 64, 'revision': 1, 'enabled': False})
    with pytest.raises(Failure, match='profiles and receipts'):
        await manager.set_endpoint(actor, saved['id'], {**value, 'host': 'other.invalid'}, 1)
    assert len(list(manager.private.path.iterdir())) == 3
    with pytest.raises(Failure, match='profiles and receipts'):
        await manager.remove_endpoint(actor, saved['id'], 1)
    disabled = await manager.set_enabled(actor, saved['id'], False, 1)
    assert not disabled['enabled']
    adapters.remove_profile('8' * 32)
    assert await manager.remove_endpoint(actor, saved['id'], 2) == {'removed': saved['id']}


async def test_endpoint_scoped_reader_sees_only_selected_endpoint_and_cannot_write(host):
    manager, actor, value, _ = host
    first = await manager.set_endpoint(actor, None, value, None)
    second = await manager.set_endpoint(actor, None, {**value, 'name': 'Other endpoint'}, None)
    _, reader = manager.service.auth.issue('token', scopes=['nodes:read', 'nodes:write'])
    with manager.service.store.db:
        manager.service.store.db.execute('UPDATE credentials SET nodes=? WHERE id=?',
                                        (json.dumps([first['id']]), reader.id))
    assert [item['id'] for item in manager.endpoints(reader.id)] == [first['id']]
    with pytest.raises(Failure, match='unrestricted'):
        await manager.set_enabled(reader.id, first['id'], False, 1)
    with pytest.raises(Failure):
        manager.authorize(reader.id, 'nodes:read', second['id'])


async def test_vmconnect_uses_only_registered_display_account_and_pin(host):
    manager, actor, value, _ = host
    saved = await manager.set_endpoint(actor, None, value, None)
    vm = 'b6b3bd5c-66e8-4c65-9cfe-35af0739c144'
    result = await manager.console_connection(saved['id'], 1, saved['machine_identity'], vm,
        check=lambda: manager.authorize(actor, 'nodes:read', saved['id']))
    assert result['host'] == value['host'] and result['port'] == 2179
    assert result['configuration'] == {'version': 1, 'protocol': 'rdp', 'transport': 'vmconnect',
        'vm_id': vm, **value['vmconnect']['credentials'], 'certificate_sha256': 'b' * 64}
    assert result['configuration']['password'] != value['credentials']['password']
    await manager.set_enabled(actor, saved['id'], False, 1)
    with pytest.raises(Failure, match='disabled or changed'):
        await manager.console_connection(saved['id'], 1, saved['machine_identity'], vm, check=lambda: None)
