# SPDX-License-Identifier: Apache-2.0
"""Bind Windows command batches to enrolled endpoints and private account references."""

import asyncio
import copy
import secrets
import time
import uuid

from . import module_windows_spec as spec
from .errors import Failure
from .module_windows_private import Private
from .module_windows_store import Records, endpoint


def references(value):
    return {value['trust_ref'], value['credential_ref']} | (
        {value['vmconnect']['credential_ref']} if value['vmconnect'] else set())


class WindowsEndpoints:
    def __init__(self, service, runner=None):
        self.service = service
        self.records = Records(service.store)
        self.private = Private(service.settings.state_dir)
        if runner is None:
            from .windows_process import Runner
            runner = Runner(getattr(service.settings, 'windows_runtime', None))
        self.runner = runner
        self.admission = asyncio.Lock()
        self.closed = False

    def authorize(self, actor, scope, identity=None):
        self.service.live()
        self.service.authorize(actor, scope, identity)
        principal = self.service.auth.current(actor)
        if principal.root_ids is not None or (scope == 'nodes:write' and principal.node_ids is not None):
            raise Failure('denied', 'Windows endpoint changes require unrestricted local access.', 403)
        if self.closed:
            raise Failure('unavailable', 'Windows endpoint access is closed.', 503)

    def endpoint(self, identity):
        return self.records.get(identity)

    def public(self, value):
        ready = self.runner.ready()
        return {**copy.deepcopy(value), 'credentials_ready': self.private.ready(value['credential_ref'], 'credentials'),
                'trust_ready': self.private.ready(value['trust_ref'], 'trust'), 'helper_ready': ready,
                'display_credentials_ready': value['vmconnect'] is not None and self.private.ready(
                    value['vmconnect']['credential_ref'], 'credentials'),
                'diagnostic': '' if ready else 'Install the Windows transport runtime for this host.'}

    def endpoints(self, actor):
        self.authorize(actor, 'nodes:read')
        selected = self.service.auth.current(actor).node_ids
        return [self.public(value) for value in self.records.all() if selected is None or value['id'] in selected]

    def retained(self, identity):
        from .module_adapter_store import retained
        if retained(self.service.store, endpoint_id=identity):
            raise Failure('windows_endpoint_retained',
                          'Remove adapter profiles and receipts before changing this endpoint connection.', 409)

    def request(self, value, commands):
        try:
            account = self.private.read(value['credential_ref'], 'credentials')
            ca = self.private.read(value['trust_ref'], 'trust')
        except (OSError, ValueError) as exc:
            raise Failure('windows_credentials_missing', 'Restore this endpoint account and trust records.', 409) from exc
        return {'version': 1, 'host': value['host'], 'port': value['port'], 'configuration': value['configuration'],
                'certificate_sha256': value['certificate_sha256'], 'ca_pem': ca, 'credentials': account,
                'commands': spec.batch(commands, value['commands'])}

    async def probe(self, value, check, timeout=10):
        check()
        result = await self.runner.run(self.request(value, [{'command': 'Get-FICCEndpointIdentity', 'parameters': {}}]),
                                       check=check, timeout=min(10, timeout))
        check()
        if not isinstance(result, list) or len(result) != 1:
            raise Failure('windows_identity', 'The Windows endpoint identity response is invalid.', 409)
        spec.fields(result[0], {'machine_identity'})
        return spec.identity(result[0]['machine_identity'], 64)

    async def set_endpoint(self, actor, identity, value, expected_revision):
        async with self.admission:
            self.authorize(actor, 'nodes:write', identity)
            spec.fields(value, {'name', 'host', 'port', 'configuration', 'commands', 'certificate_sha256', 'enabled'},
                        {'credentials', 'ca_pem', 'vmconnect'})
            if type(value['enabled']) is not bool:
                raise ValueError('Choose an explicit Windows endpoint state.')
            prior = self.records.get(identity) if identity else None
            if (prior and prior['revision'] != expected_revision) or (not prior and expected_revision is not None):
                raise Failure('windows_endpoint_changed', 'The Windows endpoint revision changed.', 409)
            pending = []
            try:
                def reference(field, kind, supplied):
                    if supplied is None:
                        if prior is None:
                            raise ValueError('Supply endpoint credentials and trust for enrollment.')
                        return prior[field]
                    ref = self.private.write(kind, supplied)
                    pending.append(ref)
                    return ref
                item = {key: copy.deepcopy(value[key]) for key in (
                    'name', 'host', 'port', 'configuration', 'commands', 'certificate_sha256', 'enabled')}
                item.update(id=identity or secrets.token_hex(16), host=spec.host(item['host']),
                            revision=prior['revision'] + 1 if prior else 1,
                            trust_ref=reference('trust_ref', 'trust', value.get('ca_pem')),
                            credential_ref=reference('credential_ref', 'credentials', value.get('credentials')),
                            machine_identity=prior['machine_identity'] if prior else None,
                            probe_at=prior['probe_at'] if prior else 0, vmconnect=None)
                display = value.get('vmconnect', prior['vmconnect'] if prior else None)
                if display is not None:
                    spec.fields(display, {'port', 'certificate_sha256'}, {'credentials', 'credential_ref'})
                    if 'credential_ref' in display and display != (prior or {}).get('vmconnect'):
                        raise ValueError('Private credential references cannot be selected by a caller.')
                    if 'credentials' in display:
                        ref = self.private.write('credentials', display['credentials'])
                        pending.append(ref)
                    elif prior and prior['vmconnect']:
                        ref = prior['vmconnect']['credential_ref']
                    else:
                        raise ValueError('Supply separate VMConnect account credentials.')
                    item['vmconnect'] = {key: display[key] for key in ('port', 'certificate_sha256')}
                    item['vmconnect']['credential_ref'] = ref
                def connection(item):
                    return {k: v for k, v in item.items() if k not in {
                        'name', 'revision', 'enabled', 'machine_identity', 'probe_at'}}
                changed = prior is None or connection(prior) != connection(item)
                if prior and changed:
                    self.retained(identity)
                    item.update(machine_identity=None, probe_at=0)
                endpoint({**item, 'enabled': False})
                def check():
                    self.authorize(actor, 'nodes:write', identity)
                    if prior and self.records.get(identity) != prior:
                        raise Failure('windows_endpoint_changed', 'The Windows endpoint revision changed.', 409)
                if item['enabled']:
                    actual = await self.probe(item, check)
                    if prior and not changed and prior['machine_identity'] not in {None, actual}:
                        raise Failure('windows_identity_changed', 'The Windows machine identity changed.', 409)
                    item.update(machine_identity=actual, probe_at=time.time())
                check()
                self.records.save(item, expected_revision)
                pending.clear()
                if prior:
                    for ref in references(prior) - references(item):
                        self.private.remove(ref)
                self.service.store.audit('windows.endpoint', item['id'], actor=actor)
                return self.public(item)
            finally:
                for ref in pending:
                    self.private.remove(ref)

    async def set_enabled(self, actor, identity, enabled, expected_revision):
        prior = self.records.get(identity)
        value = {key: prior[key] for key in ('name', 'host', 'port', 'configuration', 'commands', 'certificate_sha256')}
        value['enabled'] = enabled
        return await self.set_endpoint(actor, identity, value, expected_revision)

    async def remove_endpoint(self, actor, identity, expected_revision):
        async with self.admission:
            self.authorize(actor, 'nodes:write', identity)
            self.retained(identity)
            value = self.records.get(identity)
            self.records.remove(identity, expected_revision)
            for ref in references(value):
                self.private.remove(ref)
            self.service.store.audit('windows.endpoint.remove', identity, actor=actor)
            return {'removed': identity}

    async def execute(self, endpoint_id, expected_revision, machine_identity, commands, *, check, timeout):
        value = self.records.get(endpoint_id)
        def current():
            check()
            self.service.live()
            now = self.records.get(endpoint_id)
            if (self.closed or not now['enabled'] or now['revision'] != expected_revision
                    or now['machine_identity'] != machine_identity or now != value):
                raise Failure('windows_endpoint_changed', 'The Windows endpoint is disabled or changed.', 409)
        current()
        if not 0 < timeout <= 30:
            raise ValueError('The Windows request deadline is invalid.')
        request = self.request(value, commands)
        request['expected_machine_identity'] = spec.identity(machine_identity, 64)
        result = await self.runner.run(request, check=current, timeout=timeout)
        current()
        spec.encode(result)
        if not isinstance(result, list) or len(result) != len(commands):
            raise Failure('windows_response', 'The Windows command response count differs.', 502)
        return copy.deepcopy(result)

    async def close(self):
        self.closed = True
        await self.runner.close()

    async def console_connection(self, endpoint_id, expected_revision, machine_identity, vm_id, *, check):
        if not isinstance(vm_id, str) or str(uuid.UUID(vm_id)) != vm_id:
            raise ValueError('The VMConnect VM identity is invalid.')
        value = self.records.get(endpoint_id)
        def current():
            check()
            self.service.live()
            now = self.records.get(endpoint_id)
            if (self.closed or not now['enabled'] or now['revision'] != expected_revision
                    or now['machine_identity'] != machine_identity or now != value):
                raise Failure('windows_endpoint_changed', 'The Windows endpoint is disabled or changed.', 409)
        current()
        display = value['vmconnect']
        if display is None:
            raise Failure('windows_display_missing', 'Register a separate VMConnect display account and certificate.', 409)
        if await self.probe(value, current) != machine_identity:
            raise Failure('windows_identity_changed', 'The Windows machine identity changed.', 409)
        try:
            account = self.private.read(display['credential_ref'], 'credentials')
        except (OSError, ValueError) as exc:
            raise Failure('windows_credentials_missing', 'Restore this endpoint display account record.', 409) from exc
        current()
        return {'host': value['host'], 'port': display['port'], 'configuration': {
            'version': 1, 'protocol': 'rdp', 'transport': 'vmconnect', 'vm_id': vm_id,
            **account, 'certificate_sha256': display['certificate_sha256']}}
