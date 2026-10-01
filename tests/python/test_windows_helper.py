# SPDX-License-Identifier: Apache-2.0
"""Check identity before command dispatch within one authenticated runspace."""

import json
import sys
from types import SimpleNamespace

import pytest

from ficc import windows_helper, windows_http


@pytest.fixture
def transport(monkeypatch):
    state = SimpleNamespace(identity='a' * 64, calls=[], pools=0, closed=False, malformed=False, failed=False)

    class Client:
        def __init__(self, *args, **kwargs):
            state.client_options = kwargs
            self.transport = SimpleNamespace()

        def close(self):
            state.closed = True

    class Pool:
        def __init__(self, client, **kwargs):
            state.pools += 1
            state.pool_options = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class Shell:
        def __init__(self, pool):
            self.had_errors = False
            self.parameters = {}

        def add_cmdlet(self, command):
            self.command = command

        def add_parameter(self, key, value):
            self.parameters[key] = value

        def invoke(self):
            state.calls.append((self.command, self.parameters))
            if self.command == 'Get-FICCEndpointIdentity':
                self.had_errors = state.failed
                return [json.dumps({'other': state.identity} if state.malformed else {'machine_identity': state.identity})]
            return [json.dumps({'value': self.parameters['Value']})]

    monkeypatch.setitem(sys.modules, 'pypsrp.negotiate', SimpleNamespace(NoCertificateRetrievedWarning=type('CertificateWarning', (Warning,), {})))
    monkeypatch.setitem(sys.modules, 'pypsrp.powershell', SimpleNamespace(PowerShell=Shell, RunspacePool=Pool))
    monkeypatch.setitem(sys.modules, 'pypsrp.wsman', SimpleNamespace(WSMan=Client))
    monkeypatch.setattr(windows_http, 'session', lambda *args: object())
    monkeypatch.setattr(windows_helper, 'trust', lambda value: value)
    request = {'version': 1, 'host': 'localhost', 'port': 5986, 'configuration': 'FICC.Test',
               'certificate_sha256': 'b' * 64, 'ca_pem': 'test trust',
               'credentials': {'username': 'fixture', 'password': 'test secret', 'domain': ''},
               'expected_machine_identity': state.identity, 'commands': []}
    return state, request


@pytest.mark.parametrize('count', [1, 64])
def test_identity_and_literal_batch_share_one_authenticated_pool(transport, count):
    state, request = transport
    values = [{'index': index, 'literal': "a'; Get-Process; 'b"} for index in range(count)]
    request['commands'] = [{'command': 'Get-FICCValue', 'parameters': {'Value': value}} for value in values]
    result = windows_helper.execute(request)
    assert result == {'version': 1, 'results': [{'value': value} for value in values]}
    assert state.pools == 1 and state.closed
    assert state.calls == [('Get-FICCEndpointIdentity', {})] + [('Get-FICCValue', {'Value': value}) for value in values]
    assert state.pool_options['configuration_name'] == 'FICC.Test'
    assert state.client_options['cert_validation'] and state.client_options['negotiate_send_cbt']


@pytest.mark.parametrize('mode', ['different', 'malformed', 'command-error'])
def test_identity_refusal_never_dispatches_requested_commands(transport, mode):
    state, request = transport
    request['commands'] = [{'command': 'Invoke-FICCChange', 'parameters': {'Value': 1}}]
    if mode == 'different':
        state.identity = 'c' * 64
    elif mode == 'malformed':
        state.malformed = True
    else:
        state.failed = True
    with pytest.raises(ValueError):
        windows_helper.execute(request)
    assert state.calls == [('Get-FICCEndpointIdentity', {})]
    assert state.pools == 1 and state.closed


def test_enrollment_identity_probe_does_not_require_a_prior_identity(transport):
    state, request = transport
    request.pop('expected_machine_identity')
    request['commands'] = [{'command': 'Get-FICCEndpointIdentity', 'parameters': {}}]
    assert windows_helper.execute(request)['results'] == [{'machine_identity': state.identity}]
    assert state.calls == [('Get-FICCEndpointIdentity', {})]
