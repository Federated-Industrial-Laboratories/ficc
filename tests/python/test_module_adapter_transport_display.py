# SPDX-License-Identifier: Apache-2.0
"""Keep private display credentials behind registered, unchanged Unix identities."""

import copy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ficc.errors import Failure
from ficc.providers import adapter_transport


@pytest.fixture
def transport(monkeypatch):
    monkeypatch.setattr(adapter_transport, 'LOCAL_IPC_QUALIFIED', True)
    service = SimpleNamespace(store=SimpleNamespace(node=lambda _identity: {'id': '1' * 32}),
        ssh=SimpleNamespace(arguments=AsyncMock(return_value=['ssh', '-T', 'registered-alias'])))
    value = adapter_transport.EndpointTransport(service)
    value.rpc = AsyncMock(return_value={'socket_path': '/run/user/1000/display.sock', 'device': 1,
        'inode': 2, 'uid': 1000, 'pid': 1234, 'start': '456'})
    return value


def selection():
    selected = {'endpoint_kind': 'linux-ssh', 'endpoint_id': '1' * 32, 'transport_binding_id': '2' * 32}
    proposal = {'kind': 'vnc', 'binding_id': '2' * 32,
        'parameters': {'pid': 1234, 'socket_path': '/run/user/1000/display.sock', 'password': 'Abc12345'}}
    return selected, proposal


@pytest.mark.parametrize('count', [1, 64])
async def test_selected_unix_peer_and_private_header_do_not_expose_credentials(transport, count):
    for index in range(count):
        selected, proposal = selection()
        selected['transport_binding_id'] = proposal['binding_id'] = f'{index + 10:032x}'
        graphics = await transport.console_descriptor(selected, proposal, lambda: None)
        assert graphics == {'protocol': 'vnc', 'authentication': 'rfb-password', 'audio': False,
                            'display': transport.rpc.return_value}
        assert '"password":' not in json.dumps(graphics) and 'Abc12345' not in json.dumps(graphics)
        descriptor = {'profile': selected, 'proposal': proposal, 'graphics': graphics}
        arguments, header = await transport.console_command(descriptor, lambda: None)
        assert arguments == ['ssh', '-T', 'registered-alias', adapter_transport.CONSOLE_COMMAND]
        assert json.loads(header) == {'binding_id': proposal['binding_id'], 'display': graphics['display'], 'password': 'Abc12345'}
        assert transport.rpc.call_args.args[2]['parameters'] == {'pid': 1234, 'socket_path': '/run/user/1000/display.sock'}


@pytest.mark.parametrize('change', ['binding', 'protocol', 'credential', 'extra'])
async def test_display_proposal_refuses_before_resource_rpc(transport, change):
    selected, proposal = selection()
    if change == 'binding':
        proposal['binding_id'] = '3' * 32
    elif change == 'protocol':
        proposal['kind'] = 'tcp'
    elif change == 'credential':
        proposal['parameters']['password'] = 'PRIVATE-UNSUPPORTED-CREDENTIAL'
    else:
        proposal['parameters']['host'] = 'outside.example'
    with pytest.raises(Failure) as caught:
        await transport.console_descriptor(selected, proposal, lambda: None)
    assert 'PRIVATE-' not in str(caught.value)
    transport.rpc.assert_not_awaited()


@pytest.mark.parametrize('field,value', [('inode', 3), ('device', 2), ('pid', 1235), ('start', '457'), ('uid', 1001)])
async def test_changed_listener_or_process_cannot_reuse_a_display(transport, field, value):
    selected, proposal = selection()
    graphics = await transport.console_descriptor(selected, proposal, lambda: None)
    descriptor = {'profile': selected, 'proposal': proposal, 'graphics': copy.deepcopy(graphics)}
    transport.rpc.return_value[field] = value
    with pytest.raises(Failure, match='process or listener changed'):
        await transport.console_command(descriptor, lambda: None)
    transport.service.ssh.arguments.assert_not_awaited()


async def test_revoked_grant_prevents_resource_inspection_and_stream_start(transport):
    selected, proposal = selection()
    def revoked():
        raise Failure('denied', 'The grant was revoked.', 403)
    with pytest.raises(Failure):
        await transport.console_descriptor(selected, proposal, revoked)
    transport.rpc.assert_not_awaited()
    transport.service.ssh.arguments.assert_not_awaited()
