# SPDX-License-Identifier: Apache-2.0
"""Keep trusted node identities until their completed history is archived."""

import pytest
from conftest import node


@pytest.mark.parametrize('count', [1, 64])
@pytest.mark.parametrize('kind', ['job', 'terminal', 'file', 'source', 'destination'])
def test_closed_history_prevents_forgetting_its_last_machine(console, count, kind):
    client, service = console
    service.store.save_node(node())
    service.store.save_node(node(1))
    for index in range(count):
        target = 'node-0' if index == count - 1 else 'other-node'
        value = {'id': f'history-{index}', 'actor': 'retired', 'key': f'key-{index}',
                 'digest': 'digest', 'state': 'succeeded', 'items': []}
        if kind == 'job':
            value['targets'] = [{'node_id': target, 'state': 'succeeded'}]
            service.jobs.store.insert(value)
        elif kind == 'terminal':
            value.update(node_id=target, state='stopped')
            service.terminals.save(value)
        elif kind == 'file':
            value['root'] = {'id': 'removed-root', 'node_id': target}
            service.files.store.insert(value)
        else:
            value['kind'] = 'copy'
            local = {'root': {'id': 'local', 'node_id': None}}
            remote = {'root': {'id': 'removed-root', 'node_id': target}}
            value['items'] = [{'state': 'succeeded', 'destination': remote if kind == 'destination' else local,
                               'source': remote if kind == 'source' else local}]
            service.transfers.store.insert(value)
    response = client.delete('/api/v1/nodes/node-0')
    assert response.status_code == 409, response.text
    assert response.json()['error']['code'] == 'history_retained'
    assert service.store.node('node-0')['id'] == 'node-0'
    assert client.delete('/api/v1/nodes/node-1').status_code == 200
