# SPDX-License-Identifier: Apache-2.0
"""Check broker authority with real bounded pipes and optional platform isolation."""

import asyncio
import os
import sys

import pytest
import test_modules_registry
from test_modules_packages import bundle, package

from ficc.errors import Failure
from ficc.modules import inspect_archive
from ficc.modules.runtime import Runtime
from ficc.modules.sandbox import SandboxStatus

registry = test_modules_registry.registry

# This fixed fixture uses only stdlib framing. Host handlers and credentials are
# never available inside it. Modes exercise both valid and hostile conversations.
SOURCE = b'''import json,os,struct,sys,time
r=sys.stdin.buffer
w=sys.stdout.buffer
def get():
 n=struct.unpack('>I',r.read(4))[0]
 return json.loads(r.read(n))
def send(value):
 data=json.dumps(value,separators=(',',':')).encode()
 w.write(struct.pack('>I',len(data))+data);w.flush()
hello=get();inv=get();mode=inv['parameters'].get('mode','read')
send({'version':2,'type':'hello','protocol':1 if mode=='bad-hello' else 2})
base={'version':2,'type':'broker','id':'b'*32,'invocation_id':inv['id'],
      'primitive':'resource.read.v1','targets':inv['targets'],'parameters':{'value':'fixture'}}
if mode=='spoof':base['invocation_id']='f'*32
if mode=='outside':base['targets']=['not-selected']
if mode=='unknown':base['authority']='owner'
if mode=='stderr':sys.stderr.buffer.write(b'x'*65537);sys.stderr.flush()
if mode=='descendant':
 child=os.fork()
 if child==0:
  os.setsid();r.close();w.close();time.sleep(60);os._exit(0)
if mode=='zero':
 results=[{'target':t,'data':t} for t in inv['targets']]
else:
 for i in range(17 if mode=='excess' else 2 if mode=='duplicate' else 1):
  request=dict(base)
  if mode=='excess':request['id']=format(i,'032x')
  send(request)
  if mode=='pipeline':send(request)
  reply=get()
  if mode=='cancel':
   cancel=get()
   if cancel!={'version':2,'type':'cancel','id':inv['id']}:sys.exit(5)
   sys.exit(0)
  assert reply['version']==2 and reply['type']=='broker-result'
  assert reply['id']==request['id'] and reply['invocation_id']==inv['id']
  results=reply['results']
if mode=='bad-final':results=results[:-1]
send({'version':2,'type':'result','id':inv['id'],'results':results})
if mode=='extra':send({'version':2,'type':'result','id':inv['id'],'results':results})
if mode=='descendant':time.sleep(60)
'''


def install(registry, monkeypatch, target_ids, capabilities=None):
    import ficc.modules.registry as module

    caps = ['test:read'] if capabilities is None else capabilities
    # Admit one test-only capability; this is not a production registry policy.
    monkeypatch.setattr(module, 'SUPPORTED', module.SUPPORTED | {'test:read'})
    manifest, files = package({'main.py': SOURCE}, capabilities=caps,
        runtime={'kind': 'python', 'language': 'python', 'platform': 'linux',
                 'architecture': 'any', 'entry': 'main.py', 'protocol': 2},
        actions=[{'id': 'read', 'capabilities': caps,
                  'parameters': {'mode': {'type': 'string'}}}])
    checked = inspect_archive(bundle(manifest, files))
    registry.install(checked, checked.digest)
    registry.set_enabled(checked.digest, True,
        [{'capability': cap, 'target_ids': target_ids} for cap in caps], sandbox_ready=True)
    return checked.digest


@pytest.fixture
def pipe_runtime(registry, monkeypatch):
    import ficc.modules.sandbox as sandbox

    runtime = Runtime(registry)

    async def probe():
        return SandboxStatus(True, 'Pipe supervision test only')

    async def enforcement(_unit):
        return None

    async def management(*_args):
        return 0, b''

    # Only unit tests substitute the platform boundary. Real tests below do not.
    monkeypatch.setattr(runtime.sandbox, 'probe', probe)
    monkeypatch.setattr(sandbox, 'command', lambda path, *_args: [sys.executable, '-I', str(path / 'main.py')])
    monkeypatch.setattr(sandbox, 'enforcement', enforcement)
    monkeypatch.setattr(sandbox, 'management', management)
    return runtime


async def read(call):
    call.check()
    return [{'target': target, **({'error': {'code': 'denied', 'message': 'Fixture refusal'}}
            if target.endswith('-63') else {'data': {'target': target, 'value': call.parameters['value']}})}
            for target in call.target_ids]


@pytest.mark.parametrize('count', [1, 64])
async def test_broker_batches_and_per_target_refusal(registry, monkeypatch, pipe_runtime, count):
    selected = [f'system-{i}' for i in range(count)]
    digest = install(registry, monkeypatch, selected)
    result = await pipe_runtime.invoke(digest, 'read', selected, {}, lambda: None, broker=read)
    assert result['version'] == 2
    assert [item['target'] for item in result['results']] == selected
    if count == 64:
        assert result['results'][-1]['error']['code'] == 'denied'
    assert result['results'][0]['data']['target'] == selected[0]
    assert not registry._leases and not pipe_runtime.active


@pytest.mark.parametrize('mode', ['spoof', 'outside', 'unknown', 'pipeline', 'duplicate', 'excess', 'bad-final', 'extra', 'stderr'])
async def test_hostile_conversation_is_refused(registry, monkeypatch, pipe_runtime, mode):
    digest = install(registry, monkeypatch, ['a'])
    with pytest.raises(Failure) as error:
        await pipe_runtime.invoke(digest, 'read', ['a'], {'mode': mode}, lambda: None, broker=read)
    assert error.value.code in {'invalid_module', 'module_output_limit'}
    assert not registry._leases and not pipe_runtime.active


@pytest.mark.parametrize('results', [[], [{'target': 'outside', 'data': 1}],
    [{'target': 'a', 'data': 1}, {'target': 'a', 'data': 2}],
    [{'target': 'a', 'data': 1, 'error': {'code': 'bad', 'message': 'bad'}}]])
async def test_callback_cannot_spoof_result_batch(registry, monkeypatch, pipe_runtime, results):
    digest = install(registry, monkeypatch, ['a'])

    async def callback(call):
        return results

    with pytest.raises(Failure) as error:
        await pipe_runtime.invoke(digest, 'read', ['a'], {}, lambda: None, broker=callback)
    assert error.value.code == 'invalid_module'


async def test_missing_callback_ungranted_target_and_host_capabilities_fail_before_launch(registry, monkeypatch, pipe_runtime):
    digest = install(registry, monkeypatch, ['a'])
    for selected, callback, code in [(['a'], None, 'module_capability_unavailable'), (['b'], read, 'denied')]:
        with pytest.raises(Failure) as error:
            await pipe_runtime.invoke(digest, 'read', selected, {}, lambda: None, broker=callback)
        assert error.value.code == code
    registry.revoke(digest)
    digest = install(registry, monkeypatch, ['a'], capabilities=['workspace:read'])
    with pytest.raises(Failure) as error:
        await pipe_runtime.invoke(digest, 'read', ['a'], {}, lambda: None, broker=read)
    assert error.value.code == 'module_capability_unavailable'


async def test_zero_capability_v2_can_complete_but_cannot_call_broker(registry, monkeypatch, pipe_runtime):
    digest = install(registry, monkeypatch, ['a'], capabilities=[])
    result = await pipe_runtime.invoke(digest, 'read', ['a'], {'mode': 'zero'}, lambda: None)
    assert result['results'] == [{'target': 'a', 'data': 'a'}]
    with pytest.raises(Failure) as error:
        await pipe_runtime.invoke(digest, 'read', ['a'], {}, lambda: None, broker=read)
    assert error.value.code == 'module_capability_unavailable'


@pytest.mark.parametrize('cancel', [False, True])
async def test_revoke_or_cancel_during_callback_cleans_before_release(registry, monkeypatch, pipe_runtime, cancel):
    digest = install(registry, monkeypatch, ['a'])
    entered, cleaned = asyncio.Event(), asyncio.Event()

    async def pending(call):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.set()

    task = asyncio.create_task(pipe_runtime.invoke(digest, 'read', ['a'], {}, lambda: None, broker=pending))
    await asyncio.wait_for(entered.wait(), 2)
    if cancel:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        registry.revoke(digest)
        with pytest.raises(Failure) as error:
            await task
        assert error.value.code == 'module_revoked'
    assert cleaned.is_set() and not registry._leases and not pipe_runtime.active


REAL = pytest.mark.skipif(os.environ.get('FICC_REAL_MODULE_SANDBOX') != '1', reason='Explicit platform qualification only')


@REAL
@pytest.mark.parametrize('count', [1, 64])
async def test_real_isolated_broker_exchange(registry, monkeypatch, count):
    selected = [f'system-{i}' for i in range(count)]
    digest = install(registry, monkeypatch, selected)
    runtime = Runtime(registry)
    status = await runtime.sandbox.probe()
    assert status.available, status.reason
    result = await runtime.invoke(digest, 'read', selected, {}, lambda: None, broker=read)
    assert [item['target'] for item in result['results']] == selected
    assert result['results'][0]['data']['value'] == 'fixture'
    if count == 64:
        assert result['results'][-1]['error']['code'] == 'denied'
    assert not registry._leases and not runtime.active


@REAL
@pytest.mark.parametrize('mode', ['spoof', 'outside', 'unknown', 'pipeline', 'duplicate', 'excess', 'bad-hello', 'bad-final', 'extra', 'stderr'])
async def test_real_isolated_hostile_frames(registry, monkeypatch, mode):
    digest = install(registry, monkeypatch, ['a'])
    runtime = Runtime(registry)
    with pytest.raises(Failure) as error:
        await runtime.invoke(digest, 'read', ['a'], {'mode': mode}, lambda: None, broker=read)
    assert error.value.code in {'invalid_module', 'module_output_limit'}
    assert not registry._leases and not runtime.active


@REAL
@pytest.mark.parametrize('case', ['revoke', 'cancel', 'descendant', 'timeout'])
async def test_real_isolated_cleanup(registry, monkeypatch, case):
    import ficc.modules.sandbox as sandbox

    digest = install(registry, monkeypatch, ['a'])
    runtime = Runtime(registry)
    entered = asyncio.Event()
    groups = []
    original = sandbox.enforcement

    async def capture(unit):
        group = await original(unit)
        groups.append(group)
        return group

    async def pending(call):
        entered.set()
        if case == 'descendant':
            return await read(call)
        await asyncio.Event().wait()

    monkeypatch.setattr(sandbox, 'enforcement', capture)
    task = asyncio.create_task(runtime.invoke(digest, 'read', ['a'],
        {'mode': 'descendant' if case == 'descendant' else 'read'}, lambda: None, broker=pending))
    await asyncio.wait_for(entered.wait(), 8)
    if case == 'timeout':
        with pytest.raises(Failure) as error:
            await task
        assert error.value.code == 'module_timeout'
    elif case == 'revoke':
        registry.revoke(digest)
        with pytest.raises(Failure) as error:
            await task
        assert error.value.code == 'module_revoked'
    else:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert groups and not registry._leases and not runtime.active
    assert all(not group.exists() or 'populated 0' in (group / 'cgroup.events').read_text() for group in groups)
