# SPDX-License-Identifier: Apache-2.0
"""Check broker SDK fixtures and real installed packages for every language."""

import importlib.util
import os
import sqlite3
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from ficc.modules import Registry, initialize, inspect_archive
from ficc.modules.runtime import Runtime

ROOT = Path(__file__).resolve().parents[2]
LANGUAGES = ('c', 'cpp', 'rust', 'python', 'javascript', 'typescript')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = load('broker_sdk_build', ROOT / 'sdk/build.py')
pack = load('broker_sdk_pack', ROOT / 'tools/build-modules.py')
conformance = load('broker_sdk_conformance', ROOT / 'sdk/conformance.py')


def test_python_broker_build_and_legacy_build_are_separate(tmp_path):
    legacy, legacy_files = build.example('python', tmp_path / 'cache', False, 'node')
    manifest, files = build.example('python', tmp_path / 'cache', False, 'node', broker=True)
    assert legacy['id'] == 'org.example.echo.python' and 'protocol' not in legacy['runtime']
    assert manifest['id'] == 'org.example.resources.python' and manifest['runtime']['protocol'] == 2
    assert manifest['capabilities'] == ['system:read']
    assert manifest['actions'][0]['capabilities'] == ['system:read']
    assert files['main.py'] != legacy_files['main.py']
    path = pack.publish(manifest, files, tmp_path / 'packages')
    assert conformance.check_package(path, sys.executable, 'node', broker=True) == 32
    legacy_path = pack.publish(legacy, legacy_files, tmp_path / 'packages')
    assert conformance.check_package(legacy_path, sys.executable, 'node') == 20


def test_python_broker_freezes_context_and_retains_caught_failure(tmp_path):
    fixture = tmp_path / 'mutating_handler.py'
    helper = str(ROOT / 'sdk/python/ficc_module.py')
    fixture.write_text('import runpy\n'
        + f'serve = runpy.run_path({helper!r})["serve_broker"]\n'
        + 'def handler(request, broker):\n'
        + '    selected = list(request["targets"])\n'
        + '    request["id"] = "f" * 32\n'
        + '    request["targets"].clear()\n'
        + '    try:\n'
        + '        return broker("system.resources.read", selected, {})\n'
        + '    except Exception:\n'
        + '        return [{"target": item, "data": "caught"} for item in selected]\n'
        + 'raise SystemExit(serve(handler))\n')
    cases = load('broker_cases', ROOT / 'sdk/broker_conformance.py')
    assert cases.cases([sys.executable, '-I', str(fixture)]) == 32


@pytest.mark.parametrize('language', LANGUAGES)
def test_all_broker_archive_conformance(language):
    directory = os.environ.get('FICC_SDK_BROKER_PACKAGES')
    if not directory:
        pytest.skip('Supply the built six-language broker archive directory')
    path = Path(directory) / f'org.example.resources.{language}-1.0.0.ficc-module.zip'
    assert conformance.check_package(path, sys.executable, os.environ.get('FICC_SDK_NODE', 'node'), broker=True) == 32


@pytest.mark.parametrize('language', LANGUAGES)
@pytest.mark.parametrize('count', [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_real_host_broker_archives(tmp_path, language, count):
    directory = os.environ.get('FICC_SDK_BROKER_PACKAGES')
    if not directory or os.environ.get('FICC_REAL_MODULE_SANDBOX') != '1':
        pytest.skip('Explicit built-package and real-sandbox qualification only')
    path = Path(directory) / f'org.example.resources.{language}-1.0.0.ficc-module.zip'
    inspection = inspect_archive(path.read_bytes())
    db = sqlite3.connect(':memory:', check_same_thread=False)
    initialize(db)
    registry = Registry(SimpleNamespace(db=db, lock=threading.RLock()), tmp_path / 'modules')
    registry.install(inspection, inspection.digest)
    runtime = Runtime(registry)
    selected = [f'system-{index}' for index in range(count)]
    expected = [{'target': target, **({'error': {'code': 'denied', 'message': 'Fixture refusal'}}
        if index == 63 else {'data': {'id': target, 'memory_bytes': (index + 1) * 4096}})}
        for index, target in enumerate(selected)]
    callbacks = []

    async def broker(call):
        call.check()
        assert call.primitive == 'system.resources.read' and call.parameters == {}
        assert call.target_ids == tuple(selected) and call.action_capabilities == ('system:read',)
        callbacks.append(call.request_id)
        return list(reversed(expected))

    try:
        status = await runtime.sandbox.probe()
        assert status.available, status.reason
        registry.set_enabled(inspection.digest, True,
            [{'capability': 'system:read', 'target_ids': selected}], sandbox_ready=status.available)
        result = await runtime.invoke(inspection.digest, 'read', selected, {}, lambda: None, broker=broker)
        assert result['version'] == 2 and result['results'] == expected
        assert len(callbacks) == 1
        assert not runtime.active and not registry._leases
    finally:
        await runtime.stop()
        registry.uninstall(inspection.digest)
        db.close()
