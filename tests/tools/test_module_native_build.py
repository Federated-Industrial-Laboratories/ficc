# SPDX-License-Identifier: Apache-2.0
"""Check pinned build inputs and native observation without provider access."""

import hashlib
import io
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
from test_module_sdk import ROOT, load

native = load('native_build_checks', ROOT / 'tools/module_native_build.py')


def record(data):
    return {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
            'url': 'https://example.invalid/pinned.zip'}


def test_hash_named_cache_accepts_exact_pin_and_refuses_tampering(tmp_path):
    data = b'pinned dependency bytes'
    selected = record(data)
    path = tmp_path / (selected['sha256'] + '.zip')
    path.write_bytes(data)
    assert native.dependency(selected, tmp_path, False) == data
    path.write_bytes(b'x' * len(data))
    with pytest.raises(ValueError, match='cache changed'):
        native.dependency(selected, tmp_path, False)


@pytest.mark.parametrize('kind', ['missing', 'symlink', 'hardlink', 'directory'])
def test_cache_refuses_missing_or_aliased_input(tmp_path, kind):
    data = b'owned content'
    selected = record(data)
    path = tmp_path / (selected['sha256'] + '.zip')
    if kind == 'symlink':
        other = tmp_path / 'other'
        other.write_bytes(data)
        path.symlink_to(other)
    elif kind == 'hardlink':
        other = tmp_path / 'other'
        other.write_bytes(data)
        os.link(other, path)
    elif kind == 'directory':
        path.mkdir()
    with pytest.raises((ValueError, OSError)):
        native.dependency(selected, tmp_path, False)


@pytest.mark.parametrize('name', ['../outside', 'a.zip', 'A' * 64 + '.zip', '0' * 64 + '.zip/child'])
def test_cache_namespace_is_only_lowercase_sha256_zip(tmp_path, name):
    with pytest.raises(ValueError, match='cache name'):
        native.read(tmp_path, name, cache=True)


def test_selected_dependency_members_are_exact_regular_files(tmp_path):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as archive:
        archive.writestr('selected.h', b'public header')
        archive.writestr('unselected.h', b'excluded')
    native.extract(data.getvalue(), {'members': {'selected.h': 'headers/api.h'}}, tmp_path)
    assert (tmp_path / 'headers/api.h').read_bytes() == b'public header'
    assert not (tmp_path / 'unselected.h').exists()
    with pytest.raises(ValueError, match='missing or repeated'):
        native.extract(data.getvalue(), {'members': {'absent.h': 'absent.h'}}, tmp_path)


def test_virtualbox_build_declares_pinned_sdk_and_complete_notices():
    value = native.specification(ROOT / 'modules/virtualbox-adapter')
    dependency = value['dependencies'][0]
    assert dependency['sha256'] == 'd94e4dddd5b99c84b2e328e8a19faff906168ad1d51e9545376f638108c0edc8'
    assert set(dependency['licenses']) == {'COPYING.LIB', 'VBoxCAPIGlue.c', 'VBoxCAPIGlue.h', 'VBoxCAPI_v7_2.h'}
    assert value['language'] == 'c'


def receipt_source(source, variant):
    """Change only a temporary copy of the public observation function."""
    marker = 'cJSON *observe(const cJSON *request, const cJSON *binding) {'
    assert source.count(marker) == 1
    head, body = source.split(marker)
    body, tail = body.split('\ncJSON *display(', 1)
    if variant == 'null':
        body = '\n    return NULL;' + body
    elif variant == 'batch-null':
        body = '\n    if (cJSON_GetArraySize(JGET(binding, "resources")) == 64) return NULL;' + body
    elif variant == 'wrong-association':
        ending = '\n    return output;\n}'
        assert body.count(ending) == 1
        # Keep IDs and every receipt intact, but associate two receipts with the wrong IDs.
        body = body.replace(ending, '''
    if (cJSON_GetArraySize(items) > 1) {
        cJSON *first = cJSON_GetArrayItem(items, 0), *second = cJSON_GetArrayItem(items, 1);
        cJSON *a = cJSON_DetachItemFromObjectCaseSensitive(first, "receipt");
        cJSON *b = cJSON_DetachItemFromObjectCaseSensitive(second, "receipt");
        cJSON_AddItemToObject(first, "receipt", b); cJSON_AddItemToObject(second, "receipt", a);
    }''' + ending)
    else:
        assert variant == 'original'
    return head + marker + body + '\ncJSON *display(' + tail


@pytest.mark.parametrize('variant', ['original', 'null', 'batch-null', 'wrong-association'])
def test_native_virtualbox_batch_observation_and_negative_controls(tmp_path, variant):
    archive = ROOT / 'sdk/build/d94e4dddd5b99c84b2e328e8a19faff906168ad1d51e9545376f638108c0edc8.zip'
    cjson = ROOT / 'sdk/build/dependencies/cJSON.c'
    if not archive.is_file() or not cjson.is_file() or not shutil.which('cc') or not shutil.which('nm'):
        pytest.skip('Pinned SDK cache, compiler and nm are required for the native receipt check.')
    dependency = native.specification(ROOT / 'modules/virtualbox-adapter')['dependencies'][0]
    native.extract(native.dependency(dependency, archive.parent, False), dependency, tmp_path)
    fixture = Path(__file__).with_name('virtualbox_receipt.c').read_bytes()
    lifecycle = (ROOT / 'modules/virtualbox-adapter/native/lifecycle.c').read_text()
    changed = receipt_source(lifecycle, variant)
    (tmp_path / 'virtualbox_receipt.c').write_bytes(fixture)
    (tmp_path / 'lifecycle.c').write_text(changed)
    output = tmp_path / 'receipt'
    command = ['cc', '-std=c11', '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
        '-I'+str(tmp_path), '-I'+str(cjson.parent), '-I'+str(ROOT / 'sdk/native'),
        '-I'+str(ROOT / 'modules/virtualbox-adapter/native'),
        str(tmp_path / 'virtualbox_receipt.c'), str(cjson), '-lm', '-o', str(output)]
    compiled = subprocess.run(command, check=True, timeout=30, capture_output=True, text=True)
    symbols = subprocess.run(['nm', str(output)], check=True, timeout=10, capture_output=True, text=True)
    has_observe = any(line.endswith(' observe') for line in symbols.stdout.splitlines())
    has_observed = any(line.endswith(' observed') for line in symbols.stdout.splitlines())
    assert has_observe
    if variant == 'original':
        assert has_observed
    results = []
    for count in (1, 64):
        result = subprocess.run([str(output), str(count)], timeout=10, capture_output=True, text=True)
        should_fail = variant == 'null' or (count == 64 and variant in {'batch-null', 'wrong-association'})
        results.append({'count': count, 'exit': result.returncode, 'expected_failure': should_fail,
                        'stdout': result.stdout, 'stderr': result.stderr})
        receipt = {'variant': variant, 'compile_exit': compiled.returncode, 'command': command,
                   'compile_stderr': compiled.stderr, 'has_observe': has_observe, 'has_observed': has_observed,
                   'fixture_sha256': hashlib.sha256(fixture).hexdigest(),
                   'production_sha256': hashlib.sha256(lifecycle.encode()).hexdigest(),
                   'compiled_lifecycle_sha256': hashlib.sha256(changed.encode()).hexdigest(), 'results': results}
        (tmp_path / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        if should_fail:
            assert result.returncode == 1, result.stderr
            check = ('cJSON_Compare(JGET(receipt, "token"), saved_token, 1)' if variant == 'wrong-association'
                     else 'cJSON_IsObject(output)')
            assert 'check failed: ' + check in result.stderr
        else:
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout) == {'count': count, 'outcomes': 11,
                                                'observations': count * 22, 'refusals': 44}
