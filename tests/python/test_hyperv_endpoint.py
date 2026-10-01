# SPDX-License-Identifier: Apache-2.0
"""Run the real PowerShell endpoint join against distinct, shuffled CIM records."""

import json
import os
import random
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENDPOINT = ROOT / 'modules/hyperv-adapter/payload/endpoint/FICCHyperV.psm1'
FIXTURE = ROOT / 'tests/fixtures/hyperv_endpoint.ps1'


@pytest.fixture(scope='module')
def powershell():
    executable = os.environ.get('FICC_PWSH') or shutil.which('pwsh')
    if not executable:
        pytest.skip('Set FICC_PWSH or install pwsh to execute the actual endpoint language.')
    path = Path(executable).resolve()
    assert path.is_file() and os.access(path, os.X_OK), 'The selected PowerShell runtime is unavailable.'
    return str(path)


def fixture(count, mode):
    cim = {name: [] for name in ('Msvm_ComputerSystem', 'Msvm_VirtualSystemSettingData',
                                'Msvm_MemorySettingData', 'Msvm_ProcessorSettingData')}
    expected = {}
    for index in range(count + 2):
        key = str(uuid.UUID(int=256 + index))
        configuration = 'Microsoft:' + str(uuid.UUID(int=65536 + index))
        memory_mib, vcpus = 256 + index * 64, index + 1
        cim['Msvm_ComputerSystem'].append({'Name': key.upper(), 'ElementName': f'VM {index}', 'EnabledState': 3})
        cim['Msvm_VirtualSystemSettingData'].append({'VirtualSystemIdentifier': key.upper(),
            'InstanceID': configuration, 'VirtualSystemType': 'Microsoft:Hyper-V:System:Realized'})
        cim['Msvm_MemorySettingData'].append({'InstanceID': configuration.swapcase() + '\\memory',
            'VirtualQuantity': memory_mib, 'VirtualQuantityUnits': 'byte * 2^20'})
        cim['Msvm_ProcessorSettingData'].append({'InstanceID': configuration.upper() + '\\processor',
            'VirtualQuantity': vcpus, 'VirtualQuantityUnits': 'count'})
        if 1 <= index <= count:
            expected[key] = {'configuration': configuration, 'memory_bytes': memory_mib * 1048576, 'vcpus': vcpus}
    memory_decoy = cim['Msvm_MemorySettingData'][0]
    processor_decoy = cim['Msvm_ProcessorSettingData'][-1]
    for seed, values in enumerate(cim.values()):
        random.Random(100 + seed).shuffle(values)
    # Nonselected metadata is still returned by the provider's class-wide reads.
    # Different first records make both wrong-index controls fail even at N=1.
    for name, decoy in (('Msvm_MemorySettingData', memory_decoy), ('Msvm_ProcessorSettingData', processor_decoy)):
        cim[name].remove(decoy)
        cim[name].insert(0, decoy)
    selected = list(expected)
    random.Random(900).shuffle(selected)
    request = ({'ids': [], 'offset': 1, 'limit': count} if mode == 'inventory'
               else {'ids': selected, 'offset': 0, 'limit': 64})
    return {'cim': cim, 'request': request}, expected


def execute(powershell, tmp_path, endpoint, data):
    inputs = tmp_path / 'cim.json'
    inputs.write_text(json.dumps(data), encoding='utf-8')
    environment = {**os.environ, 'POWERSHELL_TELEMETRY_OPTOUT': '1', 'POWERSHELL_UPDATECHECK': 'Off',
                   'XDG_CACHE_HOME': str(tmp_path / 'cache'), 'XDG_CONFIG_HOME': str(tmp_path / 'config'),
                   'XDG_DATA_HOME': str(tmp_path / 'data'),
                   'DOTNET_CLI_HOME': str(tmp_path / 'dotnet')}
    result = subprocess.run([powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(FIXTURE),
                             '-Endpoint', str(endpoint), '-InputFile', str(inputs)], env=environment,
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def assert_mapping(result, expected):
    rows = result['snapshot']['rows']
    assert len(rows) == len(expected) and {row['key'] for row in rows} == set(expected)
    actual = {row['key']: {field: row[field] for field in ('configuration', 'memory_bytes', 'vcpus')}
              for row in rows}
    assert actual == expected, 'VM metadata association differs'


@pytest.mark.parametrize('count', [1, 64])
@pytest.mark.parametrize('mode', ['inventory', 'selected'])
def test_actual_endpoint_joins_distinct_shuffled_metadata(powershell, tmp_path, count, mode):
    data, expected = fixture(count, mode)
    result = execute(powershell, tmp_path, ENDPOINT, data)
    assert_mapping(result, expected)
    assert len({row['memory_bytes'] for row in result['snapshot']['rows']}) == count
    assert len({row['vcpus'] for row in result['snapshot']['rows']}) == count
    assert result['snapshot']['next_offset'] == (count + 1 if mode == 'inventory' else None)
    calls = [item['class_name'] for item in result['cim_calls']]
    expected_calls = list(data['cim'])
    if mode == 'inventory':
        expected_calls.insert(0, 'Msvm_VirtualSystemSettingData')
    assert calls == expected_calls


@pytest.mark.parametrize('count', [1, 64])
@pytest.mark.parametrize('column', ['memory', 'processor'])
def test_mapping_assertion_detects_actual_endpoint_wrong_index(powershell, tmp_path, count, column):
    data, expected = fixture(count, 'inventory')
    source = ENDPOINT.read_text(encoding='utf-8')
    correct, wrong = ({'memory': ('$ram = $memoryIndex[$prefix]', '$ram = $memory[0]'),
                       'processor': ('$cpu = $processorIndex[$prefix]', '$cpu = $processors[0]')}[column])
    assert source.count(correct) == 1
    changed = tmp_path / 'wrong-index.psm1'
    changed.write_text(source.replace(correct, wrong), encoding='utf-8')
    result = execute(powershell, tmp_path, changed, data)
    assert len(result['snapshot']['rows']) == count
    with pytest.raises(AssertionError, match='VM metadata association differs'):
        assert_mapping(result, expected)
    unchanged = 'vcpus' if column == 'memory' else 'memory_bytes'
    assert all(row[unchanged] == expected[row['key']][unchanged] for row in result['snapshot']['rows'])
