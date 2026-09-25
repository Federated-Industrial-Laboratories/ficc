# SPDX-License-Identifier: Apache-2.0
"""Require complete local and remote assets before publishing a version."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from finalize_release import required_artifacts  # noqa: E402
from publish_release import validate, verify_assets  # noqa: E402
from release_lib.common import digest  # noqa: E402


def local_release(root):
    names = required_artifacts('1.0.0') | {'ficc-bin-1.0.0-1-x86_64.pkg.tar.zst'}
    for name in names:
        (root / name).write_text('distinct synthetic ' + name)
    build = {'version': '1.0.0', 'source': {'commit': 'a' * 40, 'dirty': False}, 'formats_complete': True,
             'artifacts': {n: digest(root / n) for n in names}}
    (root / 'build.json').write_text(json.dumps(build))
    sums(root)
    return build


def sums(root):
    (root / 'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.name}\n' for p in sorted(root.iterdir())
                                          if p.name != 'SHA256SUMS'))


def test_complete_local_release_has_twelve_bound_assets(tmp_path):
    local_release(tmp_path)
    _, assets = validate(tmp_path)
    assert len(assets) == 12


@pytest.mark.parametrize('failure', ['dirty', 'incomplete', 'missing', 'changed', 'commit'])
def test_release_cannot_publish_incomplete_or_unbound_bytes(tmp_path, failure):
    build = local_release(tmp_path)
    if failure == 'dirty':
        build['source']['dirty'] = True
    elif failure == 'incomplete':
        build['formats_complete'] = False
    elif failure == 'commit':
        build['source']['commit'] = 'master'
    elif failure == 'missing':
        (tmp_path / next(iter(build['artifacts']))).unlink()
    else:
        (tmp_path / next(iter(build['artifacts']))).write_text('changed')
    (tmp_path / 'build.json').write_text(json.dumps(build))
    sums(tmp_path)
    with pytest.raises(ValueError):
        validate(tmp_path)


@pytest.mark.parametrize('count', [1, 64])
@pytest.mark.parametrize('failure', ['missing', 'size', 'digest', 'state', 'duplicate', 'extra'])
def test_remote_assets_are_checked_individually(count, failure):
    expected = {f'file-{i}': {'size': i + 1, 'digest': f'sha256:{i:064x}'} for i in range(count)}
    remote = [{'name': name, 'state': 'uploaded', **value} for name, value in expected.items()]
    verify_assets(remote, expected, complete=True)
    if failure == 'missing':
        remote.pop()
    elif failure == 'duplicate':
        remote.append(remote[-1])
    elif failure == 'extra':
        remote.append({'name': 'unexpected'})
    else:
        remote[-1][failure] = 'changed'
    with pytest.raises(ValueError):
        verify_assets(remote, expected, complete=True)


@pytest.mark.parametrize('failure', ['none', 'wrong-tag', 'wrong-master', 'uploaded-digest'])
def test_publication_occurs_only_after_source_and_remote_assets_match(tmp_path, monkeypatch, failure):
    import publish_release as module

    local_release(tmp_path)
    _, assets = validate(tmp_path)
    remote = [{'name': n, 'state': 'uploaded', **v} for n, v in assets.items()]
    if failure == 'uploaded-digest':
        remote[-1]['digest'] = 'sha256:' + 'f' * 64
    release = {'id': 42, 'tag_name': 'v1.0.0', 'draft': True, 'target_commitish': 'a' * 40, 'assets': remote, 'html_url': 'https://example.com/release'}
    calls = []

    def fake_gh(*args, **kwargs):
        endpoint = args[1]
        if endpoint == 'repos/example/ficc':
            return {'default_branch': 'master'}
        if '/git/ref/tags/' in endpoint:
            return {} if failure == 'wrong-tag' or not release['draft'] else None
        if '/commits/' in endpoint:
            changed = (failure == 'wrong-master' and endpoint.endswith('/master')) or failure == 'wrong-tag'
            return {'sha': ('b' if changed else 'a') * 40}
        if endpoint == 'repos/example/ficc/releases':
            return [[release]]
        assert endpoint == 'repos/example/ficc/releases/42'
        return release

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[:3] == ['gh', 'release', 'edit']:
            release['draft'] = False

    # A nonempty ref object models an existing version tag.
    original_gh = fake_gh

    def ref_gh(*args, **kwargs):
        result = original_gh(*args, **kwargs)
        return {'ref': 'refs/tags/v1.0.0'} if result == {} else result

    monkeypatch.setattr(module, 'gh', ref_gh)
    monkeypatch.setattr(module.subprocess, 'run', fake_run)
    if failure == 'none':
        assert module.publish(tmp_path, 'example/ficc', tmp_path / 'notes.md', True) == release['html_url']
        assert len(calls) == 1 and '--draft=false' in calls[0]
    else:
        with pytest.raises(ValueError):
            module.publish(tmp_path, 'example/ficc', tmp_path / 'notes.md', True)
        assert not calls and release['draft']


@pytest.mark.parametrize('resume', [False, True])
def test_pending_draft_uses_its_id_and_uploads_before_publication(tmp_path, monkeypatch, resume):
    import subprocess

    import publish_release as module

    local_release(tmp_path)
    _, expected = validate(tmp_path)
    assets = [{'name': n, 'state': 'uploaded', **v} for n, v in list(expected.items())[:3]] if resume else []
    release = {'id': 42, 'tag_name': 'v1.0.0', 'draft': True, 'target_commitish': 'a' * 40,
               'assets': assets, 'html_url': 'https://example.com/release'}
    created, mutations = resume, []

    def fake_run(command, **kwargs):
        nonlocal created
        if command[:2] == ['gh', 'api']:
            endpoint = command[2]
            if '/releases/tags/' in endpoint or ('/git/ref/tags/' in endpoint and release['draft']):
                return subprocess.CompletedProcess(command, 1, '', 'gh: Not Found (HTTP 404)')
            if endpoint == 'repos/example/ficc':
                value = {'default_branch': 'master'}
            elif '/commits/' in endpoint:
                value = {'sha': 'a' * 40}
            elif '/git/ref/tags/' in endpoint:
                value = {'ref': 'refs/tags/v1.0.0'}
            elif endpoint == 'repos/example/ficc/releases':
                assert command[3:] == ['--paginate', '--slurp']
                value = [[], [release]] if created else [[]]
            else:
                assert endpoint == 'repos/example/ficc/releases/42' and created
                value = release
            return subprocess.CompletedProcess(command, 0, json.dumps(value), '')
        assert command[:2] == ['gh', 'release']
        action = command[2]
        mutations.append(action)
        if action == 'create':
            assert not created and '--draft' in command
            created = True
        elif action == 'upload':
            name = Path(command[4]).name
            assert created and release['draft'] and name not in {a['name'] for a in assets}
            assets.append({'name': name, 'state': 'uploaded', **expected[name]})
        else:
            assert action == 'edit' and '--draft=false' in command
            module.verify_assets(assets, expected, complete=True)
            release['draft'] = False
        return subprocess.CompletedProcess(command, 0, '', '')

    monkeypatch.setattr(module.subprocess, 'run', fake_run)
    assert module.publish(tmp_path, 'example/ficc', tmp_path / 'notes.md', True) == release['html_url']
    assert mutations.count('create') == (0 if resume else 1)
    assert mutations.count('upload') == (9 if resume else 12)
    assert mutations[-1] == 'edit' and mutations.count('edit') == 1
    assert not release['draft']
