# SPDX-License-Identifier: Apache-2.0
"""Check source install ownership, download integrity and retained launch settings."""

import hashlib
import io
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from install_source import MARKER, check_wrapper  # noqa: E402
from source_launcher import arguments  # noqa: E402
from source_runtime import download, secure_dir, unpack  # noqa: E402


@pytest.mark.parametrize('kind', ['link', 'unmanaged', 'directory'])
def test_install_does_not_replace_existing_command(tmp_path, kind):
    path = tmp_path / 'ficc'
    if kind == 'link':
        path.symlink_to('/missing')
    elif kind == 'directory':
        path.mkdir()
    else:
        path.write_text('unrelated command')
    with pytest.raises(ValueError, match='existing command'):
        check_wrapper(path)


def test_owned_managed_command_can_be_updated(tmp_path):
    path = tmp_path / 'ficc'
    check_wrapper(path)
    path.write_text(MARKER + 'exec example "$@"\n')
    check_wrapper(path)


@pytest.mark.parametrize('kind', ['symlink', 'writable'])
def test_install_directory_rejects_unsafe_ancestor(tmp_path, kind):
    ancestor = tmp_path / 'ancestor'
    if kind == 'symlink':
        ancestor.symlink_to(tmp_path, target_is_directory=True)
    else:
        ancestor.mkdir(mode=0o777)
        ancestor.chmod(0o777)
    with pytest.raises(ValueError, match='Unsafe'):
        secure_dir(ancestor / 'install')
    assert not (tmp_path / 'install').exists()


@pytest.mark.parametrize('count', [1, 64])
def test_each_cached_download_requires_matching_bytes(tmp_path, count):
    for i in range(count):
        data = f'distinct archive {i}'.encode()
        item = {'name': f'input-{i}', 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        path = tmp_path / item['name']
        path.write_bytes(data)
        assert download(item, tmp_path) == path
        path.write_bytes(data[:-1] + b'x')
        with pytest.raises(ValueError, match='pinned'):
            download(item, tmp_path)


@pytest.mark.parametrize('kind', ['parent', 'symlink', 'device'])
def test_bootstrap_archive_cannot_escape(tmp_path, kind):
    path = tmp_path / 'bad.tar'
    with tarfile.open(path, 'w') as archive:
        member = tarfile.TarInfo('../outside' if kind == 'parent' else 'member')
        if kind == 'symlink':
            member.type, member.linkname = tarfile.SYMTYPE, '../../outside'
        elif kind == 'device':
            member.type = tarfile.CHRTYPE
        archive.addfile(member, io.BytesIO())
    with pytest.raises(tarfile.FilterError):
        unpack(path, tmp_path / 'extracted')
    assert not (tmp_path / 'outside').exists()


@pytest.mark.parametrize('count', [1, 64])
def test_reinstall_preserves_every_saved_profile_and_setting(tmp_path, monkeypatch, count):
    from ficc.launcher_config import LaunchConfig, save

    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path))
    profiles = tuple(f'rack-{i}' for i in range(count))
    value = LaunchConfig('/opt/ficc/ficc', str(tmp_path / 'state'), str(tmp_path / 'ficc-custom.service'),
                         str(tmp_path / 'ficc-custom.desktop'), 8185, profiles, str(tmp_path / 'ssh'), True)
    save(tmp_path / 'ficc/launcher.json', value)
    args = arguments([])
    assert (args.profile, args.demo, args.port, args.name) == (list(profiles), True, 8185, 'ficc-custom')
    assert (str(args.state_dir), str(args.ssh_config)) == (value.state_dir, value.ssh_config)
    assert args.autostart is False
    with pytest.raises(ValueError, match='Existing SSH profiles differ'):
        arguments(['changed-profile'])


def test_first_install_is_live_on_demand_with_only_explicit_profiles(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path))
    args = arguments(['rack-01'])
    assert args.profile == ['rack-01'] and not args.demo and not args.autostart


def test_no_argument_cli_opens_desktop_without_resetting_settings(monkeypatch):
    from ficc import cli

    calls = []
    monkeypatch.setattr(cli.launcher, 'desktop', lambda path, options: calls.append((path, options)))
    assert cli.main([]) == 0
    assert len(calls) == 1 and calls[0][1] == {}
