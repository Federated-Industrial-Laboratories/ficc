#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Publish a complete verified release with gh; inputs: artifacts and notes; exit: 0 on success.
"""Upload verified versioned assets to a draft, then optionally publish it."""

import argparse
import json
import re
import subprocess
from pathlib import Path

from finalize_release import required_artifacts, verify_original
from release_lib.common import digest


def gh(*arguments: str, missing_ok: bool = False):
    result = subprocess.run(['gh', *arguments], capture_output=True, text=True, check=False)
    if result.returncode:
        if missing_ok and 'HTTP 404' in result.stderr:
            return None
        raise ValueError('GitHub request failed: ' + result.stderr.strip())
    return json.loads(result.stdout) if result.stdout.strip() else None


def validate(output: Path) -> tuple[dict, dict]:
    build = json.loads((output / 'build.json').read_text())
    version = build['version']
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:rc\d+)?', version):
        raise ValueError('Unsupported release version')
    if (build.get('formats_complete') is not True or build['source'].get('dirty') is not False
            or not re.fullmatch('[0-9a-f]{40}', build['source']['commit'])):
        raise ValueError('Release requires complete formats and a clean source commit')
    arch = f'ficc-bin-{version}-1-x86_64.pkg.tar.zst'
    if set(build['artifacts']) != required_artifacts(version) | {arch}:
        raise ValueError('Release requires every package and source format')
    verify_original(output, build, arch)
    names = set(build['artifacts']) | {'build.json', 'SHA256SUMS'}
    for name in names:
        if (output / name).is_symlink():
            raise ValueError('Release assets must not be links')
    assets = {name: {'size': (output / name).stat().st_size, 'digest': 'sha256:' + digest(output / name)}
              for name in sorted(names)}
    return build, assets


def verify_assets(remote: list, expected: dict, *, complete: bool) -> None:
    names = [a['name'] for a in remote]
    if len(names) != len(set(names)) or set(names) - expected.keys():
        raise ValueError('GitHub release contains unexpected or duplicate assets')
    if complete and set(names) != expected.keys():
        raise ValueError('GitHub release is missing assets')
    for item in remote:
        want = expected[item['name']]
        if item.get('state') != 'uploaded' or any(item.get(key) != value for key, value in want.items()):
            raise ValueError('GitHub asset differs from the verified local file: ' + item['name'])


def find_release(endpoint: str, tag: str):
    pages = gh('api', endpoint + '/releases', '--paginate', '--slurp')
    matches = [release for page in pages for release in page if release['tag_name'] == tag]
    if len(matches) > 1:
        raise ValueError('Multiple releases use this version; resolve the drafts before retrying')
    return matches[0] if matches else None


def publish(output: Path, repo: str, notes: Path, publish_now: bool) -> str:
    build, assets = validate(output)
    version, commit = build['version'], build['source']['commit']
    tag = 'v' + version
    endpoint = 'repos/' + repo
    default = gh('api', endpoint)['default_branch']
    if gh('api', endpoint + '/commits/' + default)['sha'] != commit:
        raise ValueError('Build must use the current default-branch commit')
    existing_tag = gh('api', endpoint + '/git/ref/tags/' + tag, missing_ok=True)
    if existing_tag and gh('api', endpoint + '/commits/' + tag)['sha'] != commit:
        raise ValueError('Existing version tag points to another source commit')
    release = find_release(endpoint, tag)
    if release and not release['draft']:
        raise ValueError('Published releases are immutable; use a new version')
    if not release:
        subprocess.run(['gh', 'release', 'create', tag, '--repo', repo, '--draft', '--target', commit,
                        '--title', 'FICC ' + version, '--notes-file', str(notes)], check=True)
        release = find_release(endpoint, tag)
        if release is None:
            raise ValueError('Created draft is not visible; check repository release permissions')
    release_endpoint = endpoint + '/releases/' + str(release['id'])
    release = gh('api', release_endpoint)
    if release['target_commitish'] != commit:
        raise ValueError('Draft release source differs from the build commit')
    verify_assets(release['assets'], assets, complete=False)
    present = {item['name'] for item in release['assets']}
    for name in assets.keys() - present:
        subprocess.run(['gh', 'release', 'upload', tag, str(output / name), '--repo', repo], check=True)
    release = gh('api', release_endpoint)
    verify_assets(release['assets'], assets, complete=True)
    if publish_now:
        # Recheck the source after uploads; a draft stays private if master moved.
        if gh('api', endpoint + '/commits/' + default)['sha'] != commit:
            raise ValueError('Default branch changed during upload; retain the draft for review')
        existing_tag = gh('api', endpoint + '/git/ref/tags/' + tag, missing_ok=True)
        if existing_tag and gh('api', endpoint + '/commits/' + tag)['sha'] != commit:
            raise ValueError('Version tag changed during upload; retain the draft for review')
        subprocess.run(['gh', 'release', 'edit', tag, '--repo', repo, '--draft=false',
                        '--prerelease=' + str('rc' in version).lower(),
                        '--latest=' + str('rc' not in version).lower(), '--notes-file', str(notes)], check=True)
        release = gh('api', release_endpoint)
        verify_assets(release['assets'], assets, complete=True)
        if release['draft'] or gh('api', endpoint + '/commits/' + tag)['sha'] != commit:
            raise ValueError('Published release source verification failed')
    return release['html_url']


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repo', default='Federated-Industrial-Laboratories/ficc')
    parser.add_argument('--notes', type=Path, required=True)
    parser.add_argument('--publish', action='store_true', help='Publish after verifying every uploaded asset')
    args = parser.parse_args()
    print(publish(args.output, args.repo, args.notes, args.publish))


if __name__ == '__main__':
    main()
