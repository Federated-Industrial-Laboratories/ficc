# SPDX-License-Identifier: Apache-2.0
"""Assemble a relocatable runtime, notices and a source-bound inventory."""

import base64
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path

import runtime_packages
from viewer_runtime import install as install_viewer

from .common import digest, normalize_sdist, normalize_tree, run, unpack, write_json
from .modules import components as module_components
from .notices import install as install_notices

CLI = '''#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Run the adjacent isolated interpreter; preserve the caller's arguments.
set -eu
command_dir=$(dirname -- "$(readlink -f -- "$0")")
unset PYTHONHOME PYTHONPATH
export PYTHONDONTWRITEBYTECODE=1
exec "$command_dir/python3" -I -B -m ficc.cli "$@"
'''
ENTRY = '''#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Start the bundled command without changing the working directory.
set -eu
bundle_dir=$(dirname -- "$(readlink -f -- "$0")")
exec "$bundle_dir/python/bin/ficc" "$@"
'''


def python_notices(archive: Path, target: Path) -> dict:
    target.mkdir(parents=True)
    process = subprocess.Popen(["zstd", "-dc", str(archive)], stdout=subprocess.PIPE)
    metadata = None
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as source:
            for item in source:
                if item.name == "python/PYTHON.json" or item.name.startswith("python/licenses/"):
                    if not item.isfile() or item.size > 8 * 1024 * 1024:
                        raise ValueError("Invalid Python licence member")
                    name = Path(item.name).name
                    stream = source.extractfile(item)
                    assert stream is not None
                    value = stream.read()
                    if name == "PYTHON.json":
                        metadata = json.loads(value)
                    (target / name).write_bytes(value)
        if process.wait() or not metadata:
            raise ValueError("Python build metadata is absent")
    finally:
        if process.stdout:
            process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()
    return metadata


def retain_commands(directory: Path, original: set[str]) -> None:
    """Remove dependency utilities, including legacy wheel scripts."""
    retained = original | {"ficc", "ficc-audit-collector"}
    for item in directory.iterdir():
        if item.name not in retained:
            item.unlink()


def repair_records(site: Path, payload: Path) -> None:
    for record in site.glob("*.dist-info/RECORD"):
        rows = []
        for row in csv.reader(record.read_text().splitlines()):
            path = (site / row[0]).resolve()
            if not path.is_relative_to(payload.resolve()):
                raise ValueError("Installed distribution record escapes the payload")
            if not path.exists():
                continue
            if path == record.resolve():
                rows.append([row[0], "", ""])
            else:
                value = path.read_bytes()
                checksum = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()
                rows.append([row[0], "sha256=" + checksum, str(len(value))])
        with record.open("w", newline="") as stream:
            csv.writer(stream, lineterminator="\n").writerows(rows)


def build(source: Path, work: Path, inputs: dict[str, Path], provenance: dict, lock: dict,
          *, viewer_runtime: Path | None = None, windows_runtime: Path | None = None,
          module_cache: Path | None = None) -> tuple[Path, str]:
    version = tomllib.loads((source / "pyproject.toml").read_text())["project"]["version"]
    if windows_runtime is not None:
        from .runtimes import verify_windows_sources
        verify_windows_sources(windows_runtime, provenance['files'])
    payload = work / f"ficc-{version}-linux-x86_64"
    unpack(inputs["python"], payload)
    original_commands = {item.name for item in (payload / "python/bin").iterdir()}
    python = payload / "python/bin/python3"
    metadata = python_notices(inputs["python-metadata"], payload / "licenses/python")
    if metadata["python_version"] != lock["python"] or metadata["target_triple"] != "x86_64-unknown-linux-gnu":
        raise ValueError("Python metadata does not match the requested target")
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(provenance["epoch"]), PYTHONDONTWRITEBYTECODE="1")
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    run(["npm", "ci", "--prefix", "web"], cwd=source, env=env)
    run(["npm", "run", "build", "--prefix", "web"], cwd=source, env=env)
    run([sys.executable, "tools/build-modules.py", "defaults", "--output", "src/ficc/module_packages",
         "--cache", str(module_cache or work / "module-build"), "--fetch"], cwd=source, env=env)
    run([sys.executable, "-m", "build", "--no-isolation"], cwd=source, env=env)
    normalize_sdist(source / f"dist/ficc-{version}.tar.gz", work, provenance["epoch"])
    wheels = work / "wheels"
    wheels.mkdir()
    requirements = [str(source / "requirements.lock"), *runtime_packages.locks(source)]
    requirement_options = [argument for path in requirements for argument in ("-r", path)]
    run([str(python), "-I", "-m", "pip", "download", "--require-hashes", "--only-binary=:all:",
         "--platform", "manylinux_2_28_x86_64", "--platform", "manylinux2014_x86_64",
         "--implementation", "cp", "--python-version", "3.12", "--abi", "cp312",
         "--dest", str(wheels), *requirement_options], env=env)
    run([str(python), "-I", "-m", "pip", "install", "--no-compile", "--no-index", "--require-hashes",
         "--find-links", str(wheels), *requirement_options], env=env)
    wheel = next((source / "dist").glob("ficc-*.whl"))
    run([str(python), "-I", "-m", "pip", "install", "--no-compile", "--no-index", "--no-deps", str(wheel)], env=env)
    runtime_wheels = payload / "runtime-packages"
    providers = runtime_packages.build(source, runtime_wheels, sys.executable, env=env)
    runtime_packages.install(python, runtime_wheels, providers, env=env)
    (payload / "python/bin/ficc").write_text(CLI)
    (payload / "python/bin/ficc").chmod(0o755)
    (payload / "python/bin/ficc-audit-collector").write_text(CLI.replace("-m ficc.cli", "-m ficc_audit_https.collector"))
    (payload / "python/bin/ficc-audit-collector").chmod(0o755)
    (payload / "ficc").write_text(ENTRY)
    (payload / "ficc").chmod(0o755)
    site = payload / "python/lib/python3.12/site-packages"
    for item in site.glob("*.dist-info/direct_url.json"):
        item.unlink()
    shutil.rmtree(site / "pip")
    shutil.rmtree(payload / "python/lib/python3.12/ensurepip")
    for item in site.glob("pip-*.dist-info"):
        shutil.rmtree(item)
    for item in (payload / "python/bin").glob("pip*"):
        item.unlink()
    retain_commands(payload / "python/bin", original_commands)
    for item in payload.rglob("__pycache__"):
        shutil.rmtree(item)
    repair_records(site, payload)
    for name in ("README.md", "LICENSE", "NOTICE"):
        shutil.copy2(source / name, payload / name)
    shutil.copytree(source / "docs", payload / "docs")
    shutil.copytree(source / "sdk", payload / "sdk")
    shutil.copytree(source / "policy-packs", payload / "policy-packs")
    shutil.copytree(source / "packaging/remote", payload / "remote")
    for name in ("module-sandbox-policy", "power-policy"):
        shutil.copytree(source / "tools" / name, payload / "tools" / name)
    shutil.copytree(source / ".github/assets", payload / ".github/assets")
    shutil.copy2(source / "packaging/ficc.desktop", payload / "ficc.desktop")
    shutil.copy2(source / "web/static/mark.svg", payload / "ficc.svg")
    shutil.copy2(source / "packaging/package-guard.sh", payload / "package-guard.sh")
    (payload / "package-guard.sh").chmod(0o755)
    shutil.copy2(source / "packaging/ficc-runtime.hook", payload / "ficc-runtime.hook")
    inventory_code = '''import importlib.metadata as m,json
print(json.dumps([{'name':d.metadata['Name'],'version':d.version,'license':d.metadata.get('License-Expression') or d.metadata.get('License',''),'requires':d.requires or []} for d in m.distributions()]))'''
    distributions = json.loads(subprocess.check_output([str(python), "-I", "-B", "-c", inventory_code], env=env))
    components = [{"type": "library", "name": d["name"], "version": d["version"],
                   "purl": f"pkg:pypi/{d['name'].lower().replace('_', '-')}@{d['version']}",
                   "properties": [{"name": "ficc:license-metadata", "value": d["license"]}]}
                  for d in sorted(distributions, key=lambda d: d["name"].lower())]
    components.append({"type": "framework", "name": "CPython", "version": lock["python"],
                       "properties": [{"name": "ficc:build", "value": lock["inputs"][0]["release"]}]})
    for name, ver in (("xterm.js", "6.0.0"), ("FitAddon", "0.11.0"), ("dockview-core", "8.3.1"),
                      ("guacamole-common-js", "1.6.0"), ("Michroma", "1.100"),
                      ("Barlow Semi Condensed", "1.408"), ("JetBrains Mono", "2.304")):
        components.append({"type": "library", "name": name, "version": ver})
    components.append({"type": "file", "name": "AppArmor Bubblewrap profile", "version": "4.0-derived",
                       "licenses": [{"license": {"id": "GPL-2.0-only"}}],
                       "hashes": [{"alg": "SHA-256", "content": digest(payload / "tools/module-sandbox-policy/ficc-module-bwrap")}],
                       "properties": [{"name": "ficc:scope", "value": "Optional administrator-installed policy"}]})
    components.extend(module_components(site / "ficc/module_packages"))
    components.extend(install_notices(payload, inputs, lock))
    if viewer_runtime is not None:
        runtime = install_viewer(viewer_runtime, payload / 'viewer-runtime')
        native = json.loads((runtime / 'sbom.cdx.json').read_text())
        components.append(native['metadata']['component'])
        components.extend(native['components'])
    if windows_runtime is not None:
        from windows_runtime import install as install_windows
        runtime = install_windows(windows_runtime, payload / 'windows-runtime')
        components.extend(json.loads((runtime / 'sbom.cdx.json').read_text())['components'])
    write_json(payload / "sbom.cdx.json", {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                                          "components": components})
    manifest = {str(p.relative_to(payload)): digest(p) for p in sorted(payload.rglob("*"))
                if p.is_file() and not p.is_symlink()}
    links = {str(p.relative_to(payload)): os.readlink(p) for p in sorted(payload.rglob("*")) if p.is_symlink()}
    write_json(payload / "bundle.json", {"version": version, "architecture": "x86_64",
                                         "source": provenance, "inputs": lock, "files": manifest,
                                         "links": links, "python_distributions": distributions})
    normalize_tree(payload, provenance["epoch"])
    return payload, version
