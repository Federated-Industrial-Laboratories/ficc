# SPDX-License-Identifier: Apache-2.0
"""Build the SDK examples with pinned dependencies and no package install hooks."""

import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import tarfile
import urllib.request
from pathlib import Path

SDK = Path(__file__).resolve().parent
LANGUAGES = ("c", "cpp", "rust", "python", "javascript", "typescript")


def run(command, **kwargs):
    subprocess.run([str(item) for item in command], check=True, timeout=180, **kwargs)


def dependency(name: str, cache: Path, fetch: bool) -> Path:
    record = json.loads((SDK / "dependencies.json").read_text())[name]
    target = cache / "dependencies" / name
    if not target.exists():
        if not fetch:
            raise ValueError(f"Missing dependency {name}. Run examples with --fetch.")
        target.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(record["url"], timeout=30) as source:
            data = source.read(record["bytes"] + 1)
        if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise ValueError(f"Dependency verification failed: {name}")
        target.write_bytes(data)
    if target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest() != record["sha256"]:
        raise ValueError(f"Dependency cache changed: {name}")
    return target


def native(language: str, cache: Path, fetch: bool, broker: bool = False) -> dict[str, bytes]:
    source = dependency("cJSON.c", cache, fetch)
    dependency("cJSON.h", cache, fetch)
    license_file = dependency("LICENSE", cache, fetch)
    work = cache / (language + ("-broker" if broker else ""))
    work.mkdir(parents=True, exist_ok=True)
    common = ["-O2", "-fno-ident", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2",
              "-I", source.parent, "-I", SDK / "native"]
    run(["cc", "-std=c11", *common, "-DCJSON_NESTING_LIMIT=32", "-c", source,
         "-o", work / "cjson.o"])
    run(["cc", "-std=c11", *common, "-Wall", "-Wextra", "-Werror", "-c",
         SDK / "native/ficc_module.c", "-o", work / "sdk.o"])
    compiler, standard, extension = ("cc", "c11", "c") if language == "c" else (
        "c++", "c++17", "cpp")
    run([compiler, "-std=" + standard, *common, "-Wall", "-Wextra", "-Werror",
         SDK / "examples" / language / (("broker." if broker else "main.") + extension), work / "sdk.o",
         work / "cjson.o", "-Wl,--build-id=none,-z,relro,-z,now", "-lm", "-o", work / "program"])
    return {"program": (work / "program").read_bytes(),
            "licenses/cJSON-MIT.txt": license_file.read_bytes()}


def rust(cache: Path, fetch: bool, broker: bool = False) -> dict[str, bytes]:
    env = dict(os.environ, CARGO_HOME=str(cache / "cargo"),
               CARGO_TARGET_DIR=str(cache / "rust-target"))
    manifest = SDK / "rust/Cargo.toml"
    if fetch:
        run(["cargo", "fetch", "--locked", "--manifest-path", manifest], env=env)
    name = "broker" if broker else "echo"
    run(["cargo", "build", "--frozen", "--release", "--example", name,
         "--manifest-path", manifest], env=env)
    payload = {"program": (cache / "rust-target/release/examples" / name).read_bytes()}
    metadata = subprocess.check_output(["cargo", "metadata", "--frozen", "--format-version", "1",
                                       "--manifest-path", str(manifest)], env=env, timeout=30)
    for package in json.loads(metadata)["packages"]:
        if package["name"] == "ficc-module-sdk":
            continue
        source = Path(package["manifest_path"]).parent
        licenses = sorted(source.glob("LICENSE*"))
        if not licenses:
            raise ValueError(f"Missing dependency license: {package['name']}")
        for license_file in licenses:
            if license_file.is_file():
                name = f"licenses/{package['name']}-{package['version']}-{license_file.name}.txt"
                payload[name] = license_file.read_bytes()
    payload["licenses/Cargo.lock"] = (SDK / "rust/Cargo.lock").read_bytes()
    return payload


def typescript(cache: Path, fetch: bool, node: str, broker: bool = False) -> dict[str, bytes]:
    archive = dependency("typescript.tgz", cache, fetch)
    compiler = cache / "typescript-compiler"
    compiler.mkdir(exist_ok=True)
    # Extract verified regular package members only; never follow archive links.
    with tarfile.open(fileobj=io.BytesIO(archive.read_bytes()), mode="r:gz") as bundle:
        for member in bundle.getmembers():
            parts = Path(member.name).parts
            if not member.isfile() or parts[0] != "package" or ".." in parts:
                continue
            if len(parts) > 2 and parts[1] != "lib":
                continue
            destination = compiler.joinpath(*parts[1:])
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            assert source is not None
            destination.write_bytes(source.read())
    work = cache / ("typescript-broker" if broker else "typescript")
    work.mkdir(exist_ok=True)
    for name in ("main.ts", "tsconfig.json"):
        source = "broker.ts" if broker and name == "main.ts" else name
        shutil.copyfile(SDK / "examples/typescript" / source, work / name)
    shutil.copyfile(SDK / "javascript/ficc-module.d.mts", work / "ficc-module.d.mts")
    run([node, compiler / "lib/tsc.js", "--project", work / "tsconfig.json"])
    return {"main.mjs": (work / "main.js").read_bytes(),
            "ficc-module.mjs": (SDK / "javascript/ficc-module.mjs").read_bytes(),
            "licenses/TypeScript-Apache-2.0.txt": (compiler / "LICENSE.txt").read_bytes()}


def example(language: str, cache: Path, fetch: bool, node: str, *, broker: bool = False) -> tuple[dict, dict]:
    cache = cache.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((SDK / "examples" / language / ("broker-manifest.json" if broker else "manifest.json")).read_text())
    if language in ("c", "cpp"):
        payload = native(language, cache, fetch, broker)
    elif language == "rust":
        payload = rust(cache, fetch, broker)
    elif language == "typescript":
        payload = typescript(cache, fetch, node, broker)
    elif language == "python":
        payload = {"main.py": (SDK / "examples/python" / ("broker.py" if broker else "main.py")).read_bytes(),
                   "ficc_module.py": (SDK / "python/ficc_module.py").read_bytes()}
    else:
        payload = {"main.mjs": (SDK / "examples/javascript" / ("broker.mjs" if broker else "main.mjs")).read_bytes(),
                   "ficc-module.mjs": (SDK / "javascript/ficc-module.mjs").read_bytes()}
    if manifest["runtime"]["kind"] == "native":
        if platform.machine() not in {"x86_64", "aarch64"}:
            raise ValueError("Build native modules on x86_64 or aarch64 Linux.")
        manifest["runtime"]["architecture"] = platform.machine()
    return manifest, payload
