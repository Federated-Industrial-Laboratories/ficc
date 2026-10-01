# SPDX-License-Identifier: Apache-2.0
"""Compile declared native package sources with pinned inputs and fixed flags."""

import hashlib
import importlib.util
import io
import os
import platform
import re
import stat
import subprocess
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from ficc.modules.manifest import package_path
from ficc.modules.validation import fields, loads

ROOT = Path(__file__).resolve().parents[1]
MAX_INPUT = 32 * 1024 * 1024


def read(root, name, maximum=4 * 1024 * 1024, *, cache=False):
    if cache:
        if re.fullmatch(r"[0-9a-f]{64}\.zip", name) is None:
            raise ValueError("The native dependency cache name is invalid.")
    else:
        name = package_path(name)
    target = root / name
    if target.resolve() != target.absolute() or root.resolve() not in target.resolve().parents:
        raise ValueError("A native build input leaves its source directory.")
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            raise ValueError("A native build input is not a bounded regular file.")
        value = stream.read(maximum + 1)
        if len(value) > maximum:
            raise ValueError("A native build input exceeds its limit.")
        return value


def specification(source):
    value = loads(read(source, "build.json", 65536), 65536)
    fields(value, {"version", "language", "sources", "dependencies", "libraries"})
    if type(value["version"]) is not int or value["version"] != 1 or value["language"] not in ("c", "cpp"):
        raise ValueError("The native build version or language is unsupported.")
    if not isinstance(value["sources"], list) or not 1 <= len(value["sources"]) <= 32:
        raise ValueError("A native build requires one to 32 source files.")
    for name in value["sources"]:
        package_path(name)
        if Path(name).suffix not in {".c", ".cpp"}:
            raise ValueError("Native build sources must be C or C++ files.")
    if len(set(value["sources"])) != len(value["sources"]):
        raise ValueError("The native build repeats a source.")
    if (not isinstance(value["libraries"], list) or len(value["libraries"]) > 4
            or any(name not in ("m", "dl", "pthread", "crypto") for name in value["libraries"])):
        raise ValueError("The native build requests an unsupported link library.")
    if not isinstance(value["dependencies"], list) or len(value["dependencies"]) > 4:
        raise ValueError("The native dependency count exceeds its limit.")
    seen = set()
    for item in value["dependencies"]:
        fields(item, {"id", "url", "sha256", "bytes", "members", "sources", "licenses"})
        if (not isinstance(item["id"], str) or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", item["id"]) is None
                or item["id"] in seen or not isinstance(item["sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
                or type(item["bytes"]) is not int or not 1 <= item["bytes"] <= MAX_INPUT):
            raise ValueError("The native dependency identity or size is invalid.")
        seen.add(item["id"])
        url = urllib.parse.urlsplit(item["url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment:
            raise ValueError("A pinned native dependency requires an HTTPS URL.")
        if not isinstance(item["members"], dict) or not 1 <= len(item["members"]) <= 64:
            raise ValueError("The native dependency member count is invalid.")
        destinations = []
        for original, destination in item["members"].items():
            package_path(original)
            destinations.append(package_path(destination))
        if len({name.casefold() for name in destinations}) != len(destinations):
            raise ValueError("The native dependency repeats a destination.")
        for field in ("sources", "licenses"):
            if not isinstance(item[field], list) or len(item[field]) > 32 or any(name not in destinations for name in item[field]):
                raise ValueError("A native dependency reference is outside its selected members.")
        if any(Path(name).suffix not in {".c", ".cpp"} for name in item["sources"]):
            raise ValueError("A native dependency source has an unsupported type.")
    return value


def dependency(record, cache, fetch):
    target = cache / (record["sha256"] + ".zip")
    if not target.exists():
        if not fetch:
            raise ValueError("A pinned native build dependency is missing. Use --fetch to download it.")
        with urllib.request.urlopen(record["url"], timeout=30) as response:
            data = response.read(record["bytes"] + 1)
        if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise ValueError("The downloaded native dependency does not match its checksum.")
        with target.open("xb") as stream:
            stream.write(data)
    data = read(cache, target.name, MAX_INPUT, cache=True)
    if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
        raise ValueError("The native dependency cache changed.")
    return data


def extract(data, record, work):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        for source, destination in record["members"].items():
            if names.count(source) != 1:
                raise ValueError("A selected native dependency member is missing or repeated.")
            info = archive.getinfo(source)
            if (info.is_dir() or stat.S_IFMT(info.external_attr >> 16) not in (0, stat.S_IFREG)
                    or info.flag_bits & 1 or info.file_size > 4 * 1024 * 1024):
                raise ValueError("A selected native dependency member is not a bounded regular file.")
            content = archive.read(info)
            target = work / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)


def build(source, manifest, cache, fetch=False):
    """Return the native program and dependency notices; never run the program."""
    source, cache = Path(source).resolve(), Path(cache).resolve()
    value = specification(source)
    if (manifest["runtime"]["kind"] != "native" or manifest["runtime"]["language"] != value["language"]
            or manifest["runtime"]["platform"] != "linux" or platform.system() != "Linux"
            or manifest["runtime"]["architecture"] != platform.machine()):
        raise ValueError("Build this native module on its declared Linux architecture.")
    cache.mkdir(parents=True, exist_ok=True)
    module = importlib.util.spec_from_file_location("ficc_native_sdk_build", ROOT / "sdk/build.py")
    sdk = importlib.util.module_from_spec(module)
    module.loader.exec_module(sdk)
    cjson = sdk.dependency("cJSON.c", cache, fetch)
    sdk.dependency("cJSON.h", cache, fetch)
    license_file = sdk.dependency("LICENSE", cache, fetch)
    payload = {"licenses/cJSON-MIT.txt": license_file.read_bytes()}
    with tempfile.TemporaryDirectory(prefix="native-", dir=cache) as temporary:
        work = Path(temporary)
        include = [source, cjson.parent, ROOT / "sdk/native"]
        sources = [cjson, ROOT / "sdk/native/ficc_module.c"]
        for name in value["sources"]:
            read(source, name)
            sources.append(source / name)
            include.append((source / name).parent)
        for record in value["dependencies"]:
            directory = work / record["id"]
            directory.mkdir()
            extract(dependency(record, cache, fetch), record, directory)
            include.extend((directory / name).parent for name in record["members"].values())
            sources.extend(directory / name for name in record["sources"])
            for name in record["licenses"]:
                payload["licenses/" + record["id"] + "/" + name] = (directory / name).read_bytes()
        common = ["-O2", "-fno-ident", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-DCJSON_NESTING_LIMIT=32",
            f"-ffile-prefix-map={work}=/build", f"-ffile-prefix-map={source}=/source", f"-ffile-prefix-map={ROOT / 'sdk'}=/sdk"]
        common += [argument for directory in dict.fromkeys(include) for argument in ("-I", str(directory))]
        objects = []
        for index, path in enumerate(sources):
            target = work / f"source-{index}.o"
            language = "cpp" if path.suffix == ".cpp" else "c"
            subprocess.run(["c++" if language == "cpp" else "cc", "-std=c++17" if language == "cpp" else "-std=c11",
                *common, "-c", str(path), "-o", str(target)], check=True, timeout=120)
            objects.append(str(target))
        program = work / "program"
        subprocess.run(["c++" if value["language"] == "cpp" else "cc", *objects,
            "-Wl,--build-id=none,-z,relro,-z,now", *["-l" + name for name in dict.fromkeys(["m", *value["libraries"]])],
            "-o", str(program)], check=True, timeout=120)
        payload[package_path(manifest["runtime"]["entry"])] = program.read_bytes()
    return payload
