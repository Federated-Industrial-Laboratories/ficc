# SPDX-License-Identifier: Apache-2.0
"""Qualify the adapter SDK against real isolated pipes and bounded host transport."""

import asyncio
import hashlib
import importlib.util
import os
import platform
import subprocess
from pathlib import Path

import pytest
from test_module_adapter_manifest import adapter_package
from test_module_adapter_protocol import bindings
from test_modules_packages import bundle

from ficc.errors import Failure
from ficc.modules import inspect_archive
from ficc.modules.adapter_protocol import Conversation
from ficc.modules.adapter_runtime import ControllerRuntime
from ficc.modules.archive import publish
from ficc.modules.sandbox import command

REAL = pytest.mark.skipif(os.environ.get("FICC_REAL_MODULE_SANDBOX") != "1", reason="Explicit platform qualification only")
SDK = Path(__file__).resolve().parents[2] / "sdk/python"
SOURCE = '''import sys
sys.path.insert(0, "/module")
from ficc_adapter import serve
def run(request, transport):
    result = []
    for binding in request['bindings']:
        commands = [{'command': 'Get-TestItem', 'parameters': {'index': i}} for i in range(len(binding['resources']))]
        rows = transport(binding['id'], commands)
        result.append({'profile_id': binding['id'], 'data': {'rows': rows}})
    return result
raise SystemExit(serve(run))
'''


def package(tmp_path, source=SOURCE, language="python"):
    if language != "python":
        return native_package(tmp_path, language)
    manifest, files = adapter_package()
    files = {"main.py": source.encode(), "ficc_adapter.py": (SDK / "ficc_adapter.py").read_bytes(),
             "ficc_module.py": (SDK / "ficc_module.py").read_bytes()}
    manifest["files"] = {key: hashlib.sha256(value).hexdigest() for key, value in files.items()}
    manifest["adapter"].update(execution="controller", transport="winrm-jea", consistency="checked-before-dispatch")
    inspection = inspect_archive(bundle(manifest, files))
    return publish(tmp_path, inspection), manifest, inspection.digest


def test_apply_uses_only_the_fixed_extended_service_limit(tmp_path):
    ordinary = command(tmp_path, ["/usr/bin/true"], "ficc-module-test")
    extended = command(tmp_path, ["/usr/bin/true"], "ficc-module-test", adapter_apply=True)
    assert "--property=RuntimeMaxSec=12" in ordinary
    assert "--property=RuntimeMaxSec=32" in extended
    assert [arg.replace("RuntimeMaxSec=32", "RuntimeMaxSec=12") for arg in extended] == ordinary
    broker = command(tmp_path, ["/usr/bin/true"], "ficc-module-test", broker_request=True)
    assert "--property=RuntimeMaxSec=32" in broker
    assert [arg.replace("RuntimeMaxSec=32", "RuntimeMaxSec=12") for arg in broker] == ordinary


@REAL
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("phase", ["status", "apply"])
async def test_real_broker_wait_uses_its_bounded_transport_deadline(tmp_path, monkeypatch, count, phase):
    from ficc.modules import sandbox
    monkeypatch.setattr(sandbox, "MAX_SECONDS", 1)
    monkeypatch.setattr(sandbox, "BROKER_SECONDS", 3)
    monkeypatch.setattr(sandbox, "ADAPTER_APPLY_SECONDS", 3)
    path, manifest, digest = package(tmp_path)
    value = bindings()[0]
    value["resources"] = [{"id": f"{index + 1:032x}", "key": f"guest-{index}", "birth": "a" * 64,
                           "revision": "b" * 64, "state": "off"} for index in range(count)]
    async def transport(call):
        await asyncio.sleep(1.2)
        call.check()
        return [{"value": item["parameters"]["index"]} for item in call.commands]
    if phase == "apply":
        value["intent"] = {"selected": [item["key"] for item in value["resources"]]}
    conversation = Conversation(digest, phase, "start" if phase == "apply" else "status", [value], lambda: None, transport)
    result = await ControllerRuntime().execute(path, manifest, conversation)
    assert len(result["results"][0]["data"]["rows"]) == count


@REAL
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("language", ["python", "c", "cpp"])
async def test_real_adapter_sdk_complete_batch_and_authority_check(tmp_path, count, language):
    path, manifest, digest = package(tmp_path, language=language)
    value = bindings()[0]
    value["consistency"] = "checked-before-dispatch"
    value["resources"] = [{"id": f"{index + 1:032x}", "key": f"guest-{index}", "birth": "a" * 64,
                           "revision": "b" * 64, "state": "off"} for index in range(count)]
    checks, calls = [], []
    def check():
        checks.append(True)
    async def transport(call):
        call.check()
        calls.append(call)
        return [{"value": item["parameters"]["index"]} for item in call.commands]
    conversation = Conversation(digest, "status", "status", [value], check, transport)
    result = await ControllerRuntime().execute(path, manifest, conversation)
    assert result["results"][0]["data"]["rows"] == [{"value": index} for index in range(count)]
    assert len(calls) == 1 and len(checks) >= 4


@REAL
async def test_real_adapter_revocation_during_host_transport_stops_context(tmp_path):
    path, manifest, digest = package(tmp_path)
    value = bindings()[0]
    value["resources"] = [{"id": "1" * 32, "key": "guest", "birth": "a" * 64, "revision": "b" * 64, "state": "off"}]
    revoked = False
    def check():
        if revoked:
            raise Failure("revoked", "Provider authority was revoked.", 403)
    async def transport(call):
        nonlocal revoked
        revoked = True
        await asyncio.sleep(0)
        return [{}]
    conversation = Conversation(digest, "status", "status", [value], check, transport)
    with pytest.raises(Failure, match="revoked"):
        await ControllerRuntime().execute(path, manifest, conversation)


C_SOURCE = r'''#include "ficc_module.h"
static cJSON *run(const cJSON *request, ficc_adapter *adapter) {
    cJSON *output = cJSON_CreateArray();
    const cJSON *bindings = cJSON_GetObjectItemCaseSensitive(request, "bindings");
    for (const cJSON *binding = bindings->child; binding; binding = binding->next) {
        const char *profile = cJSON_GetObjectItemCaseSensitive(binding, "id")->valuestring;
        const cJSON *resources = cJSON_GetObjectItemCaseSensitive(binding, "resources");
        cJSON *commands = cJSON_CreateArray();
        for (int index = 0; index < cJSON_GetArraySize(resources); ++index) {
            cJSON *command = cJSON_CreateObject(), *parameters = cJSON_CreateObject();
            cJSON_AddStringToObject(command, "command", "Get-TestItem");
            cJSON_AddNumberToObject(parameters, "index", index);
            cJSON_AddItemToObject(command, "parameters", parameters);
            cJSON_AddItemToArray(commands, command);
        }
        cJSON *rows = ficc_adapter_call(adapter, profile, commands);
        cJSON_Delete(commands);
        if (!rows) { cJSON_Delete(output); return NULL; }
        cJSON *item = cJSON_CreateObject(), *data = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "profile_id", profile);
        cJSON_AddItemToObject(data, "rows", rows);
        cJSON_AddItemToObject(item, "data", data);
        cJSON_AddItemToArray(output, item);
    }
    return output;
}
int main(void) { return ficc_serve_adapter(run); }
'''


def native_package(tmp_path, language):
    sdk = SDK.parent
    specification = importlib.util.spec_from_file_location("adapter_sdk_build", sdk / "build.py")
    build = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(build)
    cache = Path(os.environ.get("FICC_SDK_CACHE", "/tmp/ficc-sdk-build"))
    source = build.dependency("cJSON.c", cache, False)
    build.dependency("cJSON.h", cache, False)
    work = tmp_path / "build"
    work.mkdir()
    common = ["-O2", "-Wall", "-Wextra", "-Werror", "-I", str(source.parent), "-I", str(sdk / "native")]
    for name, path in (("cjson", source), ("sdk", sdk / "native/ficc_module.c")):
        subprocess.run(["cc", "-std=c11", *common, "-c", str(path), "-o", str(work / (name + ".o"))], check=True, timeout=60)
    entry = work / ("main.c" if language == "c" else "main.cpp")
    entry.write_text(C_SOURCE)
    subprocess.run(["cc" if language == "c" else "c++", "-std=c11" if language == "c" else "-std=c++17",
        *common, str(entry), str(work / "sdk.o"), str(work / "cjson.o"), "-lm", "-o", str(work / "program")], check=True, timeout=60)
    manifest, files = adapter_package()
    files = {"program": (work / "program").read_bytes()}
    manifest["files"] = {"program": hashlib.sha256(files["program"]).hexdigest()}
    manifest["runtime"] = {"kind": "native", "language": language, "entry": "program", "platform": "linux", "architecture": platform.machine()}
    manifest["adapter"].update(execution="controller", transport="winrm-jea", consistency="checked-before-dispatch")
    inspection = inspect_archive(bundle(manifest, files))
    (tmp_path / "installed").mkdir(mode=0o700)
    return publish(tmp_path / "installed", inspection), manifest, inspection.digest


@REAL
@pytest.mark.parametrize("language", ["python", "c", "cpp"])
@pytest.mark.parametrize("change", ["identity", "nul", "cancel"])
async def test_real_sdk_refuses_changed_host_reply_identity(tmp_path, language, change):
    from ficc.modules.protocol import frame

    path, manifest, digest = package(tmp_path, language=language)
    value = bindings()[0]
    value["resources"] = [{"id": "1" * 32, "key": "guest", "birth": "a" * 64, "revision": "b" * 64, "state": "off"}]
    conversation = Conversation(digest, "status", "status", [value], lambda: None)
    async def exchange(channel):
        await channel.receive()
        call = conversation.call(await channel.receive())
        reply = {"version": 1, "type": "adapter-transport-result", "id": call.request_id,
                 "invocation_id": conversation.id, "profile_id": call.profile_id, "results": [{}]}
        if change == "identity":
            reply["profile_id"] = "f" * 32
        elif change == "nul":
            import json
            import struct
            reply["id"] += "\x00suffix"
            encoded = json.dumps(reply).encode()
            await channel.send(struct.pack(">I", len(encoded)) + encoded)
        else:
            reply = {"version": 1, "type": "adapter-cancel", "id": conversation.id}
        if change != "nul":
            await channel.send(frame(reply))
        await channel.receive()
        pytest.fail("The adapter SDK accepted an invalid host response.")
    conversation.exchange = exchange
    with pytest.raises((Failure, EOFError)):
        await ControllerRuntime().execute(path, manifest, conversation)
