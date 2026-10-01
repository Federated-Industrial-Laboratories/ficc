# SPDX-License-Identifier: Apache-2.0
"""Supervise one bounded adapter request through an enrolled SSH account."""

import asyncio
import hashlib
import importlib.resources
import os
import signal
import struct
import sys

from ficc.errors import Failure
from ficc.modules.adapter_protocol import Conversation, request
from ficc.modules.adapter_vm_protocol import result as validate_result
from ficc.modules.sandbox import PROBE, entry_command, execute
from ficc.modules.validation import dumps, fields, loads
from ficc.modules.watcher import identity as process_identity

from . import adapter_binding, adapter_display, adapter_journal
from .adapter_store import directory, install, locked, read, verify


def watcher(base):
    data = importlib.resources.files("ficc.modules").joinpath("watcher.py").read_bytes()
    path = directory(base, "support") / (hashlib.sha256(data).hexdigest() + ".py")
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    if read(path) != data:
        raise Failure("adapter_support_changed", "The trusted adapter supervisor changed.")
    return path


async def run(base, parameters, check):
    fields(parameters, {"binding_id", "digest", "request"})
    value = request(parameters["request"])
    if value["digest"] != parameters["digest"] or len(value["bindings"]) != 1:
        raise Failure("adapter_request_invalid", "The node request must match one exact package and profile.")
    package, manifest = verify(base, parameters["digest"])
    binding, phase = value["bindings"][0], value["phase"]
    if binding["consistency"] != manifest["adapter"]["consistency"]:
        raise Failure("adapter_request_invalid", "The adapter consistency declaration changed.")
    journal = None
    if phase in {"apply", "observe"}:
        path, saved, previous = adapter_journal.prepare(base, value["digest"], binding, phase)
        journal = path, saved
        if previous is not None:
            if phase == "apply":
                return {"version": 1, "type": "adapter-result", "id": value["id"],
                        "results": [{"profile_id": binding["id"], "data": previous}]}
            # The durable node acknowledgement takes precedence over a lost host reply.
            binding["receipt"] = {"targets": [{"id": item["id"], "receipt": item["receipt"]} for item in previous["results"]]}
    conversation = Conversation.received(value, check)
    with adapter_binding.selected(base, parameters["binding_id"]) as pinned:
        output = await execute(package, entry_command(manifest), conversation.payload, check,
            conversation=conversation, adapter_apply=phase == "apply", provider_socket=pinned, watcher=watcher(base))
    result = conversation.result(loads(output))
    row = result["results"][0]
    if "data" in row:
        validate_result(row["data"], phase, value["action"], binding)
        if journal is not None:
            adapter_journal.completed(*journal, row["data"])
    return result


async def dispatch(value, stream, check):
    fields(value, {"version", "action", "parameters"})
    if type(value["version"]) is not int or value["version"] != 1:
        raise Failure("adapter_request_invalid", "The provider helper version is unsupported.")
    action, parameters = value["action"], value["parameters"]
    with locked() as base:
        check()
        if action == "install":
            return install(base, parameters, stream)
        if stream.read(1):
            raise Failure("adapter_request_invalid", "The provider request has extra input.")
        if action == "binding-register":
            return adapter_binding.register(base, parameters)
        if action == "binding-list":
            fields(parameters, set())
            return adapter_binding.listing(base)
        if action == "display-describe":
            fields(parameters, {"binding_id", "parameters"})
            with adapter_binding.selected(base, parameters["binding_id"]):
                return adapter_display.describe(parameters["parameters"])
        if action == "forget":
            return adapter_journal.forget(base, parameters)
        if action == "qualify":
            fields(parameters, {"binding_id"})
            with adapter_binding.selected(base, parameters["binding_id"]) as pinned:
                output = await execute(directory(base, "probe"), ["/usr/bin/python3", "-I", "-c", PROBE], b"", check,
                                       provider_socket=pinned, watcher=watcher(base))
            if loads(output) != {"seccomp": "2", "nnp": "1", "network_denied": True, "home_absent": True, "env_safe": True}:
                raise Failure("module_sandbox_unavailable", "The node adapter sandbox check failed.")
            return {"available": True}
        if action == "execute":
            return await run(base, parameters, check)
        raise Failure("adapter_request_invalid", "The provider helper action is unsupported.")


def main():
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(40)
    parent = os.getppid()
    parent_start = process_identity(parent)
    def check():
        if os.getppid() != parent or process_identity(parent) != parent_start:
            raise Failure("adapter_controller_closed", "The provider SSH controller closed.")
    try:
        header = sys.stdin.buffer.read(4)
        if len(header) != 4:
            raise Failure("adapter_request_invalid", "The provider request header is incomplete.")
        size = struct.unpack(">I", header)[0]
        if not 0 < size <= 1024 * 1024:
            raise Failure("adapter_request_invalid", "The provider request exceeds its limit.")
        value = loads(sys.stdin.buffer.read(size))
        data = asyncio.run(dispatch(value, sys.stdin.buffer, check))
        output = {"version": 1, "data": data}
    except Failure as exc:
        output = {"version": 1, "error": {"code": exc.code, "message": exc.message[:256]}}
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        output = {"version": 1, "error": {"code": "adapter_unavailable", "message": "The provider helper could not complete the bounded request."}}
    sys.stdout.buffer.write(dumps(output))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
