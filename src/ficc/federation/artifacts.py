# SPDX-License-Identifier: Apache-2.0
"""Resume immutable model ranges across finite HyperNet sessions and verify before publication."""
import asyncio

from ..errors import Failure
from ..models.cache import WRITE_CHUNK
from ..models.schema import Manifest
from .identity import digest

MAX_RECONNECTS = 3


async def acquire(manager, peer, remote, actor, state):
    for attempt in range(MAX_RECONNECTS + 1):
        error = await _acquire(manager, peer, remote, actor, state)
        transient = isinstance(error, (ConnectionError, TimeoutError, asyncio.IncompleteReadError)) or (
            isinstance(error, Failure) and error.code in {
                "hypernet_connect", "hypernet_unavailable", "federation_interrupted"})
        if not transient or attempt == MAX_RECONNECTS:
            return
        # Only immutable, digest-bound reads resume. Every new stream rechecks
        # both authorities; duplicate bytes still consume the existing grant.
        state.update(state="reconnecting", retry=attempt + 1, retry_limit=MAX_RECONNECTS)
        try:
            await asyncio.sleep(2 ** attempt)
        except asyncio.CancelledError:
            state["state"] = "paused"
            raise
        state.update(state="connecting", error=None)


async def _acquire(manager, peer, remote, actor, state):
    cache = item = None
    index = 0
    try:
        metadata, _ = await manager.client.request(peer, "models.manifest", {"model": remote}, actor)
        manifest = Manifest.model_validate(metadata["manifest"])
        if metadata["manifest_digest"] != digest(manifest.model_dump()):
            raise Failure("federation_manifest", "The returned model manifest digest is invalid.", 502)
        if state.setdefault("manifest_digest", metadata["manifest_digest"]) != metadata["manifest_digest"]:
            raise Failure("federation_manifest_changed", "The remote model manifest changed during acquisition.", 409)
        local = manager.service.models.create(manifest.model_dump(), actor)
        state["model"] = local["id"]
        cache = manager.service.models.cache_for(local)
        for index, item in enumerate(manifest.files):
            while not cache.status(item)["complete"]:
                manager.current(actor, "federation:invoke")
                manager.service.models.get(local["id"], actor, "models:manage")
                offset = cache.status(item)["offset"]
                if offset == item.bytes:
                    await cache.write_async(item, offset, b"")
                    continue
                length = min(64*1024*1024, item.bytes-offset)
                result, stream = await manager.client.request(peer, "models.range", {
                    "model": remote, "file": index, "digest": item.digest, "offset": offset, "length": length}, actor)
                if (result.get("digest") != item.digest or result.get("offset") != offset
                        or result.get("length") != length or stream is None):
                    if stream is not None:
                        await stream.aclose()
                    raise Failure("federation_range", "The remote range differs from its immutable request.", 502)
                cursor = offset
                durable = offset
                buffered = bytearray()
                try:
                    async for data in stream:
                        manager.service.models.get(local["id"], actor, "models:manage")
                        if cursor+len(data) > offset+length:
                            raise Failure("federation_range", "The remote model range exceeded its declared length.", 502)
                        cursor += len(data)
                        while data:
                            take = min(WRITE_CHUNK-len(buffered), len(data))
                            buffered.extend(data[:take])
                            data = data[take:]
                            if len(buffered) == WRITE_CHUNK:
                                await cache.write_async(item, durable, buffered)
                                durable += len(buffered)
                                buffered = bytearray()
                                state.update(file=index, offset=durable, state="transferring")
                finally:
                    await stream.aclose()
                if cursor != offset+length:
                    raise Failure("federation_interrupted", "The model range ended early; resume from the verified local offset.", 502)
                if buffered:
                    await cache.write_async(item, durable, buffered)
                    state.update(file=index, offset=cursor, state="transferring")
        state.update(state="complete", error=None)
    except asyncio.CancelledError:
        if cache is not None and item is not None:
            state.update(file=index, offset=cache.status(item)["offset"])
        state["state"] = "paused"
        raise
    except (Failure, OSError, RuntimeError, asyncio.IncompleteReadError, ValueError, KeyError) as exc:
        state.update(state="interrupted", error={"code": getattr(exc, "code", "federation_interrupted"),
                                                "message": str(exc)})
        return exc
    return None


def start(manager, peer, remote, actor):
    actor = manager.current(actor, "federation:invoke")
    actor.require("models:manage")
    identity = digest([actor.project_id, peer, remote])[:32]
    previous = manager.transfers.get(identity)
    if previous and not previous["task"].done():
        return view(previous)
    if sum(not item["task"].done() for item in manager.transfers.values()) >= 2:
        raise Failure("federation_capacity", "Two model transfers are already active.", 429)
    if len(manager.transfers) >= 256:
        finished = next((key for key, item in manager.transfers.items() if item["task"].done()), None)
        if finished is not None:
            manager.transfers.pop(finished)
    state = {"id": identity, "project_id": actor.project_id, "peer": peer, "remote": remote,
             "state": "connecting", "model": None, "offset": 0, "error": None}
    manager.transfers[identity] = state
    state["task"] = asyncio.create_task(acquire(manager, peer, remote, actor, state))
    return view(state)


def view(state):
    return {key: value for key, value in state.items() if key != "task"}
