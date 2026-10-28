# SPDX-License-Identifier: Apache-2.0
"""Acquire immutable HTTPS objects with explicit source policy and durable offsets."""
import asyncio
from urllib.parse import urljoin, urlsplit

import httpx

from ..errors import Failure
from .cache import WRITE_CHUNK
from .schema import Manifest

DEFAULT_HOSTS = ["huggingface.co", "cdn-lfs.huggingface.co", "cdn-lfs.hf.co", "cas-bridge.xethub.hf.co",
                 "cas-server.xethub.hf.co", "cas-server.xethub-eu.hf.co", "transfer.xethub.hf.co",
                 "transfer.xethub-eu.hf.co", "us.aws.cdn.hf.co", "us.gcp.cdn.hf.co",
                 "cdn-lfs-us-1.hf.co", "cdn-lfs-eu-1.hf.co"]


def allowed(url, hosts):
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in hosts or parts.username or parts.password or parts.port not in (None, 443):
        raise Failure("model_source_denied", "This download host is not in the administrator's model source allowlist.", 403)


async def acquire(models, identity, actor):
    value = models.get(identity, actor, "models:manage")
    hosts = models.service.store.get_setting("models.https_hosts", DEFAULT_HOSTS)
    state = models.downloads[identity]
    try:
        async with httpx.AsyncClient(follow_redirects=False, trust_env=False, timeout=httpx.Timeout(30, read=60)) as client:
            for item in Manifest.model_validate(value["manifest"]).files:
                status = models.cache_for(value).status(item)
                if status["complete"]:
                    continue
                if status["offset"] == item.bytes:
                    models.get(identity, actor, "models:manage")
                    await models.cache_for(value).write_async(item, item.bytes, b"")
                    continue
                if item.url is None:
                    raise Failure("model_source_missing", "Upload this model file or supply its immutable HTTPS source.", 409)
                url, offset = item.url, status["offset"]
                for _ in range(6):
                    allowed(url, hosts)
                    models.get(identity, actor, "models:manage")
                    async with client.stream("GET", url, headers={"Range": f"bytes={offset}-", "Accept-Encoding": "identity"}) as response:
                        if response.status_code in {301, 302, 303, 307, 308}:
                            url = urljoin(url, response.headers.get("location", ""))
                            continue
                        response.raise_for_status()
                        if offset and (response.status_code != 206 or not response.headers.get("content-range", "").startswith(f"bytes {offset}-")):
                            raise Failure("model_source_changed", "The source did not honour the verified resume range.", 409)
                        async for data in response.aiter_bytes(WRITE_CHUNK):
                            models.get(identity, actor, "models:manage")
                            if data:
                                receipt = await models.cache_for(value).write_async(item, offset, data)
                                offset = receipt["offset"]
                        if offset != item.bytes:
                            raise Failure("model_download_incomplete", "The source ended before the declared model size; resume acquisition.", 409)
                        break
                else:
                    raise Failure("model_redirects", "The model source exceeded five redirects.", 409)
        state["state"] = "complete"
    except asyncio.CancelledError:
        state["state"] = "interrupted"
        raise
    except Exception as exc:
        state["state"] = exc.code if isinstance(exc, Failure) else "download_failed"


def start(models, identity, actor):
    models.get(identity, actor, "models:manage")
    previous = models.downloads.get(identity, {}).get("task")
    if previous and not previous.done():
        return {"state": "downloading"}
    if sum(not item["task"].done() for item in models.downloads.values()) >= 2:
        raise Failure("model_download_capacity", "Two model acquisitions are already running.", 429)
    state: dict = {"state": "downloading"}
    models.downloads[identity] = state
    state["task"] = asyncio.create_task(acquire(models, identity, actor))
    return {"state": "downloading"}


async def pause(models, identity, actor):
    models.get(identity, actor, "models:manage")
    state = models.downloads.get(identity)
    if state and not state["task"].done():
        state["task"].cancel()
        await asyncio.gather(state["task"], return_exceptions=True)
        state["state"] = "paused"
    return {"state": state["state"] if state else "idle"}
