# SPDX-License-Identifier: Apache-2.0
"""Route explicitly approved external APIs without taking ownership of their processes."""
import asyncio
import ipaddress
import json
import time
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import Field, field_validator

from ..errors import Failure
from ..execution.spec import Digest, Identity, Name, digest
from ..schema import Model
from ..state_provider import read_private
from .stream import Stream


class Profile(Model):
    name: Name
    projects: Annotated[list[Identity], Field(min_length=1, max_length=256)]
    url: Annotated[str, Field(max_length=2048)]
    model: Annotated[str, Field(min_length=1, max_length=200)]
    capabilities: Annotated[list[Literal["chat", "embeddings"]], Field(min_length=1, max_length=2)]
    concurrency: Annotated[int, Field(ge=1, le=32)] = 1
    deadline_seconds: Annotated[int, Field(ge=1, le=600)] = 120
    token_file: str | None = None

    @field_validator("url")
    @classmethod
    def endpoint(cls, value):
        parts = urlsplit(value)
        if not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or not parts.path.endswith("/v1"):
            raise ValueError("Choose an exact compatible /v1 endpoint without credentials, query or fragment.")
        if parts.scheme == "http":
            try:
                loopback = ipaddress.ip_address(parts.hostname).is_loopback
            except ValueError:
                loopback = False
            if not loopback:
                raise ValueError("Plain HTTP is permitted only at an explicit numeric loopback address.")
        elif parts.scheme != "https":
            raise ValueError("Use verified HTTPS or an explicit loopback HTTP endpoint.")
        return value

    @field_validator("token_file")
    @classmethod
    def credential(cls, value):
        if value is not None and not Path(value).is_absolute():
            raise ValueError("Use an absolute private token-file path.")
        return value


class Attachment(Model):
    alias: Name
    engine: Literal["attached"]
    profile: Name
    profile_digest: Digest


def configure(state, source):
    from ..state_lock import StateLock
    from ..store import Store
    profiles = [Profile.model_validate(item) for item in json.loads(source.read_bytes())]
    if len(profiles) > 128 or len({p.name for p in profiles}) != len(profiles):
        raise ValueError("Configure at most 128 uniquely named endpoint profiles.")
    with StateLock(state):
        store = Store(state / "state.sqlite3")
        try:
            for profile in profiles:
                if profile.token_file:
                    credential(profile)
            store.set_setting("inference.endpoint_profiles", [p.model_dump() for p in profiles])
        finally:
            store.close()
    return {"configured": len(profiles), "restart_required": True}


def credential(profile):
    if not profile.token_file:
        return {}
    token = read_private(Path(profile.token_file), 8192).decode().strip()
    if not token or any(ord(char) < 33 or ord(char) > 126 for char in token):
        raise ValueError("The attached endpoint credential is invalid.")
    return {"Authorization": "Bearer " + token}


class Attached:
    def __init__(self, manager):
        self.manager = manager
        self.profiles = {p.name: p for p in [Profile.model_validate(item) for item in manager.service.store.get_setting("inference.endpoint_profiles", [])]}
        self.probed = {}
        self.checking = {}

    def available(self, actor):
        return [{"name": p.name, "digest": digest(p.model_dump()), "model": p.model,
                 "capabilities": p.capabilities, "concurrency": p.concurrency}
                for p in self.profiles.values() if actor.project_id in p.projects]

    def profile(self, spec, project):
        profile = self.profiles.get(spec["profile"])
        if profile is None or project not in profile.projects or digest(profile.model_dump()) != spec["profile_digest"]:
            raise Failure("endpoint_profile_changed", "The approved endpoint profile is absent or changed; configure this stopped service again.", 409)
        return profile

    async def health(self, value):
        profile = self.profile(value["spec"], value["project_id"])
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=10) as client:
            async with client.stream("GET", profile.url + "/models", headers=credential(profile)) as response:
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes(65536):
                    body.extend(chunk)
                    if len(body) > 2 * 1024 * 1024:
                        raise ValueError("The attached endpoint model list exceeds its limit.")
        if not any(item.get("id") == profile.model for item in json.loads(body).get("data", [])):
            raise ValueError("The configured model is not advertised by the attached endpoint.")

    async def reconcile(self, value):
        identity = value["id"]
        if value["desired"] != "running":
            if self.manager.gateway.active.get(identity, 0):
                value["state"] = "draining"
            else:
                value.update(desired="stopped", state="stopped", reason=None)
            task = self.checking.pop(identity, None)
            if task:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            return
        task = self.checking.get(identity)
        if task and task.done():
            try:
                task.result()
                value.update(state="ready", reason=None)
            except (Failure, OSError, ValueError, httpx.HTTPError):
                value.update(state="failed", reason="attached_endpoint_unavailable")
            self.probed[identity] = time.monotonic()
            del self.checking[identity]
        if identity not in self.checking and time.monotonic() - self.probed.get(identity, 0) > 15 and len(self.checking) < 4:
            self.checking[identity] = asyncio.create_task(self.health(value))

    async def invoke(self, record, path, body, actor):
        manager = self.manager
        identity = record["id"]
        profile = self.profile(record["spec"], record["project_id"])
        capability = "embeddings" if path == "/v1/embeddings" else "chat"
        if path not in {"/v1/chat/completions", "/v1/embeddings"} or capability not in profile.capabilities:
            raise Failure("inference_capability", "The attached endpoint does not offer this operation.", 409)
        body = {**body, "model": profile.model}
        if len(json.dumps(body).encode()) > 512 * 1024:
            raise Failure("inference_limit", "The inference request exceeds 512 KiB.", 413)
        count = manager.gateway.active.get(identity, 0)
        profile_key = "attached:" + record["spec"]["profile_digest"]
        load = manager.gateway.loads.get(profile_key, 0)
        if load >= profile.concurrency or sum(manager.gateway.active.values()) >= 128:
            raise Failure("inference_capacity", "All attached endpoint request slots are occupied.", 429)
        manager.gateway.active[identity] = count + 1
        manager.gateway.loads[profile_key] = load + 1
        client = httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=profile.deadline_seconds)
        end = time.monotonic() + profile.deadline_seconds
        def check():
            current = manager.get(identity, actor, "inference:invoke")
            self.profile(current["spec"], current["project_id"])
            if current["generation"] != record["generation"] or current["desired"] == "stopped":
                raise Failure("service_changed", "The inference service generation changed.", 409)
        try:
            check()
            request = client.build_request("POST", profile.url + path.removeprefix("/v1"), headers={"Accept-Encoding": "identity", **credential(profile)}, json=body)
            async with asyncio.timeout(profile.deadline_seconds):
                response = await client.send(request, stream=True)
        except BaseException:
            manager.gateway.active[identity] -= 1
            manager.gateway.loads[profile_key] -= 1
            await client.aclose()
            raise
        async def finish():
            try:
                await response.aclose()
            finally:
                await client.aclose()
                manager.gateway.active[identity] -= 1
                manager.gateway.loads[profile_key] -= 1
        async def chunks():
            received = 0
            try:
                async with asyncio.timeout(max(0.01, end - time.monotonic())):
                    async for chunk in response.aiter_raw():
                        check()
                        received += len(chunk)
                        if received > 64 * 1024 * 1024:
                            raise Failure("inference_limit", "The attached response exceeds 64 MiB.", 502)
                        yield chunk
            finally:
                await response.aclose()
        return response.status_code, Stream(chunks(), finish)

    async def close(self):
        for task in self.checking.values():
            task.cancel()
        await asyncio.gather(*self.checking.values(), return_exceptions=True)
