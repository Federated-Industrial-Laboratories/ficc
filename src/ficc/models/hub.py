# SPDX-License-Identifier: Apache-2.0
"""Resolve public Hub metadata into immutable manifests without downloading weights."""
import asyncio
import json
import re
from typing import Annotated
from urllib.parse import quote

import httpx
from pydantic import Field

from ..errors import Failure
from ..schema import Model
from .schema import File, Manifest
from .sources import allowed


class Selection(Model):
    repository: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")]
    revision: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$")] = "main"
    filename: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.gguf$")] | None = None
    licence: Annotated[str, Field(min_length=1, max_length=200)] | None = None


async def inspect(selection, hosts):
    url = "https://huggingface.co/api/models/" + selection.repository + "/revision/" + quote(selection.revision, safe="")
    allowed(url, hosts)
    try:
        async with asyncio.timeout(30), httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=20) as client:
            async with client.stream("GET", url, params={"blobs": "true"}) as response:
                if response.status_code != 200:
                    raise Failure("model_hub_unavailable", "The public repository or revision is unavailable. Use a local manifest for gated or private weights.", 409)
                body = bytearray()
                async for data in response.aiter_bytes(65536):
                    body.extend(data)
                    if len(body) > 4 * 1024 * 1024:
                        raise Failure("model_hub_limit", "The repository metadata exceeds the import bound. Use an explicit manifest.", 409)
        return manifests(selection, json.loads(body))
    except (httpx.HTTPError, TimeoutError, ValueError, KeyError, TypeError):
        raise Failure("model_hub_metadata", "The Hub did not return complete immutable file metadata. Retry or register an explicit manifest.", 502) from None


def manifests(selection, metadata):
    revision = metadata["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("A full source commit is required.")
    licence = selection.licence or (metadata.get("cardData") or {}).get("license")
    if not isinstance(licence, str) or not licence:
        raise Failure("model_licence_required", "This repository does not declare a licence. Enter the publisher's licence before import.", 409)
    result = []
    for item in metadata["siblings"]:
        name = item["rfilename"]
        if selection.filename and name != selection.filename:
            continue
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.gguf", name) or re.search(r"-\d{5}-of-\d{5}\.gguf$", name):
            continue
        lfs = item.get("lfs") or {}
        if not re.fullmatch(r"[0-9a-f]{64}", lfs.get("sha256", "")) or lfs.get("size") != item.get("size"):
            continue
        quantization = re.search(r"(?:^|[-.])((?:I?Q|BF|F)\d[A-Za-z0-9_]*)\.gguf$", name, re.IGNORECASE)
        manifest = Manifest(name=(selection.repository.split("/")[1] + " / " + name)[:120], revision=revision,
            licence=licence, source=selection.repository, format="gguf", entrypoint=name,
            quantization=quantization[1] if quantization else "unspecified", files=[File(name=name,
                digest="sha256:" + lfs["sha256"], bytes=item["size"],
                url="https://huggingface.co/" + selection.repository + "/resolve/" + revision + "/" + quote(name, safe=""))])
        result.append(manifest.model_dump())
    if not result:
        raise Failure("model_hub_files", "No complete single-file GGUF with a published SHA256 matched. Use an explicit manifest for split or safetensors weights.", 409)
    if len(result) > 64:
        raise Failure("model_hub_limit", "This repository has more than 64 matching weights. Enter an exact GGUF filename.", 409)
    return {"repository": selection.repository, "revision": revision, "licence": licence, "manifests": result}
