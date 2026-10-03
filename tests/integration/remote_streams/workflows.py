# SPDX-License-Identifier: Apache-2.0
"""Drive authenticated HTTPS operations and binary terminal traffic."""

import asyncio
import contextlib
import hashlib
import json
import secrets
import time

from websockets.asyncio.client import connect


async def request(client, method, path, **kwargs):
    response = await client.request(method, path, **kwargs)
    if response.status_code not in (200, 201, 202):
        try:
            code = response.json().get("error", {}).get("code", "unknown")
        except ValueError:
            code = "non_json_response"
        assert False, f"Remote HTTP{response.status_code}: {str(code)[:80]}."
    return response.json()


async def terminal(client, node, index):
    return await request(client, "POST", "/api/v1/terminals", json={"node_id": node,
        "mode": "ephemeral", "label": f"Remote stream {index}", "cols": 80, "rows": 24,
        "confirm_execution": True, "idempotency_key": secrets.token_hex(16)})


@contextlib.asynccontextmanager
async def attached(lab, client, record):
    value = await request(client, "POST", f"/api/v1/terminals/{record['id']}/tickets")
    url = lab.origin.replace("https://", "wss://") + value["websocket_path"]
    async with connect(url, ssl=lab.tls, origin=lab.origin, proxy=None,
                       open_timeout=10, close_timeout=2, max_size=65536, compression=None) as socket:
        await socket.send(json.dumps({"type": "auth", "ticket": value["ticket"]}))
        result = json.loads(await asyncio.wait_for(socket.recv(), 15))
        assert result["state"] == "attached"
        yield socket, value


async def until(socket, marker):
    result = bytearray()
    async with asyncio.timeout(15):
        while marker not in result:
            value = await socket.recv()
            assert isinstance(value, bytes), "The terminal closed before its output proof."
            result.extend(value)
            assert len(result) <= 262144
            await socket.send(json.dumps({"type": "ack", "bytes": len(value)}))
    return bytes(result)


async def proof(socket, identity):
    marker = ("PROOF_" + identity).encode()
    await socket.send(f"stty -echo; printf '\\120ROOF_%s\\n' '{identity}'\n".encode())
    return await until(socket, marker)


async def detached(client, record):
    end = time.monotonic() + 5
    while time.monotonic() < end:
        value = await request(client, "GET", f"/api/v1/terminals/{record['id']}")
        if value["state"] in {"exited", "interrupted", "stopped"}:
            return
        await asyncio.sleep(0.05)
    raise AssertionError("The disconnected terminal did not release its session.")


async def download(client, root_id, filename):
    roots = (await request(client, "GET", "/api/v1/file-roots"))["roots"]
    root = next(value for value in roots if value["id"] == root_id)
    listing = await request(client, "POST", "/api/v1/files/list", json={
        "root_id": root_id, "entry_id": root["entry_id"], "limit": 200})
    entry = next(value for value in listing["entries"] if value["name"] == filename)
    preview = await request(client, "POST", "/api/v1/transfer-previews", json={"kind": "download",
        "sources": [{"root_id": root_id, "entry_id": entry["entry_id"]}]})
    operation = await request(client, "POST", "/api/v1/transfers", json={
        "preview_id": preview["preview_id"], "confirm": True},
        headers={"Idempotency-Key": secrets.token_hex(16)})
    end = time.monotonic() + 60
    progress = []
    while time.monotonic() < end:
        current = await request(client, "GET", "/api/v1/transfers/" + operation["id"])
        item = current["items"][0]
        state = (item["state"], item["offset"])
        if not progress or progress[-1] != state:
            progress = [*progress[-15:], state]
        if item["state"] == "succeeded":
            return f"/api/v1/transfers/{operation['id']}/items/{item['id']}/content", item
        code = (item.get("error") or {}).get("code", "none")
        assert item["state"] not in {"failed", "unknown", "cancelled", "interrupted"}, str(code)[:80]
        await asyncio.sleep(0.05)
    raise AssertionError(f"The file download was not prepared: {progress}, {item['offset']}/{item['size']} bytes.")


async def verify_download(client, path, content):
    result = hashlib.sha256()
    count = 0
    async with client.stream("GET", path) as response:
        assert response.status_code == 200
        assert response.headers["x-content-sha256"] == hashlib.sha256(content).hexdigest()
        async for data in response.aiter_bytes(65536):
            count += len(data)
            result.update(data)
            assert count <= len(content)
    assert count == len(content) and result.digest() == hashlib.sha256(content).digest()
