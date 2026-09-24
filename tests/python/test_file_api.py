# SPDX-License-Identifier: Apache-2.0
"""Exercise authenticated browser upload, download, and content refusal routes."""

import hashlib
import time


def test_http_upload_verified_download_and_cleanup(console, tmp_path):
    client, service = console
    path = tmp_path / "files"
    path.mkdir()
    root = client.portal.call(service.files.register, str(path), "Files")
    roots = client.get("/api/v1/file-roots").json()["roots"]
    assert len(roots) == 1 and "path" not in roots[0]
    location = {"root_id": root["id"], "entry_id": roots[0]["entry_id"]}
    payload = bytes([0, 255, 60, 62, 10])
    preview = client.post("/api/v1/transfer-previews", json={"kind": "upload", "sources": [
        {"name": "input.bin", "size": len(payload), "last_modified": 1}], "destination": location})
    assert preview.status_code == 200, preview.text
    operation = client.post("/api/v1/transfers", json={"preview_id": preview.json()["preview_id"], "confirm": True},
                            headers={"Idempotency-Key": "api-upload-identity"})
    assert operation.status_code == 202, operation.text
    operation = operation.json()
    item = operation["items"][0]
    url = f"/api/v1/transfers/{operation['id']}/items/{item['id']}"
    headers = {"Content-Type": "application/octet-stream", "X-Chunk-SHA256": hashlib.sha256(payload).hexdigest()}
    assert client.put(url + "/chunks?offset=0", content=payload, headers={**headers, "X-CSRF-Token": "wrong"}).status_code == 403
    assert not (path / "input.bin").exists()
    assert client.put(url + "/chunks?offset=0", content=payload, headers=headers).status_code == 200
    assert client.post(url + "/finish", json={}).json()["state"] == "succeeded"
    entries = client.post("/api/v1/files/list", json=location).json()["entries"]
    preview = client.post("/api/v1/transfer-previews", json={"kind": "download", "sources": [
        {"root_id": root["id"], "entry_id": entries[0]["entry_id"]}]})
    download = client.post("/api/v1/transfers", json={"preview_id": preview.json()["preview_id"], "confirm": True},
                           headers={"Idempotency-Key": "api-download-identity"}).json()
    for _ in range(100):
        current = client.get("/api/v1/transfers/" + download["id"]).json()
        if current["state"] == "succeeded":
            break
        time.sleep(0.02)
    assert current["state"] == "succeeded", current
    item = current["items"][0]
    url = f"/api/v1/transfers/{current['id']}/items/{item['id']}/content"
    response = client.get(url)
    assert response.status_code == 200 and response.content == payload
    assert response.headers["content-disposition"].startswith("attachment;")
    assert response.headers["x-content-sha256"] == hashlib.sha256(payload).hexdigest()
    response = client.post("/api/v1/transfers/" + current["id"] + "/cancel",
                           json={"item_ids": [item["id"]], "discard_partial": True})
    assert response.status_code == 200 and response.json()["state"] == "cancelled"
    assert client.get(url).status_code == 409 and (path / "input.bin").read_bytes() == payload


def test_http_scoped_root_and_required_confirmation(console, tmp_path):
    client, service = console
    path = tmp_path / "files"
    path.mkdir()
    root = client.portal.call(service.files.register, str(path), "Files")
    entry = service.files.refs.issue(root, root["reference"])
    denied, _ = service.auth.issue("token", scopes=["files:read"], root_ids=[])
    assert client.post("/api/v1/files/list", json={"root_id": root["id"], "entry_id": entry},
                       headers={"Authorization": "Bearer " + denied}).status_code == 403
    preview = client.post("/api/v1/file-operation-previews", json={"action": "mkdir", "root_id": root["id"],
                           "parent_id": entry, "name": "created"}).json()
    response = client.post("/api/v1/file-operations", json={"preview_id": preview["preview_id"], "confirm": False},
                           headers={"Idempotency-Key": "unconfirmed-mutation"})
    assert response.status_code == 422 and not (path / "created").exists()


def test_transfer_history_requires_read_but_write_receipts_remain_usable(console, tmp_path):
    client, service = console
    path = tmp_path / "files"
    path.mkdir()
    root = client.portal.call(service.files.register, str(path), "Files")
    location = {"root_id": root["id"], "entry_id": service.files.refs.issue(root, root["reference"])}
    preview = client.post("/api/v1/transfer-previews", json={"kind": "upload", "sources": [
        {"name": "owner-private-name", "size": 0}], "destination": location}).json()
    operation = client.post("/api/v1/transfers", json={"preview_id": preview["preview_id"], "confirm": True},
                            headers={"Idempotency-Key": "owner-private-upload"}).json()
    detail = "/api/v1/transfers/" + operation["id"]
    assert client.post(detail + "/items/" + operation["items"][0]["id"] + "/finish", json={}).status_code == 200
    writer, _ = service.auth.issue("token", scopes=["files:write"], root_ids=[root["id"]])
    reader, reader_actor = service.auth.issue("token", scopes=["files:read"], root_ids=[root["id"]])
    denied, _ = service.auth.issue("token", scopes=["files:read"], root_ids=[])
    for token in (writer, denied):
        headers = {"Authorization": "Bearer " + token}
        assert client.get("/api/v1/transfers", headers=headers).json() == {"transfers": []}
        assert client.get(detail, headers=headers).status_code == 404
    for headers in ({}, {"Authorization": "Bearer " + reader}):
        assert client.get(detail, headers=headers).json()["items"][0]["name"] == "owner-private-name"
        assert len(client.get("/api/v1/transfers", headers=headers).json()["transfers"]) == 1
    service.auth.revoke(reader_actor.id)
    assert client.get(detail, headers={"Authorization": "Bearer " + reader}).status_code == 401
    headers = {"Authorization": "Bearer " + writer}
    preview = client.post("/api/v1/transfer-previews", json={"kind": "upload", "sources": [
        {"name": "write-only-upload", "size": 0}], "destination": location}, headers=headers).json()
    response = client.post("/api/v1/transfers", json={"preview_id": preview["preview_id"], "confirm": True},
                           headers={**headers, "Idempotency-Key": "write-only-upload"})
    assert response.status_code == 202, response.text
    own = response.json()
    response = client.post(f"/api/v1/transfers/{own['id']}/items/{own['items'][0]['id']}/finish", json={}, headers=headers)
    assert response.status_code == 200 and response.json()["state"] == "succeeded"
    assert (path / "write-only-upload").read_bytes() == b""
    assert client.get("/api/v1/transfers", headers=headers).json() == {"transfers": []}
