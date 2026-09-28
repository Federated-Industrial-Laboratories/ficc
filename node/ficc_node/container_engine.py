# SPDX-License-Identifier: Apache-2.0
"""Expose fixed Docker and Podman inventory, logs and existing-container power APIs."""

import os
from pathlib import Path

from . import container_spec as spec
from .container_http import HTTP, UnixConnection, log_text


class Engine:
    def __init__(self, value):
        self.provider = value["provider"]
        self.uid = 0 if value["connection"] == "rootful" else os.getuid()
        path = "/run/docker.sock" if self.uid == 0 and value["connection"] == "rootful" else (
            f"/run/user/{self.uid}/docker.sock" if self.provider == "docker" else f"/run/user/{self.uid}/podman/podman.sock")
        self.http = HTTP(lambda: UnixConnection(path, self.uid))
        version = self.http.json("GET", "/version", timeout=10)
        self.version = spec.text(version["Version"], 128)
        if self.provider == "docker":
            maximum, minimum = self.api_version(version["ApiVersion"]), self.api_version(version.get("MinAPIVersion", "1.24"))
            selected = min(maximum, 51)
            if selected < max(minimum, 24):
                raise spec.ProviderError("container_version", "This Docker API version is not supported.")
            self.prefix = f"/v1.{selected}"
            info = self.http.json("GET", self.prefix + "/info")
            engine_id = spec.text(info["ID"])
        else:
            major = int(self.version.split(".", 1)[0])
            if major not in {4, 5}:
                raise spec.ProviderError("container_version", "This Podman API version is not supported.")
            self.prefix = "/v4.0.0/libpod"
            info = self.http.json("GET", self.prefix + "/info")
            if info["host"]["security"]["rootless"] is not True:
                raise spec.ProviderError("container_socket", "Select the current account's rootless Podman socket.")
            engine_id = spec.digest({"machine": Path("/etc/machine-id").read_text().strip(), "store": info["store"]["graphRoot"]})
        self.binding = spec.digest({"provider": self.provider, "uid": self.uid, "engine": engine_id})
        if value["binding"] is not None and value["binding"] != self.binding:
            raise spec.ProviderError("container_profile_changed", "The registered container service identity changed.")

    @staticmethod
    def api_version(value):
        major, minor = value.split(".")
        if major != "1" or not minor.isdecimal():
            raise ValueError("Invalid Docker API version.")
        return int(minor)

    def probe(self):
        return {"binding": self.binding, "provider": self.provider, "version": self.version, "account_uid": self.uid}

    def describe(self, value):
        identity = spec.fingerprint(value["Id"])
        name = spec.text(value["Name"].removeprefix("/"))
        state = spec.text(value["State"]["Status"], 64)
        definition = spec.digest({key: value.get(key) for key in ("Id", "Created", "Image", "Config", "HostConfig")})
        revision = spec.digest({"definition": definition, "state": value["State"], "name": name})
        image = value.get("Config", {}).get("Image") or value.get("Image", "unknown")
        return {"resource": {"kind": "container", "id": identity, "namespace": "", "name": name},
                "state": state, "revision": revision, "definition": definition, "image": spec.text(image),
                "replicas": None, "ready": None, "containers": []}

    def inspect(self, resource):
        spec.pointer(resource)
        if resource["kind"] != "container":
            raise spec.ProviderError("container_kind", "This engine profile contains containers only.")
        value = self.http.json("GET", self.prefix + f"/containers/{resource['id']}/json")
        if value["Id"] != resource["id"]:
            raise spec.ProviderError("container_stale", "The selected container identity changed.")
        return value

    def inventory(self, kind, offset, limit):
        if kind not in {"all", "container"}:
            return {"results": [], "next_offset": None, "truncated": False}
        values = self.http.json("GET", self.prefix + "/containers/json", {"all": "true", "limit": 4097})
        if not isinstance(values, list) or len(values) > 4096:
            raise spec.ProviderError("container_limit", "The engine inventory exceeds 4096 containers.")
        ids = sorted(spec.fingerprint(item["Id"]) for item in values)
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate engine container identity.")
        results = []
        for identity in ids[offset:offset + limit]:
            pointer = {"kind": "container", "id": identity, "namespace": "", "name": identity}
            try:
                results.append({"resource": pointer, "data": self.describe(self.inspect(pointer))})
            except spec.ProviderError as exc:
                results.append({"resource": pointer, "error": spec.error(exc.code, exc.message)})
        next_offset = offset + len(results) if offset + len(results) < len(ids) else None
        return {"results": results, "next_offset": next_offset, "truncated": next_offset is not None}

    def status(self, resource):
        return self.describe(self.inspect(resource))

    def logs(self, resource, tail, limit, container):
        if container:
            raise spec.ProviderError("container_kind", "An engine container has no pod container selection.")
        value = self.inspect(resource)
        _, data, truncated = self.http.request("GET", self.prefix + f"/containers/{resource['id']}/logs",
            {"stdout": "true", "stderr": "true", "follow": "false", "tail": tail}, limit=min(1048576, limit * 4 + 65536))
        if value.get("Config", {}).get("Tty"):
            output = data
        else:
            output = bytearray()
            offset = 0
            while offset < len(data):
                if len(data) - offset < 8:
                    if truncated:
                        break
                    raise ValueError("Invalid engine log frame.")
                header = data[offset:offset + 8]
                size = int.from_bytes(header[4:], "big")
                if header[0] not in {0, 1, 2} or header[1:4] != b"\0\0\0":
                    raise ValueError("Invalid engine log stream.")
                available = min(size, len(data) - offset - 8)
                output.extend(data[offset + 8:offset + 8 + min(available, max(0, limit + 1 - len(output)))])
                offset += 8 + size
                if available < size and not truncated:
                    raise ValueError("Incomplete engine log frame.")
                if len(output) > limit:
                    truncated = True
                    break
        return {"text": log_text(output, limit), "truncated": truncated or len(output) > limit}

    def apply(self, action, expected, replicas):
        current = self.status(expected["resource"])
        if any(current[key] != expected[key] for key in ("revision", "definition", "state")):
            return {"state": "refused", "error": spec.error("container_stale", "The container changed after preview.")}
        allowed = {"start": {"created", "exited", "stopped"}, "stop": {"running"}}
        if action not in allowed or current["state"] not in allowed[action] or replicas is not None:
            return {"state": "refused", "error": spec.error("container_state", "The selected state action is not valid.")}
        query = ({"t": 10} if self.provider == "docker" else {"timeout": 10}) if action == "stop" else None
        self.http.request("POST", self.prefix + f"/containers/{expected['resource']['id']}/{action}", query, limit=4096, timeout=30)
        return {"state": "accepted"}

    def close(self):
        pass
