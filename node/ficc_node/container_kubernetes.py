# SPDX-License-Identifier: Apache-2.0
"""Use fixed Kubernetes read, pod-log and conditional scale subresources."""

import os
import uuid

from . import container_spec as spec
from .container_http import log_text
from .container_kubeconfig import load

KINDS = {"pod": ("/api/v1", "pods"), "deployment": ("/apis/apps/v1", "deployments"),
         "statefulset": ("/apis/apps/v1", "statefulsets")}


class Kubernetes:
    def __init__(self, value):
        self.http, self.binding = load(value)
        self.namespace = value["namespace"]
        self.version = spec.text(self.http.json("GET", "/version")["gitVersion"], 128)

    def probe(self):
        return {"binding": self.binding, "provider": "kubernetes", "version": self.version, "account_uid": os.getuid()}

    def path(self, resource):
        spec.pointer(resource)
        if resource["kind"] not in KINDS or resource["namespace"] != self.namespace:
            raise spec.ProviderError("container_namespace", "The workload is outside the registered Kubernetes namespace.")
        prefix, plural = KINDS[resource["kind"]]
        return f"{prefix}/namespaces/{self.namespace}/{plural}/{resource['name']}"

    def describe(self, value, kind):
        metadata, definition = value["metadata"], value["spec"]
        identity = uuid.UUID(metadata["uid"]).hex
        pointer = {"kind": kind, "id": identity, "namespace": spec.name(metadata["namespace"], 63),
                   "name": spec.name(metadata["name"])}
        if pointer["namespace"] != self.namespace:
            raise ValueError("The Kubernetes response selected a different namespace.")
        template = definition if kind == "pod" else definition["template"]["spec"]
        containers = template.get("containers", [])
        if not isinstance(containers, list) or not 1 <= len(containers) <= 64:
            raise ValueError("The workload container count exceeds its limit.")
        names = [spec.name(item["name"], 63) for item in containers]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate pod container name.")
        images = ", ".join(str(item.get("image", "unknown")) for item in containers)
        status = value.get("status", {})
        replicas = None if kind == "pod" else spec.integer(definition.get("replicas", 1), 0, 1000000)
        ready = (sum(item.get("ready") is True for item in status.get("containerStatuses", [])) if kind == "pod"
                 else spec.integer(status.get("readyReplicas", 0), 0, 1000000))
        state = str(status.get("phase", "Unknown")).lower() if kind == "pod" else "ready" if replicas == ready else "progressing"
        return {"resource": pointer, "state": spec.text(state, 64), "revision": spec.text(metadata["resourceVersion"], 128),
                "definition": spec.digest(definition), "image": spec.text(images[:256]), "replicas": replicas,
                "ready": ready, "containers": names}

    def inventory(self, kind, offset, limit):
        selected = sorted(KINDS) if kind == "all" else [kind] if kind in KINDS else []
        rows: list[dict] = []
        needed = offset + limit + 1
        for current in selected:
            prefix, plural = KINDS[current]
            token = None
            while len(rows) < needed:
                query = {"limit": min(64, needed - len(rows))}
                if token:
                    query["continue"] = token
                page = self.http.json("GET", f"{prefix}/namespaces/{self.namespace}/{plural}", query)
                items = page["items"]
                if not isinstance(items, list) or len(items) > query["limit"]:
                    raise ValueError("Invalid Kubernetes inventory page.")
                for item in items:
                    data = self.describe(item, current)
                    rows.append({"resource": data["resource"], "data": data})
                next_token = page.get("metadata", {}).get("continue")
                if not next_token:
                    break
                spec.text(next_token, 4096)
                if next_token == token or not items:
                    raise ValueError("The Kubernetes inventory cursor did not advance.")
                token = next_token
            if len(rows) >= needed:
                break
        selected_rows = rows[offset:offset + limit]
        more = len(rows) > offset + limit
        return {"results": selected_rows, "next_offset": offset + len(selected_rows) if more else None, "truncated": more}

    def status(self, resource):
        value = self.http.json("GET", self.path(resource))
        if uuid.UUID(value["metadata"]["uid"]).hex != resource["id"]:
            raise spec.ProviderError("container_stale", "The named workload was replaced. Refresh its identity.")
        return self.describe(value, resource["kind"])

    def logs(self, resource, tail, limit, container):
        current = self.status(resource)
        if resource["kind"] != "pod":
            raise spec.ProviderError("container_kind", "Select a pod for Kubernetes logs.")
        names = current["containers"]
        if not container and len(names) == 1:
            container = names[0]
        if container not in names:
            raise spec.ProviderError("container_selection", "Select one named container from this pod.")
        _, data, truncated = self.http.request("GET", self.path(resource) + "/log",
            {"container": container, "tailLines": tail, "limitBytes": limit, "follow": "false"}, limit=limit)
        self.status(resource)
        return {"text": log_text(data, limit), "truncated": truncated or len(data) == limit}

    def apply(self, action, expected, replicas):
        resource = expected["resource"]
        if action != "scale" or resource["kind"] not in {"deployment", "statefulset"}:
            return {"state": "refused", "error": spec.error("container_kind", "Only Deployment and StatefulSet replica counts can be changed.")}
        current = self.status(resource)
        if any(current[key] != expected[key] for key in ("definition", "revision", "replicas")):
            return {"state": "refused", "error": spec.error("container_stale", "The workload changed after preview.")}
        path = self.path(resource) + "/scale"
        scale = self.http.json("GET", path)
        if (uuid.UUID(scale["metadata"]["uid"]).hex != resource["id"] or scale["metadata"]["resourceVersion"] != expected["revision"]
                or scale["spec"].get("replicas", 0) != expected["replicas"]):
            return {"state": "refused", "error": spec.error("container_stale", "The workload scale changed after preview.")}
        patch = [{"op": "test", "path": "/metadata/uid", "value": scale["metadata"]["uid"]},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": expected["revision"]},
                 {"op": "test", "path": "/spec", "value": scale["spec"]},
                 {"op": "add", "path": "/spec/replicas", "value": spec.integer(replicas, 0, 64)}]
        self.http.json("PATCH", path, body=patch, content_type="application/json-patch+json")
        return {"state": "accepted"}

    def close(self):
        pass
