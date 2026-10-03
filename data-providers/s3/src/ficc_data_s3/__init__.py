# SPDX-License-Identifier: Apache-2.0
"""Approved S3-compatible object access and explicit resumable multipart writes."""

import base64
import hashlib
import io
import math
import socket
from contextlib import contextmanager
from urllib.parse import urlsplit

from pydantic import Field

from ficc.data_sdk import DataError
from ficc.schema import Model

API_VERSION = 1
METADATA = {"kind": "network", "source_consistency": "version", "write": True, "objects": True,
            "description": "Approved S3 bucket/prefix, versioned reads and SHA256-verified resumable multipart uploads."}


class Configuration(Model):
    bucket: str = Field(min_length=3, max_length=63, pattern=r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")
    prefix: str = Field(max_length=1024)
    region: str = Field(default="us-east-1", min_length=1, max_length=80)
    part_bytes: int = Field(default=8 * 1024**2, ge=5 * 1024**2, le=5 * 1024**3)


class Query(Model):
    key: str = Field(min_length=1, max_length=1024)
    version_id: str | None = Field(default=None, max_length=2048)
    sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


def configuration(value):
    return Configuration.model_validate(value).model_dump()


def query(value, mode):
    if mode != "read":
        raise DataError("object_upload_required", "Use the explicit dataset multipart workflow for object writes.")
    result = Query.model_validate(value).model_dump()
    if not result["version_id"] and not result["sha256"]:
        raise DataError("version_required", "Pin an object version or an expected whole-object SHA256.")
    return result


@contextmanager
def client(context):
    import boto3  # type: ignore[import-untyped]
    from botocore.awsrequest import (  # type: ignore[import-untyped]
        AWSHTTPSConnection,
        AWSHTTPSConnectionPool,
    )
    from botocore.config import Config  # type: ignore[import-untyped]

    endpoint = context.endpoint

    class PinnedConnection(AWSHTTPSConnection):
        def _new_conn(self):
            if self.host != endpoint["host"] or self.port != endpoint["port"]:
                raise DataError("endpoint_unapproved", "The object request changed its approved endpoint.")
            return socket.create_connection((endpoint["address"], endpoint["port"]), timeout=10)

    class PinnedPool(AWSHTTPSConnectionPool):
        ConnectionCls = PinnedConnection

    with context.ca_file() as ca:
        value = boto3.client("s3", endpoint_url=f"https://{endpoint['host']}:{endpoint['port']}", region_name=context.configuration["region"],
            aws_access_key_id=context.secret["access_key_id"], aws_secret_access_key=context.secret["secret_access_key"],
            aws_session_token=context.secret.get("session_token"), verify=ca,
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"total_max_attempts": 1},
                          connect_timeout=10, read_timeout=60, proxies={}))
        manager = value._endpoint.http_session._manager
        manager.pool_classes_by_scheme = {**manager.pool_classes_by_scheme, "https": PinnedPool}

        def approved(request, **kwargs):
            url = urlsplit(request.url)
            if url.scheme != "https" or url.hostname != endpoint["host"] or (url.port or 443) != endpoint["port"]:
                raise DataError("endpoint_unapproved", "Object redirects cannot expand the approved endpoint.")
        value.meta.events.register("before-send.s3", approved)
        try:
            yield value
        finally:
            value.close()


def selected(context, key):
    if not isinstance(key, str) or not key.startswith(context.configuration["prefix"]) or "\0" in key or len(key) > 1024:
        raise DataError("object_denied", "The object key is outside its approved prefix.")
    return {"Bucket": context.configuration["bucket"], "Key": key}


def execute(context, action, request):
    with client(context) as api:
        if action == "object":
            yield from multipart(api, context, request)
            return
        if action == "catalogue":
            result = api.list_objects_v2(Bucket=context.configuration["bucket"], Prefix=context.configuration["prefix"], MaxKeys=100,
                **({"ContinuationToken": request["cursor"]} if request.get("cursor") else {}))
            yield {"kind": "catalogue", "resources": [{"id": item["Key"], "name": item["Key"], "kind": "object", "size": item["Size"]} for item in result.get("Contents", [])],
                   "next_cursor": result.get("NextContinuationToken")}
            yield {"kind": "receipt", "consistency": "paged-current-list", "rows": 0}
            return
        spec = request["specification"] if action == "query" else {"key": request["resource"]}
        target = selected(context, spec["key"])
        if spec.get("version_id"):
            target["VersionId"] = spec["version_id"]
        head = api.head_object(**target)
        receipt = {"kind": "receipt", "consistency": "object-version", "version_id": head.get("VersionId"),
                   "etag": head["ETag"], "bytes": head["ContentLength"], "rows": 0,
                   "sha256_metadata": head.get("Metadata", {}).get("ficc-sha256"), "tls_verified": True}
        yield {"kind": "schema", "schema": {"fields": [], "description": "Immutable object bytes."}}
        if action == "describe":
            yield receipt
            return
        response = api.get_object(**target, IfMatch=head["ETag"], **({"Range": "bytes=0-4095"} if context.limit is not None and head["ContentLength"] else {}))
        digest = hashlib.sha256()
        count = 0
        try:
            while chunk := response["Body"].read(131072):
                digest.update(chunk)
                count += len(chunk)
                yield {"kind": "bytes", "data": base64.b64encode(chunk).decode()}
        finally:
            response["Body"].close()
        if context.limit is None and (count != head["ContentLength"] or spec.get("sha256") and digest.hexdigest() != spec["sha256"]):
            raise DataError("object_changed", "The object does not match its pinned size and checksum.")
        yield {**receipt, "sha256": digest.hexdigest(), "read_bytes": count, "partial": context.limit is not None}


class Part(io.RawIOBase):
    def __init__(self, source, start, size):
        self.source, self.start, self.size, self.position = source, start, size, 0
        source.seek(start)

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        position = offset if whence == 0 else self.position + offset if whence == 1 else self.size + offset
        if not 0 <= position <= self.size:
            raise ValueError("Part seek")
        self.position = position
        self.source.seek(self.start + position)
        return position

    def read(self, size=-1):
        data = self.source.read(min(131072, self.size - self.position, size if size >= 0 else 131072))
        self.position += len(data)
        return data


def digest_part(source, start, size, full=None):
    part = Part(source, start, size)
    digest = hashlib.sha256()
    while chunk := part.read():
        digest.update(chunk)
        if full is not None:
            full.update(chunk)
    if part.tell() != size:
        raise DataError("source_changed", "The dataset source ended before its pinned size.")
    part.seek(0)
    return part, base64.b64encode(digest.digest()).decode()


def verified_object(api, context, request, version=None):
    target = selected(context, request["key"])
    result = api.head_object(**target, **({"VersionId": version} if version else {}))
    metadata = result.get("Metadata", {})
    if (result["ContentLength"] != request["size"] or metadata.get("ficc-sha256") != request["sha256"]
            or metadata.get("ficc-dataset") != request["manifest_digest"]):
        raise DataError("publication_unknown", "The published object does not match the retained dataset upload.")
    response = api.get_object(**target, IfMatch=result["ETag"], **({"VersionId": result["VersionId"]} if result.get("VersionId") else {}))
    digest = hashlib.sha256()
    try:
        while chunk := response["Body"].read(131072):
            digest.update(chunk)
    finally:
        response["Body"].close()
    if digest.hexdigest() != request["sha256"]:
        raise DataError("publication_unknown", "The object bytes do not match the retained dataset checksum.")
    return {"kind": "receipt", "outcome": "completed", "version_id": result.get("VersionId"), "etag": result["ETag"],
            "sha256": request["sha256"], "bytes": request["size"], "reconciled": request["operation"] == "reconcile"}


def multipart(api, context, request):
    target = selected(context, request["key"])
    operation = request["operation"]
    if operation == "reconcile":
        yield verified_object(api, context, request)
        return
    if operation == "begin":
        size = request["size"]
        part_bytes = max(context.configuration["part_bytes"], math.ceil(max(1, size) / 10000))
        if part_bytes > 5 * 1024**3:
            raise DataError("provider_limit", "The object exceeds the S3 multipart protocol limits.")
        yield {"kind": "committing"}
        result = api.create_multipart_upload(**target, ChecksumAlgorithm="SHA256", Metadata={
            "ficc-sha256": request["sha256"], "ficc-dataset": request["manifest_digest"]})
        yield {"kind": "receipt", "upload_id": result["UploadId"], "part_bytes": part_bytes,
               "parts": max(1, math.ceil(size / part_bytes)), "outcome": "created"}
        return
    target["UploadId"] = request["upload_id"]
    acknowledged = {item["part_number"]: item for item in context.part_receipts()}

    def acknowledged_checksum(item):
        saved = acknowledged.get(item["PartNumber"])
        if saved and saved["size"] == item["Size"] and saved["etag"] == item["ETag"]:
            return saved["checksum_sha256"]
        return None
    if operation == "abort":
        yield {"kind": "committing"}
        api.abort_multipart_upload(**target)
        yield {"kind": "receipt", "outcome": "aborted"}
        return
    if operation == "status":
        result = api.list_parts(**target, MaxParts=100, PartNumberMarker=request.get("cursor", 0))
        yield {"kind": "receipt", "outcome": "uploading", "parts": [{"part_number": item["PartNumber"], "size": item["Size"],
            "checksum_sha256": acknowledged_checksum(item), "verified": bool(acknowledged_checksum(item)) and
                item.get("ChecksumSHA256", acknowledged_checksum(item)) == acknowledged_checksum(item),
            "etag": item["ETag"]} for item in result.get("Parts", [])],
            "next_cursor": result.get("NextPartNumberMarker") if result.get("IsTruncated") else None}
        return
    with context.open_source() as source:
        size, part_bytes = request["size"], request["part_bytes"]
        if operation == "part":
            number = request["part_number"]
            start = (number - 1) * part_bytes
            if start > size or number < 1 or number > max(1, math.ceil(size / part_bytes)):
                raise DataError("invalid_part", "The part is outside the immutable dataset source.")
            body, checksum = digest_part(source, start, min(part_bytes, size - start))
            yield {"kind": "committing"}
            result = api.upload_part(**target, PartNumber=number, Body=body, ContentLength=body.size, ChecksumSHA256=checksum)
            if result.get("ChecksumSHA256") != checksum:
                raise DataError("checksum_unsupported", "The object service did not confirm the uploaded part checksum.")
            context.source_unchanged()
            yield {"kind": "receipt", "outcome": "part_uploaded", "part_number": number, "size": body.size,
                   "checksum_sha256": checksum, "etag": result["ETag"]}
            return
        parts: list[dict] = []
        cursor, full = 0, hashlib.sha256()
        while True:
            response = api.list_parts(**target, MaxParts=100, PartNumberMarker=cursor)
            for item in response.get("Parts", []):
                number = len(parts) + 1
                expected = min(part_bytes, size - (number - 1) * part_bytes)
                if expected < 0 or item["PartNumber"] != number or item["Size"] != expected:
                    raise DataError("parts_incomplete", "The retained object parts differ from the immutable dataset.")
                _, checksum = digest_part(source, (number - 1) * part_bytes, expected, full)
                if acknowledged_checksum(item) != checksum or item.get("ChecksumSHA256", checksum) != checksum:
                    raise DataError("parts_changed", "An object part checksum differs from the immutable dataset.")
                parts.append({"PartNumber": number, "ETag": item["ETag"], "ChecksumSHA256": checksum})
            if not response.get("IsTruncated"):
                break
            following = response["NextPartNumberMarker"]
            if following <= cursor or len(parts) >= 10000:
                raise DataError("parts_invalid", "The object service returned invalid part pagination.")
            cursor = following
        if len(parts) != max(1, math.ceil(size / part_bytes)) or full.hexdigest() != request["sha256"]:
            raise DataError("parts_incomplete", "Complete and verify every part of the same dataset before publication.")
        context.source_unchanged()
        yield {"kind": "committing"}
        try:
            result = api.complete_multipart_upload(**target, MultipartUpload={"Parts": parts}, IfNoneMatch="*")
            verified = verified_object(api, context, request, result.get("VersionId"))
        except Exception:
            yield {"kind": "receipt", "outcome": "unknown", "reason": "completion_acknowledgement_missing"}
            return
        yield {**verified, "parts": len(parts), "checksum_algorithm": "sha256", "verification": "whole-object-readback"}
