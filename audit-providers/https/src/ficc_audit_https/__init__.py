# SPDX-License-Identifier: Apache-2.0
"""Send authenticated bounded audit batches to one administrator-selected TLS endpoint."""

import json
import re
import ssl
from urllib.parse import urlsplit

import httpx

from ficc.audit_sdk import MAX_ACK, AuditError, batch

API_VERSION = 1


class Destination:
    def __init__(self, config):
        try:
            if set(config) != {"url", "ca_pem"}:
                raise ValueError()
            url = urlsplit(config["url"])
            if (url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment
                    or not url.path or len(config["url"]) > 2048 or len(config["ca_pem"]) > 16384):
                raise ValueError()
            self.url = config["url"]
            self.context = ssl.create_default_context(cadata=config["ca_pem"])
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            raise AuditError("audit_configuration") from None

    async def append(self, raw, credential):
        batch(raw)
        try:
            token = credential.decode("ascii")
            if not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", token):
                raise ValueError()
            async with httpx.AsyncClient(verify=self.context, trust_env=False, follow_redirects=False,
                                         timeout=3, limits=httpx.Limits(max_connections=1, max_keepalive_connections=0)) as client:
                async with client.stream("POST", self.url, content=raw, headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + token}) as response:
                    if response.status_code != 200 or response.headers.get("content-encoding", "identity") != "identity":
                        raise AuditError("audit_acknowledgement")
                    data = bytearray()
                    async for chunk in response.aiter_raw():
                        data.extend(chunk)
                        if len(data) > MAX_ACK:
                            raise AuditError("audit_acknowledgement")
                    return json.loads(data)
        except AuditError:
            raise
        except Exception:
            raise AuditError() from None


def configure(configuration):
    return Destination(configuration)
