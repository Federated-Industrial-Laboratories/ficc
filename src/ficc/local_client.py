# SPDX-License-Identifier: Apache-2.0
"""Keep owner CLI requests on the private controller path in remote mode."""

from urllib.parse import urlsplit

import httpx

from .remote_settings import configuration


def client(grant, state, *, timeout=90, base_path=""):
    headers = {"Authorization": "Bearer " + grant["credential"]}
    remote = configuration(state)
    if remote is None:
        return httpx.Client(base_url=grant["origin"] + base_path, headers=headers,
                            timeout=timeout, trust_env=False, follow_redirects=False)
    if grant["origin"] != remote.origin:
        raise ValueError("The remote origin changed. Restart the controller before using its command line.")
    host = urlsplit(remote.origin).netloc
    headers.update({"Host": host, "X-FICC-Gateway": remote.secret, "X-FICC-Client-IP": "127.0.0.1"})
    return httpx.Client(base_url="http://" + host + base_path, headers=headers, timeout=timeout,
                        transport=httpx.HTTPTransport(uds=str(remote.socket)), trust_env=False, follow_redirects=False)
