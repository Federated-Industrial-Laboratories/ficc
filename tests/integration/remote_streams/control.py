# SPDX-License-Identifier: Apache-2.0
"""Revoke a disposable identity through the actual private owner API."""

import os
from pathlib import Path

from ficc.cli import local_request
from ficc.local_client import client


def main():
    state = Path(os.environ["FICC_STREAM_STATE"])
    grant = local_request(state, {"action": "ephemeral"})
    try:
        with client(grant, state) as admin:
            response = admin.get("/api/v1/external-identities")
            assert response.status_code == 200
            matches = [item for item in response.json()["mappings"] if item["external_subject"] == "person-0"]
            assert len(matches) == 1
            value = matches[0]
            response = admin.put("/api/v1/external-identities", json={key: value[key]
                for key in ("issuer", "external_subject", "subject_id", "revision")} | {"disabled": True})
            assert response.status_code == 200
    finally:
        local_request(state, {"action": "revoke", "id": grant["id"]})


if __name__ == "__main__":
    main()
