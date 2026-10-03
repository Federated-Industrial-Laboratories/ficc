# SPDX-License-Identifier: Apache-2.0
"""Create isolated TLS fixtures and provider instances for protocol tests."""

import pytest
from issuer import Issuer

from ficc_identity_oidc import create

CALLBACK = "https://controller.example/auth/callback"


@pytest.fixture
def issuer(tmp_path):
    result = Issuer(tmp_path)
    try:
        yield result
    finally:
        result.close()


@pytest.fixture
def provider(issuer):
    result = create(issuer.configuration(), CALLBACK)
    try:
        yield result
    finally:
        result.close()
