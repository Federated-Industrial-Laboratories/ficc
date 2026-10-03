# SPDX-License-Identifier: Apache-2.0
"""Expose the trusted OpenID Connect identity provider interface."""

from .config import configuration
from .provider import Provider

API_VERSION = 1


def create(config: dict, callback_uri: str) -> Provider:
    try:
        return Provider(configuration(config, callback_uri))
    except Exception:
        raise ValueError("The identity provider configuration or discovery failed.") from None
