# SPDX-License-Identifier: Apache-2.0
"""Expose the trusted certificate provider interface."""

from .provider import Provider

API_VERSION = 1


def create(configuration: dict) -> Provider:
    """Read private installation settings and return the authority adapter."""
    return Provider(configuration)
