# SPDX-License-Identifier: Apache-2.0
"""Install immutable module packages and enforce their local execution boundary."""

from .archive import Inspection, inspect_archive
from .registry import Registry, initialize

__all__ = ["Inspection", "Registry", "initialize", "inspect_archive"]
