# SPDX-License-Identifier: Apache-2.0
"""Load trusted identity drivers and validate their short-lived assertions."""

import importlib.metadata
import json
import math
import re
import time
from pathlib import Path

from .external_identity_store import subject
from .remote_settings import https_url
from .state_provider import read_private

CONFIG = "identity-provider.json"
API_VERSION = 1
ASSERTION_FIELDS = {"handle", "issuer", "subject", "auth_time", "expires_at", "valid_until"}


def configuration(state):
    path = Path(state) / CONFIG
    if not path.exists() and not path.is_symlink():
        return None
    value = json.loads(read_private(path))
    if (not isinstance(value, dict) or set(value) != {"provider", "configuration"}
            or not isinstance(value["configuration"], dict)
            or not isinstance(value["provider"], str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", value["provider"])):
        raise ValueError("The trusted identity provider configuration is invalid.")
    return value


def create(value, callback):
    matches = list(importlib.metadata.entry_points(group="ficc.identity", name=value["provider"]))
    if len(matches) != 1:
        raise ValueError("Install exactly one trusted driver for the configured identity provider.")
    driver = matches[0].load()
    if driver.API_VERSION != API_VERSION:
        raise ValueError("The identity provider interface is not supported.")
    instance = driver.create(value["configuration"], callback)
    try:
        https_url(instance.issuer)
        for method in ("authorization", "complete", "renew", "forget", "close"):
            if not callable(getattr(instance, method, None)):
                raise ValueError("The identity provider interface is incomplete.")
    except BaseException:
        instance.close()
        raise
    return instance


def assertion(value, issuer, previous=None):
    now = time.time()
    if not isinstance(value, dict) or set(value) != ASSERTION_FIELDS or value["issuer"] != issuer:
        raise ValueError("The identity provider returned an invalid assertion.")
    if not isinstance(value["handle"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value["handle"]):
        raise ValueError("The external session handle is invalid.")
    subject(value["subject"])
    for key in ("auth_time", "expires_at", "valid_until"):
        if type(value[key]) not in {int, float} or not math.isfinite(value[key]):
            raise ValueError("The identity assertion timestamps are invalid.")
    if (not 0 < value["auth_time"] <= now + 30 or not now < value["valid_until"] <= now + 30
            or not value["valid_until"] <= value["expires_at"] <= now + 86400):
        raise ValueError("The external authority expired or exceeds its verification lease.")
    if previous is not None and any(value[key] != previous[key] for key in
                                    ("handle", "issuer", "subject", "auth_time", "expires_at")):
        raise ValueError("External renewal changed the bound identity or session lifetime.")
    return dict(value)
