# SPDX-License-Identifier: Apache-2.0
"""Resolve bounded secrets through explicitly configured trusted runtime packages."""

import importlib.metadata
import json
import re
import secrets
from pathlib import Path

from . import secret_io
from .secret_sdk import API_VERSION, SecretError, SecretValue, payload, reference, revision

PRIVATE = "secrets-private"
CONFIG = "provider.json"


def load(name):
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name):
        raise SecretError("secret_configuration")
    try:
        matches = list(importlib.metadata.entry_points(group="ficc.secret", name=name))
        if len(matches) != 1:
            raise SecretError("secret_provider_unavailable")
        module = matches[0].load()
        if module.API_VERSION != API_VERSION or not callable(getattr(module, "configure", None)):
            raise SecretError("secret_provider_version")
        return module
    except SecretError:
        raise
    except Exception:
        raise SecretError("secret_provider_unavailable") from None


class Secrets:
    def __init__(self, state):
        self.state = Path(state).absolute()
        self.directory = self.state / PRIVATE

    def provider(self):
        try:
            value = json.loads(secret_io.private_file(self.directory / CONFIG))
            if not isinstance(value, dict) or set(value) != {"provider", "configuration"} or not isinstance(value["configuration"], dict):
                raise SecretError("secret_configuration")
            driver = load(value["provider"]).configure(value["configuration"], self.directory)
            if any(not callable(getattr(driver, method, None)) for method in ("health", "get", "put", "delete")):
                raise SecretError("secret_provider_version")
            driver.health()
            return driver
        except SecretError:
            raise
        except Exception:
            raise SecretError() from None

    def invoke(self, method, *args):
        try:
            return getattr(self.provider(), method)(*args)
        except SecretError as exc:
            raise SecretError(exc.code) from None
        except Exception:
            raise SecretError() from None

    def resolve(self, identity):
        value = self.invoke("get", reference(identity))
        if not isinstance(value, SecretValue):
            raise SecretError()
        payload(value.value)
        revision(value.revision)
        return value

    def status(self, identity=None):
        if identity is None:
            self.provider()
            return {"available": True, "api_version": API_VERSION}
        value = self.resolve(identity)
        return {"reference": identity, "revision": value.revision}

    def put(self, identity, value, expected_revision=None, *, imported_revision=None):
        reference(identity)
        payload(value)
        if expected_revision is not None:
            revision(expected_revision)
        updated = revision(imported_revision) if imported_revision is not None else secrets.token_hex(32)
        self.invoke("put", identity, value, expected_revision, updated)
        return {"reference": identity, "revision": updated}

    def delete(self, identity, expected_revision):
        self.invoke("delete", reference(identity), revision(expected_revision))
        return {"reference": identity, "deleted": True}
