# SPDX-License-Identifier: Apache-2.0
"""Bind an existing private model volume while the controller is stopped."""
from ..execution.files import directory
from ..settings import private_directory
from ..state_lock import StateLock
from ..store import Store


def configure(state, path, hosts):
    import os
    path = path.absolute()
    # Provisioning creates only the selected directory, never changes its ancestors.
    private_directory(path)
    info = directory(path, owner=os.getuid(), private=True)
    if hosts is not None and any(not name or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for char in name) for name in hosts):
        raise ValueError("Use exact lower-case HTTPS host names.")
    with StateLock(state):
        store = Store(state / "state.sqlite3")
        try:
            store.set_setting("models.directory", str(path))
            store.set_setting("models.directory_binding", [info.st_dev, info.st_ino])
            if hosts is not None:
                store.set_setting("models.https_hosts", hosts)
        finally:
            store.close()
    return {"directory": str(path), "configured": True, "restart_required": True}
