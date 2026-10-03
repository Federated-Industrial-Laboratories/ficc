# SPDX-License-Identifier: Apache-2.0
"""Bind remote HTTP only to an explicitly protected Unix gateway socket."""

import os
import socket
import stat

import uvicorn

from .api import create_app


def serve(settings):
    stream = None

    def close_ingress():
        nonlocal stream
        if stream is not None:
            stream.close()
            stream = None
            settings.remote.socket.unlink(missing_ok=True)

    app = create_app(settings, close_ingress=close_ingress)
    try:
        options = {"host": "127.0.0.1", "port": settings.port}
        if settings.remote:
            path = settings.remote.socket
            parent = path.parent
            info = parent.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o027 or parent.resolve() != parent):
                raise ValueError("The gateway socket directory must be owned by this account, without group write or other access.")
            if path.exists() or path.is_symlink():
                info = path.lstat()
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                    raise ValueError("The existing gateway path is not an owned socket.")
                path.unlink()
            stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stream.bind(str(path))
            os.chmod(path, 0o660)
            stream.listen(128)
            options = {"fd": stream.fileno()}
        uvicorn.run(app, **options, access_log=False, proxy_headers=False, server_header=False,
                    limit_concurrency=192 if settings.contributors else 64, timeout_keep_alive=5, ws="websockets",
                    ws_max_size=16384, ws_max_queue=4, ws_per_message_deflate=False)
    finally:
        close_ingress()
        # Uvicorn normally closes the service through its lifespan handler.
        if app.state.service.state_lock.fd is not None:
            app.state.service.close()
