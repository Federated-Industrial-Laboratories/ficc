# SPDX-License-Identifier: Apache-2.0
"""Select a persistent executable for installed and AppImage launchers."""

import os
import stat
import sys
from pathlib import Path

from .launcher_bundle import install


def executable() -> Path:
    interpreter = Path(sys.executable).absolute()
    appdir, appimage = os.environ.get("APPDIR"), os.environ.get("APPIMAGE")
    if appdir and appimage:
        expected = Path(appdir) / "usr/lib/ficc/python/bin"
        if interpreter.parent.resolve() == expected.resolve():
            image = Path(appimage)
            if not image.is_absolute():
                raise ValueError("The AppImage path must be absolute.")
            fd = os.open(image, os.O_RDONLY | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.getuid()}
                        or info.st_mode & 0o022 or not os.access(image, os.X_OK)):
                    raise ValueError("The AppImage must be an owned executable regular file.")
                header = os.read(fd, 12)
                if header[:4] != b"\x7fELF" or header[8:11] != b"AI\x02":
                    raise ValueError("The AppImage must be a type 2 image.")
            finally:
                os.close(fd)
            return install(Path(appdir) / "usr/lib/ficc")
    command = interpreter.parent / "ficc"
    if not command.is_file() or not os.access(command, os.X_OK):
        raise ValueError("Install the FICC package or virtual environment before installing its launcher.")
    return command
