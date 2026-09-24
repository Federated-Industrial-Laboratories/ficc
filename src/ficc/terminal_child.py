# SPDX-License-Identifier: Apache-2.0
"""Acquire the inherited PTY as a controlling terminal before exec."""

import fcntl
import os
import sys
import termios


def main() -> None:
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
