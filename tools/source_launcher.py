#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Preserve saved launcher settings during source installation; exit: 0 on success.
"""Install the user launcher with the newly built application's interpreter."""

import sys
from pathlib import Path

from ficc import launcher
from ficc.cli import parser
from ficc.launcher_config import config_path, load


def arguments(profiles: list[str]):
    args = parser().parse_args(['install-launcher'])
    path = config_path()
    if path.exists() or path.is_symlink():
        config = load(path)
        if profiles and tuple(profiles) != config.profiles:
            raise ValueError('Existing SSH profiles differ; change them explicitly with install-launcher')
        args.state_dir = Path(config.state_dir)
        args.port = config.port
        args.profile = list(config.profiles)
        args.ssh_config = Path(config.ssh_config) if config.ssh_config else None
        args.demo = config.demo
        args.name = Path(config.unit_path).stem
    else:
        args.profile = profiles
    return args


if __name__ == '__main__':
    launcher.install(arguments(sys.argv[1:]))
