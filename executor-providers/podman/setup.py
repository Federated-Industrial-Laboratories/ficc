# SPDX-License-Identifier: Apache-2.0
"""Build the static payload barrier into a platform-specific executor wheel."""

import subprocess
from pathlib import Path

from setuptools import Distribution, setup
from setuptools.command.bdist_wheel import bdist_wheel
from setuptools.command.build_py import build_py


class Build(build_py):
    def run(self):
        super().run()
        target = Path(self.build_lib) / "ficc_executor_podman"
        subprocess.run(["cc", "-static", "-Os", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-fstack-protector-strong", "-Wl,--build-id=none", str(target / "barrier.c"),
                        "-o", str(target / "barrier")], check=True)
        (target / "barrier").chmod(0o755)


class Platform(Distribution):
    def has_ext_modules(self):
        return True


class Wheel(bdist_wheel):
    def get_tag(self):
        return "py3", "none", super().get_tag()[2]


setup(cmdclass={"build_py": Build, "bdist_wheel": Wheel}, distclass=Platform)
