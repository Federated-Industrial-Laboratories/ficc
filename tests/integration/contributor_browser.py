#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Run browser contributor checks against disposable TLS services and node identities.
# Inputs: qualified fixture environment, count. Output: browser result. Exit: test status.
"""Exercise node administration through the real browser, client and gateway."""

import argparse
import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path

from contributor_tls.lab import laboratory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, choices=(1, 64), required=True)
    parser.add_argument("--browser-source", type=Path, required=True)
    parser.add_argument("--node-modules", type=Path, required=True)
    args = parser.parse_args()
    # Collect CPU resources without invoking a host GPU management command.
    os.environ["PATH"] = ""
    with laboratory() as lab:
        if args.count > 1:
            asyncio.run(lab.cohort(args.count - 1))
        runner = lab.directory / "browser"
        files = runner / "tests/browser"
        files.mkdir(parents=True)
        for name in ("contributors.spec.mjs", "support.mjs", "playwright.config.mjs"):
            shutil.copy2(args.browser_source / "tests/browser" / name, files / name)
        (runner / "web").mkdir()
        (runner / "web/node_modules").symlink_to(args.node_modules.resolve(), target_is_directory=True)
        cli = lab.directory / "ficc-cli"
        cli.write_text(f"#!{sys.executable}\nfrom ficc.cli import main\nraise SystemExit(main())\n")
        cli.chmod(0o700)
        environment = {**os.environ, "FICC_CLI": str(cli), "FICC_URL": lab.browser_origin,
            "FICC_STATE_DIR": str(lab.state), "FICC_TEST_CONTRIBUTOR_DIRECTORY": str(lab.directory),
            "FICC_TEST_CONTRIBUTOR_SERVER_CA": str(lab.gateway.root),
            "FICC_TEST_CONTRIBUTOR_COUNT": str(args.count)}
        result = subprocess.run(["/usr/bin/node", str(args.node_modules / "@playwright/test/cli.js"),
            "test", "--config", str(files / "playwright.config.mjs"), "contributors.spec.mjs"],
            cwd=runner, env=environment, timeout=180)
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
