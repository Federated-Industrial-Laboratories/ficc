# SPDX-License-Identifier: Apache-2.0
"""Terminate all kubeconfig reader children after bounded output or timeout failures."""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from ficc_node import container_kubeconfig as config


@pytest.mark.parametrize("mode", ["output", "timeout", "orphan"])
def test_reader_closes_descriptor_and_process_group(tmp_path, monkeypatch, mode):
    real_popen, real_selector = subprocess.Popen, config.selectors.DefaultSelector
    child_file = tmp_path / "child"
    if mode == "output":
        source = "import os,time;os.write(1,b'x'*4096);time.sleep(30)"
    elif mode == "timeout":
        source = "import time;time.sleep(30)"
    else:
        source = ("import os,time;from pathlib import Path;child=os.fork();"
                  f"Path({str(child_file)!r}).write_text(str(child)) if child else None;"
                  "os._exit(0) if child else time.sleep(30)")
    processes, descriptors = [], []

    def launch(arguments, **options):
        assert arguments[0] == "/usr/bin/kubectl"
        assert arguments[3:] == ["config", "view", "--raw", "--merge=false", "-o", "json"]
        descriptors.extend(options["pass_fds"])
        child = real_popen([sys.executable, "-I", "-c", source], **options)
        processes.append(child)
        return child

    class ShortSelector(real_selector):
        def select(self, timeout=None):
            return super().select(min(timeout, 0.3))

    monkeypatch.setattr(config.subprocess, "Popen", launch)
    monkeypatch.setattr(config.Path, "is_file", lambda path: str(path) == "/usr/bin/kubectl")
    monkeypatch.setattr(config.selectors, "DefaultSelector", ShortSelector)
    monkeypatch.setattr(config.spec, "MAX_MESSAGE", 1024)
    start = time.monotonic()
    with pytest.raises(ValueError, match="exceeded"):
        config.convert(b"apiVersion: v1\n")
    assert time.monotonic() - start < 3 and processes[0].poll() is not None
    assert processes[0].stdout.closed
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    if mode == "orphan":
        child = int(child_file.read_text())
        for _ in range(50):
            try:
                state = Path(f"/proc/{child}/stat").read_text().split(") ", 1)[1].split()[0]
            except FileNotFoundError:
                break
            if state == "Z":
                break
            time.sleep(0.01)
        else:
            os.kill(child, 9)
            raise AssertionError("The kubeconfig reader left an active descendant.")
