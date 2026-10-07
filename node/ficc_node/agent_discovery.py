# SPDX-License-Identifier: Apache-2.0
"""Find installed coding CLIs in the enrolled account without starting sessions."""

import os
import shlex
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

COMMANDS = (
    ("codex", "Codex", "codex"), ("claude", "Claude Code", "generic"),
    ("pi", "Pi", "generic"), ("omp", "OMP", "omp"),
    ("kimi", "Kimi Code", "generic"), ("opencode", "OpenCode", "generic"),
    ("copilot", "GitHub Copilot", "generic"), ("gemini", "Gemini CLI", "generic"),
    ("grok", "Grok", "generic"), ("cursor-agent", "Cursor Agent", "generic"),
)


def search_path():
    home = Path.home()
    paths = [part for part in os.get_exec_path() if Path(part).is_absolute() and not part.endswith("/mise/shims")]
    paths += [str(home / part) for part in (".local/bin", "bin", ".npm-global/bin", ".bun/bin", ".cargo/bin", ".opencode/bin", ".codex/bin")]
    # mise's active/latest links are also useful in non-interactive SSH sessions.
    installs = home / ".local/share/mise/installs"
    if installs.is_dir():
        for tool in sorted(installs.iterdir())[:64]:
            for current in (tool / "latest", tool / "current"):
                if current.is_dir():
                    paths.extend(str(current / suffix) for suffix in ("bin", "", "node_modules/.bin", "pi"))
        node = installs / "node"
        if node.is_dir():
            for current in sorted(node.iterdir(), key=lambda p: p.name, reverse=True)[:8]:
                if current.is_dir():
                    paths.append(str(current / "bin"))
    paths += ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]
    return os.pathsep.join(dict.fromkeys(paths))


def arguments(path, search):
    executable = Path(path).resolve(strict=True)
    with executable.open("rb") as stream:
        header = stream.read(256).split(b"\n", 1)[0]
    if header.startswith(b"#!/usr/bin/env node"):
        node = shutil.which("node", path=search)
        if not node:
            raise ValueError("Node.js is required by the installed command.")
        return [str(Path(node).resolve(strict=True)), str(executable)]
    if header.startswith(b"#!"):
        # Shell launchers may invoke Node or sibling tools through env/PATH.
        node = shutil.which("node", path=search)
        paths = [str(executable.parent)]
        words = shlex.split(header[2:].decode("utf-8", "replace"))
        if (not words or not Path(words[0]).is_absolute() or not Path(words[0]).is_file()
                or not os.access(words[0], os.X_OK)):
            raise ValueError("The command's interpreter is not installed or executable.")
        if words and Path(words[0]).name == "env":
            interpreter = next((word for word in words[1:] if not word.startswith("-") and "=" not in word), None)
            resolved = shutil.which(interpreter, path=search) if interpreter else None
            if not resolved:
                raise ValueError("The command's interpreter is not installed.")
            paths.append(str(Path(resolved).absolute().parent))
        if node:
            paths.append(str(Path(node).resolve(strict=True).parent))
        paths += [str(Path.home() / folder) for folder in (".local/bin", "bin", ".bun/bin", ".cargo/bin")]
        paths += ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]
        return ["/usr/bin/env", "PATH=" + os.pathsep.join(dict.fromkeys(paths)), str(executable)]
    return [str(executable)]


def find_command(command, search):
    for folder in search.split(os.pathsep):
        executable = shutil.which(command, path=folder)
        if executable is None:
            continue
        try:
            with open(executable, "rb") as stream:
                header = stream.read(8192)
            # Convenience launchers can install or change the active version.
            # Discovery must reach an existing runtime without running setup.
            if header.startswith(b"#!") and any(part in header for part in (b"mise use ", b"mise install ")):
                continue
            return executable
        except OSError:
            continue
    return None


def discover():
    from .agents import probe

    search, workspace = search_path(), str(Path.home().resolve())

    def inspect(definition):
        command, name, adapter = definition
        executable = find_command(command, search)
        if executable is None:
            return None, None
        try:
            checked = probe({"argv": arguments(executable, search), "workspace": workspace, "adapter": adapter})
            if not checked["version"]:
                raise ValueError("The installed agent did not report a version.")
            return {"command": command, "name": name, **checked}, None
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            return None, {"command": command, "message": str(exc)[:240]}

    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(inspect, COMMANDS))
    return {"profiles": [profile for profile, _ in results if profile is not None],
            "errors": [error for _, error in results if error is not None]}
