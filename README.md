<p align="center">
  <img src=".github/assets/mark.png" width="720" alt="FICC, Federated Industrial Cluster Commander. Orange-haired systems operator beside a silver wordmark.">
</p>

<p align="center">A local console for Linux clusters, connected through OpenSSH.</p>

<p align="center">
  <img src=".github/assets/badges.svg" width="720" alt="Apache 2.0 | Version 0.1.0.dev5 | Python 3.12 or later | OpenSSH">
</p>

<p align="center">
  <a href="docs/install.md">Install</a> |
  <a href="docs/operations.md">Operate</a> |
  <a href="docs/agents.md">Coding agents</a> |
  <a href="docs/README.md">Documentation</a>
</p>

<p align="center"><img src=".github/assets/divider.svg" width="720" alt=""></p>

FICC brings machine status, managed jobs, files, terminals and coding agents into
one local web interface. A Python service owns the local API and recorded state.
Approved SSH connections reach small helpers on enrolled machines. Existing SSH
tools continue to work.

The interface uses white and silver panels, orange controls and compact tables.
All application assets are local, including fonts. The controller listens on
loopback; shared remote access remains outside this development version.

## Overview

| Surface | Function |
| --- | --- |
| Overview | CPU, memory, storage and network samples; optional NVIDIA reporting; explicit stale and unavailable states. |
| Jobs | Preview commands, set CPU/RAM limits, follow durable output and reconcile interrupted work. |
| Files | Registered roots, two-pane tables, explicit file changes and verified transfers. |
| Terminals | Interactive SSH and tmux sessions with machine tabs, adjustable splits, tile zoom and fullscreen. |
| Agents | Registered OMP, Codex and generic commands with their own managed terminal sessions. |
| Bus | Host-owned runs, explicit recipients, direct adapters and a tool-readable inbox. |
| Access and Activity | Expiring scoped credentials, node/root restrictions and recorded actions. |

> [!NOTE]
> GPU reservations are advisory. A delivery receipt records transport or runtime
> admission; it does not mean that an agent completed the requested work.

Stopped-controller backups remove credentials. Explicit archives retain completed
history and node output. No history expires automatically.

<p align="center"><img src=".github/assets/divider.svg" width="720" alt=""></p>

## Requirements

<details>
<summary>Controller, node and development requirements</summary>

| Role | Requirements |
| --- | --- |
| Controller | Linux, Python 3.12 or later, OpenSSH and GNU coreutils `timeout`. |
| Nodes | OpenSSH server and Python 3.12 or later. |
| Managed jobs | A usable systemd user manager and the controls shown in the job preview. |
| Persistent terminals | tmux on the selected node. |
| Coding agents | An installed runtime and its provider sign-in on the selected node. |
| Build and browser checks | Node.js 20 or later and the locked development dependencies. |

An installed wheel needs no Node.js. Package checks use an Ubuntu 24.04 controller
with Python 3.12; actual node checks use Ubuntu 26.04 with Python 3.14.
Other combinations need their own qualification. Missing NVIDIA support does not
prevent CPU and memory observation.

See [installation](docs/install.md) and [testing](docs/testing.md).

</details>

<p align="center"><img src=".github/assets/divider.svg" width="720" alt=""></p>

## Build and install

From the source directory:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.lock
npm ci --prefix web
npm run build --prefix web
python -m pip install --no-deps --no-build-isolation -e .
```

Run `python -m build --no-isolation` to produce a distributable package after the
web build. Keep state, credentials and captures outside the source directory.
[Installation](docs/install.md) covers clean environments and machine enrollment.

## Try the interface

```sh
ficc serve --demo --state-dir /tmp/ficc-demo --port 8171
```

In another terminal with the environment active:

```sh
ficc open --state-dir /tmp/ficc-demo
```

The browser receives a short-lived, one-use sign-in. Demo mode uses synthetic
machines and disables live collection and changes. Use separate state for live work.

<p align="center"><img src=".github/assets/divider.svg" width="720" alt=""></p>

## Run the cluster console

First establish key authentication and independently verify the SSH host key.
Approve a trusted SSH alias, then start the local console:

```sh
ficc serve --profile rack-01
```

In another terminal, run `ficc open`. Select **Enroll node**, inspect the account
and fingerprint, and confirm helper installation when required. Repeat
`--profile` to approve more aliases. The helper runs through SSH and opens no
node listener. [Installation](docs/install.md#connect-a-machine) documents the
complete enrollment procedure.

After the first setup, stop the foreground service and install the desktop
launcher with the same profiles and state settings:

```sh
ficc install-launcher --profile rack-01
ficc launch
```

Open **FICC Cluster Commander** from the application menu thereafter. Startup is
on demand by default. Use `ficc status` and `ficc stop` to inspect or stop it.
See [operation](docs/operations.md) before changing existing launcher settings.

## Coding agents and messages

Install and sign in to the chosen coding agent on its node. Register its exact
executable and workspace with `ficc agent-profile-add`. In **Bus**, create a run;
in **Agents**, select that run and profile, review the preview, then launch.
**Open terminal** selects that agent's native terminal in the tiled workspace.

OMP 18.1.12 and Codex 0.156.1 have native direct adapters. Other commands can use
the generic inbox tool. Direct delivery can start model work and always needs
explicit recipients. FICC does not install runtimes, copy provider credentials,
select a model or automatically reply. See [coding agents](docs/agents.md) and
[the bus](docs/bus.md) for registration, grants, receipts and retained history.

<p align="center"><img src=".github/assets/divider.svg" width="720" alt=""></p>

## Layout

<details>
<summary>The source directories</summary>

```text
src/ficc/       local service, API, CLI and durable state
node/ficc_node/ node helper, job runners, terminal and agent adapters
web/            HTML, CSS, JavaScript and locked build dependencies
tests/          Python, SSH, browser and source checks
docs/           operator guides and reference; start at docs/README.md
tools/          source and development checks
```

</details>

## Documentation

The [documentation index](docs/README.md) provides a reading order, shared terms
and a guide to each manual. Start with [architecture](docs/architecture.md),
[installation](docs/install.md) and [operation](docs/operations.md).

Read [security](SECURITY.md) before issuing credentials or opening a terminal.
[Testing](docs/testing.md) states qualification boundaries;
[contributing](CONTRIBUTING.md) describes the branch, check and pull-request policy.
[Dependencies](docs/dependencies.md) retain their separate licences and notices.

<p align="center"><img src=".github/assets/divider.svg" width="720" alt=""></p>

<p align="center">Apache License, Version 2.0. See <a href="LICENSE">LICENSE</a> and <a href="NOTICE">NOTICE</a>.</p>
