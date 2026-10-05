<p align="center">
  <img src=".github/assets/header.png" width="720" alt="FICC, Federated Industrial Cluster Commander. Graphite wordmark on a silver engineering grid.">
</p>

<p align="center">A modular console for cluster operations, remote teams and compute workloads.</p>

<p align="center">
  <img src=".github/assets/badges.svg" width="720" alt="Apache 2.0 | Version 0.2.6 | Python 3.12 or later | OpenSSH">
</p>

<p align="center">
  <a href="docs/install.md">Install</a> |
  <a href="docs/operations.md">Operate</a> |
  <a href="docs/agents.md">Coding agents</a> |
  <a href="docs/README.md">Documentation</a>
</p>

<p align="center"><img src=".github/assets/divider.svg" width="720" alt=""></p>

FICC brings machine status, jobs, files, terminals, coding agents and data workflows
into one web interface. A Python controller owns the API and recorded state.
Approved SSH connections reach small helpers on managed machines. Remote teams
use explicitly configured HTTPS sign-in, project permissions and runtime policies.
Invited Linux contributors connect over mutual TLS and execute approved workloads
within their local resource offers.

Runtime modules add saved workspaces, VM and container controls, text editors and
shared sound. Supplied modules use the same inspected archives and explicit grants
as other packages. The [SDK](sdk/README.md) supports C, C++, Rust, Python and
JavaScript, including TypeScript authoring.

KVM/libvirt, Proxmox VE, Hyper-V and VirtualBox provide verified VM inventory, power actions and display.
VirtualBox requires its qualified Linux provider version and separately installed runtime packages.
Hyper-V requires the registered Windows transport and fixed JEA endpoint.
See [Windows endpoints](docs/windows-endpoints.md) for the qualified environment and setup.

See [provider support](docs/testing.md#runtime-modules-and-providers) for requirements and limits.

The interface defaults to white and silver panels, orange controls and compact tables.
[Appearance and themes](docs/themes.md) adds Classic Dark with the PRISM Graphite
palette, 24 named alternatives, flat materials and portable JSON themes with custom
vector logos. All application assets are local, including fonts. The desktop controller listens
on loopback by default. [Remote access](docs/remote-access.md) requires the separate
authenticated gateway and identity setup; exposing the local listener is unsupported.

## Overview

| Surface | Function |
| --- | --- |
| Overview | CPU, memory, storage and network samples; optional NVIDIA reporting; explicit stale and unavailable states. |
| Jobs | Preview commands, set CPU/RAM limits, follow durable output and reconcile interrupted work. |
| Contributors and Workloads | Approved managed or voluntary Linux nodes, local resource offers, fair queues, pause/drain and verified results. |
| Files and Data sources | Registered roots, resumable transfers, immutable datasets, SQL/query templates, CSV, Arrow/Parquet, DuckDB and S3 workflows. |
| Terminals | Interactive SSH and tmux sessions with machine tabs, adjustable splits, tile zoom and fullscreen. |
| Agents | Registered OMP, Codex and generic commands with their own managed terminal sessions. |
| Bus | Host-owned runs, explicit recipients, direct adapters and a tool-readable inbox. |
| Workspace | Runtime modules, saved docked or floating panels, workspace tiling, separate monitor windows and sound. |
| Access and Activity | Individual identities, projects, scoped credentials, signed runtime policies and recorded actions. |
| Operations | Redacted diagnostics, connection and certificate status, backup receipts, durable audit delivery and retained usage. |

> [!NOTE]
> Managed SSH job GPU reservations are advisory. Contributor jobs require their
> separate executor and resource enforcement. A delivery receipt records transport or runtime
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
| Program modules | Bubblewrap, a systemd user manager and enforced namespace, syscall and cgroup controls. |
| VM displays | A separate compatible native viewer runtime and the provider's supported console. |
| Remote teams | Explicit HTTPS gateway, configured identity provider and approved project memberships. |
| Contributor workloads | Linux, approved mTLS enrollment, local resource controls and the separately configured Podman executor. |
| Optional inspection | Separately installed ClamAV engine, approved rules and supported controller-local data. |
| Build and browser checks | Node.js 22 or later, C/C++ tools, OpenSSL development files and locked dependencies. |

Binary packages bundle Python and need no Node.js. See the
[Linux packages](docs/releases.md) for AppImage, Debian, Arch and portable formats.
Controller and node qualification are separate; nodes still need Python and SSH. Missing NVIDIA support does not
prevent CPU and memory observation.

See [installation](docs/install.md) and [testing](docs/testing.md).
See [modules](docs/modules.md) for grants and [native viewer installation](docs/viewer-runtime.md) for display requirements.

</details>

<p align="center"><img src=".github/assets/divider.svg" width="720" alt=""></p>

## Install

Download AppImage, Debian, Arch Linux or portable packages from
[GitHub Releases](https://github.com/Federated-Industrial-Laboratories/ficc/releases/latest),
then follow [Linux packages](docs/releases.md). Native packages add
**FICC Cluster Commander** to the application menu. This release targets x86_64.

### Install a source checkout

On a Linux desktop, from the cloned repository:

```sh
./install.sh
~/.local/bin/ficc
```

The installer downloads verified Python and Node build tools, builds this source,
and installs a private runtime outside the checkout. It creates an on-demand
service and application-menu entry without sudo. It approves no SSH aliases.
Use `./install.sh --profile rack-01` to approve an existing trusted alias.

When `~/.local/bin` is on PATH, use `ficc` to open the console, `ficc status`
to check it and `ficc stop` to stop it. The installer prints a PATH command when
needed. Use an updated system Python 3.10 or later.
Install OpenSSH, coreutils, systemd, xdg-utils and native build prerequisites.
[Installation](docs/install.md) covers prerequisites,
command-only setups, updates and development environments.

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
executable and workspace with `ficc agent-profile-add`.

Create a run in Bus. Select that run and profile in Agents, review the preview,
then launch.
**Open terminal** selects that agent's native terminal in the tiled workspace.

OMP 18.1.12 and Codex 0.156.1 have native direct adapters. Other commands can use
the generic inbox tool. Direct delivery can start model work and always needs
explicit recipients. FICC does not install runtimes, copy provider credentials,
select a model or automatically reply. See [coding agents](docs/agents.md) and
[the bus](docs/bus.md) for registration, grants, receipts and retained history.

The separate [ficc-harness](https://github.com/Federated-Industrial-Laboratories/ficc-harness)
companion supplies portable skills, agent templates
and optional session hooks for assisted setup and operation. See
[external agent assistance](docs/agents.md#external-agent-assistance) for its
relationship to FICC permissions and native adapters.

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
modules/        independent supplied module sources
sdk/            language libraries, examples, component format and conformance
```

</details>

## Documentation

Read the [website](https://ficc.federatedindustrial.com/) and
[searchable manuals](https://ficc.federatedindustrial.com/docs/).

The [documentation index](docs/README.md) provides a reading order, shared terms
and a guide to each manual. Start with [architecture](docs/architecture.md),
[installation](docs/install.md) and [operation](docs/operations.md).

Read [security](SECURITY.md) before issuing credentials or opening a terminal.

[Testing](docs/testing.md) states qualification boundaries.
[Contributing](CONTRIBUTING.md) describes the branch, check and pull-request policy.
[Dependencies](docs/dependencies.md) retain their separate licenses and notices.

<p align="center"><img src=".github/assets/divider.svg" width="720" alt=""></p>

<p align="center">Apache License, Version 2.0. See <a href="LICENSE">LICENSE</a> and <a href="NOTICE">NOTICE</a>.</p>
