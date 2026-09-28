<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Documentation

Install and operate a local console for Linux clusters. FICC connects to approved
SSH profiles and keeps inventory, operation history and message records on the
controller. Start with the guides below, then use the task manuals as needed.

The [online documentation](https://ficc.federatedindustrial.com/docs/) provides
page contents, command copying and a search index that runs in your browser.

[Project README](../README.md) | [Security](../SECURITY.md) | [Contributing](../CONTRIBUTING.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

## Start here

1. Read the [architecture](architecture.md) and [security model](../SECURITY.md).
2. Choose a [Linux package](releases.md) or [source installation](install.md).
3. Try the [demonstration console](install.md#try-the-interface) with separate state.
4. [Connect a machine](install.md#connect-a-machine) and inspect its pinned identity.
5. Set up [normal startup and maintenance](operations.md).

## Manual library

| Order | Manual | Subject |
| --- | --- | --- |
| 01 | [Architecture](architecture.md) | Controller, node helpers, trust and state ownership. |
| 02 | [Installation](install.md) | Requirements, build, demo and first machine enrollment. |
| 03 | [Operation](operations.md) | Desktop startup, service settings, trust changes and upgrades. |
| 04 | [Managed jobs](jobs.md) | Command previews, resource controls, output and recovery. |
| 05 | [Files](files.md) | Registered roots, explorer tables, file changes and transfers. |
| 06 | [Terminals](terminals.md) | Interactive SSH, tmux, tiling, fullscreen and session lifetime. |
| 07 | [Coding agents](agents.md) | Runtime profiles, native adapters, inbox tools and authority. |
| 08 | [Agent bus](bus.md) | Run membership, explicit delivery, receipts and portable history. |
| 09 | [Backup and restore](backup.md) | Consistent private state bundles and verified restore. |
| 10 | [History archives](history.md) | Explicit retention, export and capacity recovery. |
| 11 | [Local API](api.md) | Authentication, scopes, endpoints and request contracts. |
| 12 | [Testing](testing.md) | Source, Python, SSH, browser and installed-system checks. |
| 13 | [Dependencies](dependencies.md) | Locked components, bundled assets and their licences. |
| 14 | [Linux packages](releases.md) | Binary formats, verification, first startup, upgrade and removal. |
| 15 | [Runtime modules](modules.md) | Inspect packages, select grants, enable, update and remove modules. |
| 16 | [Workspaces](workspaces.md) | Saved panels, tiling, separate windows, notes and file editing. |
| 17 | [Workspace sound](audio.md) | Local playback, master controls and window ownership. |
| 18 | [Remote displays](viewer.md) | Input release, nested fullscreen and display limits. |
| 19 | [Native viewer runtime](viewer-runtime.md) | Build, install, platform checks, licenses and corresponding sources. |
| 20 | [Libvirt provider](providers/libvirt.md) | VM inventory, confirmed lifecycle requests and VNC prerequisites. |
| 21 | [Containers](containers.md) | Docker, Podman and Kubernetes profiles, operations and recovery. |
| 22 | [Module SDK](../sdk/README.md) | Five language families, package tools, protocols and host components. |
| 23 | [System administration](system-admin.md) | Systemd profiles, service actions, logs and confirmed power requests. |
| 24 | [Proxmox provider](providers/proxmox.md) | Pinned provider builds, VM tasks and recovery. |
| 25 | [Windows endpoints](windows-endpoints.md) | Registered JEA commands, private credentials and separate display connections. |
| 26 | [Provider adapter SDK](../sdk/ADAPTERS.md) | Runtime provider packages, account grants and operation receipts. |

## Terms used in the manuals

| Term | Meaning |
| --- | --- |
| Controller | The local FICC service and its canonical database. |
| Node | An enrolled machine reached through a pinned SSH identity. |
| SSH profile | A locally approved SSH alias used for connection and enrollment. |
| Agent profile | An exact installed command, adapter and working directory on one node. |
| File root | A registered directory with explicit permitted actions. |
| Run | A host-owned group of enrolled agents and their bus messages. |
| Receipt | Evidence of a delivery stage, separate from task completion. |
| Reconcile | Inspect a saved operation identity after its outcome became uncertain. |
| Archive | Explicitly preserve completed history before reclaiming active capacity. |
| Module package | An immutable runtime archive identified by its exact digest. |
| Module panel | A package instance with saved data and a specific target selection. |
| Workspace | A saved group of module panels. |
| Workspace view | One window's panel arrangement, separate from shared workspace data. |

## Find a task

| Task | Start here |
| --- | --- |
| Install a binary package | [Linux packages](releases.md) |
| Try FICC without touching nodes | [Demo mode](install.md#try-the-interface) |
| Start from the application menu | [User service](operations.md#user-service) |
| Open several terminals | [Terminal workspace](terminals.md) |
| Register a coding agent | [Coding agents](agents.md) |
| Contact another agent | [Agent bus](bus.md) |
| Prepare a controller upgrade | [Operation](operations.md#state-copy-and-upgrades) and [backup](backup.md) |
| Reclaim retained capacity | [History archives](history.md) and [closed bus runs](bus.md#portable-runs-and-explicit-archival) |
| Add a module | [Package inspection and grants](modules.md#install-and-enable) |
| Use multiple monitors | [Workspace windows](workspaces.md#separate-windows-and-fullscreen) |
| Edit a system file | [Registered-root editor](workspaces.md#included-productivity-panels) |
| Release VM keyboard input | [Remote display controls](viewer.md) |

## Conventions

Commands use generic machine aliases and opaque IDs. Replace those values with
the identities shown by the local console. Keep credentials in protected files;
never put them in command arguments, repository text or shared captures.

Each guide states its own prerequisites, effects and limits. A preview does not
perform an operation. A receipt does not prove completed work. Active and
uncertain records remain retained until their outcome can be resolved.

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Return to the project README](../README.md)
