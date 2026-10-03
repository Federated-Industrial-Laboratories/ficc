<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Documentation

Install and operate a console for Linux clusters. FICC connects to approved
SSH profiles and contributors, with project access, workload queues and dataset
pipelines. The controller retains identities, approvals and operation receipts.
Remote browser access requires explicit HTTPS and identity-service configuration.
Start with the guides below, then use the task manuals as needed.

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

The v0.2.5 source installer and binary payload supply 17 separately built
[provider wheels](dependencies.md#supplied-runtime-providers). Their presence
does not configure external services, enroll contributors or grant access.
Follow the relevant workflow guide before enabling a provider.

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
| 27 | [VirtualBox provider](providers/virtualbox.md) | Account-bound native adapter, local IPC and display setup. |
| 28 | [Module sandbox setup](../tools/module-sandbox-policy/README.md) | Optional AppArmor policy, installation checks and removal. |
| 29 | [System power policy](../tools/power-policy/README.md) | Optional group-scoped shutdown and restart permissions. |
| 30 | [Identities and projects](identities.md) | Local user identities, project workspace ownership, membership and recovery. |
| 31 | [Controller state storage](state-storage.md) | SQLite, optional PostgreSQL driver, verified transport, migration and recovery. |
| 32 | [Runtime policies](policies.md) | Signed packages, role assignments, effective access and recovery. |
| 33 | [Remote access](remote-access.md) | HTTPS gateway, approved identities, MFA and revocation. |
| 34 | [Contributor connections](contributors.md) | Private CA setup, invitations, independent key approval, node leases and recovery. |
| 35 | [OpenSSH certificate trust](ssh-trust.md) | Installation-approved CAs, principals, user certificates, KRLs and live connection checks. |
| 36 | [Certificate provider SDK](../sdk/certificates.md) | Trusted runtime authority providers, issuance contracts and credential boundaries. |
| 37 | [Contributor workloads](workloads.md) | Project queues, placement, output, cancellation and uncertain outcome recovery. |
| 38 | [Contributor execution](execution.md) | Local consent, enforced resources, isolated runtimes and executor installation. |
| 39 | [Scheduler SDK](../sdk/schedulers.md) | Separately installed scheduling and project concurrency providers. |
| 40 | [Datasets](datasets.md) | Immutable project manifests, source digests, explicit schemas and provenance. |
| 41 | [Artifact SDK](../sdk/artifacts.md) | Runtime filesystem providers, source binding and bounded dataset consumption. |
| 42 | [Data sources](data-sources.md) | Approved connections, registered queries, dataset exports and resumable object publication. |
| 43 | [Data provider SDK](../sdk/data-sources.md) | Installable source/format contracts, bounded streams and customer REST extensions. |
| 44 | [Dataset inspection](inspection.md) | Optional local scanning, recorded coverage, quarantine, sensitivity and explicit exemptions. |
| 45 | [Inspection SDK](../sdk/inspection.md) | Separately installed local scanner packages and immutable file receipts. |
| 46 | [Secret storage](secrets.md) | Encrypted references, private provisioning, rotation, migration and key recovery. |
| 47 | [Secret provider SDK](../sdk/secrets.md) | Runtime secret contracts, revision checks and failure behavior. |
| 48 | [Durable audit delivery](audit.md) | Separate destination custody, acknowledgments, retention gaps and required admission. |
| 49 | [Audit provider SDK](../sdk/audit.md) | Bounded append batches, strict acknowledgments and recovery. |
| 50 | [Executor SDK](../sdk/executors.md) | Contributor runtime isolation, staged inputs and retained output contracts. |

## Terms used in the manuals

| Term | Meaning |
| --- | --- |
| Controller | The local FICC service and its canonical database. |
| Managed node | An enrolled machine reached through an approved SSH identity. |
| Contributor | A separately approved machine with an outbound TLS connection and a current certificate lease. |
| Dataset | An immutable project manifest binding registered file versions, complete digests, schema and provenance. |
| Workload attempt | One fenced contributor execution with its own lease, observed outcome and retained storage. |
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
| Invite a remote contributor | [Contributor enrollment](contributors.md#invite-a-machine) |
| Submit compute to contributors | [Contributor workloads](workloads.md) |
| Export a source query for a workload | [Data sources](data-sources.md) and [datasets](datasets.md) |
| Publish a workload result | [Output publication](workloads.md#inspect-output-and-finish) |
| Inspect dataset coverage and restrictions | [Dataset inspection](inspection.md) |
| Provision or rotate a source credential | [Secret storage](secrets.md) |
| Configure an independent audit destination | [Durable audit delivery](audit.md) |
| Inspect health and download diagnostics | [Operational status](operations.md#operational-status-and-recovery) |
| Configure SSH certificate trust | [OpenSSH certificates](ssh-trust.md) |

## Conventions

[Runtime access policies](policies.md) cover publisher trust, installation,
role assignments, effective access and recovery.

Commands use generic machine aliases and opaque IDs. Replace those values with
the identities shown by the local console. Keep credentials in protected files;
never put them in command arguments, repository text or shared captures.

Each guide states its own prerequisites, effects and limits. A preview does not
perform an operation. A receipt does not prove completed work. Active and
uncertain records remain retained until their outcome can be resolved.

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Return to the project README](../README.md)
