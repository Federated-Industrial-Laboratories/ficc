# Changes

## 0.2.6r1

- Add a scoped agent observation API and JSON CLI for enrolled Linux SSH inventory and saved resource readings.
- Require explicit observation disclosure permission and retain attributed access records.
- Add generic read-only AMDGPU sysfs/hwmon observations alongside NVIDIA readings, with unknown values preserved.
- Keep AMD observations out of CUDA reservation controls and admission.
- Check the AMD method against kernel documentation and synthetic fixtures; direct AMD hardware qualification remains pending for 0.2.6r2.
- Correct the supported stable series and remote-access description in the security policy.
- Use package version 0.2.6.post1 with release tag v0.2.6r1-stable.

## 0.2.6

- Add browser-local appearance controls with Classic Light, PRISM Graphite Classic Dark and 24 named themes.
- Add versioned JSON theme import/export, configurable material gradients, flat materials and replaceable vector logos.
- Apply themes across panels, dialogs, tables, workspaces, audio controls and terminal surfaces.
- Improve narrow navigation, panel alignment, toolbar wrapping and form control sizing.
- Preserve floating-panel positions when restoring a workspace before its layout is measured.
- Replace the README character header with a professional text treatment on a silver grid.
- Remove unused dependency launchers with temporary build paths from Linux packages.

## 0.2.5

- Add durable identities, project membership and resource assignments, with SQLite and PostgreSQL support through controller schema 15.
- Add signed runtime policy packages, role assignments, effective-access previews, activation, rollback and revocation checks.
- Add explicit HTTPS remote mode with approved OIDC identities and MFA, contributor mTLS enrollment and polling, and installation-approved OpenSSH certificate trust.
- Add contributor workload queues, runtime and resource offers, enforced CPU/RAM/storage limits, whole-GPU allocation, renewable authority, cancellation and retained cleanup receipts.
- Add resumable large-file transfers with bounded memory, disk reservations, source commitments and explicit recovery after uncertain publication.
- Add immutable dataset manifests, schemas and lineage, controller-relayed workload inputs, and complete output publication to registered files and datasets.
- Add registered SQL queries, CSV/Arrow/Parquet formats, local DuckDB analytics and S3-compatible reads and multipart publication with separate write authority.
- Add encrypted runtime secret storage with explicit key custody, revision-bound references, rotation and migration of older plaintext source credentials.
- Add optional local ClamAV inspection with recorded coverage, logical quarantine, inherited sensitivity restrictions and explicit exemptions.
- Add operational health, redacted diagnostics, audit export, completed backup/restore receipts, project usage accounting and shared workspace/workload templates.
- Add durable audit delivery to a separately administered append-only HTTPS destination, with visible gaps and optional admission gates for workload submissions and external source writes.
- Supply 17 separately built provider wheels through the source installer and binary payload, retaining runtime installation and extension interfaces.

Remote access, policy enforcement, executors, source accounts, inspection and audit
destinations need explicit deployment configuration and authority. Dataset traffic
currently relays through the controller; uncertain writes are retained for explicit
recovery. Inspection reports bounded coverage, and secret keys and external data
need separate custody and backups. See the [operator manuals](docs/README.md) for
setup and the limits of each workflow.

## 0.2.0-stable

- Add installable runtime modules with archive inspection, sandboxing and explicit capability grants.
- Add C, C++, Rust, Python and JavaScript SDK helpers, plus TypeScript authoring.
- Add declarative components, saved workspaces, floating panels, tiling and separate monitor windows.
- Add shared fullscreen controls, private VM display sessions and explicit input release.
- Add VM inventory and durable power actions with provider profiles and outcome recovery.
- Add packaged provider adapters with separate account grants and registered transports.
- Add native VirtualBox runtime packages with verified private IPC and display connections.
- Qualify Hyper-V power actions and VMConnect with bounded, batched Windows inventory.
- Add Docker, Podman and Kubernetes controls through constrained provider profiles.
- Add service controls, bounded logs and explicitly confirmed system power actions.
- Add a registered-root text editor, notes, clocks and a shared audio player.
- Add private Windows endpoint credentials and optional native display and transport runtimes.
- Preserve workspace and module data in backups; restore provider profiles without active grants.
- Recover incomplete module staging before startup and stopped backups.
- Resume saved window arrangements after a fresh desktop launch.
- Refuse incompatible module updates before changing the active version or its grants.
- Refuse native replacements with invalid executable headers or unavailable ELF loaders.
- Show exact package identity and sandbox diagnostics in the module manager.
- Repair older generated services and use private systemd-managed temporary directories.
- Show system power permission and refuse actions that need interactive authentication.
- Retain libvirt display authentication compatibility and window controls after display restoration.
- Validate remote cursor updates for native VMConnect displays.
- Bind bundled module archives and Windows transport helpers to the release source inventory.

### Provider limits

VirtualBox supports the qualified Linux x86_64 provider version, account sandbox and private display extension.
See the provider guide for its exact runtime requirements.

Hyper-V is qualified on Windows Server 2025 through HTTPS WinRM, fixed JEA commands and a pinned VMConnect display.
Other Windows versions are not qualified. Domain controller endpoints are refused.

VMware vSphere is not included.

## 0.1.0

- Install source checkouts with one command and preserve saved launcher settings.
- Start the desktop console with `ficc` without arguments.
- Publish complete, verified package sets to versioned GitHub Releases.

- Add Linux x86_64 AppImage, Debian, Arch and portable release formats.
- Bundle a pinned Python runtime, notices, source archives, inventory and checksums.
- Add first-use desktop startup and active-runtime package replacement guards.
- Add a tiled terminal workspace, native coding-agent adapters and a host-owned bus.
- Add registered file roots, verified transfers, backups and explicit history archives.
- Add white, silver and orange controls, compact tables and linked operator guides.

- Add durable managed jobs, bounded output, cancellation and recovery.
- Add required CPU/RAM/task/runtime limits and advisory GPU reservations.
- Add explicit helper upgrades and separate job execution, observation and log grants.
- Add an on-demand desktop launcher and local service startup controls.
- Add private CLI submission receipts for uncertain-response recovery.
- Add an authenticated local cluster observation console.
- Add explicit SSH trust enrollment and a bounded resource helper.
- Add scoped API credentials, revocation and audit history.
- Add a synthetic demonstration mode and local web assets.
- Add reproducible dependency locks and source, protocol and browser checks.
