# Changes

## 2.0.0-stable

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
