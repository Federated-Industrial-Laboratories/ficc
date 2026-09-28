# Changes

## 0.2.0 (unreleased)

- Add installable runtime modules with archive inspection, sandboxing and explicit capability grants.
- Add C, C++, Rust, Python and JavaScript SDK helpers, plus TypeScript authoring.
- Add declarative components, saved workspaces, floating panels, tiling and separate monitor windows.
- Add shared fullscreen controls, private VM display sessions and explicit input release.
- Add VM inventory and durable power actions with provider profiles and outcome recovery.
- Add packaged provider adapters with separate account grants and registered transports.
- Add Docker, Podman and Kubernetes controls through constrained provider profiles.
- Add service controls, bounded logs and explicitly confirmed system power actions.
- Add a registered-root text editor, notes, clocks and a shared audio player.
- Add private Windows endpoint credentials and optional native display and transport runtimes.
- Preserve workspace and module data in backups; restore provider profiles without active grants.
- Recover incomplete module staging before startup and stopped backups.

### Provider limits

Hyper-V and VirtualBox are not supported for operational use in version 0.2.0.
Hyper-V includes experimental package sources; real Windows lifecycle and VMConnect remain unqualified.
VirtualBox has no complete provider package, and its local IPC transport remains disabled.
Use KVM/libvirt or Proxmox VE for verified VM inventory, power actions and display.

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
