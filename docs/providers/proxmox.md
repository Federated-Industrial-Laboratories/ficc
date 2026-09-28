# Proxmox VM provider

The runtime package `org.ficc.proxmox` uses an enrolled SSH system and a fixed
local Proxmox API adapter. The profile requires an explicitly enrolled root
account. It does not use sudo. A module cannot supply a URL, command, socket,
environment variable or credential.

This adapter is an internal integration for qualified Proxmox VE 9.2 builds.
The profile records the node, machine ID, manager version, provider package
versions and implementation hashes. A changed provider must pass compatibility
checks before its profile can be replaced. An installed package alone does not
establish compatibility. Power and console qualification are separate.

The package requires `workspace:read` and `vm:read`. `vm:power` and `vm:console`
are optional. Each requires an explicit grant for each enrolled system. The caller must also have
the matching VM scope. Inventory works without power grants. Power requests
produce a host confirmation preview; a module cannot commit that preview.

## Identity and actions

A numeric VMID can be reused. A FICC resource ID includes the profile identity
and a digest of the node machine ID, SMBIOS UUID and generation UUID. Both UUIDs
must be valid and nonzero. Changing either creates a different resource.
Configuration digests are additional confirmation conditions. A VM without
verified UUIDs produces an inventory error and cannot be selected for power.

Start and graceful shutdown use registered Proxmox tasks. Before dispatch, the
node writes a durable intent. The provider worker takes the real VM configuration
lock, refreshes the cluster configuration cache, and checks the frozen resource,
configuration and state. It holds that lock for the fixed lifecycle call. There
is no module-controlled force or lock-bypass option.

The first adapter refuses templates, locked or suspended configurations, pending
configuration changes, hook scripts and HA-managed VMs. Shutdown requires a
running VM and uses a 60 second graceful limit with force disabled. These cases
need their own provider semantics before they can be supported safely.

The host records the exact UPID separately from the observed VM state. A stopped
task with an error has state `failed`; it is not retried. An accepted task becomes
`observed` only after a successful stopped task and the desired VM state are both
observed. A lost task result stays `unknown`. Reading or repeating a receipt never
repeats the mutation.

Recovery and receipt removal use the shared VM confirmation
and retention rules. A known running or unreadable provider task keeps its receipt.
Profile removal requires all operation receipts to be removed.

Requests contain one to 64 targets. Inventory pages contain at most 64 rows per
system, with at most 256 rows across a host batch and an explicit continuation.
The supplied table limits the complete page to 128 rows across all selected systems.
The local inventory limit is 4096 definitions.

Helper messages are bounded to 1 MiB,
stderr to 8 KiB and the local bridge to 4.5 seconds. Read and console requests
keep a 6 second helper bound and an 8 second SSH bound. Host power commits use
a 12 second total helper bound and a 14 second SSH bound for both durable writes.
The module can request a preview but cannot enter this longer commit path.

Registered provider tasks can continue after the SSH request ends; their durable
task IDs and logs establish recovery authority.

## Host integration

`Proxmox(service)` provides `set_profile(actor, node_id, enabled=True)`,
`profiles(actor)`, `remove_profile(actor, node_id)` and the shared VM operation
methods. Profile setup is asynchronous because it verifies the local provider.
Records use `module_proxmox_profiles` and `module_proxmox_operations`.

The fixed broker family is `vm.proxmox.list`, `vm.proxmox.status`,
`vm.proxmox.preview`, `vm.proxmox.operation` and `vm.proxmox.console`.
Host confirmation and history use
the common VM surface. Public previews and operations identify the provider as
`proxmox`; operation targets can contain the bounded provider task record.

Console access uses the host viewer. At attachment, the helper holds the provider
configuration lock and checks both UUIDs. It connects the fixed local QEMU Unix
socket and verifies its root peer PID and process start time before releasing the
lock. A separate private lock permits one FICC attachment per VM.

The helper sets a short-lived VNC password. The private SSH readiness envelope
passes that password directly to the isolated native viewer. The module and
browser receive no address, socket, ticket or password. This VNC path has no audio,
clipboard or file transfer. Keyboard and pointer controls use the shared viewer.

Read, lifecycle and display calls require an exact qualified provider build tuple.
The current tuple is manager `9.2.2/b9984c6d90a4bd80` with implementation fingerprint
`d89f96fdd413e8c3bbe4819eebaf48bd006609f57b81c1043cd7344b4b594f49`.
A generated version literal and bounded source hashes establish that fingerprint;
the adapter does not evaluate the version file. A provider upgrade requires new
compatibility checks. Terminal receipt removal does not call the provider API.

## Provider sources

- [Local root API](https://pve.proxmox.com/pve-docs/pvesh.1.html)
- [VM management](https://pve.proxmox.com/pve-docs/qm.1.html)
- [Provider configuration implementation](https://git.proxmox.com/?p=qemu-server.git;a=blob;f=src/PVE/QemuConfig.pm;hb=HEAD)
- [Provider task implementation](https://git.proxmox.com/?p=pve-common.git;a=blob;f=src/PVE/RESTEnvironment.pm;hb=HEAD)

Published upstream source explains the contract. Qualification must use the exact
installed source and package versions because these internal APIs can change.
