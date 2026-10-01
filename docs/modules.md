# Runtime modules

[Contents](README.md) | [Workspaces](workspaces.md) | [Module SDK](../sdk/README.md)

Modules add panels after FICC installation. Each package contains a manifest,
host component descriptions and optional program files. Default modules use the
same archive format and permission checks as other modules.

Packages use documented host components and broker operations. Provider adapter
packages use separate account grants and registered transports. They supply
provider logic outside the controller. Some supplied integrations retain fixed
controller adapters. See the [extension boundary](../sdk/README.md#extension-boundary).

## VM provider support

KVM/libvirt, Proxmox VE, Hyper-V and VirtualBox provide verified VM inventory, power actions and display.
VirtualBox uses separate native adapter and workspace packages with registered account transport.
See [VirtualBox](providers/virtualbox.md) for the exact supported environment and setup.
Hyper-V requires the registered Windows transport and fixed JEA endpoint.
See [Windows endpoints](windows-endpoints.md) for the qualified environment and setup.

See [provider qualification](testing.md#runtime-modules-and-providers).

## Install and enable

1. Open **Workspace** and create a named workspace.
2. Select **Manage modules**.
3. Select a supplied package, choose a local file, or enter a package URL.
4. Select the corresponding **Inspect** control.
5. Check the package identity, digest, platform, architecture, host API and permissions.
6. Accept the source only if it is trusted.
7. Select **Install disabled**.
8. Select **Enable** and choose exact targets for the required permissions.
9. Select any optional permissions needed for the intended actions.
10. Select **Enable with selected grants**.
11. Close the manager, select the installed module and select **Add module**.

Provider adapters cannot be workspace panels. After installation, select
**Provider adapters** and create a profile for its registered endpoint.
Review the exact package digest, account authority and declared consistency.
Grant account access only to a trusted adapter. Its account access can change
all provider resources, including during an inventory request.

Grant workspace VM permissions to an ordinary panel module separately.
See [the adapter protocol](../sdk/ADAPTERS.md) and [Windows endpoints](windows-endpoints.md).

Installation does not execute package code. The current publisher field remains
**Unverified**, including supplied packages. A SHA-256 digest identifies bytes;
it does not authenticate a publisher. There is no automatic trust-key import.

The installed table shows package IDs and digest prefixes. Select **Details**
to read the full identity and runtime requirements. Grant and removal controls
show the full digest, version, role and publisher status. Equal display names
do not identify equal packages.

Workspace permissions select workspaces. System permissions select enrolled
machines. File permissions select registered folders. A panel also has its own
saved target selection. Package grants, panel targets and current caller access
must all permit each request.

Optional permissions can remain ungranted. For example, VM inventory can be
enabled without power or console access. **Edit grants** changes the exact
package digest's permissions. Revocation closes affected calls and displays.

## Package sources

Local packages are ZIP files with a `.ficc-module.zip` extension. A package on a
mounted network share can use the local file path. FICC does not mount shares.

HTTPS is the default address transport. Private network addresses require
**Allow this private network source**. Plain HTTP also requires an expected
SHA-256 digest and **Allow HTTP with an expected digest**. Obtain the expected
digest through a trusted channel. Loopback, link-local and metadata addresses
are refused. Redirects and embedded URL credentials are refused.

Archives have a 16 MiB compressed limit and a 64 MiB expanded limit. Each archive
has at most 256 members. Links, device files, unsafe paths, duplicate names and
digest mismatches are refused. Packages have no installation scripts or hooks.
The installer does not fetch package dependencies.

## Command line

These commands use the running local controller's private control socket.
No API credential needs to appear in a shell argument.

```sh
ficc module-supplied
ficc module-inspect --supplied org.ficc.clock
ficc module-inspect --file /path/to/package.ficc-module.zip
ficc module-sandbox
ficc module-list
```

After inspection, use the exact reported digest for installation:

```sh
ficc module-install --file /path/to/package.ficc-module.zip \
  --expected-digest DIGEST --accept-unverified
ficc module-enable DIGEST --grants /path/to/grants.json
ficc module-disable DIGEST
ficc module-remove DIGEST --confirm
```

Replace `DIGEST` with the 64-character lowercase SHA-256 value. The grant file
contains a JSON list. Replace the sample target with the selected workspace ID:

```json
[
  {
    "capability": "workspace:read",
    "target_ids": ["0123456789abcdef0123456789abcdef"]
  }
]
```

Use `--url` or `--supplied` instead of `--file` when needed. Address commands use
`--allow-private-network` and `--allow-http` for their explicit transport choices.
Every command accepts `--state-dir` for a separate controller.

## Updates, removal and recovery

Install a new version disabled and review its grants before enabling it. Only
one digest of a package ID can be enabled. Enabling another version disables
the previous version. Grants are not copied to the new digest.
The grant screen identifies the enabled version that will be disabled.

Activation checks the platform, architecture, interpreter and native ELF loader
before changing the active version. A refused replacement retains the previous
version and its grants. Native packages require a Linux ELF64 executable and
a loader available inside the sandbox. These checks do not prove compatibility
with every shared library or required symbol. Build for the target distribution.

Saved panels remain bound to their exact package digest. An unavailable digest
shows a placeholder and retains its saved state. Re-enable the original digest
to recover that panel. A new version uses a new panel; state migration is not
automatic. Retain the original package until its state is no longer needed.

Operation history retains the authority needed for inspection and cleanup.
Remove completed action receipts through the panel's history before removing its package,
panel or provider profile. Unknown outcomes require explicit inspection and
resolution. Disabling a package remains available while history is retained.

## Execution requirements

Program modules require Bubblewrap, a systemd user manager and working namespace,
syscall and cgroup controls. Select **Check module sandbox** in Module manager
before enabling them. The result gives the current status or refusal reason.
The same check is available through `ficc module-sandbox`.
An unavailable sandbox refuses execution. Declarative clock, notes and audio
panels use host components and start no module process.

If AppArmor blocks user namespaces, an administrator must review the
[scoped policy instructions](../tools/module-sandbox-policy/README.md).
The check does not install a policy or change host security settings.
Keep isolation enabled; do not run the controller as root to bypass a refusal.

Each program receives private process, network and file namespaces. It receives
no home directory, SSH keys, controller database, display socket or container
socket. The host broker supplies only declared, currently granted operations.
The broker does not accept arbitrary shell commands or provider addresses.

Each process has 128 MiB memory, no swap, 32 tasks and a 50 percent CPU quota.
Plain programs have a 10-second request deadline and a 12-second service bound.
Supervised broker conversations have a 30-second deadline and a 32-second service
bound. Provider commit sandboxes have the same 30/32-second limits. The separate
outer SSH deadline for Linux-node commits remains 20 seconds.
These longer waits do not change memory, task, CPU or capability limits. At most
four module actions run at once. These limits are separate from the
[native viewer limits](viewer.md).

See the [security model](../SECURITY.md), [supplied packages](../modules/README.md)
and [SDK](../sdk/README.md). A sandbox limits authority; it does not establish
that an unverified package is trustworthy.
