# VirtualBox

VirtualBox uses two separately installed runtime packages:

- `org.ficc.virtualbox-adapter` runs the provider C API inside the enrolled
  account's required sandbox.
- `org.ficc.virtualbox` supplies the workspace table, provider selector,
  power previews and common viewer controls.

The supported provider host is Linux x86_64 with VirtualBox 7.2.20 revision
175154. A different provider version is refused. The provider host also needs
the current FICC node helper, a functioning Bubblewrap/systemd user sandbox,
and its normal VirtualBox device permissions. The module sandbox receives one
verified IPC socket; it does not receive the host home directory or VM devices.
Windows and macOS VirtualBox hosts are not qualified.

The qualified provider environment is Ubuntu 26.04 x86_64. The release adapter
requires glibc 2.34 or later, the x86_64 glibc loader, `libm.so.6` and
`libcrypto.so.3` with `OPENSSL_3.0.0`. Build the display extension on the provider
host with its matching VirtualBox and LibVNCServer libraries. Controller package
installation on a distribution does not qualify that distribution's provider
runtime. Other Linux provider environments require their own qualification.

## Connect an account

Keep the account's VBoxSVC running and its socket private. Follow the supplied
[provider setup and display build guide](../../modules/virtualbox-adapter/payload/README.md).
That guide includes a checked setup command and explains service restart recovery.

In Manage modules, inspect and install both archives. Accept the source only
if trusted. Register the account's private Unix socket on the enrolled SSH node,
create a profile for the installed adapter digest, then explicitly grant provider
administration. This grants the adapter authority over that VirtualBox account.
It is separate from a workspace module's system grants and does not make the
underlying provider account read-only.

Add VirtualBox virtual machines to a workspace and select the enrolled system.
Grant `vm:read`; add `vm:power` and `vm:console` only where needed. Use Read
provider profiles, select the profile, then Read VM inventory. The table supports
multiple selection and inventory offsets. A power request produces a separate
host confirmation with the selected VM identities and consistency class.

## VM identity and lifecycle

Explicit provider setup assigns a durable, random `FICC/Birth` marker to a VM
that lacks one. Inventory never writes it. A VM without the marker remains
visible but cannot receive a power or console request. Do not copy the marker
onto a replacement VM that reuses its UUID.

Start applies to powered-off VMs. Graceful shutdown requires the guest to have
entered ACPI mode and sends one power-button event. An early boot framebuffer
does not prove this readiness. There is no forced shutdown fallback. This
package does not create, delete, reset, migrate, snapshot or edit VM disks.

The profile reports `checked-before-dispatch`. The package rechecks UUID, birth,
state and the lifecycle/display fields used by the operation. This is not an
atomic provider lock or a complete settings hash. Concurrent external changes
remain possible between checking and dispatching.

FICC retains operation intent before dispatch. Reusing a request identity returns
its receipt without repeating the provider action. An uncertain response does
not become success merely because the VM has the desired state. Missing progress
objects retain an unknown result; completed or no-task outcomes require explicit
resolution before cleanup. Unknown active tasks cannot be discarded.

## Display

The free FICC VNC extension is built from the pinned upstream free VirtualBox
VNC source. It is separately named and is not the proprietary Oracle Extension
Pack. Its GPL-3.0-only source, build instructions and notices are included in the
adapter package; each built extension contains its complete matching source.
The provider-host administrator installs it explicitly.

The extension listens on a private Unix socket. FICC verifies the socket's
inode and owner, plus the kernel-reported peer PID and process start identity,
against the selected VM session. It transports that stream over the enrolled
SSH connection to the isolated native viewer. The display password is absent
from the browser's opaque reference and attachment ticket.

Input focus, input release, fitting, expansion and fullscreen use the common
[viewer](../viewer.md). Fixed guest resolutions fit a resized workspace panel;
guest resolution changes require driver support. Guest audio is not supplied.
A provider restart, socket replacement or revoked grant requires a new attachment.
A provider account restart requires a new binding/profile and new explicit grants.
