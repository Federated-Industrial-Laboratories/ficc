# VirtualBox provider setup

This package manages VirtualBox 7.2.20 revision 175154 on Linux x86_64 through
its local C API. It supplies inventory, status, start, graceful ACPI shutdown,
and a private VNC display. Install `org.ficc.virtualbox` for the workspace table.
Other VirtualBox versions, Windows and macOS provider hosts are not qualified.
The controller can use an enrolled Linux SSH endpoint; the adapter executes on
that endpoint, under the same account as the registered VMs.

The adapter receives the selected account's provider administration authority.
A sandbox isolates its process and filesystem; the provider IPC connection can
still administer that account's VMs. Grant `provider:admin` only to trusted
packages. Workspace `vm:read`, `vm:power` and `vm:console` grants are separate.

## Provider prerequisites

Install the free VirtualBox base package from its official source. Install the
FICC node helper for the enrolled account, with the supported Bubblewrap and
systemd user sandbox. Keep the account's VM settings and display directory
private. The account requires its normal VirtualBox device permissions. Those
devices are not mounted into the module sandbox.

The release adapter needs the x86_64 glibc loader at
`/lib64/ld-linux-x86-64.so.2`, glibc 2.34 or later, `libm.so.6`, and
`libcrypto.so.3` with the `OPENSSL_3.0.0` interface. The provider account also
needs Python 3 for the setup command. Keep `setup.py` beside the package's
compiled `program` when running setup. The tested provider host is Ubuntu
26.04 x86_64. Controller installation checks on other distributions do not
qualify their VirtualBox runtime or native library ABI. Build and validate the
adapter and extension against the intended provider host before using another
distribution.

Keep `/usr/lib/virtualbox/VBoxSVC` running as that account with its ordinary
provider environment. A systemd user service may run that exact program with
`--pidfile %t/ficc-vboxsvc.pid`, `Type=exec`, `UMask=0077` and
`Restart=on-failure`. Do not put the provider service in a private `/tmp`
namespace. It must expose its ordinary account IPC socket. Apply the following
setup after the service starts:

```sh
python3 setup.py transport --confirm
```

This verifies the owned socket and kernel peer, then makes the socket mode
0600. Register the printed socket path through FICC's provider binding form.
The usual path is `/tmp/.vbox-ACCOUNT-ipc/ipcd`, in an owned mode 0700 directory.
A provider service restart changes the binding identity. Revoke the old profile
and register a new binding and profile; administration grants do not transfer.

## Build and install the free display extension

The Oracle proprietary Extension Pack is not required. The supplied FICC VNC
source modifies the free upstream VNC extension to use an owned Unix socket.
It has no TCP, IPv6, HTTP or UDP listener. This retains VirtualBox process
hardening and lets the kernel bind the display peer to the selected VM process.

Build on the VirtualBox Linux x86_64 host with C++17 build tools, the matching
VirtualBox base package and LibVNCServer development headers. Qualification
used LibVNCServer 0.9.15 and VirtualBox 7.2.20r175154. Fetch the matching source:

- Source: <https://download.virtualbox.org/virtualbox/7.2.20/VirtualBox-7.2.20.tar.bz2>
- SHA256: `5c2138213b72f36c129b92c2c267f2a40e9c98513f4c86a584327f09f9be706d`
- Size: 256073076 bytes.

```sh
python3 extension/build.py --source VirtualBox-7.2.20.tar.bz2 --output vnc-build
sudo VBoxManage extpack install vnc-build/FICC_VNC-7.2.20.vbox-extpack
```

Inspect the source and license before running the provider-host administrator
installation. This command installs the separately named `FICC VNC` extension.
It does not replace the stock `VNC` extension. Stop VMs that use FICC VNC before
an extension update. To remove it after those VMs stop, use
`sudo VBoxManage extpack uninstall 'FICC VNC'`.

The extension is GPL-3.0-only. Original copyright and contributor notices remain
in the source. Each built extension contains `ExtPack-license.txt`, `NOTICE.txt`
and the complete matching source in `source.tar.gz`, including selected headers,
generated version inputs, the Unix listener and the build script. Extract that
source archive and rebuild without another download:

```sh
python3 build.py --prepared-source source --output rebuilt
```

The same compiler and installed library inputs produce the same archive. The
external VirtualBox and LibVNCServer libraries remain separately installed
prerequisites. The extension builder performs no download or privileged action.

## Set up one VM

The selected VM must be powered off and its settings directory must be owned,
private and without symbolic links. Run as its VirtualBox account:

```sh
python3 setup.py vm --vm REGISTERED-VM-UUID --confirm
```

Setup preserves an existing nonzero `FICC/Birth` identity; otherwise it creates
a random 256-bit value. It configures the private Unix listener and a new random
VNC credential. The credential stays in the account's private VM settings and
is neither printed nor passed in process arguments. The package's C API setup
performs this change while holding the VM's write lock. Do not reuse the birth identity for a replacement VM with the
same UUID. VMs without this identity remain visible but cannot receive power
or display requests through FICC.

Install the adapter and UI archives through Modules. Register the provider
socket, create the adapter profile, inspect its identity, and explicitly grant
provider administration. Add the UI module to a workspace, grant the selected
system capabilities, read provider profiles, then select this profile and read
inventory. VM actions produce a host-owned confirmation and retained receipt.

## Operation and display limits

Start is available for powered-off VMs. Shutdown sends one ACPI power-button
request after the guest reports ACPI support. There is no forced power-off
fallback. Paused, saved, crashed and transient states are shown, with no resume,
reset or disk-management operation in this package.

Each operation checks VM UUID, birth identity and its selected lifecycle
revision before dispatch. That revision includes name, memory, CPU count,
state, last state change, session state/PID and display configuration. It is
not a complete VM configuration hash or an atomic provider lock. A concurrent
external administrator can still change the VM between check and dispatch.

An acknowledged operation is observed separately. A lost response stays
unknown and cannot be replayed. Missing provider progress records cannot prove
success. A completed or no-task unknown outcome requires explicit operator
resolution before receipt removal. Provider transport failures remain unknown.

Console proposals carry only the selected VM process and an owned Unix path.
The helper binds device, inode, owner, kernel peer PID and process start identity;
replacement or revocation closes access. The display credential crosses the
private SSH stream to the isolated native decoder and is absent from browser
tickets. Viewer input, focus release, fitting and fullscreen use the host's
common controls. Guest resolution changes depend on its display driver; a
fixed framebuffer still fits a resized viewer. Guest audio is not supplied.
