# Default module sources

These are independent runtime packages. Build them with:

```sh
python tools/build-modules.py defaults --output dist/modules
```

Install the resulting ZIP files in the module manager and grant the requested
workspace and system permissions. Installation and enablement use the same checks as any
other module. These sources do not register modules during the application build.

| Package | Host component | Capabilities |
| --- | --- | --- |
| org.ficc.clock | UTC clock | workspace:read |
| org.ficc.notes | Plain text editor with explicit Save | workspace:read, workspace:write |
| org.ficc.audio-player | Local audio file player with shared sound controls | workspace:read, workspace:write, audio:playback |
| org.ficc.system-status | Saved system resource table | workspace:read, system:read |
| org.ficc.component-gallery | Component and table examples | None |
| org.ficc.file-editor | Registered-root text editor | workspace:read, files:read; optional files:write |
| org.ficc.libvirt | VM table and console controls | workspace:read, vm:read; optional vm:power, vm:console |
| org.ficc.proxmox | Proxmox VM inventory and qualified provider actions | workspace:read, vm:read; optional vm:power, vm:console |
| org.ficc.containers | Docker, Podman and Kubernetes table | workspace:read, container:read; optional container:logs, container:power |
| org.ficc.system-admin | Systemd status, services, logs and power controls | workspace:read, admin:read; optional admin:logs, admin:services, admin:power |
| org.ficc.hyperv-adapter | Packaged Windows provider adapter through registered JEA transport | provider:admin |
| org.ficc.hyperv | Hyper-V table, power confirmation and VMConnect controls | workspace:read, vm:read; optional vm:power, vm:console |
| org.ficc.virtualbox-adapter | Native VirtualBox provider adapter through registered private IPC | provider:admin |
| org.ficc.virtualbox | VirtualBox table, power confirmation and private console controls | workspace:read, vm:read; optional vm:power, vm:console |

Hyper-V and VirtualBox require their qualified provider versions and explicit
account setup. Both use separately installed adapter and workspace packages. See [provider qualification](../docs/testing.md#runtime-modules-and-providers).

Clock, notes and audio use declarative host components. System status runs a Python
module in the required sandbox. It reads saved measurements through the constrained
host broker. It receives no SSH credentials. Its table marks stale measurements.
Each status panel has a saved, explicit system selection.

The host owns rendering, state storage and permission checks. The audio player
does not request microphone access. See [the SDK](../sdk/README.md) to create a module.

Release and source installers include separate archives in the supplied module
catalog. They do not install or enable those archives. In Manage modules, select
a supplied module and inspect it. The local-file and address paths use the same
archive checks. Accept the source, install disabled, then select exact grants.
