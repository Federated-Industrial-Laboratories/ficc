# Podman executor provider

This package implements version 1 of the trusted `ficc.executor` interface.
Its entry-point name is `podman`. Install it separately from the FICC host.
The provider runs with machine-administrator authority. It is not a workspace
module and must come from a reviewed source.

Build the wheel on Linux with a C compiler and static C library development files:

```sh
python -m build --wheel ./executor-providers/podman
```

The wheel includes a static executable barrier. The supervisor verifies this
executable before it permits the container command to start. Install the host
and provider wheels into the same root-owned environment. Then obtain the
installed package digest:

```sh
sudo /opt/ficc-executor/bin/python -I -B -m ficc.execution provider-digest podman
```

Use this digest in the administrator configuration and each approved runtime.
The runtime isolation name is `shared-kernel`. Its network name is `none`.
Stronger isolation and other network profiles are refused.

The provider requires Linux with cgroup v2, a systemd system manager, Podman,
crun, subordinate UID/GID mappings, and fuse-overlayfs. Use separate locked
workload accounts for separate storage slots. CPU, memory, process, and device
limits belong to the root-owned ancestor service. Podman uses cgroupfs below
that service. No privileged or cgroups-disabled fallback exists.

Each image has an administrator-owned OCI archive, its archive SHA256, and its
exact loaded image digest. The provider copies the archive into the bounded slot
before the rootless engine loads it. It never pulls from a registry. Local inputs
have administrator-approved paths, object IDs, sizes, and SHA256 digests. Each
local input is copied into the bounded slot. Streamed inputs arrive through the
host's authenticated input protocol after the slot is reserved. The host verifies
their full byte count and SHA256 before provider preparation. The provider links
these root-owned immutable files into the same filesystem without storing a
second payload copy. Both forms are exposed read-only at `/inputs/<name>`.
The provider rechecks streamed file identities before start. Job outputs are
relative paths below writable `/work`.

Configuration contains exactly `version`, `images`, `inputs`, and `gpu`:

```json
{
  "version": 1,
  "images": [{
    "digest": "sha256:<loaded image digest>",
    "archive": "/var/lib/ficc-executor/images/approved.oci.tar",
    "archive_digest": "sha256:<archive digest>"
  }],
  "inputs": [],
  "gpu": null
}
```

GPU configuration selects an administrator-owned NVIDIA CDI 0.7.0 document by
path and digest. It also lists approved compute libraries by path and digest:

```json
{
  "cdi": "/etc/ficc-executor/nvidia.json",
  "digest": "sha256:<CDI document digest>",
  "libraries": [{
    "path": "/usr/lib/x86_64-linux-gnu/libcuda.so.<driver version>",
    "digest": "sha256:<library digest>"
  }]
}
```

Include the driver libraries required by the approved image. That image must
have the corresponding library search path and soname links. The provider
does not run CDI hooks or modify its read-only image root. It derives a private
compute-only CDI document with selected physical GPU nodes, shared control/UVM
nodes, and those exact read-only library mounts. It excludes graphics, modeset,
DRI, MPS sockets, environment edits, and unselected GPU nodes.

The current kernel UUID-to-device-minor mapping must match the approved CDI
document. The ancestor device policy permits only selected devices and required
shared nodes. The runner verifies actual selected access and unselected EPERM
denial before the image starts. CUDA visibility variables are not an access
control. This profile provides whole-device access, not VRAM quotas, fractional
GPU allocation, or isolation from other machine-administrator workloads.

See [the executor SDK](../../sdk/executors.md) and
[local installation](../../packaging/remote/executor/README.md).
