# Local executor installation

The contributor transport and privileged executor are separate services.
The transport keeps its existing confined account. It receives access only to
the executor's private Unix socket. It cannot change contribution settings.

Install the FICC host and the selected executor provider into a root-owned
Python environment made with `python3 -m venv --copies`. The environment and
every parent directory must prevent non-root writes. Use pinned, verified wheels
and the host dependency lock. The optional Podman provider is a separate wheel.
Do not install executor code into a user-writable application environment.
Use installation umask 022 so package directories have mode 0755 and files have
mode 0644. Root ownership prevents shared writes; workload accounts need read and
execute access to the fixed interpreter, provider runner and static barrier.
Configuration and state remain private with their stricter modes below.

Prepare one locked workload account per storage slot. Each account needs its own
primary group and nonoverlapping subordinate UID/GID ranges. It must have no
interactive shell or supplementary groups. Never reuse the contributor transport
or a local owner account. Existing process trees prevent slot admission.

Prepare independent finite filesystems with recorded UUIDs, byte capacities,
inode capacities, and generations. Mount them with `nosuid,nodev` below root-owned
paths. The initial storage boundary requires ext4 with fixed byte and inode
capacities. The mounted capacity must not exceed the
configured slot class or the admitted job maximum. Never use an ordinary
directory on an unbounded host filesystem as a storage slot. A missing or changed
mount refuses work; uncertain cleanup retains the reservation.

The installer does not create accounts, format disks, resize filesystems, or
change LSM policy. Those administrator actions require a reviewed deployment
configuration. Preserve existing disks and mount data. The supplied service
renderer only writes a unit to standard output.

Write the executor configuration as a root-owned regular file with mode 0600.
Its version is 1. The exact schema is `ficc.execution.settings.Settings`.
The required fields are:

| Field | Purpose |
| --- | --- |
| installation_id | A fresh 32-character hexadecimal installation identity |
| deployment_id, node_id | Exact approved controller and contributor identities |
| mode | `managed` or `voluntary` |
| transport_uid | Existing confined contributor transport UID |
| local_owner_uids | Local voluntary owners; empty for managed mode |
| maximum_lease_seconds | Local authority ceiling from 5 through 30 seconds |
| service | `ficc-executor-<installation_id>.service` |
| state | Separate private root-owned state directory, mode 0700 |
| sockets | Separate root-owned socket directory without shared write access |
| ceiling | Administrator-approved projects, runtimes, resources, and schedule |
| initial_offer | Same offer schema, initial revision 1, installed mode and control |
| slots | Independent account and finite-filesystem bindings |
| providers | Explicit executor names, package digests, and typed provider configuration |

State, socket, and slot paths must be separate. Paths must have no aliases,
parent components, whitespace, colon, comma, or backslash. Create the state and
socket directories before service startup. A socket directory may be mode 0755;
each socket is mode 0600 and belongs to its allowed local account.

Each slot contains `id`, `generation`, `mount`, `filesystem_uuid`, `account`,
`uid`, `gid`, `storage_bytes`, and `storage_inodes`. Each runtime contains
`provider`, `package_digest`, `image_digest`, `isolation`, and `network`.
The supplied provider uses `shared-kernel` and `none` for the last two fields.

Render and inspect the service unit before installation:

```sh
sudo /opt/ficc-executor/bin/python -I -B render_service.py \
  --config /etc/ficc-executor/settings.json \
  --python /opt/ficc-executor/bin/python
```

Install the reviewed output under its exact configured service name. Reload the
system manager and start that service. Confirm its private socket snapshot before
enabling controller dispatch. The controller must use the snapshot's local lease
ceiling and current offer revision.

The service has a two-second watchdog. Attempt units use `BindsTo` and `After`
dependencies on this exact supervisor service. The supervisor must remain the
service's main process. The process monitor sends watchdog notifications only
while local enforcement progresses. Do not disable the watchdog or dependencies.
Network loss expires job leases. A dead or stalled supervisor stops its dependent
workloads. No total job-runtime limit is installed.

All image copies, extraction, runtime state, temporary files, inputs, outputs,
engine diagnostics, and service logs stay in the reserved finite filesystem.
The separate state database stores bounded control receipts and attempt fences.
Retain that database across restarts. Do not restore it over a running executor.
Recovery reconciles and stops retained live work before accepting new starts.
Unknown outcomes remain unknown; release after confirmed cleanup preserves that
outcome. Controller retry requires an explicit operator decision.

A filesystem remount can change its live mount identity. Keep the retained slot
quarantined. To recover it, stop the supervisor, confirm the same filesystem and
account, and increase that slot's configured generation. Use the exact retained
attempt fence and old slot generation:

```sh
sudo /opt/ficc-executor/bin/python -I -B -m ficc.execution recover-storage \
  --config /etc/ficc-executor/settings.json --attempt ATTEMPT_ID \
  --generation ATTEMPT_GENERATION --plan-digest PLAN_DIGEST \
  --old-slot-generation OLD_SLOT_GENERATION
```

The command refuses a running supervisor, a changed filesystem UUID, byte or inode
capacity, workload account, or live process tree. It records the old and new
bindings. It confirms cleanup only; it cannot turn uncertainty into success or
restart a job. Restart the service, inspect the retained result, then release its
storage through the normal fenced operation. A missing attempt record is not
proof that work never ran. Preserve unknown controller outcomes after lost local
state and require explicit operator acknowledgement before a retry.

Before a deployment accepts jobs, qualify CPU, memory, process and storage bounds,
device denial, actual selected-GPU computation, lost leases, restart, watchdog
failure, and complete process cleanup. Qualification must use the installed host,
provider, kernel, engine and driver versions. A provider or operating-system
upgrade requires the affected boundary checks again.
The maintained [local fixtures](../../../tests/integration/execution_local/README.md)
build a small offline image and exercise the installed private socket.

Local owners can inspect and control a voluntary offer:

```sh
python -m ficc.execution status --socket /run/ficc-executor/owner-1000.sock
python -m ficc.execution control --socket /run/ficc-executor/owner-1000.sock paused
python -m ficc.execution control --socket /run/ficc-executor/owner-1000.sock draining
python -m ficc.execution control --socket /run/ficc-executor/owner-1000.sock stopped
python -m ficc.execution control --socket /run/ficc-executor/owner-1000.sock active
```

The administrator uses `admin.sock`. The transport uses `transport.sock` and
cannot issue local offer changes. Every command checks actual socket peer UID.
