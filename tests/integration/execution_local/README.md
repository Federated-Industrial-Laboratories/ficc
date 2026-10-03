# Installed executor qualification

These fixtures operate on an explicitly prepared, isolated executor installation.
They do not provision accounts, format storage, install services, pull images,
change driver policy, or discover real credentials. Run machine mutations only
through the machine administrator. Keep one active qualification attempt per
slot, with new job and attempt identities for each case.

Build the CPU image as an ordinary user, outside the source tree:

```sh
python tests/integration/execution_local/build_image.py /tmp/ficc-execution-image
```

The destination must be new. `build.json` contains the image configuration digest,
archive digest, byte count and exact compiler command. The image contains one
small static executable and empty system directories. It needs no registry or
network. Install the archive as a root-owned immutable input and pin both digests
in the Podman provider configuration. Build and install the provider wheel with
the same host version and dependency lock before enabling the local service.

Create a validated `ficc.execution.spec.Plan` with the current socket snapshot's
deployment, node, offer revision, approved project and runtime. Use a fresh job ID
and attempt ID, generation 1, and the authorized subject and policy revision.
Select the exact finite slot class. The plan's storage maximum must cover both
the slot's byte capacity and inode capacity. The payload uses one of these forms:

| Case | Container arguments | Required result |
| --- | --- | --- |
| Arithmetic | `/fixture compute 1 101` and `/fixture compute 64 201` | A declared `result.json` output containing distinct rows; each value is input squared plus three times input plus seven |
| Isolation | `/fixture isolation 1 /host-test-canary /dev/nvidia0 /dev/nvidia1` | Read-only root, absent host canary, loopback-only network, no GPU, private PID 1 |
| CPU | `/fixture cpu 4000` | Actual ancestor CPU limit and measured process CPU time consistent with that limit |
| PIDs | `/fixture pids 1` | `fork` reaches EAGAIN below the fixed process ceiling; all children reaped |
| Memory | `/fixture memory 268435456` under a 128 MiB memory maximum | Kernel OOM counters and stopped complete process tree; an uncertain application exit is retained as unknown |
| Storage | `/fixture disk 268435456` in a 256 MiB slot | ENOSPC or EDQUOT, bounded bytes, and recovered free space after deleting its own fill file |
| Crash | `/fixture crash 1` | Live core soft and hard limits are zero; observed application failure, no payload core file outside its slot |
| Lease and service faults | `/fixture wait 1` | Complete termination after lease expiry, explicit stop, supervisor death or watchdog failure |

Use at least 128 MiB for ordinary CPU cases, 512 MiB for the small CUDA fixture,
and enough process capacity for the engine. The PID case requires a smaller
explicit process maximum. The memory profile uses MemoryHigh equal to MemoryMax;
it tests the hard maximum without an earlier soft-throttle fixture timeout.
Fixture timeouts are test bounds and are not job runtime limits.
Use `--expected unknown` when an OOM kills the complete engine and the application
exit cannot be observed. The kernel OOM evidence and confirmed empty cleanup must
still be checked. Unknown is an outcome to preserve, not application success.
For the crash case, record the host crash-directory inventory before and after,
and qualify the installed crash handler's container behavior. The supervisor
watchdog uses SIGKILL, so it cannot create a privileged diagnostic core.

Run the real socket workflow with the installed interpreter:

```sh
/opt/ficc-executor/bin/python -I -B tests/integration/execution_local/run.py \
  --socket /run/ficc-executor/admin.sock --plan /root/fixture-plan.json \
  --output /root/fixture-observation --case complete
```

The output directory must be new. Preparation remains renewable while the image
is staged. The fixture observes readiness before start and records real kernel
cgroup values alongside typed replies. It collects at most 64 KiB per fixture
output; this is an observation bound, not a product data-size limit. All plans,
source hashes, installed package versions and receipts belong in the qualification
record. This fixture deliberately leaves storage reserved for inspection.
Release only through the exact attempt fence after recording the outcome and
confirmed process cleanup.

For a wait payload, use `--case expire`, `stop`, `restart`, or `watchdog`.
Expire stops renewal. Stop sends the normal fenced stop command. Restart sends
SIGKILL to the exact supervisor main process. Watchdog sends SIGSTOP and requires
the service manager to kill the stalled supervisor and its dependent attempt.
The latter two cases require administrator privileges and the isolated test
service. They do not signal unrelated services. Retained outcomes must be unknown
after these faults; they are never reported as successful execution.

A fixture failure retains its reservation and evidence. Do not delete a live
slot or repeat the job automatically. Inspect all workload-account processes,
unit state and cgroups, then use the documented recovery and release controls.
For N=64, use distinct records, projects or input rows and state precisely which
boundary each check covers. A 64-row arithmetic payload is not 64 independent
VM or GPU launches. Qualify each approved physical GPU UUID with the actual CUDA
payload, prove selected-device access and unselected-device denial, and preserve
its N=1 and N=64 arithmetic outputs.
