# Contributor execution

The local executor accepts jobs from approved projects and exact installed
runtime images. A separate privileged supervisor enforces local contribution
settings. The network transport cannot change those settings or acquire general
administrator access.

Each job requests CPU, memory, swap, process, storage and whole-GPU resources.
The initial runtime uses a shared Linux kernel and has no workload network.
It exposes approved staged inputs read-only and one bounded writable work
directory. Required isolation that this runtime cannot provide is refused.

Local voluntary owners can pause new starts, drain current work, stop current
work, or resume contribution. Managed settings require the machine administrator.
All local settings remain within the administrator's installed ceiling.
Stop records an explicit cancellation before the monitor acts. It does not
replace an observed completed or uncertain result with cancellation.
Enforced stops terminate the complete workload process tree immediately. The
supervisor confirms empty processes before releasing compute capacity. A local
executor restart is treated as a recoverable connection loss by the node relay.

Preparation and execution have distinct states. Preparation reserves capacity
and stages approved inputs. A current lease is required throughout this work.
The host checks the actual running container before its command starts. Jobs may
run while current authority and renewable leases continue; there is no total
job-duration limit. Network loss, expired authority, or supervisor failure stops
the workload through local enforcement.

Output reads use bounded chunks with resumable offsets. They select only stdout,
stderr or declared output names. Unknown runtime outcomes remain visible and
must not be retried automatically. Storage and devices return to available
capacity only after the workload tree is confirmed empty. Unconfirmed cleanup
quarantines the reservation.

Admission failures remain durable. A refusal before a provider call records a
failed attempt that cannot execute through a later retry of the same request.
Provider calls follow the durable reservation, so a failed provider check still
has an attempt to inspect and clean. Missing records from an older executor do
not prove that no effects occurred. The machine administrator can acknowledge an
absent legacy attempt only after independent idle and storage checks. Its outcome
remains unknown through release; retry requires a separate explicit decision.

GPU control selects complete physical devices by UUID. It does not promise VRAM
quotas, fractional GPU allocation, GPU fault isolation, or control of unrelated
administrator processes. Node administrators can inspect workload plaintext.
Use approved managed nodes for sensitive data.

After a reboot or driver change, verify runtime readiness and all pinned runtime
inputs before accepting jobs. For the supplied GPU provider, verify the current
NVIDIA CDI device map and refresh the administrator-pinned copy when device
identities change. Preserve the approved GPU UUIDs and allowed device set. A
stale map is refused; the host does not broaden or replace it automatically.
The [NVIDIA CDI documentation](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/cdi-support.html)
describes regeneration after reboot or driver changes.

See [local installation](../packaging/remote/executor/README.md),
[provider configuration](../executor-providers/podman/README.md), and
[the executor SDK](../sdk/executors.md).
