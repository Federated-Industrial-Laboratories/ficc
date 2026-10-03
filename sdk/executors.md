# Executor provider interface

An executor is a separately installed trusted Python distribution. It registers
an entry point in `ficc.executor`. The configured entry name selects exactly one
distribution. The administrator pins a digest of its verified installed files,
metadata, version, and entry point. The host checks the distribution before it
imports provider code. This provider class has administrator authority.

The module exports `API_VERSION = 1` and `configure(configuration)`.
Configuration comes from a private administrator-owned file. It never comes from
browser requests, remote job payloads, or contributor transport claims.

Configure returns a driver with these synchronous batch methods:

| Method | Input and result |
| --- | --- |
| probe | Validate each approved plan, runtime input and device mapping; return readiness |
| prepare | Prepare each reserved slot; return its fixed invocation, barrier, devices and mounts |
| start | Recheck prepared inputs and return the fixed invocation for the host envelope |
| observe | Return the current bounded runtime phase, payload PID or observed exit code |
| stop | Observe provider state after the host stops the complete workload tree |
| collect | Return requested bounded log or declared-output chunks |
| release | Remove private runtime storage after the host confirms process cleanup |

Methods take ordered lists of 1 through 64 contexts and return one dictionary per
input. The host may group compatible requests or call a one-row batch. A context
contains the validated immutable plan, plan digest, configured slot, verified
storage binding, owned attempt directory, exact service name, cgroup, and supervisor
service. Prepared contexts also contain the persisted `prepared` result.

The host can stage immutable input objects in the reserved filesystem. These
objects use `delivery: "stream"` in the plan. Ordinary administrator-configured
objects use `delivery: "local"`; the serializer omits this default so existing
plans keep their serialized bytes and digests. Both forms bind the exact object
ID, name, byte count, and full SHA256 digest in the immutable plan.

Completed streams are supplied as `inputs`, a list of host-created capabilities
in the provider context. Each capability contains the declared `id`, `name`,
`bytes`, `digest`, and `delivery`, plus a host-owned `path` and filesystem
`identity`. Paths never come from remote requests. The files are regular,
read-only, owned by root, and readable by the reserved workload group. Their
parent is private to root. A provider may hard-link a capability into its own
runtime layout on the same reserved filesystem. It must preserve root ownership
and read-only access, and verify the recorded file identity before start.
Creating a hard link changes ctime; the stable capability identity consists of
device, inode, mode, byte count, and mtime. The provider remains responsible for
its runtime layout. It must not copy a large stream into a second unreserved
location or interpret an object ID as an administrator path.

Prepare receives a `check()` callback. Call it before preparation and between
bounded input-copy operations. It checks the current lease and local authority.
Do not serialize the callback. Preparation runs asynchronously after atomic
admission of the plan, first lease and reservations. The host commits admission
before calling any provider method, including `probe`. A probe failure retains
that record and reservation until independent cleanup and explicit release.
Renewals remain valid while
the public attempt is `prepared` with `ready: false`. Start is permitted only
after `ready: true`, with a current lease and unchanged start authority.

For streamed inputs, admission reserves the slot and lease before bytes are
accepted. Provider preparation waits until every stream reaches its declared
size and full digest. Hashing is incremental, and input I/O runs outside the
monitor lock. Disk capacity comes from the selected finite slot, including
runtime images, temporary files, logs, and outputs; there is no separate total
input-size limit. A source that cannot fit its slot is refused. Disk or digest
failure prevents start and retains the normal cleanup and release lifecycle.

The prepare result contains `argv`, `barrier`, `devices`, `mounts`, `generated_targets`,
`positive_devices`, and `negative_devices`. These resolve solely from installed
provider code and administrator configuration. The host creates the enclosing
system service; the provider cannot request larger resource or device limits
through the remote protocol. Each mount binds a source, target, read-only flag,
and recorded filesystem identity. Device entries bind exact character nodes.

The host independently checks the live payload's UID/GID, namespace separation,
capabilities, system-call filter, cgroup membership, resource limits, device
policy, mount identities, and file descriptors. It checks the actual executable
against the trusted barrier before releasing the command. A descriptor alone is
not evidence that the running process has these controls.

Observe phases are `waiting`, `ready`, `payload`, and `finished`. Ready includes
the runner's actual device-open results. Payload includes its host PID. Finished
includes an observed exit code from 0 through 255. The host preserves uncertainty
if process cleanup or the runtime outcome cannot be confirmed. It never treats a
missing reply as permission to replay the job.

`ficc.execution.protocol` defines the version-1 Unix request models.
`ficc.execution.wire` defines the exact response models. The async
`Client(socket_path).request(message)` checks the root server peer, protocol
version, request ID and bounded response. The transport may prepare, renew,
start, observe, stop, collect, stage inputs, release, reject an absent new admission, and read
snapshots. It cannot set offers or acknowledge an absent legacy attempt.

Requests and replies use a four-byte unsigned network-order length followed by
UTF-8 JSON. Requests are at most 8 MiB and replies at most 2 MiB. These are control
frame bounds, not total job-data limits. Each collect batch reads at most 1 MiB;
use returned offsets to read larger results. Only declared output names and the
two log streams can be read. Files must be regular and below the reserved storage.

`input_status` has an `objects` list of one through 64 entries. Each entry has
the attempt fence and `object`, the declared streamed input ID. `input_write`
has a `writes` list of one through 64 entries, adding `offset`, canonical base64
`data`, and `digest`, the SHA256 of that chunk. Aggregate decoded data is at most
1 MiB per request. Offsets and declared sizes use nonnegative 64-bit integers;
clients must preserve integer precision. Empty chunks are valid only for an
empty object, whose declared full digest must equal SHA256 of empty bytes.

Both operations return the ordinary ordered batch envelope. A successful row
contains its fence, `ok: true`, `object`, durable next `offset`, declared `bytes`,
declared full-object `digest`, and `complete`. Bytes are synced before their
offset is committed. A missing write acknowledgement does not imply failure:
query `input_status` and continue at the returned offset. Repeated prepare for
the same plan preserves the partial and its lease deadline. Do not resend a
chunk at an old offset or silently bind changed source data to the old plan.

Status and writes require current lease and local authority while the attempt
remains prepared. Continue lease renewal during transfer. `inputs_preparing`
means that the admitted staging directory is still being initialized;
`input_busy` means another write for the attempt is in flight. Retry these on a
later polling cycle. `input_offset_changed` requires another status read.
Completed inputs stay read-only. The provider starts preparation automatically
when all streams complete; poll attempt readiness before requesting start.

A controller reconnect can resume the same active attempt. An executor restart
retains the existing unknown-outcome behavior and does not resume or replay an
uncertain attempt. Release removes the host's staged files only after confirmed
cleanup, finished input writes, and provider release. Failed storage cleanup
keeps the reservation. Input files are not a cross-attempt cache, and release
never removes the retained attempt fence.

Snapshot includes the configured lease ceiling, current offer, available resource
counts, slot classes, provider identities, and up to 64 attempts. Follow `next`
with the next request's `after` cursor. Capacity is an observation, not a durable
reservation. Admission rechecks every resource and authority binding.

New snapshots also include `ledger_id` and `admission_version: 1`. The ledger ID
is a durable random identity. A new database has a different ID even when the
installation configuration is unchanged. Old saved snapshots remain readable
with `ledger_id: null` and `admission_version: 0`; they do not prove admission
under the new contract. The controller must save the observed installation ID,
ledger ID and admission version before queueing a new prepare request.

Prepare requires those three bindings in addition to its ordered `attempts`.
`reject_absent` requires the same bindings and `plans`, an ordered list of one
through 64 complete immutable plans with distinct attempt IDs. Use this operation
only when no start was requested and preparation was queued under the saved
version-1 binding. It commits a failed rejection that cannot execute. A matching
existing attempt returns its actual state; a different fence or conflicting job
generation is refused. An installation or ledger change is refused before any
record is written. Never infer these bindings for an old attempt after a restart.

A refusal before any provider call also retains a failed rejection. It has no
resource slot, no output, and reason `admission_rejected`. Repeated prepare or
start cannot run it. The normal explicit release operation retains its failed
outcome. A provider failure follows reservation and cleanup instead; it cannot
use this no-resource proof.

`reconcile_absent` is a separate machine-administrator operation. It requires the
three current bindings, complete `plans`, and `acknowledge_unknown: true`.
The host checks every configured slot, account, attempt directory, service and
workload tree without running a provider or stopping work. Unconfirmed idle
state or retained attempt storage refuses reconciliation. A missing record then
receives an unknown result with confirmed cleanup and no resource slot. Its
reason is `legacy_absence_acknowledged`. This records an operator acknowledgement
and current cleanup evidence; it does not assert that past execution had no
effects. Existing matching records are returned unchanged. Ordinary release
preserves `outcome: unknown`; a later retry still requires a separate explicit
controller acknowledgement. Send the reviewed JSON through `python -m
ficc.execution request --socket <administrator-socket>` as the machine
administrator. Socket peer credentials prevent use by the transport or a local
voluntary owner.

No-resource rejections return bounded empty stdout and stderr with stable
identities, `complete: true` and `eof: true`. They cannot return declared output
files. Collect and release do not call a runtime provider for these records.

Every operation binds attempt ID, generation and immutable plan digest. Each
renewal also has a strictly increasing sequence. An identical duplicate renewal
retains its original deadline. The local clock uses boot identity and
`CLOCK_BOOTTIME`; suspend, clock rollback and restart cannot extend expired work.
Release retains the prior terminal state as `outcome`. An unknown outcome stays
unknown after resource cleanup and requires an operator decision before retry.

See [the Podman provider](../executor-providers/podman/README.md) and
[installation instructions](../packaging/remote/executor/README.md).
