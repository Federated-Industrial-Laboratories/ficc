# Contributor workloads

Submit project jobs to approved Linux contributors from the **Workloads** tab.
The controller records the request, selects an eligible node and retains the
observed result. This queue is separate from [managed SSH jobs](jobs.md).

## Prepare the installation

Configure [identities and projects](identities.md), an active required
[policy package](policies.md), and [contributor connections](contributors.md).
Install the [local executor](execution.md) on each contributor. A connected
transport alone cannot execute a job.

Install an approved [scheduler package](../scheduler-providers/fair/README.md)
in the controller environment. Stop the controller before configuring it:

```sh
ficc workloads-configure --state-dir /path/to/private-state --input /path/to/scheduler.json
```

The input is a private regular file owned by the controller account:

```json
{
  "provider": "fair",
  "configuration": {"global_active": 16, "project_active": 4}
}
```

These concurrency values are examples. Choose them for the installed capacity.
Restart the controller after configuration. An absent scheduler keeps execution
disabled. The provider proposes ordering; the host checks every placement.

Connect the node transport with `node-connect --executor-socket` set to the
installed transport socket. Keep its account separate from workload accounts.
Never expose the executor socket through a network listener.

## Submit a job

1. Select the project, then open **Workloads**.
2. Inspect contributor offers and their availability reasons.
3. Select candidate contributors and an exact approved runtime.
4. Enter the absolute container executable and its arguments as a JSON array.
5. Set environment values, resource limits, inputs and declared outputs.
6. Submit the workload and inspect its placement and observed state.

An argument array is not a shell command. An explicitly selected shell can still
interpret its own arguments inside the approved container. Do not put credentials
in arguments or environment values. Requests are retained in controller state.

CPU limits use thousandths of one CPU. Memory, swap and storage use bytes.
Process and inode limits are counts. GPU requests select whole device UUIDs.
The first executor profile disables workload networking. Select a registered
[dataset version](datasets.md) to bind its immutable manifest digest, file sizes,
names and complete SHA-256 digests to the request. The controller relays bounded
chunks from the authorized registered files to the selected contributor. Placement
does not promise that data is already local or schedule by data locality. The
details panel shows staging progress and this controller-relay route.

The executor reserves the storage slot before staging and starts the runtime
only after every input's complete size and digest match. Interrupted transfers
resume from acknowledged offsets while the same attempt and lease remain valid.
Source changes or revoked source access prevent execution. Include input bytes
and expected working/output data in the storage allowance. Datasets can contain
at most 64 files for a workload; submitted requests show the resolved input names.
Administrator-configured local input objects remain supported and must match
their declared size and digest. An input name appears under `/inputs`; declared
output paths are relative to the writable job directory. See the installed
provider's path contract.

A storage slot is an independently bounded allocation. Its actual byte and inode
capacities must fit the request. Increasing a request does not enlarge a slot.
Queued jobs retain concrete reasons when capacity, local consent, runtime identity
or policy prevents placement.

Background work continues after browser logout. The job holds a specific durable
delegation, not a reusable login credential. Changed membership, identity, policy
or local authority prevents renewal. Cancellation also prevents renewal.
There is no total job-duration limit while current authority and leases continue.

## Inspect output and finish

The details panel shows the attempt, lease, observed result and cleanup status.
Output previews read bounded byte ranges from stdout, stderr or a declared output.
**Save this byte range** saves only the displayed page. To retain a complete object,
select it and choose **Publish complete output** after cleanup is confirmed.
Choose a registered destination and folder, then enter a new filename. Existing
filenames are refused, including a name created while the transfer is running.
Publication requires current `jobs:logs`, `files:read` and `files:write` access.

Publication hashes the closed source, relays bounded chunks through the controller,
and verifies the complete destination digest before committing it. It uses the
normal durable Files transfer records and destination storage reservation, without
spooling a second complete file on the controller. Each read remains bound to the
same job, attempt, generation, plan digest and output identity. Progress and
recovery actions appear under **Published outputs and recovery** and in Files.

Optionally register the verified destination as a new dataset with its format and
explicit schema. The sealed manifest records machine-readable workload origin,
transfer identity and input-dataset lineage. This proves which retained bytes were
published; it does not prove computational correctness. The registered file remains
subject to the normal dataset snapshot and access checks.

After interruption, **Resume publication** checks the durable destination prefix
before appending. **Reconcile publication** resolves an uncertain file commit;
do this before creating another request. **Cancel and discard partial** removes
only an uncommitted partial copy. A committed file is preserved. If dataset
registration fails after the file succeeds, retry registration with the same
publication, or choose **Skip dataset registration** to retain only the file.
Registration recovery never repeats the output copy. The publication requester
must finish dataset registration with current permissions; logout or credential
revocation interrupts credential-bound publication work.

**Cancel workload** records cancellation and requests a stop. It does not claim
that external effects were reversed. Inspect the final result and cleanup status.

**Release retained output** deletes the attempt's local output and releases its
reserved capacity after the executor confirms empty workload processes. Save
needed data first. An active or uncertain publication blocks release until it
succeeds or cancellation is confirmed. A pending requested dataset registration
blocks workload removal until registration succeeds or is explicitly skipped.
Retained completed attempts continue to consume capacity until release. A released
record keeps its final outcome and publication history for inspection.

Only the original submitter can retry a workload. Retry requires released storage
and captures new authority. Each retry creates a new attempt and generation.
Unknown outcomes require explicit acknowledgment and are never retried automatically.

## Unknown outcomes and recovery

A lost response does not prove that a command failed to run. The controller
records start intent before sending it and reconciles the existing attempt after
restart. It does not resend a start because its response was lost.

New admissions bind the executor installation, ledger identity and durable admission
contract. A refused admission remains a retained result. If no start was issued,
the same ledger can seal a missing admission as failed without executing it.
Release remains explicit before another attempt can be requested.

Older or replaced ledgers do not provide that absence proof. Local administrator
reconciliation can confirm cleanup while preserving an unknown outcome. It does
not establish whether external effects occurred. Retry still requires acknowledgment.

Keep unknown attempts while the node can be recovered. Missing state, changed
storage or unconfirmed cleanup cannot release reservations. Use the executor's
documented local recovery procedure when necessary.

If a node is permanently retired, revoke its contributor identity first.
**Abandon retired attempt** then requires `jobs:cancel`, `contributors:manage`
and explicit acknowledgment of unresolved effects and cleanup. The attempt remains
unknown. This removes it from scheduler concurrency accounting only. It does not
free storage or devices on the retired node, permit reuse of that identity, or
authorize a retry. A new contributor and a new submission require separate actions.

Removal is allowed for completed records whose attempts are released, and unknown
records whose attempts are all released or explicitly abandoned. Abandonment
requires a revoked node. Removal deletes controller history;
it does not prove local cleanup. Preserve any needed audit and result records first.
Local replay fences remain after controller history is removed. Reconciliation
reads this lifetime history in bounded pages without a total attempt-count limit.

[Portable backup](backup.md) requires quiescent workload records. Restore suspends
dispatch and clears authority through the normal identity and contributor recovery
steps. Inspect the restored state before the installation owner resumes dispatch.

## Local commands

The local owner socket issues short-lived project credentials for each command.
The command revokes its credential when the request finishes.

```sh
ficc workload-offers --state-dir /path/to/private-state --project PROJECT_ID
ficc workload-list --state-dir /path/to/private-state --project PROJECT_ID
ficc workload-submit --state-dir /path/to/private-state --project PROJECT_ID --input /path/to/workloads.json
ficc workload-get --state-dir /path/to/private-state --project PROJECT_ID JOB_ID
ficc workload-cancel --state-dir /path/to/private-state --project PROJECT_ID JOB_ID --revision REVISION
ficc workload-release --state-dir /path/to/private-state --project PROJECT_ID JOB_ID --revision REVISION --confirm
```

Read the current revision before a mutation. `workload-retry` accepts
`--acknowledge-unknown`. `workload-abandon` requires both `--confirm` and
`--acknowledge-unknown`. `workload-remove` requires `--confirm`.

## API contract

All paths below start with `/api/v1`. Normal authentication, project permissions
and browser mutation protections apply. Restricted node/root credentials cannot
operate this project queue.

| Method and path | Request and result |
| --- | --- |
| `GET /workloads` | Project jobs, scheduler availability and dispatch suspension. |
| `GET /workload-offers` | Project-visible offers, timestamps and current availability. |
| `POST /workloads` | `requests`: 1 to 64 objects with distinct `key` and `request` fields. Returns HTTP 202 with one success or error per key. |
| `GET /workloads/{id}` | Current job revision, request and attempt observations. |
| `POST /workloads/{id}/cancel` | Current `revision`; records cancellation intent. |
| `POST /workloads/{id}/retry` | Current `revision` and optional `acknowledge_unknown`; explicit new attempt. |
| `POST /workloads/{id}/release` | Current `revision`; deletes retained local output after cleanup. |
| `POST /workloads/{id}/abandon` | Current `revision` and `acknowledge_unknown: true`; retired-node recovery only. |
| `POST /workloads/{id}/remove` | Current `revision`; removes eligible controller history. |
| `POST /workloads/{id}/output` | `reads` with `object`, byte `offset` and `length`; at most 1 MiB across the batch. |
| `POST /workloads/{id}/artifacts` | `Idempotency-Key` and publication body below; HTTP 202 with a durable transfer. |
| `GET /workloads/{id}/artifacts` | Up to 50 publications; use `next_cursor` as `before` for older records. |
| `GET /workloads/{id}/artifacts/{transfer_id}` | Source identity, transfer progress and optional dataset result. |
| `POST /workloads/{id}/artifacts/{transfer_id}/resume` | Resume or reconcile the existing copy, or retry dataset registration. |
| `POST /workloads/{id}/artifacts/{transfer_id}/cancel` | `discard_partial: true` cancels an uncommitted copy; after file success, skips pending dataset registration. |
| `POST /workload-control` | `suspended` boolean; installation owner with `policies:manage` only. Suspension also stops lease renewal. |

A submission key is 16 to 128 ASCII letters, digits, underscores, periods, colons or hyphens.
It is unique within its submitting subject and project. Reuse with the same
request returns the same job; different content returns an idempotency conflict.

Each `request` contains `node_ids` and `job`. Select 1 to 64 distinct contributors.
An optional `dataset: {"id":"DATASET_ID","manifest_digest":"64_LOWERCASE_HEX_DIGITS"}`
selects one immutable dataset version. Use its returned manifest digest without a
`sha256:` prefix. Leave `job.inputs` empty for the controller
to resolve its files, or supply exactly the resolved input objects. Explicit
streamed inputs require this dataset binding.

| Job field | Required content |
| --- | --- |
| `name` | Display name of 1 to 80 characters. |
| `runtime` | Exact offered `provider`, `package_digest`, `image_digest`, `isolation` and `network`. |
| `payload` | `argv` array and `environment` object. Executable paths are absolute inside the container. |
| `limits` | `cpu_millis`, `memory_bytes`, `swap_bytes`, `processes`, `storage_bytes`, `storage_inodes`, `gpu_devices`. |
| `inputs` | Up to 64 distinct objects with opaque `id`, SHA256 `digest`, `bytes`, `name` and optional `delivery: "stream"`; the default is local. |
| `outputs` | Up to 64 distinct declared `name` and relative `path` pairs. |
| `sensitive` | Boolean; requires approved managed contribution and local permission. |

Output objects are `stdout`, `stderr` or `output:NAME`. Each reply binds the exact
attempt fence and range, with base64 `data`, `next_offset`, `total_bytes` and `eof`.
Advance from `next_offset`; verify the same attempt throughout a transfer.
Control-message limits bound memory use and do not limit total workload data.

An output publication body selects one object and an opaque directory reference
returned by Files. `dataset` is optional; it requires the installed artifact
provider. The controller supplies origin and input lineage, so callers cannot
declare a different source attempt:

```json
{
  "revision":3,
  "object":"output:result",
  "destination":{"root_id":"ROOT_ID","entry_id":"OPAQUE_DIRECTORY_REFERENCE"},
  "name":"result.bin",
  "dataset":{"name":"Result dataset","format":"binary","schema":{"fields":[]}}
}
```

Use a distinct 16-to-128-character idempotency key for each publication. Reuse the
same key and body after an uncertain admission response. The response includes
`transfer`, immutable `source`, `phase`, `hashed_bytes`, optional `dataset`, and
`dataset_error`. Byte counters outside JavaScript's exact integer range use
decimal strings. No overwrite
option is accepted. Cancellation of an unknown commit is refused until the
existing transfer is reconciled.

Admission, start intent, observed state changes, confirmed cleanup and operator
actions enter the audit log. Events retain the initiating subject, project and
credential identity after logout. Repeated unchanged observations do not add events.

## Project usage

The Workloads view reports retained attempt counts, observed outcomes, declared
input bytes, reported stdout/stderr bytes and unreleased resource reservations.
Retries count as separate attempts. Reservations use the admitted resource
ceilings, including completed and uncertain attempts until release. They are
not measurements of CPU time, GPU utilization or actual disk consumption.
Removing records reduces the totals. Keep separate audit records for longer
retention; these counters are not a lifetime billing system.

`GET /api/v1/workloads` includes `usage` for the current project. Byte and count
totals beyond JavaScript's safe integer range use decimal strings.

## Shared templates and runbooks

Open **New workload**, then **Project workload templates and runbooks**. Share
the reviewed command, approved runtime and image digests, resource request, output
declarations and runbook instructions as an immutable project template version.
Project members with `jobs:read` can read templates. Sharing or removing a
version requires `jobs:execute`. Template removal does not change existing jobs.

Commands and instructions are shared explicitly. Remove credentials and private
text before sharing. The host excludes environment variables, input bindings,
GPU identities and candidate-node selections. Select current contributors and
input data each time a template is used. The normal admission, consent and policy
checks still apply. A template cannot grant execution rights or execute a runbook
instruction. It is a recipe for one workload, not a workflow scheduler.

`GET /api/v1/workload-templates` lists the current project's recipes.
`POST` accepts `name`, `instructions` and a validated workload `job`; the response
contains the immutable version and content digest. `DELETE` on a template ID
removes that version. Recipes are part of metadata backups. Private workspace
geometry is separate from [shared panel templates](workspaces.md#project-templates).

[Contents](README.md) | [Execution boundary](execution.md) | [Scheduler SDK](../sdk/schedulers.md)
