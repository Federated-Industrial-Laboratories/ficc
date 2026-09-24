<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Managed jobs

[Contents](README.md) | [Project README](../README.md) | [Previous: Operation](operations.md) | [Next: Files](files.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

A managed job runs an explicit program under an enrolled remote account.
The node keeps its request, output and result independently of the controller.
Closing the browser or stopping FICC does not cancel it. A node reboot does not
restart the program. An uncertain remote outcome remains visible as unknown.

Execution has the full authority of the SSH account. CPU/RAM limits and GPU
visibility do not make an untrusted program safe. Use separate remote accounts
when workloads need different filesystem or account privileges.

## Prepare a node

Observation works with the original helper. Managed jobs require helper version 2,
Python 3.12 or later, systemd 255 or later, cgroup v2, and delegated CPU, memory
and task controllers. Use **Upgrade helper** on the node and confirm its enrolled
fingerprint. This preserves the enrollment ID. Unsupported nodes remain useful
for observation, with their job limitation shown explicitly.

The systemd user manager must remain available for the job's lifetime. FICC
checks logout persistence. If it is absent, either configure the node separately
or explicitly accept remote-session lifetime in the job request. FICC does not
enable lingering automatically. Signing out remotely can stop a session-lifetime
job, even when the local console remains open.

## Submit and inspect

Open **Jobs**, select **New job**, and choose the target machines. Enter a label,
program arguments, working directory and required limits. The default command
mode accepts a JSON array, with one entry per argument. The separate shell mode
explicitly runs a shell script. Preview the frozen target list, resolve any
errors, then confirm it. Changing selections requires a new preview.

Each machine has its own status. Select a row to inspect its requested and
effective limits, result and stdout/stderr. Unknown values are not zero. Logs
show truncation and byte cursors; text is never interpreted as HTML or terminal
control sequences. Log access needs the separate jobs:logs grant.

Normal cancellation asks the recorded service to stop, then applies a finite
grace period. Forced stop is a separate explicit action. The UI shows a request
before it shows confirmed termination. A lost connection during cancellation
does not prove that the job stopped. The pending request survives a controller
restart and retries connection failures with its current cancellation grant.
If that grant expires or is revoked, retries stop and a denial stays visible.
Request cancellation again with current authority. FICC cannot cancel unrelated
processes.

## Limits and reservations

Every job specifies CPU percentage, memory high/max, swap maximum, task count
and runtime. CPU 100 means one logical CPU's quota; larger values allow more.
Memory and swap values use bytes. The runner verifies effective cgroup files
before starting the program. It refuses missing required controls and reports
stricter ancestor limits when present. Runtime is finite, at most 86400 seconds.

One managed job is admitted per node. A running or unknown job prevents a
conflicting launch. GPU choices use device UUIDs and declared memory need.
Fresh capacity is checked before launch, but another program can still allocate
the device. Reservations coordinate FICC jobs; they do not enforce VRAM limits
or exclusive use. CUDA_VISIBLE_DEVICES is set from the reservation and is empty
when no GPU was selected. External programs remain outside FICC ownership.

Output is drained after the combined 64 MiB stdout/stderr limit, with discarded
bytes reported. Each node reserves output space against a 2 GiB retained limit
and retains at most 256 job receipts. The controller retains at most 2048
operations and lists the newest 200. New work is refused when retained capacity
is full. Active or uncertain receipts are never evicted to make room. Automated
expiry is disabled. Use the explicit [history archive command](history.md) to
retain completed history and recover admission capacity. Preserve receipts while
reconciling a job or an uncertain submission. Archived logs still consume disk
space. New jobs require at least their 64 MiB output allowance plus 256 MiB of
free storage for state and other bounded work. This preflight check cannot reserve
space against unrelated programs that write to the same filesystem.

## CLI

Save a request as a JSON file. Use actual enrolled node IDs from `ficc nodes`:

```json
{
  "action": "job.submit",
  "node_ids": ["NODE_ID"],
  "job": {
    "label": "Hello",
    "argv": ["/usr/bin/printf", "Hello from FICC\n"],
    "cwd": "",
    "env": {},
    "limits": {
      "cpu_percent": 100,
      "memory_high_bytes": 201326592,
      "memory_max_bytes": 268435456,
      "memory_swap_max_bytes": 0,
      "tasks_max": 32,
      "runtime_seconds": 300
    },
    "allow_session_lifetime": false,
    "gpu_reservations": {}
  }
}
```

```sh
ficc job-preview --request job.json
ficc job-submit --request job.json --confirm --idempotency-key request-example-0001
ficc job-list
ficc job-status OPERATION_ID
ficc job-logs OPERATION_ID --node NODE_ID --stream stdout
ficc job-cancel OPERATION_ID --node NODE_ID
```

Without `--confirm`, job-submit only previews. Logs default to JSON containing
base64 data, so raw control sequences do not reach the local terminal. Add
`--output NEW_FILE` to save raw bytes in a new private file. Use `--offset` and
`--limit` for the next chunk; the maximum chunk is 64 KiB.

The CLI prints the idempotency key before dispatch and keeps a private receipt
under `STATE_DIR/cli-requests`. If the response is lost, repeat the same request
and key. The receipt reuses the original credential and preview; once acknowledged,
it queries the recorded operation instead of dispatching again. Reusing a key
with different request content is refused. An expired, unresolved receipt needs
manual reconciliation through job-list before any new submission.

CLI job credentials expire after one hour and can be revoked in **Access**.
Revocation prevents queued work from launching; it does not stop an already
running job. The CLI revokes its submission credential after dispatch is known.
An uncertain or queued submission retains the credential until expiry. Receipts
are private and bounded to 1024; archive completed receipts deliberately when
that cap is reached. Removing a receipt also removes that CLI key's recovery
record, so do not reuse its key afterwards.

## Recovery

The controller records intent before SSH dispatch. The helper durably binds a
job ID to its request digest before starting a deterministic systemd unit.
The helper stages a complete runner and request before publishing that intent.
Interrupted staging is recovered under the node lock; published intents and
records with possible execution evidence are preserved.
Repeated matching submissions query that job. Different content under the same
identity is refused. A missing acknowledgement triggers reconciliation, never
automatic payload replay. This prevents duplicate dispatch within retained
state; it is not a guarantee of exactly-once external program effects.

On controller restart, FICC queries retained node receipts and unit identity.
Keep an unknown job's reservations until the outcome can be established. Do not
forget a node with active or unknown work. Archive completed history before
forgetting its machine, so the archive can verify the saved node identity.
Only one controller may own a node's
FICC job namespace. Restoring or migrating controller state requires preserving
its identity and job records; a new empty controller cannot claim that namespace.


<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Previous: Operation](operations.md) | [Next: Files](files.md)
