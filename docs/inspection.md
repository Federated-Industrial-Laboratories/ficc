# Local inspection and dataset safety

[Datasets](datasets.md) | [Workloads](workloads.md) | [Inspection SDK](../sdk/inspection.md)

Inspection is optional. An installation with no scanner and no inspection
requirement continues to use datasets normally. A required inspection fails
closed when the configured package, engine, assets or supported file location
are unavailable. Inspection does not establish that arbitrary content is safe.

## Install and approve a local scanner

The standard installer supplies the separately built `ficc-inspection-clamav`
wheel. A host-only Python installation needs the wheel installed separately,
followed by a controller restart. Install the native ClamAV engine and approve
its signature collection separately. The web interface neither installs software
nor downloads signatures.

```sh
python -m pip install --no-deps /approved/ficc_inspection_clamav-0.2.5-py3-none-any.whl
```

In Files, open a dataset's Inspect dialog, then Local scanner settings. An
unrestricted local owner can approve this configuration, adapting paths and
limits to the deployment:

```json
{
  "provider":"clamav",
  "configuration":{
    "engine":"/usr/bin/clamscan",
    "database":"/var/lib/clamav",
    "certificate_directory":"/etc/clamav/certs",
    "max_file_bytes":104857600,
    "max_scan_bytes":419430400,
    "max_files":10000,
    "max_recursion":16,
    "scan_milliseconds":120000
  },
  "scan_on_create":false,
  "required_new":false,
  "memory_bytes":"2147483648",
  "temp_bytes":"268435456",
  "seconds":600,
  "workers":1,
  "max_age_seconds":86400
}
```

The shipped adapter is qualified with ClamAV 1.5.4. Its certificate directory
supplies the roots used by ClamAV's detached database-signature verifier. It is
an explicit read-only scanner asset, not the controller's general `/etc` tree.
`certificate_directory: null` omits this asset and option for a separately
qualified engine that does not need it. The rule collection is either one file
or a flat directory with at most 128 ordinary files. Symbolic links and nested
asset collections are refused. No YARA-X adapter is shipped or claimed qualified.

ClamAV's file, expanded-content, recursion and member limits are inspection
coverage bounds, not FICC transfer limits. Encrypted content is not decrypted.
The adapter enables archive scanning, encrypted/broken-content alerts and limit
alerts. Additional format-specific engine parser limits still apply. See the
[ClamAV 1.5.4 options](https://github.com/Cisco-Talos/clamav/blob/clamav-1.5.4/docs/man/clamscan.1.in)
and [scanner documentation](https://docs.clamav.net/manual/Usage/Scanning.html).

Each file gets a separate bounded worker: a private network namespace with no
IP sockets, read-only runtime and approved assets, only the exact selected input
file, a private size-limited temporary filesystem, and the existing systemd
memory, process, CPU and time controls. FICC rechecks current authority while
the worker runs and stops its complete process group on every exit. The configured
`seconds` limit applies per file. A dataset still uses one worker slot while its
files are inspected in sequence. Keep private state outside runtime installation
trees; an overlapping layout is refused. Installed provider code remains a
trusted deployment component, separate from sandboxed workspace module grants.

Only files local to this controller are supported. Files on SSH roots or
contributors return `unavailable`; FICC does not copy them to a public service or
relay them to another controller for inspection. A required stage remains blocked.
An operator must use an explicitly approved local deployment and data location
to inspect those bytes. Scanning never approves a contributor or changes its mode.

## Review coverage and control use

Inspect / re-scan locally creates a durable operation. Coverage and provenance
shows each file's digest, size, outcome, limits, findings, engine version and
executable hash, rule hashes and modification times. Certificate hashes are also
retained in the engine receipt. An owner-approved rule hash identifies bytes;
it does not establish the rules' publisher or quality. Asset updates during a
scan invalidate that receipt. Keep signature updates under normal deployment
control; FICC does not run an updater.

| Outcome | Meaning |
| --- | --- |
| `no_detection` | The engine reported no detection within its recorded coverage. |
| `detected` | The engine reported at least one finding; logical quarantine is set. |
| `incomplete` | A coverage limit, encrypted/broken content, cancellation or restart prevented a usable completion. |
| `unavailable` | The approved scanner, assets or local execution location is unavailable. |
| `error` | The worker, scanner or immutable source verification failed. |

Owner safety controls separately set Sensitive, Inspection required and
Quarantine, with a recorded reason and optimistic revision check. Ordinary
dataset names, descriptions and user workload labels cannot clear these controls.
Quarantine blocks dataset inputs, source object uploads and workload result
publication. It does not delete or move originals, change a manifest, revoke an
independent file-root permission, or claim to remove copies already delivered.

Known lineage carries restrictions: declared input datasets, previous versions,
host-bound workload inputs, local query sources, and same-project registrations
of matching file paths or content. A changed parent policy applies to existing
descendants. This cannot discover undeclared external transformations or data
which the host has never identified. Restrictions are project-scoped; matching
content does not grant cross-project access.
Local connection capabilities establish path/inode lineage. They do not invent
a complete source digest; content-based matching requires an actual registered
file digest.

Sensitive dataset inputs force sensitive workload placement even when a request
says `sensitive: false`. Submission, input delivery and subsequent workload
authority/lease renewal check current controls. Already running computation is
bounded by the existing lease and stop protocol; this is not retroactive erasure.
Required use needs a completed, current `no_detection` result for the dataset
and required known ancestors, with the approved package and configuration.
Receipts expire after `max_age_seconds`. A new scan invalidates the previous
usable result until it completes. Cancellation, timeout and controller restart
never produce an allowed result or automatic scan replay.

Explicit exemption requires an unrestricted local owner, a reason and optional
expiry. It is bound to the exact current safety and inspection state, is audited,
and does not reduce sensitivity. Changes to that state or a new scan invalidate
it. An exemption applies only to its selected dataset; descendants and duplicate
registrations do not inherit permission from it. Revoke exemption removes it
immediately. A successful rescan does not silently clear an existing quarantine;
the owner must make that separate decision or explicitly exempt the dataset.

`scan_on_create` requests an optional scan after registration. `required_new`
adds an owner requirement to new datasets. Source exports and dataset result
publication wait for an admitted required scan. When all slots are busy, the
manifest remains registered and a required dataset remains blocked; select
Inspect / re-scan locally when capacity is available. Original published file
bytes are retained if inspection cannot complete. Registration and policy are
separate durable stages.

## API and recovery

All routes use the current project and file-root authority. Read operations need
`files:read`; starting/cancelling inspections also needs `files:write`. Owner
controls additionally require an unrestricted local-owner credential.

| Route under `/api/v1` | Operation |
| --- | --- |
| `GET /inspection-settings` | Provider availability and owner configuration. |
| `PUT /inspection-settings` | Owner approval of a configuration; active scans must finish first. |
| `GET /datasets/ID/safety` | Current effective controls, lineage and latest inspection summary. |
| `PUT /datasets/ID/safety` | `{revision,sensitive,inspection_required,quarantined,reason}`. |
| `PUT /datasets/ID/exemption` | `{revision,enabled,reason,expires_at}`; expiry is Unix seconds or null. |
| `POST /datasets/ID/inspections` | Start with an `Idempotency-Key`; returns an inspection ID. |
| `GET /inspections/ID` | Durable aggregate status and manifest binding. |
| `GET /inspections/ID/files?after=N` | Up to 20 bounded file receipts and `next_cursor`. |
| `POST /inspections/ID/cancel` | Cancel and reap an active worker. |

Metadata backup retains restrictions, lineage and receipts, and refuses active
inspections. Restore revokes exemptions and scanner approval. Reinstall and
reapprove the scanner, then inspect again before required use. Original data and
scanner asset bytes need separate backups. Inspection metadata uses schema 15
with the same SQLite and PostgreSQL storage contracts as the rest of FICC.
