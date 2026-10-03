# Data sources and pipelines

Approve a project connection, register a query, preview its declared parameters,
and export a verified dataset. That dataset is available to the existing
[dataset-backed job workflow](datasets.md). Source providers are separate from
the controller state-storage provider.

## Installation and access

The standard installer supplies the separate [data runtime packages](../data-providers/README.md).
For a host-only Python installation, install the host first, then the selected
packages in its Python environment. CSV supplies the default export encoder; Arrow supplies
Arrow IPC and Parquet encoders. An absent optional package makes only its sources
unavailable. Workers require the existing Linux systemd user service, cgroup and
bubblewrap boundary.

In **Data sources**, choose **Approve source**. Local sources select one ordinary
file under a controller Files root outside the private state directory. Transfer
remote node files to an approved controller root first. Network connections
instead specify the TLS hostname, port, approved IP addresses and CA certificate.
Private addresses require explicit approval; link-local, multicast and unspecified
addresses are refused. Normally dispatch rechecks DNS and dials an approved
address while verifying the original TLS identity. The optional **Fixed approved
IP** bypasses DNS and dials that exact approved address, still verifying the TLS
hostname/CA. This supports private names and local forwards without editing DNS.
S3 redirects cannot expand the approved origin.

The form accepts secret references, never passwords. The deployment administrator
configures an [encrypted secret-store provider](secrets.md), then provisions JSON
values through its private CLI input. SQL values contain `username` and `password`;
object values contain `access_key_id`, `secret_access_key` and optionally
`session_token`. Keep values out of command arguments and browser fields. Existing
private `data-secrets/REFERENCE` JSON files require explicit `secret-migrate-source`
migration; source execution does not silently fall back to plaintext files.
Metadata contains references and opaque credential revisions. Secret-store
backup and key recovery are separate from metadata backup. Encrypted credential
storage does not encrypt query results, working files or all controller state;
use the deployment's approved storage encryption and key-recovery arrangements.

Connections default to read access. Exports and writes need both explicit
connection permission and the corresponding project scope:

| Scope | Authority |
| --- | --- |
| `data:read` | Catalogue, schema and registered read-query preview. |
| `data:export` | Registered read-query export to a dataset. |
| `data:write` | Registered write or dataset object upload. |
| `data:manage` | Connection approval and query registration. |

Local sources also need current `files:read` root access. Exports need a writable
controller destination and `files:write`. Managed policy roles include
data-observer, data-operator, data-writer and data-administrator. Contribution
policy provides data-observer and data-operator.

Network writes require a separate credential reference. Database accounts, views
and server grants enforce actual SQL rights. Parameter binding does not restrict
account authority; FICC makes no SQL keyword-filter security claim. Restrict read
accounts to the required data and remove server file, extension, UDF and admin
powers. Disabling a connection increments its approval revision and stops active
operations at the next authority check. Rotated credentials require new approval.

## Preview, export and use in a job

1. Browse a catalogue and inspect its schema. Catalogue pages contain at most 100
   resources. **Register query** saves a template and typed parameters; it requires
   `data:manage`. SQLite placeholders use `:name`; PostgreSQL and MariaDB/MySQL
   use `%(name)s`. CSV/Arrow use registered projections and predicates.
2. Open the pipeline and supply parameter values. Integer inputs remain exact
   signed 64-bit values. **Preview rows** returns at most 100 rows/128 KiB; an object
   preview shows at most 4 KiB as base64. It performs no write or export.
3. Choose an output directory, new filename, dataset name and format. **Export
   to dataset** streams into reserved temporary storage, hashes and synchronizes
   it, then publishes without replacing an existing filename. Registration verifies
   the completed file again.
4. Open the operation receipt for its dataset ID and manifest SHA-256. Select that
   dataset in Workloads. The dataset guide covers contributor staging and result
   publication.

Authenticated export origin records connection/query IDs, template/parameter
digests, provider identity, run ID and receipt. Raw parameter values are not saved
in the run or audit event. Templates are retained: do not embed secrets or
sensitive values as SQL literals. Receipts state actual snapshot consistency;
the same template can observe a different snapshot on a later run.

Explicit writes have a separate consent control. A lost commit acknowledgement,
interrupted dispatched mutation or controller restart can leave `unknown`.
FICC never automatically replays it. Inspect external state before submitting a
new write. Reusing an idempotency key returns the existing run; it does not make
arbitrary external SQL exactly once.

## Format and snapshot contracts

| Provider | Implemented contract |
| --- | --- |
| SQLite | Read-only registered database transaction, including SQLite journal/WAL; engine authorization denies mutations/extension loading. Do not copy an active database without its journal. |
| PostgreSQL | Verified TLS, repeatable-read snapshot, server-side cursor and snapshot/server-version receipt. |
| MariaDB/MySQL | Verified TLS, read-only consistent transaction, unbuffered cursor and actual server-family/version receipt. Qualify both servers separately. |
| CSV | Explicit header/schema, encoding/dialect, null convention, UTC default and dot decimal. Schema-invalid rows fail or are counted as skipped; lexical parse errors fail. |
| Arrow | One Parquet file or Arrow IPC stream. Parquet projection occurs in the reader; predicates run on record batches. No partition discovery or predicate-pushdown claim. |
| DuckDB, optional | One approved Parquet/Arrow input exposed as `source`; bound `$name` parameters in one SELECT. External access, automatic extensions, Python replacements and spill are disabled. |
| S3 | Approved bucket/prefix, paged listing, range preview, version- or SHA-256-bound reads and original-byte export. |

CSV types are `string`, `integer`, `number`, `boolean`, `date` and `timestamp`.
Boolean input uses `true`/`false`. Export is UTF-8, comma-separated, LF-terminated,
with an empty null field. Formula-like text is preserved as dataset content;
this is not a spreadsheet-safe presentation export.

Arrow output preserves supported primitive integer, floating, boolean and date
types. Other values use explicit string representations, including decimal and
timestamp text and JSON for structured values. The manifest records the actual
output schema. Parser metadata/batch limits and the worker memory bound constrain
allocation, including allocations made before a decoded batch can be inspected.

The optional DuckDB package uses its own in-memory connection and one SQL/Arrow
thread. Its `memory_bytes` configuration defaults to 128 MiB within the host worker
limit; increase both budgets for larger analytical state. There is no disk spill
in this initial provider. Queries needing more memory fail within those budgets.
[DuckDB configuration](https://duckdb.org/docs/stable/configuration/overview).

## Resumable object publication

For a writable S3 connection, **Upload dataset** selects one verified local dataset
file and an object key inside the approved prefix. The retained upload binds its
manifest, file identity, size and SHA-256. **Upload remaining parts** checks stored
parts and uploads sequentially. Pause or close the dialog to retain progress;
reopen it to resume explicitly with the same immutable source.

Each part must return its SHA-256 acknowledgement. **Complete** checks all part
numbers/sizes/checksums, rehashes the source and applies a create-only destination
precondition. Multipart ETags are not content hashes. S3 protocol bounds remain
10000 parts and 5 GiB per part; the host imposes no 16 GiB total-object ceiling.
Implementations may have smaller limits.
[S3 multipart limits](https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html).

SeaweedFS 4.46 does not return part checksums in ListParts. FICC binds each durable
UploadPart checksum acknowledgement to its part number, size and returned ETag;
status must match that exact receipt. A missing/mismatched receipt requires
uploading that same immutable part again. ETag is an opaque part identity here,
not a derived checksum. Completion is reported successful only after reading
the entire published object and verifying SHA-256, including on this backend.

Missing completion acknowledgement leaves `unknown`. **Reconcile** reads published
metadata and the full content digest, without replaying completion. **Check parts**
inspects staged work; **Abort** explicitly removes an unfinished upload. A lost
initial creation response may leave a provider-side orphan with no received ID;
an administrator must inspect the bucket's multipart inventory. Creation is never
automatically replayed.

## Resources, recovery and deployment trust

`GET/PUT /api/v1/source-limits` exposes deployment quotas. Only an unrestricted
local owner may update them while operations are idle. Defaults are 512 MiB memory,
one hour per operation, four workers, 64 GiB per export and 256 MiB disk reserve.
Raise these quotas or set `export_bytes` to null as appropriate. Reservation
never exceeds measured disk headroom. Fixed control bounds remain 256 KiB frames,
128 rows/128 KiB per batch and 64 KiB per cell. Large JSON counters use decimal strings.

Cancellation stops and reaps the worker. Incomplete exports remove temporary files.
After a hard controller interruption, a retained partial has a durable staging
identity. Select **Clean up partial export** on its receipt to remove that exact
partial under current root authority. A replaced inode is refused. Cleanup never
removes the final published filename or replays the query. Failures after rename
are recorded as unknown even if the later directory sync or reference step fails.
Interruption after file publication but before registration can leave an unknown
run with a retained file: inspect it in Files and register it explicitly if
appropriate. Startup never replays active operations. Restored approvals are
disabled until reviewed.

Exports retain host-known local dataset lineage and obey current
[dataset inspection and safety controls](inspection.md). A required scan may
leave a registered dataset blocked while original published bytes remain present.

Runtime packages are privileged deployment components. Their validation executes
in the controller; drivers execute in bounded children with read-only runtime
mounts, only the selected local root and no controller state/secret directory.
One scoped credential is delivered in memory. Local drivers have no network
access. Network drivers share the host network namespace and enforce pinned
endpoints in trusted driver code. This is not an OS egress jail against a malicious
installed package. Ordinary sandboxed module grants do not confer this trust.

Current pipelines relay through the controller and publish into its registered
filesystem. Provision disk and bandwidth accordingly. The
[SDK](../sdk/data-sources.md) documents the generic provider and REST extension
contract; it does not promise compatibility with unqualified external services.
