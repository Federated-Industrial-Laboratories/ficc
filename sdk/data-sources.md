# Data provider SDK

The installed host wheel exports `ficc.data_sdk`. Separately installed wheels
register a `ficc.data` entry point; encoders register `ficc.format`. Install the
host first. A source checkout or controller patch is not needed to add a provider.
These are trusted deployment packages, distinct from ordinary module archives.
See [deployment authority and isolation](../docs/data-sources.md).

## Package interface

```toml
[project.entry-points."ficc.data"]
example = "example_data"
```

The entry-point module exports `API_VERSION = 1`, `METADATA`,
`configuration(value)`, `query(value, mode)` and `execute(context, action, request)`.
Metadata declares `kind` (`local` or `network`), `source_consistency` (`immutable`,
`transaction` or `version`), boolean `write` support and a description.
`configuration` and `query` are pure validation functions returning JSON objects;
they execute in the controller and must not perform I/O. `execute` is a synchronous
frame iterator in the supervised worker. For example, its result stream can use:

```python
from ficc.data_sdk import rows, schema

yield {"kind": "schema", "schema": schema(["count"], ["int64"])}
yield from rows([[1], [2]])
yield {"kind": "receipt", "rows": 2, "consistency": "service-snapshot"}
```

Installed Python source bytes plus package version form the fingerprint bound
to each connection. Updating the package requires a new approval. Pin and qualify
dependencies separately: that fingerprint is not a signature or a digest of the
whole dependency closure.

`context.configuration` is the approved configuration. `context.endpoint` contains
`host`, `port`, selected `address` and `ca_pem`. Connect to `address` while verifying
the original TLS `host`; disable proxies and unapproved redirects. Optional fixed
address approval explicitly bypasses DNS without bypassing TLS verification.
`context.secret` holds only the selected read or write account. Never log it or
include it in exceptions, receipts, environment variables or child arguments.

For local input, `context.open_source()` yields a verified read-only file handle
inside the mounted root. `context.source_unchanged()` rechecks the reference.
Transactional providers use the database's own snapshot semantics.
`context.ca_file()` supplies an in-memory CA descriptor to native drivers needing
a filename. Controller state and secret directories are not mounted into workers.

## Actions and frames

| Action | Request and response |
| --- | --- |
| `catalogue` | `{cursor}`; yield `{kind:"catalogue",resources:[{id,name,kind}],next_cursor}` then receipt. Maximum 100 resources. |
| `describe` | `{resource}`; yield schema and receipt. |
| `query` | `{specification,parameters}`; yield schema, rows or bytes, then receipt. `context.limit` is 101 for preview, null for export. |
| `write` | Registered specification/parameters; yield `committing` before mutation, then receipt with `outcome:"committed"` or `"unknown"`. |
| `object` | Optional multipart contract below; declare `objects:true` in metadata. |

A schema has `fields:[{name,type,nullable}]` and a description. Names must be
distinct; at most 256 fields are accepted. `rows(iterator)` converts dates/times
and decimals to text, binary values to `{base64:...}`, rejects nonfinite numbers,
and bounds batches by 128 rows/128 KiB. Cells are limited to 64 KiB. Byte frames use
base64 under `data`; chunks of at most 128 KiB fit the 256 KiB encoded frame. Do not
collect a full result set or unbounded checksum array before yielding.

Raise `DataError(code, safe_message)` for predefined actionable outcomes. Messages
must not contain query values, rows, paths or driver diagnostics. Other exceptions
receive a generic error. Receipts fit one frame and can include server version,
snapshot/isolation, object version, checksum algorithm, counts and malformed-row
coverage. Successful exports seal these receipts into dataset origin. Raw
parameter values are not persisted.

The host rechecks authority during streaming and kills/reaps the worker service
on cancellation, deadline or revocation. Close cursors and response bodies in
`finally`. Never retry a mutation because a pipe or commit acknowledgement was
lost. A mutation can execute before the host consumes `committing`; interrupted
dispatched writes are therefore unknown even if that frame was not received.

For customer REST packages, approve a fixed endpoint and resource set. A registered
query selects a resource and typed values, not an arbitrary URL/method. Declare
pagination tokens, consistency and rate limits. Bound encoded/decoded page size,
honor cancellation, dial the approved IP, verify TLS, and reject redirects outside
the exact origin. Pagination confers no new endpoint authority. Retry only reads
whose service contract permits it. Use the same schema/rows/receipt stream and
qualify the customer's actual service; no universal REST compatibility is implied.

## Encoders and object writes

`encoder(name)` returns an object implementing `start(schema)`, `write(rows)` and
`finish()`. Write/finish yield bounded byte chunks. An optional `schema` property
after start declares the actual encoded schema. Encoders do not receive source
credentials. Source drivers remain responsible for their snapshot receipt.

Object requests contain `operation`, `key`, `size`, `sha256`, `manifest_digest`,
`part_bytes`, `upload_id`, `part_number` and `cursor` as applicable. Operations:

- `begin`: return `outcome:"created"`, upload ID, part size and part count.
- `status`: return at most 100 part receipts and `next_cursor`.
- `part`: upload one range and return number, bytes and acknowledged checksum.
- `complete`: verify the full source and all parts, apply a create-only destination
  precondition, and return completed or unknown.
- `abort`: explicitly remove unfinished provider storage.
- `reconcile`: verify published identity/content without repeating completion.

The host supplies a local source capability only for part/complete operations.
`context.part_receipts()` streams the latest durable part acknowledgements through
a read-only mounted NDJSON file. This avoids a growing control-message array.
Receipts are bound to the upload's immutable dataset. Reconcile provider part
identity/size with these receipts; missing acknowledgements require re-upload.
The S3 package is the reference implementation. Its 10000-part protocol bound is
not a host total-file quota.

## Host API and dataset seam

Routes are relative to `/api/v1`. Public routes authenticate current project
principals. Admissions need `Idempotency-Key`; a changed body needs a new key.
Lists page 50 records using `next_cursor` as `before`.

| Route | Body/result |
| --- | --- |
| `GET /data-providers` | Installed provider metadata. |
| `GET/POST /sources` | List/approve `{name,provider,configuration,source,endpoint,read_secret,write_secret,permissions}`. Local source is `{root_id,entry_id}`. |
| `GET /sources/ID` | Accessible approved connection, without internal file references. |
| `PUT /sources/ID/approval` | `{enabled,revision}`; revision-checked update. |
| `GET /sources/ID/catalogue?cursor=...` | Bounded catalogue. |
| `POST /sources/ID/describe` | `{resource}`. |
| `GET /source-queries` | Registered templates. |
| `POST /sources/ID/queries` | `{name,mode,specification,parameters:[{name,type,nullable}]}`. |
| `POST /source-queries/ID/preview` | `{parameters:{...}}`; bounded schema/rows/receipt. |
| `POST /source-queries/ID/runs` | Export or write request; durable run. |
| `GET /source-runs/ID` | State, counts, receipt, exported `dataset_id`/`manifest_digest`. |
| `POST /source-runs/ID/cancel` | Stop worker, retain uncertain mutation. |
| `POST /sources/ID/uploads` | `{key,dataset_id,file_index}`. |
| `GET /source-uploads/ID` | Retained upload and receipt. |
| `POST /source-uploads/ID/operations` | `{operation,part_number?,cursor?}`; operation run. |

Example SQLite registration and export bodies:

```json
{"name":"Readings","mode":"read",
 "specification":{"statement":"SELECT id,value FROM readings WHERE id >= :minimum ORDER BY id"},
 "parameters":[{"name":"minimum","type":"integer","nullable":false}]}
```

```json
{"action":"export","parameters":{"minimum":"2"},
 "destination":{"root_id":"ROOT_ID","entry_id":"OPAQUE_DIRECTORY_REFERENCE"},
 "filename":"readings.csv","dataset_name":"Readings","format":"csv"}
```

Signed 64-bit integer parameters accept decimal strings. Formats are `csv`,
`arrow`, `parquet` or `original` for object bytes. The host publishes verified
bytes and calls `Datasets.create(..., origin=...)`. A successful run returns the
dataset ID and manifest digest directly to workload clients. No database secret
travels with a dataset or to a contributor. See [artifact consumption](artifacts.md).
