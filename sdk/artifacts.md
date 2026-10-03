# Artifact and dataset interfaces

[SDK contents](README.md) | [Dataset manual](../docs/datasets.md)

## Source and publication contracts

File operations use the existing registered-root transport, with at most
262144 bytes per chunk. Total sizes and offsets are non-negative signed 64-bit
filesystem offsets. JSON sizes above 2^53-1 are decimal strings; client integer
code must preserve them exactly. Administrator quotas and backend capabilities
can refuse smaller objects. Chunk and control-message bounds remain independent
of object size.

For uploads, include `source_manifest` with the file's name, size and optional
`last_modified` in a transfer preview. Use `{"algorithm":"sha256","digest":HEX}`
for the full original source digest. Resume resends accepted prefix chunks,
which are checked against both staged bytes and their digest journal. Finishing
checks the entire original digest before atomic publication. A changed suffix
cannot be appended to an old prefix and published as the original source.
Clients without a supplied source manifest can complete an uninterrupted upload,
but cannot resume a legacy accepted partial.

Browsers use the fixed-size `sha256-chain-v1` source commitment. Start with
`SHA256(ASCII("ficc-upload-v1:" + decimal_size + ":262144"))`. For each chunk in
file order, replace the 32-byte value with
`SHA256(previous_value || SHA256(chunk_bytes))`. Encode the final value as
64 lowercase hex characters. Empty files use the initial value. This algorithm
uses native browser SHA-256 with one chunk in memory, rather than an array of
per-file chunk hashes. The committed artifact's public content digest remains
the conventional SHA-256 of all file bytes.

Registered-source copies bind the resolved file identity and complete SHA-256
before admission. Every read checks the saved identity. The destination reserves
physical blocks with Linux `fallocate(FALLOC_FL_KEEP_SIZE)`, records progress
durably, validates accepted parts and complete digests, then syncs and atomically
publishes. Unsupported reservation fails explicitly. Interrupted reservations
are released only through cleanup. Unknown publication outcomes require the
existing reconciliation operation.

## Runtime provider contract

Trusted installable distributions register an entry point in `ficc.artifact`.
The entry point exports `API_VERSION = 1` and `configure(configuration)` returning
an object with asynchronous methods:

| Method | Result |
| --- | --- |
| `snapshot(capability)` | `{name,size,sha256,identity}` for an exact source |
| `read(capability,offset,limit)` | `(header,bytes)` for one bounded range |

The filesystem implementation is the separate `ficc-artifact-filesystem`
distribution. The host selects the installed provider through optional private
configuration. Provider packages execute trusted controller code. Packaging and
installation must receive the same review as other trusted controller providers.

The host gives a capability restricted to one resolved registered file. It
supports only `file.stat`, `file.hash` and `file.read` calls and rechecks current
project and root authority before and after each transport request. Providers
cannot use this interface to choose another source reference. The host validates
snapshot identity, size, digests, exact range offsets and returned byte counts.
No provider adds a permission merely by returning a capability or manifest.
SQL, object stores and content parsing use the separate
[data provider contract](data-sources.md). They do not extend this filesystem
capability with arbitrary paths or database authority.

## Dataset consumption inside the host

`service.datasets.get(dataset_id, actor)` returns the authenticated immutable
manifest, including private source references. `inputs(dataset_id, actor)` is
asynchronous and revalidates complete source digests. It returns `dataset_id`,
`manifest_digest`, `project_id` and `files`. Each file includes `name`, `size`,
`sha256`, `root_id`, `root_revision`, `reference`, `provider`, `provider_version`
and `snapshot_id`. Never put private references in public workload views.

`read(dataset_id, index, actor, offset, limit=262144)` returns one verified header
and byte range. A job supplies `actor` as an internal callback which obtains a
freshly checked `Principal` from its durable delegation; the callback runs again
at read and transport boundaries. Public routes pass authenticated credential IDs
and never accept callbacks. Bind the dataset ID, manifest digest and project in
the immutable job plan, allocate capacity before staging, and verify the full
staged digest before admitting the workload. A chunk digest alone does not prove
that all received chunks constitute the original source.
