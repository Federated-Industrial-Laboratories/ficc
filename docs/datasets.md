# Datasets and artifact identity

[Manual contents](README.md) | [Files](files.md) | [Artifact SDK](../sdk/artifacts.md)

Owner sensitivity, required inspection and logical quarantine are separate
mutable controls over an immutable manifest. Known lineage inherits restrictions;
ordinary descriptions and false workload sensitivity labels cannot clear them.
See [Local inspection and dataset safety](inspection.md) for optional ClamAV
installation, current-use enforcement, coverage receipts and audited exemptions.

A dataset is an immutable, project-scoped manifest over registered source files.
It records each file's complete SHA-256 digest, exact byte size, filesystem
identity, root registration revision and storage provider version. It also
records an explicit schema, provenance, creator, project and creation time.
Metadata authentication detects alteration of a retained manifest. It does not
protect against an administrator who controls the controller and its keys.

The standard installer supplies the separately built filesystem provider. For a
host-only Python installation, install it into the controller's environment and
restart the controller:

```sh
python -m pip install --no-deps /approved/ficc_artifact_filesystem-0.2.5-py3-none-any.whl
```

The package uses existing registered roots and their access checks. It does not
discover directories or grant access to new paths. No provider package is
downloaded or installed by the web interface. An optional private
`artifact-provider.json` beside controller state selects an installed provider:

```json
{"provider":"filesystem","configuration":{}}
```

The default selection is `filesystem`. Provider configuration is deployment state
and is excluded from portable metadata backups. Reinstall the trusted package
and review its configuration after a restore.

## Register and use a version

In Files, select ordinary files in either pane and select Register left selection
or Register right selection. Supply a dataset name, format, explicit schema and
source provenance. Registration hashes each entire file using bounded chunks.
The schema describes the data; registration does not parse or certify the file's
columns. A binary dataset can declare an empty field list. Format validation and
conversion are separate data connector operations.

Inspect shows the dataset ID, schema, complete file digests, manifest digest and
previous version. Verify current sources checks every complete file again.
To update data or its schema, register a new version and optionally identify the
previous dataset ID. API callers can declare input dataset IDs in provenance;
the controller verifies access to every referenced dataset. These declarations
describe supplied lineage rather than proving an external transformation.

Registration pins an identity and digest; it does not make a mutable filesystem
read-only or create a historical copy. Keep reproducible sources in an
operator-managed immutable location, or make a verified copy first. A moved,
replaced or edited source fails validation and cannot silently become the old
version. Jobs must verify input snapshots and verify their complete digest after
staging, before execution. The internal host interface supports current durable
job authority without issuing a new API credential.

In Workloads, select a dataset version when submitting a job. The controller
records the manifest digest and resolves each file into a named input. Bounded
chunks pass through the controller to the selected contributor under the job's
current durable authority. The contributor verifies the complete sizes and
digests before runtime preparation. This path uses controller relay; placement
does not claim data locality. See [Workloads](workloads.md) for capacity and
recovery behavior.

Completed workload output can be published to a registered folder and optionally
registered as a dataset in the same workflow. Publication never overwrites an
existing destination. Its authenticated manifest contains a host-supplied `origin`
with `kind: "workload"`, job and attempt IDs, generation, plan digest, contributor,
output identity, transfer and item IDs, and the input dataset ID and manifest
digest when present. The normal provenance also lists the input dataset ID.
Public registration requests cannot set this origin. It binds the published bytes
to the retained attempt without certifying the result's scientific or business
meaning. The file copy and dataset registration have separate recovery states;
retrying registration reuses the same dataset request and preserves the file.

## API and access

The [Data sources pipeline](data-sources.md) can register a dataset directly from
a verified query export. Its host-authenticated query origin records source/query
identities, template and parameter digests, installed provider identity and snapshot
receipt. Query credentials and raw parameter values are not included in the dataset.

`POST /api/v1/datasets` takes an `Idempotency-Key` and this shape:

```json
{
  "name":"Measurements",
  "format":"csv",
  "schema":{"fields":[{"name":"count","type":"int64","nullable":false}]},
  "sources":[{"root_id":"ROOT_ID","entry_id":"OPAQUE_FILE_REFERENCE"}],
  "provenance":{"description":"Instrument export","input_dataset_ids":[]},
  "previous_version_id":null
}
```

Replace placeholders with IDs from Files. Registration requires `files:write`
in the project and current read access to every source. Read-only source roots
can be registered. `GET /api/v1/datasets` lists up to 50 summaries; pass its
`next_cursor` as `before` for the next page. `GET /api/v1/datasets/DATASET_ID`
returns a public manifest. `POST /api/v1/datasets/DATASET_ID/verify` checks current
sources. Public manifests do not expose absolute host paths or reusable internal
references. Dataset IDs and matching content digests confer no access across
projects. Root and project permissions are checked again on every data read.

A version contains at most 128 files and 256 KiB of metadata. These bounds keep
control messages and schema work finite; they do not bound the source file size.
Metadata backups preserve the manifest, authentication key and registered
references, while external file bytes require a separate storage backup. A
restored reference remains usable only if its source and authorization still
match. Source backup health is not inferred from a successful read.
