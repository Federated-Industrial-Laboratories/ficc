# Policy package interface

Policy packages supply Rego rules and JSON data to a trusted evaluator. They
are distinct from workspace modules. See [operation and recovery](../docs/policies.md).

## Build and sign

Copy a preset from `policy-packs/managed` or `policy-packs/contribution`.
Edit `package.json`, the Rego decision and its data. Keep role names and defaults
in the package. The host supplies reusable authority and enforcement.

A minimal `package.json` contains:

```json
{
  "format": "ficc-policy", "version": 1,
  "id": "organisation-policy", "release": "1.0.0", "decision_api": 1,
  "roles": [{"id": "reader", "label": "Reader", "description": "Read permitted project data."}]
}
```

Place rules under `payload/`. The builder adds the publisher and payload hashes.
For OPA, name JSON data files `data.json`; subdirectories provide separate data paths.

```sh
python tools/pack-policy.py --help
python tools/pack-policy.py ./my-policy --publisher organisation-policy \
  --key /home/operator/.config/policy-signing-key --output ./my-policy.ficcpolicy
```

Use an existing Ed25519 key. Its path goes directly to OpenSSH; the builder does
not read the key or include it in the archive. Protect it separately from the
public key. The builder refuses to overwrite an existing output file.

The ZIP contains `manifest.json`, `manifest.sig` and `payload/` files. Exact
manifest bytes use OpenSSH SSHSIG namespace `ficc-policy-v1`. Verification uses
the publisher as the allowed signer and an explicitly trusted public key.
Manifest fields are exactly `format`, `version`, `id`, `release`, `publisher`,
`decision_api`, `roles` and `files`. Format is `ficc-policy`; both versions are 1.
Roles contain `id`, `label` and `description`. `files` maps payload-relative
paths to SHA256 digests. Only `.rego` and `.json` payload files are accepted.
Links, duplicate names, path traversal and unsigned or undeclared files fail.

## Decision API

The evaluator reads `data.ficc.decisions`. Input has `version:1`, a monotonic
`revision` and 1 to 64 `requests`. Each request has a unique `id`, an `action`,
an `authority` object and a separate `labels` object. Authority fields are:

| Field | Meaning |
| --- | --- |
| subject_id, project_id | Current authenticated identity and project |
| credential_id | Opaque record ID, never the bearer secret |
| local_owner | Host-established recovery identity |
| roles | Current explicit policy role assignments |
| scopes | Current host-granted permission ceiling |
| node_id, root_id | Selected resource identities, or null |
| contributor_enforcement | False until the host supplies contributor execution enforcement |

Caller-controlled labels cannot establish authority. Credential values, workload
contents and database passwords are excluded. Return one ordered decision per
request, with exactly `id`, Boolean `allow` and a reason matching
`[a-z][a-z0-9_.-]{0,79}`:

```json
[{"id":"unique-request-id","allow":false,"reason":"role_not_permitted"}]
```

The compact JSON envelope, including its `input` wrapper and escaped authority
and labels, must fit within 256 KiB. Reduce labels or batch size when it does not.
Preview evaluation uses a separate supervised process from active enforcement.
Invalid caller data cannot disable the active evaluator. Two previews can run
at once; additional requests receive HTTP 429.

Undefined, incomplete, reordered or malformed results fail closed. The host
rechecks current authority and revision before use. An allow cannot expand grants.
Role and publisher changes also advance the global revision. Read the current
revision immediately before activation; a stale revision receives HTTP 409.
The activation response is the saved policy state. Inspect `/api/v1/policies`
and its `state.ready` field to check evaluator readiness after a change.
Return a valid denial for unsupported actions, including `policy:probe` at
activation. Policies use the provider's explicit deterministic builtin list;
HTTP, network, environment, time, random and print functions are unavailable.

## Trusted provider interface

A trusted Python distribution registers an entry point in group `ficc.policy`.
Its module exports `API_VERSION = 1` and
`prepare(configuration, source_directory, run_directory)`. The source is verified
and private. Its runner implements synchronous `evaluate(envelope)` and
idempotent `close()`. Close confirms process termination before returning.

Providers execute with controller authority and require operator installation.
They must enforce isolation and resource limits before admitting policy data.
An ordinary module cannot register or select a provider. The host normalizes
provider errors and validates every decision. See the [OPA contract](../policy-providers/opa/README.md)
for limits and deadlines.

Tests cover signing, host-denial controls, role changes, job and terminal
revocation, and portable recovery. Real evaluator tests require `FICC_TEST_OPA`.
Unavailable prerequisites are explicit skips, not successful integration results.
