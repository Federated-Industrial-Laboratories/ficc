# Secret-provider runtime contract

Trusted packages register an entry point in `ficc.secret`. The supplied package
is `ficc-secret-local`, entry point `local`. The host discovers it at runtime;
install it after building/installing the host. Provider code has controller
authority. This interface is a resource mechanism, not a sandbox or permission
grant, and vendor integration belongs in the provider package.

The entry point exports `API_VERSION = 1` and
`configure(configuration: dict, private_directory: Path)`. It returns an object
with these synchronous bounded operations:

| Method | Contract |
| --- | --- |
| `health()` | Verify current provider/key availability; return no secret. |
| `get(reference)` | Return `ficc.secret_sdk.SecretValue(value: bytes, revision: str)`. |
| `put(reference, value, expected_revision, new_revision)` | Atomically create if expectation is `None`, or replace exactly the expected revision; durably publish the supplied revision. |
| `delete(reference, expected_revision)` | Durably remove exactly the expected revision. |

Reference syntax is `[A-Za-z0-9][A-Za-z0-9_.-]{0,79}`. Values are at most
32768 bytes, including empty values. Revisions are opaque 64-character lowercase
hexadecimal tokens. Ordinary writes receive a fresh random revision from the
host. Imported revisions are for explicit trusted migrations, never normal API
callers. Providers must not silently create missing keys, replace a store,
reinterpret a missing reference, overwrite a different revision, or replay an
uncertain mutation. Use `SecretError` with its fixed SDK codes; never include
driver, credential, response-body or plaintext diagnostics. The host sanitizes
unexpected exceptions and does not return secret values from CLI/API routes.
Each operation owns and closes its handles before returning. Provider instances
must not retain background work, plaintext values or connection resources between
calls; the host creates them for individual operations and does not cache them.

Configuration is a private JSON file at `STATE/secrets-private/provider.json`:
`{"provider":"NAME","configuration":{...}}`. The host passes the private
directory to the provider. Configuration and provider records are excluded from
normal FICC state export. Providers manage their own concurrency and durable
storage; they must place key custody outside exported controller state and
document separate backup/recovery. External services can use the same contract;
the local package does not claim an OpenBao implementation or qualification.

The shipped local provider additionally exports
`initialize({"key_file": ABSOLUTE_PATH, "create_key": bool}, private_directory)`
for its explicit local setup command. It returns the normalized configuration
`{"key_file": ABSOLUTE_PATH, "store_id": HEX32}`. Creation refuses an existing
key. Recovery with an existing key verifies the retained authenticated store
check. The host writes configuration only after that verification.

## Host use

```python
from ficc.secrets import Secrets

resolved = Secrets(state_dir).resolve(approved_reference)
if resolved.revision != approved_revision:
    raise ValueError("The approved credential revision changed.")
# Pass resolved.value only to the already authorized operation.
```

The caller owns current actor/project/resource authority and must obtain the
reference from an approved immutable operation. Secret resolution does not
authorize a caller. Do not accept a caller-selected reference as a substitute
for a resource grant. `SecretValue` excludes its payload from its representation,
but consumers must still avoid logging or serializing it. Values are not cached
across operations; authorized consumers can hold them for that operation's
lifetime. Revocation cannot erase bytes already delivered to a process.

Data sources resolve references at registration and at each worker dispatch.
Connection records contain the reference and revision. Source credentials are
JSON with the existing approved username/password or S3 credential fields.
The source adapter validates that shape; the reusable secret host has no source
vendor logic. Explicit legacy migration preserves
`HMAC-SHA256(file_reference_key, b"ficc-source-secret\0" + original_bytes)`.
No implicit plaintext fallback exists, and no state-schema migration is required.

## Local record format and assurance

The provider uses the pinned `cryptography` AESGCM implementation with a random
256-bit key, random 96-bit nonce per encryption, and full 128-bit tags. The
authenticated header includes format version, random store identity, record
kind, reference and revision. Header JSON uses sorted keys, compact separators
and UTF-8. The record adds base64 `nonce` and `ciphertext` fields; the latter
includes the tag. A separate health record verifies an empty store's key.
Reference, store or revision substitution therefore fails authentication.
See [the primary AESGCM API](https://cryptography.io/en/50.0.2/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM).

Private descriptor-based reads refuse symlinks, non-regular files, extra links
and group/other access. Writes publish synced temporary files atomically and
sync their containing directory. A private advisory lock serializes mutations.
Missing provider/key, invalid permissions or authentication failure fail closed.
Filesystem and process administrators remain trusted. The provider offers no
rollback resistance, secure media erasure, automatic key rotation, or encryption
of surrounding state/data. See [administration and recovery](../docs/secrets.md).
