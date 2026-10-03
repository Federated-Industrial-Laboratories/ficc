# Audit destination API1

Install a trusted wheel after the FICC host. Register one entry point under
`ficc.audit`; the shipped package registers `https = ficc_audit_https`. Declare
literal `API_VERSION = 1` in the package. Do not import the host's current version
as the package's compatibility declaration.

`configure(configuration: dict)` returns an object exposing
`async append(raw: bytes, credential: bytes) -> dict`. Configuration is supplied
only by the local administrator. It must contain no secret value. The host
resolves the configured secret reference for each delivery and supplies its bytes
only to this call. Provider diagnostics must use fixed `ficc.audit_sdk.AuditError`
codes; never return transport errors, credentials or response bodies as messages.

The provider owns destination-specific authentication and transport. The host owns
redaction, stream identity, retained-event pagination, a durable pending batch,
acknowledgement validation, cursor advancement and selected admission waits.
Providers execute as trusted controller packages, not untrusted sandbox modules.
Their async append must yield during network I/O and support cancellation. The
host imposes a five-second network deadline and one concurrent append; no blocking
network or disk calls belong in that coroutine. Setup and secret/checkpoint file
I/O are handled outside event-loop admission and node locks.

## Canonical request and acknowledgement

The body is at most 65536 bytes of UTF-8 JSON, serialized by
`ficc.audit_sdk.encoded`: sorted keys, compact separators and no non-finite numbers.
It has exactly these fields:

```json
{
  "version": 1,
  "stream_id": "0123456789abcdef0123456789abcdef",
  "sequence": 1,
  "after": 0,
  "through": 1,
  "events": [
    {"kind": "retention_gap", "first_id": 1, "last_id": 1}
  ]
}
```

`sequence` increases by one per acknowledged batch. `after` is the last acknowledged
local audit ID, and `through` is this batch's last covered ID. An intent or initial
stream marker may leave these equal. Each batch contains 1 to 128 objects. Normal
events have `kind=event`, `id`, `at`, action/outcome categories and the SHA-256
identity fields documented in `audit_state.page`. Intent events have `kind=intent`,
a random request ID, timestamp, one fixed protected action and hashed identities.
`kind=stream` opens an otherwise empty stream. Gap objects explicitly represent
missing local events. There are no query, data, command or credential fields.

After durable append, return exactly:

```json
{
  "version": 1,
  "stream_id": "0123456789abcdef0123456789abcdef",
  "sequence": 1,
  "sha256": "SHA256_OF_THE_EXACT_CANONICAL_REQUEST_BYTES",
  "durable": true
}
```

The real digest is 64 lowercase hexadecimal characters. The host compares the
entire response, including types. A generic HTTP success or an asynchronous queue
receipt is insufficient. The HTTPS provider accepts only status 200, no content
encoding, and at most 1024 response bytes. It uses a trusted CA and verified TLS
hostname, disables environment proxies and redirects, and sends a Bearer token
from its secret reference. The token must be 32 to 256 ASCII letters, digits,
underscores or hyphens. No newline is stripped implicitly.

## Receiver obligations

Authenticate an append-only principal. Keep the destination under separately
authorized custody. For each stream, require sequence1/after0 initially and then
the next sequence with the previous `through` as `after`. Store the exact request
and its digest durably before acknowledging. An exact duplicate must return the
same durable acknowledgement; a different digest at that sequence must fail.
No new event may overwrite an earlier event. A crash between append and reply
must reconcile through the same identity, without accepting conflicting bytes.

The shipped collector implements these obligations using SQLite transactions and
private storage, and deliberately provides no HTTP read/delete/update interface.
The append caller cannot ask it to rotate or truncate data. Destination operators
still own filesystem permissions, backup, availability and the truth of their
durability claim. FICC cannot protect against a malicious collector administrator
or guarantee exactly-once external mutations.

The host's `Delivery.require(action, target, principal)` is used by the protected
workload/source entry points. It must be awaited outside the main Store lock.
Admission resumes only after the exact intent acknowledgement and checkpoint
synchronization; authority must be rechecked before the mutation. Failure or
cancellation may leave a durable unused intent. Cleanup/lease maintenance must not
call this gate.

See [administration and recovery](../docs/audit.md). HTTP behavior follows
[HTTPX timeout semantics](https://www.python-httpx.org/advanced/timeouts/) and
[TLS configuration](https://www.python-httpx.org/advanced/ssl/); the host adds an
overall deadline to HTTPX's individual inactivity timeouts.
