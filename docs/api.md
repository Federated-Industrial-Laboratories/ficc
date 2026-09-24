# Local API

The service listens on 127.0.0.1. It does not trust proxy headers or allow CORS.
Use the exact configured host and port. Remote proxy deployment is unsupported.
The CLI uses the same API as the browser.

Browser login exchanges a single-use bootstrap credential for an HttpOnly,
SameSite=Strict cookie. Obtain that credential through `ficc open`. The URL
fragment is removed before the browser sends the login request. Do not save
that URL in a log or share it with another person.

Browser mutations require the session's X-CSRF-Token value and allowed Origin.
API clients use `Authorization: Bearer TOKEN`. Read tokens from protected files
or stdin. Do not expose them in process arguments. Each request checks expiry,
current grants and node scope.

| Method and path | Result |
| --- | --- |
| GET /api/v1/health | Minimal service status; no authentication required |
| POST /api/v1/session | Exchange a bootstrap credential for a browser session |
| GET /api/v1/session | Current principal, mode, version and CSRF value |
| DELETE /api/v1/session | Revoke the current session |
| GET /api/v1/nodes | Machines permitted by the current credential |
| GET /api/v1/nodes/{id} | One permitted machine and its current observation |
| GET /api/v1/nodes/{id}/resources | Resource sample, timestamp and stale flag |
| POST /api/v1/nodes/refresh | Refresh one to 64 distinct machine IDs |
| GET /api/v1/profiles | Approved local SSH profiles |
| POST /api/v1/node-previews | Resolve and verify an enrollment candidate |
| POST /api/v1/nodes | Confirm a preview and any required helper installation |
| DELETE /api/v1/nodes/{id} | Forget a local enrollment; does not uninstall remotely |
| GET /api/v1/permissions | Effective scopes and node restriction |
| GET /api/v1/tokens | Token metadata; never secret values |
| DELETE /api/v1/tokens/{id} | Revoke a token |
| GET /api/v1/audit | Bounded recent audit events |
| POST /api/v1/nodes/{id}/helper-upgrade | Explicitly update the enrolled node helper |
| POST /api/v1/operation-previews | Validate and freeze a managed-job request |
| POST /api/v1/operations | Persist a previewed job batch; requires Idempotency-Key |
| GET /api/v1/operations | Up to 200 visible operations, newest first |
| GET /api/v1/operations/{id} | Per-machine states, limits and authoritative results |
| POST /api/v1/operations/{id}/cancel | Record cancellation for selected node_ids and optional force |
| GET /api/v1/operations/{id}/logs/{node_id} | Bounded base64 stdout/stderr chunk and byte cursor |

The available scopes are nodes:read, nodes:write, resources:read, tokens:manage
and audit:read, plus jobs:read, jobs:execute, jobs:cancel and jobs:logs. Existing
credentials do not gain new scopes during an upgrade. Sign in again as owner
or issue an appropriate new token. Node lists filter inaccessible machines. Enrollment, profile
inspection, token administration and global audit access require unrestricted
node access as well as their operation scope.

Control requests have a 1 MiB limit. Invalid fields are rejected. Errors have
this shape, with an appropriate HTTP status:

```json
{"error":{"code":"denied","message":"This credential does not permit the action."}}
```

Resource values use bytes, seconds and percentages. Missing values are null or
explicitly unavailable. A stale sample remains visible with its age. Do not
treat an old sample as current capacity or a connection failure as zero use.
The helper response contract is [node-v1.json](../schemas/node-v1.json).
Generate it with `python tools/export_schema.py schemas/node-v1.json`.
The current collector reports the root filesystem and cumulative network counters.
GPU measurements use a bounded structured nvidia-smi query when supported.

See [managed jobs](jobs.md) for the typed request and lifetime rules. A job preview
expires after 120 seconds and belongs to its credential. Submit `{"preview_id":"ID"}`
with an Idempotency-Key of 16 to128 printable ASCII characters. Deduplication is
credential-bound. A matching previously accepted request returns its original
operation even after preview expiry. A conflicting request returns 409.

Log queries accept stream=stdout or stderr, nonnegative offset and limit 1..65536.
They return data_base64, next_offset, total_bytes, dropped_bytes and complete.
Cancellation accepts `{"node_ids":["ID"],"force":false}` and returns 202 with the
current operation. Neither acceptance nor a transport error proves termination.

The service provides a development contract under /api/v1. Clients
should check the returned application version. Additive and breaking changes
are documented before a stable API release.
