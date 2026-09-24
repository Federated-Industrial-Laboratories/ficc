<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Local API

[Contents](README.md) | [Project README](../README.md) | [Previous: History archives](history.md) | [Next: Testing](testing.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

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
current grants and node/root scope.

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
and audit:read, plus jobs:read, jobs:execute, jobs:cancel and jobs:logs.
Files add files:read, files:write, files:mode and files:delete. Terminals add
terminals:read, terminals:execute and terminals:stop. Existing
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

## File routes

Root registration uses the private owner CLI only. GET /api/v1/file-roots returns
permitted root IDs and their available actions. POST /api/v1/files/list accepts
root_id, opaque entry_id, optional cursor and limit up to 200. POST
/api/v1/files/preview accepts root_id, entry_id and limit up to 65536.

POST /api/v1/file-operation-previews prepares mkdir, rename, mode or delete.
POST /api/v1/file-operations accepts preview_id and confirm:true with an
Idempotency-Key header. GET the collection or /{id} for per-entry outcomes.
Previews expire after 120 seconds; accepted keys retain their original result.
POST /{id}/reconcile checks durable receipts for an uncertain file operation.

POST /api/v1/transfer-previews prepares copy, upload or download, with sources,
optional destination and an explicit overwrite choice. POST /api/v1/transfers
accepts preview_id and confirm:true with Idempotency-Key. GET the collection or
/{id} for progress. POST /{id}/resume takes item_ids; POST /{id}/cancel also takes
discard_partial. Existing source entries use root_id and opaque entry_id.
Upload source metadata uses name, size and last_modified.

PUT /api/v1/transfers/{id}/items/{item_id}/chunks?offset=N accepts at most
262144 binary bytes as application/octet-stream and X-Chunk-SHA256. POST the
item's /finish endpoint verifies and publishes it. GET the /content endpoint
serves a successfully prepared download attachment. See [files](files.md) for
recovery, resource limits and the trusted-account boundary.

## Terminal routes

GET /api/v1/terminals lists permitted records. POST creates an intent with
node_id, mode (ephemeral or tmux), label, cols, rows, confirm_execution:true
and idempotency_key (16-80 ASCII letters, digits, hyphens or underscores).
A matching key returns the same record; changed content returns 409.
GET /{id} reads a record; POST /{id}/stop requires confirm_stop:true.
POST /{id}/reconcile queries an uncertain tmux session's exact saved identity.
It requires terminals:execute and never creates or attaches a session.

POST /api/v1/terminals/{id}/tickets returns ticket, expires_at and websocket_path.
Connect to that path on the same origin and send {"type":"auth","ticket":"..."}
as the first text frame. No ticket or credential belongs in the WebSocket URL.
Binary frames carry raw input/output. Text controls are
{"type":"resize","cols":80,"rows":24} and {"type":"ack","bytes":1024}.
ACK counts newly processed output bytes, not characters or socket receipt.
The server sends {"type":"status","state":"attached"} and explicit exit/error
states. See [terminals](terminals.md) for bounds, reattachment and grant semantics.

## Agent and bus routes

GET `/api/v1/agent-profiles` returns registered profiles visible under
`agents:read`. Owner-only profile registration uses the private local socket.
GET `/api/v1/agents` and `/api/v1/agents/{id}` return runtime, node, run and
terminal identities, delivery capability, state and observed contact time.

POST `/api/v1/agent-previews` takes `profile_id`, `label`, `run_id`, `cols` and
`rows`. It requires `agents:execute` and `bus:send` for the selected enrollment.
POST `/api/v1/agents` takes `preview_id`, `idempotency_key` and
`confirm_execution:true`. Repeated matching requests return the saved agent;
an uncertain launch is never automatically repeated. POST `/{id}/stop` requires
`agents:stop` and `confirm_stop:true`. POST `/{id}/reconcile` uses
`agents:execute` and queries the saved identity. POST `/{id}/rebind` requires
`agents:execute`, `runtime_session_id` and `confirm_rebind:true`; the requested
ID must equal the node's observed changed session. Attachment uses the ordinary
terminal ticket route and terminal execution scope.

GET `/api/v1/bus/runs` requires `bus:read`. POST takes `name` and
`idempotency_key` under `bus:send`. GET `/{id}/messages` takes optional `after`
(nonnegative ordinal) and `limit` (1-100), returning `messages` and `next_after`
(null when no further page exists). POST takes `type`, validated `body`, explicit
`recipient_ids` (at most64), `delivery` (`inbox` or `direct`), optional `reply_to`,
`idempotency_key` and `confirm_delivery:true`. It returns a canonical `message`
and separate `deliveries`. POST `/{id}/close` takes `confirm_close:true` and
refuses unresolved deliveries or active agents. A restricted credential must
cover every node enrolled in a run before viewing its shared message content.

GET `/api/v1/bus/deliveries` accepts optional `run_id` and returns the newest
1,000 visible receipts. Receipt states describe storage and inclusion layers,
never work completion. Node replies bind sender identity and run from the saved
launch record and use its original grant. No API endpoint accepts a host bus
file path. See [agents](agents.md) and [bus](bus.md) for tooling, resource limits,
revocation and explicit archival.

Agent records can include `outbox_rejections`, the latest 16 permanent reply
refusals. Each summary contains `id`, `code`, `detail` (at most 240 characters),
and `rejected_at` (Unix seconds). These are separate from bus delivery receipts
and do not claim host storage. Exact rejected content remains in the node spool
and is available through the registered local `rejects` and `rejected` tools.


<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Previous: History archives](history.md) | [Next: Testing](testing.md)
