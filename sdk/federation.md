# Federation API

[Operator guide](../docs/federation.md) | [Inference API](inference.md)

All routes use the normal FICC authentication, selected project and CSRF rules.
The prefix below is `/api/v1/federation`.

| Method and path | Required scope | Input or result |
| --- | --- | --- |
| GET `/` | `federation:read` | Companion state, public cluster identity, project peers, offers, grants and transfers |
| PUT `/configuration` | `federation:manage`, local owner | `agent_directory`, `label` |
| POST `/offers` | `federation:manage` | `service` (HyperNet ID), `requested` scope list |
| POST `/offers/{id}/approve` | `federation:manage` plus delegated scopes | `revision`, `grant` |
| POST `/offers/{id}/finish` | `federation:manage` | Complete the exact accepted receipt |
| DELETE `/offers/{id}` | `federation:manage` | Discard an unaccepted request |
| DELETE `/peers/{id}` | `federation:manage` | Revoke local access and remove pairing |
| POST `/peers/{id}/grants` | `federation:manage` plus delegated scopes | Create a new exact local grant |
| DELETE `/grants/{id}` | `federation:manage` | Revoke; no credential is returned |
| POST `/peers/{id}/refresh` | `federation:manage` | `{}` lists current grants; `{"grant":"ID"}` selects one |
| POST `/peers/{id}/request` | `federation:invoke` | `operation`, `body`, mutation `id` |
| POST `/peers/{id}/models` | `federation:invoke`, `models:manage` | `model` remote ID; start or resume local acquisition |
| POST `/transfers/{id}/pause` | `federation:invoke` | Pause acquisition, retaining partial bytes |

A grant names `scopes`, `services`, `models`, `nodes`, `lifetime` in seconds,
`concurrent`, `requests`, `transfer_bytes`, `request_bytes`, `response_bytes` and
`stop_on_revoke`. Defaults are one day, two concurrent requests, 1,000 total
requests, no model transfer, 512 KiB request and 64 MiB inference response.
Maximum lifetime is 30 days, concurrency 16, requests 1,000,000, model allowance
16 TiB and response 256 MiB. Remote scopes are `discover`, `inference:invoke`,
`inference:manage`, `models:read`, `models:transfer`, `models:manage`,
`resources:read`. Exact resource IDs are required; there is no wildcard. Each grant can create at
most 64 service records and 64 model records. Their IDs are usable only with
the grant's corresponding operation scopes. Uncertain creations retain their
capacity until inspection; existing unselected model records cannot be adopted
by submitting the same manifest.

| Remote operation | Body | Contract |
| --- | --- | --- |
| `discover` | `{}` | Granted aliases, service IDs, capabilities and model IDs |
| `inference.prepare` | `{}` | Granted model names, revisions, readiness and eligible node/runtime offers |
| `inference.preview` | `spec` | Receiving-cluster admission preview, no launch |
| `inference.get` | `service` | Granted service specification, state and revision |
| `inference.create` | `spec` | Managed specification from the inference API |
| `inference.replace` | `service`, `revision`, `spec` | Replace a stopped managed service |
| `inference.control` | `service`, `revision`, `operation`, optional `acknowledge_unknown` | `start`, `drain`, `stop`, `remove` |
| `inference.invoke` | `service`, `path`, `body` | Compatible inference path and JSON body |
| `models.manifest` | `model` | Immutable manifest without URLs, plus canonical SHA-256 |
| `models.range` | `model`, `file`, `offset`, `length`, `digest` | Verified complete source, at most 256 MiB |
| `models.create` | `manifest` | Catalogue only; upstream URLs are refused |
| `models.remove` | `model` | Remove an unused granted catalogue record |
| `resources` | `{}` | Availability of selected nodes |
| `operation.status` | `id` | Retained outcome within the selected grant |

Starting a stopped service with an unknown earlier replica outcome requires
`acknowledge_unknown: true`. This strict boolean defaults to false and is accepted
only for `start`. Earlier attempts must be released before new attempts start;
previous inference requests are not replayed. After a refused start, inspect the
service and use a new mutation ID for the acknowledged request. Reusing an ID
with changed acknowledgement or other arguments is a conflict.

Create, replace, control and model mutations require a 32-character lowercase
hexadecimal operation `id`. Save it before submitting. Use the same ID and exact
arguments for a retry. The receiver records uncertainty before an effect and
retains the completed result. A timeout is not proof that the operation failed.

The compatible base URL is `/api/v1/federation/peers/{id}/v1`. It supports
`GET /models` and the underlying service's supported inference subset. Pass a
published remote service ID as `model`. Streaming uses SSE; closing the response
cancels the remote request. Requests are never replayed automatically.

CLI commands are `federation-status`, `federation-configure`, `federation-pair`,
`federation-approve`, `federation-finish`, `federation-remove`, `federation-grant`,
`federation-revoke`, `federation-refresh`, `federation-request`,
`federation-acquire` and `federation-pause`. Use `--state-dir` and optional
`--project`; commands requiring JSON accept `--input FILE`. Request streams use
an exclusive `--output FILE`. Acquisition waits with a finite deadline and pauses
on interruption before releasing its local credential. Run it again to resume.

FICC's wire protocol `ficc.federation/1` uses bounded length-prefixed frames on
the maintained HyperNet SDK. A fresh signed challenge binds the exact transport
session and generation. Each request proves the separate FICC cluster key and
the receiving grant rechecks the SDK-verified application principal. Browser
headers, peer payloads and transport voucher possession are not identity proofs.

`POST /grants/{id}/retire` deletes a revoked grant and its operation receipts. `POST /peers/{id}/forget` deletes a removed peer and its associated retired grants and pairing receipts. Both require `federation:manage`; the CLI commands are `federation-retire` and `federation-forget`. Neither action can revive an old grant.
