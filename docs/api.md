<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Local API

[Contents](README.md) | [Project README](../README.md) | [Previous: History archives](history.md) | [Next: Testing](testing.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

<details>
<summary>On this page</summary>

- [Authentication](#authentication)
- [Controller and job routes](#controller-and-job-routes)
- [File routes](#file-routes)
- [Terminal routes](#terminal-routes)
- [Agent and bus routes](#agent-and-bus-routes)
- [Module and workspace routes](#module-and-workspace-routes)
- [Provider actions and displays](#provider-actions-and-displays)

</details>

The browser and CLI use the same authenticated HTTP API. Local mode binds the
configured port on `127.0.0.1`. [Remote mode](remote-access.md) binds a protected
Unix socket behind the configured HTTPS gateway. Arbitrary proxy headers and
CORS do not grant access. Owner CLI requests remain local.

## Authentication

Browser login exchanges a single-use bootstrap credential for an HttpOnly,
SameSite=Strict cookie. Obtain that credential through `ficc open`. The URL
fragment is removed before the browser sends the login request. Do not save
that URL in a log or share it with another person.

Browser mutations require the session's X-CSRF-Token value and allowed Origin.
API clients use `Authorization: Bearer TOKEN`. Read tokens from protected files
or stdin. Do not expose them in process arguments. Each request checks expiry,
current grants and node/root scope.

Credentials also name a durable user and selected project. Current membership
limits their original scopes. Session responses include the public identity and
project records. Browser requests send `X-FICC-Project` and `X-FICC-Session`;
an outdated window receives `409 project_changed` or `409 session_changed`.
These headers supplement authentication and do not grant access.

Session responses also include `expires_at` as Unix seconds and the `remote`
mode flag. Remote cookies use the `__Host-ficc_session` name with Secure and
HttpOnly attributes. External access tokens are not FICC bearer credentials.
`GET /api/v1/login` reports remote identity readiness without requiring a login.
`POST /auth/start` requires the exact configured origin. `GET /auth/callback`
consumes browser-bound one-use state. Only this callback permits cross-site
navigation. Normal origin and CSRF checks remain in force elsewhere.

Owner-only `GET /api/v1/external-identities` lists approvals and provider status.
`PUT /api/v1/external-identities` accepts `issuer`, `external_subject`, `subject_id`,
`disabled` and `revision`. Revision zero creates a mapping. Later edits require
its current revision. Mapping the local recovery owner is refused.

`GET /api/v1/projects` lists the caller's projects. `POST /api/v1/session/project`
accepts `project_id` and rotates a browser session without extending its expiry.
Bearer tokens cannot switch projects. Owner identity administration uses
`GET/POST /api/v1/identities`, `POST /api/v1/projects`, and
`PUT /api/v1/identities/{id}` or `/api/v1/projects/{id}` with label, disabled and revision.
`GET /api/v1/projects/{id}/members` lists memberships;
`PUT /api/v1/projects/{id}/members/{subject}` accepts scopes and revision.
These administration routes require `identities:manage` and local owner authority.
Owner resource administration uses `GET /api/v1/project-resource-options` and
`GET/PUT /api/v1/projects/{id}/resources`. The PUT body contains `node_ids`,
`root_ids` and `revision`. It replaces the project selection. Remote folders
require their machine assignment. Stale revisions return `409 revision_conflict`.
The permissions and session responses report effective machine and folder lists;
project switching preserves the original credential limits separately.
Job, file-operation, transfer and terminal responses include durable `subject_id`
and `project_id` fields. Cross-project object access returns `404`; lists include
only the selected project. Terminals also require their subject, except for the
local recovery owner within that project.
See [identities and projects](identities.md) for the current capability boundary.

## Controller and job routes

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
Files add files:read, files:write, files:mode and files:delete. Data sources add
data:read, data:export, data:write and data:manage; see the
[source API and provider contract](../sdk/data-sources.md). Terminals add
terminals:read, terminals:execute and terminals:stop. Existing
credentials do not gain new scopes during an upgrade.

Sign in again as owner
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
Binary frames carry raw input/output.

Text controls are
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
an uncertain launch is never automatically repeated.

POST `/{id}/stop` requires
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
`idempotency_key` and `confirm_delivery:true`.

It returns a canonical `message`
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

## Module and workspace routes

Module management requires unrestricted local node and root access.
The scopes are `modules:read`, `modules:manage` and `modules:execute`.
Workspace access uses `workspaces:read` and `workspaces:write`; shared sound uses `audio:playback`.
These caller scopes are separate from each installed archive's capability grants.

| Method and path | Request or result |
| --- | --- |
| GET /api/v1/modules | Installed manifests, digests, activation and grants |
| GET /api/v1/modules/sandbox | Current executable-module isolation prerequisites |
| GET /api/v1/module-targets | Permitted capability targets and labels |
| GET /api/v1/supplied-modules | Separate archives supplied with this installation |
| POST /api/v1/supplied-module-previews | Inspect `package_id` from that catalog |
| POST /api/v1/module-install-previews | Inspect raw local archive bytes, at most 16 MiB |
| POST /api/v1/module-fetch-previews | Inspect `url`, optional `expected_digest`, `allow_private_network` and `allow_http` |
| POST /api/v1/modules | Install `preview_id`, exact `digest` and `accept_unverified:true` |
| DELETE /api/v1/module-install-previews/{id} | Release the caller's unused inspection |
| POST /api/v1/modules/{digest}/activation | Set `enabled` and exact capability/target `grants` |
| DELETE /api/v1/modules/{digest} | Remove a package after retained operations are cleared |
| POST /api/v1/module-invocations | Invoke a declared action within a saved panel's target selection |
| GET, POST /api/v1/workspaces | List workspaces or create one with `name` |
| GET, PUT, DELETE /api/v1/workspaces/{id} | Read, update or delete a revision-checked workspace |
| PUT /api/v1/workspaces/{id}/instances/{instance}/state | Save `revision` and bounded `state` |
| GET, PUT, DELETE /api/v1/workspaces/{id}/views/{view} | Read, save or remove one panel layout |
| GET, PUT, DELETE /api/v1/workspace-surfaces/{surface} | Read, save or remove one workspace tile layout |
| GET /api/v1/workspace-layouts | Saved surfaces and views |
| GET, PUT /api/v1/audio/preferences | Read or update `revision`, `volume` and `muted` |
| POST /api/v1/audio/leases | Acquire playback for `instance_id` and `surface_id` |
| PUT, DELETE /api/v1/audio/leases/{id} | Renew or release using the owning `surface_id` |

Inspections expire after 300 seconds. Installation leaves the package disabled with no grants.
Activation uses grants shaped as `{"capability":"workspace:read","target_ids":["WORKSPACE_ID"]}`.
Each digest has its own grants. An update does not inherit another archive's authority.

An invocation supplies `workspace_id`, `instance_id`, `action`, `targets` and optional `parameters`.
The host obtains the package digest from the saved panel; the request cannot substitute another digest.
`targets` contains one to 64 distinct IDs within that panel's selection.
See the [protocol](../sdk/PROTOCOL.md) and [component format](../sdk/UI.md) for module-side contracts.

Workspace updates supply the current `revision`, `name` and complete `instances` list.
Each instance has `id`, `digest`, `title`, optional `state` and selected `targets`.
View saves use `revision` and `layout`; surface saves also include `tiles`.
Delete requests supply `revision` as a query parameter. A stale revision returns 409.
No save silently replaces another window's newer data.

The `/api/v1/module-editor/` POST routes use `workspace_id` and `instance_id`.
`roots` lists permitted roots; `list` uses `root_id`, opaque `entry_id` and optional `cursor`.
`read` takes distinct `items` with those identities.
`save` adds each file's `sha256` and UTF-8 `text`, plus `accept_retained_exchange:true`.

It requires an Idempotency-Key and retains original or conflicting copies for explicit recovery.
`operations`, `status`, `recovery`, `cleanup` and `remove-receipt` expose that history.
See [the editor workflow](workspaces.md#included-productivity-panels) before removing retained copies.

## Provider actions and displays

VM actions use `vm:read`, `vm:power` and `vm:console`.
Containers use `container:read`, `container:logs` and `container:power`.
Administration uses `admin:read`, `admin:logs`, `admin:services` and `admin:power`.
Current caller scopes and package grants must both permit each selected system and action.

GET `/api/v1/vm-profiles` lists libvirt connections.
PUT or DELETE `/api/v1/nodes/{id}/vm-profile` changes one enrolled connection.
PUT uses `connection` (`system` or `session`) and `enabled`.
GET `/api/v1/proxmox-profiles` lists Proxmox connections.
PUT `/api/v1/nodes/{id}/proxmox-profile` probes and saves `enabled`; DELETE removes the profile after receipt cleanup.

Packaged provider management requires `providers:write` on the selected endpoint.
GET and POST `/api/v1/adapter-profiles` list profiles and create a disabled binding.
POST uses `digest`, `endpoint_kind`, `endpoint_id` and `transport_binding_id`.
POST `/{profile_id}/grant` adds `expected_revision` and `confirm:true`.
POST `/{profile_id}/revoke` removes account access. DELETE `/{profile_id}` requires `confirm:true` and no retained receipts.

These suffixes are relative to `/api/v1/adapter-profiles`.
GET `/api/v1/adapter-bindings` uses `endpoint_kind` and `endpoint_id` query parameters.
POST registers an owner-selected `socket_path` for an enrolled Linux endpoint.
Unavailable transports refuse registration or use.

GET and POST `/api/v1/windows-endpoints` list and register separate Windows endpoints.
PUT and DELETE `/{endpoint_id}` require `expected_revision`; DELETE also requires `confirm:true`.
POST `/{endpoint_id}/activation` uses `expected_revision` and `enabled`.
Endpoint writes require unrestricted `nodes:write`. See [Windows endpoint fields and trust](windows-endpoints.md).

Registration uses `name`, `host`, `port`, `configuration`, `commands`, `certificate_sha256`, `ca_pem`, `credentials` and optional `vmconnect`.
Credentials contain `username`, `password` and `domain`. VMConnect has its own port, certificate digest and credentials.
An update can omit credentials and CA data to preserve saved values; `vmconnect:null` removes the display connection.

GET, PUT and DELETE `/api/v1/container-profiles` manage container connections; DELETE adds `/{profile_id}`.
Administration uses the same methods under `/api/v1/admin-profiles`.
Its PUT body has `node_id`, `manager` (`user` or `system`), optional `profile_id` and `enabled`.
Registration checks the existing remote account's authority; it does not obtain an elevated password.

Provider mutations share these POST suffixes under `/api/v1/module-vms/`, `/api/v1/module-containers/` and `/api/v1/module-admin/`:

| Suffix | Fields beyond `workspace_id` and `instance_id` |
| --- | --- |
| preview | `preview_id` returned by a module action; reads the host confirmation |
| commit | `preview_id`, `confirm:true` and an Idempotency-Key header |
| history | None; returns this panel's permitted operation history |
| operation | `operation_id`; inspects current outcome without replay |
| resolve | `operation_id`, `confirm:true` and selected `vm_ids` or `resource_ids` |
| forget | `operation_id` and `confirm:true`; removes terminal receipts after node acknowledgment |

The host classifies effects and freezes resource identities before confirmation.
A retry uses the same key and returns the same intent. Unknown outcomes require inspection.
Resolve records that inspection; it does not establish success or dispatch another action.

VM adapter receipts include the immutable profile and declared consistency.
An `adapter_orphan_ack_required` response permits a separate retry with `acknowledge_orphans:true`.
This removes only terminal local receipts when the original system identity is absent or changed.
Active provider tasks remain retained. A transient connection failure requires cleanup retry, not local-only removal.

Power acceptance means queued. A lost SSH connection does not prove shutdown.
See [libvirt](providers/libvirt.md), [Proxmox](providers/proxmox.md), [containers](containers.md) and [administration](system-admin.md) for provider-specific limits.

A permitted console module action returns an opaque `viewer_ref`.
POST `/api/v1/viewers/{reference}/tickets` issues one single-use ticket valid for 15 seconds.
Open the same-origin WebSocket `/api/v1/viewers/{reference}/stream` and send `{"type":"auth","ticket":"..."}` first.
The URL must have no query string. Provider addresses and temporary passwords never enter browser messages.

Binary output contains bounded Guacamole display instructions, not raw provider bytes.
Text input uses `{"type":"input","instruction":"..."}` or processed-byte acknowledgments `{"type":"ack","bytes":N}`.
Only permitted input instructions pass; clipboard and file channels are refused.
Current authority remains checked during the stream. See [remote displays](viewer.md) for input release and time limits.


<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Previous: History archives](history.md) | [Next: Testing](testing.md)

## Runtime policy administration

Policy administration requires an unrestricted local owner credential with
`policies:manage`. It remains available for recovery when normal policy decisions
fail. It cannot be delegated through project membership.

| Route | Method | Result |
| --- | --- | --- |
| `/api/v1/policy-status` | GET | Current revision and enforcement availability for the caller |
| `/api/v1/policies` | GET | Owner inspection of state, publishers and installed manifests |
| `/api/v1/policy-publishers` | PUT | Explicit trust update with ID, public key, enabled state and revision |
| `/api/v1/policy-packages` | POST | Verify and install `archive_base64`; no activation |
| `/api/v1/policy-packages/{digest}` | GET | Download the verified signed archive |
| `/api/v1/policy-activation` | POST | Prepare and activate a digest with the expected global revision |
| `/api/v1/projects/{id}/policy-roles` | GET | Current project role bindings |
| `/api/v1/projects/{id}/policy-roles/{subject}` | PUT | Replace roles with an expected binding revision |
| `/api/v1/policy-preview` | POST | Compare host, policy and effective permission for 1 to 64 requests |

Preview requests contain an action and optional node_id, root_id and labels.
An optional digest selects an installed candidate. Only the local owner can
select a candidate or supply subject_id/project_id for another identity's
membership ceiling. A normal preview uses the authenticated credential.
The runtime decision contract is documented in [the policy SDK](../sdk/policies.md).
See [policy operations](policies.md) for revocation, rollback and restore.
