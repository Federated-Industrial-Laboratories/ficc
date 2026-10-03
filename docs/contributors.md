# Contributor connections

Linux contributors initiate authenticated outbound connections to a remote
FICC controller. The controller reports their connection state and resource
samples. Contributor workload execution is not enabled: these connections do
not accept jobs, run commands or grant access to datasets. Existing
[managed SSH jobs](jobs.md) remain a separate workflow.

An invitation permits one enrollment request. An administrator must independently
verify the requesting machine's public-key fingerprint before issuing its
certificate. The machine then proves possession of that key over TLS before
its connection becomes active.

## Prepare the installation

Use an explicit [remote deployment](remote-access.md), a separate controller
account, a verified HTTPS gateway and a private certificate authority. A public
IP address can be used when the gateway's server certificate covers that IP;
a DNS name is not required. Contributors need outbound access to the browser
gateway for enrollment and to the separate node listener for their connections.
The supplied profile uses TCP 443 and TCP 8443. Nodes need no inbound listener.

Install the [Smallstep certificate provider](../certificate-providers/smallstep/README.md)
separately in the controller's Python environment. Its guide covers the private
CA, accounts, provisioner, dependency lock and service profile. Certificate
providers are trusted installation components, not sandboxed panel modules.
The [certificate provider SDK](../sdk/certificates.md) supports other authorities.

Keep the root private key offline. Run a dedicated CA with its own online
intermediate and database. The controller receives the public root chain and
a restricted provisioner credential, never the root or intermediate private
key. Use separate authority material for contributor identities and the
identity service's backend TLS. Keep controller, gateway, CA and node clocks
synchronized.

Prepare a private JSON file from the
[contributor configuration example](../packaging/remote/contributors.json.example).
Its contents select the following fields:

| Field | Meaning |
| --- | --- |
| `deployment_id` | Immutable identifier: 32 lowercase hexadecimal characters. It must match the CA provider's `installation_id`. |
| `origin` | Exact HTTPS origin for the client-certificate node listener. |
| `ca_file` | Absolute path to the public contributor root bundle, containing one to four certificates. |
| `gateway_secret_file` | Absolute path to a separate random node-gateway credential with at least 256 bits of entropy. |
| `issuer` | Installed certificate provider name and its private configuration. |
| `limits` | Certificate, invitation, lease, heartbeat and node-count limits. |

For Smallstep, replace the example's empty `issuer.configuration` object with:

```json
{
  "ca_url": "https://localhost:9000",
  "installation_id": "0123456789abcdef0123456789abcdef",
  "provisioner": "ficc-nodes",
  "signing_key_file": "/etc/ficc/certificates/provisioner.json",
  "root_file": "/etc/ficc/certificates/root_ca.crt",
  "request_seconds": 15
}
```

Replace the example installation ID with the actual deployment ID. Keep the
configuration, controller CA bundle and gateway credential owned by the
controller account with mode `0600`. State directories use mode `0700`.
The node-gateway credential must differ from the browser-gateway credential.
Follow the provider's ownership rules for its provisioner and CA files.

| Limit | Supplied value | Accepted range |
| --- | --- | --- |
| `certificate_seconds` | 3600 | 60 to 86400 seconds |
| `invitation_seconds` | 900 | 60 to 3600 seconds |
| `lease_seconds` | 30 | 5 to 30 seconds |
| `heartbeat_seconds` | 5 | 1 to 10 seconds, at most half the lease |
| `max_nodes` | 64 | 1 to 64 contributors |

With the controller stopped, configure it as its installation account:

```sh
ficc contributors-configure --state-dir /var/lib/ficc-controller \
  --input /path/to/private-contributors.json
```

The command validates and writes `contributors.json` in controller state. A
restart is required. It restores the previous configuration if validation fails.
Changing an existing deployment ID is refused when the controller starts.

Add the [separate node gateway profile](../packaging/remote/contributors.caddy)
to the remote gateway deployment. It requires TLS 1.3 and verified client
certificates, forwards only node-channel routes over the protected controller
Unix socket, and replaces node identity headers. Give it the public contributor
CA at `/etc/ficc-gateway/node-ca.pem` and the matching node-gateway credential.
The [browser proxy](../packaging/remote/controller.caddy) strips incoming node
identity headers. Keep the CA endpoint, database, health and administrative
services private. Do not expose the controller's local-mode HTTP listener.

Keep port 8443 dedicated to contributors. The supplied global server block
permits IP clients that omit TLS SNI. Both the named and fallback TLS policies
require the same verified client certificate. Unknown HTTP hosts are refused.
Do not add browser sites or weaker client-certificate policies to that port.
Server certificate and address verification remain required on every client.

## Invite a machine

Select the intended project and open **Contributors**. A project credential
needs `contributors:read` to view records and `contributors:manage` to invite,
approve or revoke. These operations refuse credentials restricted to particular
managed SSH nodes or file roots. Existing identity and project restrictions
still apply.

Enter the machine name and choose **Centrally managed** or **Voluntary
contribution**, then select **Download invitation**. These values record the
intended control mode. They do not enable workload execution or resource offers.
Share the invitation privately with the intended machine owner. It contains a
single-use secret and the controller's public authority information.

The private controller CLI provides the same administration path:

```sh
ficc contributor-invite --state-dir /var/lib/ficc-controller \
  --project PROJECT_ID --name "Renderer A" --mode managed \
  --output /path/to/private-invitation.json
```

Use `--mode voluntary` for an invited volunteer. The output file must not
exist; the CLI creates it with mode `0600`. It prints the node ID, expiry and
file location without printing the invitation secret. These administrative
commands use the private local control socket and a short-lived project token.

## Join and approve

Install FICC on the Linux contributor. Check the invitation's controller,
node endpoint and installation identity through a trusted administrative
channel. Set the invitation file to mode `0600`, then run as the account that
will maintain the connection:

```sh
ficc node-join --state-dir /var/lib/ficc-contributor \
  --invitation /path/to/private-invitation.json
ficc node-status --state-dir /var/lib/ficc-contributor
```

The account must own the state directory and be able to create it. A normal
user can omit `--state-dir` to use `$XDG_STATE_HOME/ficc-contributor`, or
`~/.local/state/ficc-contributor` when that variable is unset. Keep this state
separate from controller state and other contributors.

The node generates its private Ed25519 key locally, submits a signed request
and saves a private enrollment receipt. The private key never leaves the node.
The output includes `node_id`, `public_key` and the `awaiting_approval` stage.
`public_key` is a 64-character lowercase SHA-256 fingerprint, not a private key
or certificate file. After a successful claim, remove the invitation file;
the node resumes with its saved receipt.

If the gateway uses a private HTTPS server CA, add `--server-ca /path/to/ca.pem`
to `node-join`. That file must be private and independently trusted. It supplies
server trust without disabling name or certificate verification. The node's
client-certificate CA is already bound by the approved invitation.

Obtain the `public_key` value directly from the node owner or local console.
In **Contributors**, select **Approve key** and enter that independently verified
fingerprint. Do not treat a fingerprint copied only from the pending request
as independent verification.

For CLI approval, first list the selected project's records:

```sh
ficc contributor-list --state-dir /var/lib/ficc-controller --project PROJECT_ID
ficc contributor-approve --state-dir /var/lib/ficc-controller \
  --project PROJECT_ID REQUEST_ID --revision REQUEST_REVISION \
  --public-key VERIFIED_PUBLIC_KEY_FINGERPRINT
```

Use the pending request's ID and revision, not the node's ID or revision.
Replace the uppercase placeholders with the current values. A changed revision
or mismatched fingerprint is refused. Approval issues a pending certificate;
it does not by itself establish a live node connection. Complete approval and
activation before the invitation's enrollment window expires.

## Connect and inspect

On the approved node, start the connection:

```sh
ficc node-connect --state-dir /var/lib/ficc-contributor
```

The client retrieves its pending certificate, verifies its authority and key,
then proves possession over the node TLS listener. Activation makes that exact
certificate current. The client sends resource samples and renews a bounded
connection lease. Resource measurements are reported by the node; they are not
independent hardware attestation.

`--transport auto` is the default. It starts with a persistent WebSocket and
falls back to HTTPS polling after connection failures. It can retry the
persistent path later. Select `--transport persistent` or `--transport polling`
to require one method. Both use the same TLS identity and current authorization
checks. Environment proxies and redirects cannot replace the configured peer.

`--once` completes one heartbeat and exits, or reports that approval is still
pending. It is a connection check, not a background service. **Contributors**
shows current connection status, transport, resource sample, certificate expiry
and last observation. Its **Refresh contributors** control reloads that data.
`node-status` reports saved identity, enrollment stage, fingerprint and expiry;
the private `connection.json` records the running client's latest connection
status and lease. A saved `active` stage alone does not prove current reachability.

For unattended use, adapt the supplied
[contributor service](../packaging/remote/ficc-contributor.service). It expects
the `ficc-contributor` account, `/var/lib/ficc-contributor` state and an installed
FICC environment at `/opt/ficc-contributor/venv`. Enroll using that account and
state before starting the service. Keep one client process per node state;
the CLI refuses concurrent mutation of the same directory.

Every node request and stream message checks the exact current certificate,
enabled identity and project. A connection cannot obtain a lease longer than
the configured maximum or its certificate lifetime. The client anchors its
lease to request start, so network delay cannot extend authority. Loss of a
valid response expires connection authority within the configured lease.
The API explicitly reports `execution_available: false`.

## Rotate, revoke and remove

The running client rotates before its certificate expires. It creates a new
key, authenticates the rotation with its current certificate, and activates the
replacement only after proving possession over the new TLS connection. The old
certificate then loses access. The client deletes its old local key and
certificate after acknowledged activation. A lost activation response resumes
the saved pending identity instead of creating an unrelated node.

For explicit rotation, stop the connection service, then run as its account:

```sh
ficc node-rotate --state-dir /var/lib/ficc-contributor
```

Restart the connection afterwards. Rotation requires an unexpired current
certificate and an enabled node. An expired, disabled or lost identity must
use a new invitation and approval; it cannot silently renew itself.

Select **Revoke** on the contributor, or use its current node revision:

```sh
ficc contributor-disable --state-dir /var/lib/ficc-controller \
  --project PROJECT_ID NODE_ID --revision NODE_REVISION
```

The controller immediately marks the identity and its certificates revoked,
clears its session, refuses further operations and closes guarded streams.
It also requests CA revocation. An unavailable CA does not undo local denial;
the audit records pending or failed CA revocation separately. Disabling the
project also refuses node authority. Certificate expiry or a revoked identity
cannot be bypassed by an existing TLS connection.

Revoked records remain visible. To remove one, reload the list and use the
revoked node's new revision:

```sh
ficc contributor-list --state-dir /var/lib/ficc-controller --project PROJECT_ID
ficc contributor-remove --state-dir /var/lib/ficc-controller \
  --project PROJECT_ID NODE_ID --revision REVOKED_NODE_REVISION
```

Removal is refused for an enabled node or a stale revision. It removes the
node's enrollment and certificate records while retaining the audit history.
It grants no access and does not reactivate certificates. Rejoining requires
a new invitation, a fresh private node state directory and independent approval.

## Recover safely

| Condition | Action |
| --- | --- |
| `awaiting_approval` | Verify the key with the node owner, approve its current request, then run or retain `node-connect`. |
| `claiming` after a lost claim response | Do not replay the one-use secret. Inspect the controller, revoke any created record and replace the enrollment with a new invitation and private node state. |
| Issuance failed or its result is uncertain | Reload the request and certificate state. Retry approval explicitly with the current request revision while its window remains valid. An unregistered CA result grants no access. |
| Rotation or activation response lost | Preserve the node state and run `node-connect` again. It resumes the saved pending key while the current authority remains valid. |
| Certificate expired, node revoked or local key lost | Retire the old record and enroll a new identity. There is no re-enable command. |
| Controller restarted | Node certificates remain registered, but in-memory channel leases are gone. The running client establishes a fresh authorized session. |
| Controller backup restored | Contributor identities remain suspended. Invitation, request and certificate authority records are excluded from the backup. Verify installation trust, then use new invitations and approvals. |

Back up the CA database and encrypted intermediate separately, with the root
recovery material offline. Never restore an old CA database without reconciling
revocations and consumed issuance tokens. Controller backups do not preserve
node private keys or make restored machines trusted. Use the
[backup guide](backup.md) and the provider's recovery procedure.

## API contracts

Project administration uses the normal authenticated API. Browser mutations
require the current CSRF token and origin checks. Revision values are optimistic
concurrency checks, not authorization credentials.

| Method and path | Required authority and body |
| --- | --- |
| `GET /api/v1/contributors` | `contributors:read`; returns the selected project's records, issuer status and connection-only scope. |
| `POST /api/v1/contributor-invitations` | `contributors:manage`; `name` and `mode` (`managed` or `voluntary`). Returns the private invitation once. |
| `POST /api/v1/contributor-requests/{id}/approve` | `contributors:manage`; independently verified `public_key` and request `revision`. |
| `POST /api/v1/contributors/{id}/disable` | `contributors:manage`; current node `revision`. |
| `POST /api/v1/contributors/{id}/remove` | `contributors:manage`; revoked node's current `revision`. |
| `POST /api/v1/node-enrollment/claim` | HTTPS enrollment; single-use `secret`, assigned `node_id` and signed `csr_pem`. Returns a private receipt. |
| `POST /api/v1/node-enrollment/status` | HTTPS enrollment; `request_id` and private `receipt`. |
| `POST /api/v1/node-channel/activate` | Verified TLS client certificate; empty body. Only its registered pending or current certificate can activate. |
| `POST /api/v1/node-channel/rotate` | Current TLS client certificate; unique `request_id` and new-key `csr_pem`. |
| `POST /api/v1/node-channel/poll` | Current TLS client certificate; heartbeat fields below. |
| `WSS /api/v1/node-channel/stream` | Current TLS client certificate; the same heartbeat object and acknowledgement per message. |

A heartbeat contains `version: 1`, `session_id`, `sequence` and the supported
resource `sample`. A new session starts with `session_id: null` and sequence 1.
Use the returned session ID and increment the sequence for later samples.
Repeating the latest sequence does not extend its lease. Node-channel routes
reject browser cookies, bearer authorization, origin headers and URL queries.
The gateway, not a client-supplied header, establishes the certificate fingerprint.
Keep invitation secrets, receipts and private keys out of URLs and shared logs.

For managed machine certificates, use the separate
[OpenSSH trust workflow](ssh-trust.md). Contributor identities do not provide
SSH credentials or access to an existing managed account.
