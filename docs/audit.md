# Durable audit delivery

FICC can automatically deliver redacted audit metadata to a separately administered
append-only destination. Install the host first, then the `ficc-audit-https` runtime
wheel in the same environment. The provider uses the reusable `ficc.audit` API1
contract. No host rebuild is needed to install a compatible provider.

The HTTPS package also supplies `ficc-audit-collector`, a small TLS receiver. Run
it under another account or host whose storage, administration and backup are not
controlled by the FICC service account. The controller credential permits appends
only. There is no HTTP read, replacement, deletion or configuration operation.
The destination administrator can still change its database or software. Neither
local files nor remote acknowledgements prove resistance to a compromised
administrator. A receiver on the controller under the same account is useful for
testing but does not provide separate custody.

## Provision the destination

Install FICC and the HTTPS runtime package in the destination environment. Prepare
a server certificate and private key for its actual TLS hostname. Keep the key,
append token and destination state in private directories. Generate the token
without putting it in arguments, shell history or output:

```sh
umask 077
python -c 'import pathlib,secrets; pathlib.Path("append-token").write_text(secrets.token_urlsafe(32))'
ficc-audit-collector --listen 127.0.0.1 --port 8443 \
  --state-dir /private/audit-records \
  --cert-file /private/tls/server.pem --key-file /private/tls/server.key \
  --token-file /private/append-token
```

Select the intended listen address and restrict network access to the controller.
Use durable storage and arrange process supervision, disk monitoring and separate
backups. The shipped collector serializes requests, caps each request at 64 KiB,
uses a five-second socket timeout and acknowledges only after a SQLite FULL/WAL
transaction commits. Storage exhaustion returns failure. It performs no automatic
retention or rotation; the destination administrator owns capacity and archival.
Temporary memory filesystems do not provide crash durability.

Copy the append token through a private administrative channel to a temporary
private controller input file. Provision it through the [secret store](secrets.md):

```sh
ficc secret-put --state-dir /private/ficc --reference audit-append \
  --input /private/input/append-token
```

The secret value is the ASCII token alone, with no newline or JSON wrapper. The
token grants only the collector append operation. Manage the input file's removal
and independent recovery explicitly. Restart the collector with its new private
token file and update the secret revision when rotating this credential.

## Configure the controller

Stop the controller. Create a private JSON configuration file with these fields:

```json
{
  "provider": "https",
  "configuration": {
    "url": "https://audit.example.org:8443/v1/audit/append",
    "ca_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
  },
  "secret_reference": "audit-append",
  "required": true,
  "max_lag_events": 1000
}
```

Use the actual trusted CA PEM. TLS hostname verification is mandatory. Environment
proxies, redirects and credential-bearing URLs are disabled. The administrator
selects the destination; this is not a user-supplied network fetch capability.

```sh
ficc audit-configure --state-dir /private/ficc --input /private/input/audit.json
ficc audit-flush --state-dir /private/ficc
ficc audit-status --state-dir /private/ficc
```

Configuration creates a new stream and refuses to overwrite an existing one.
`audit-flush` attempts delivery for at most 30 seconds and retains pending work if
it cannot finish. These local commands require exclusive state access. Start the
controller for automatic delivery. Operations shows delivery status, the backlog,
acknowledged sequence, last acknowledgement time and known retention gaps through
its API; the health table highlights pending and missing events. Status and
diagnostics omit destination addresses, secret references and event contents.

Delivery reads up to 64 retained events per batch. Events carry numeric local
identities, timestamps, host action/outcome categories and hashed actor/resource
identities. Parameters, query text, names, paths, credentials and workload payloads
are omitted. The existing owner-only audit download remains available when full
retained actor/resource identities are needed. Review that download before sharing.

## Required admission and backpressure

Required mode protects new contributor workload submission and explicit retry,
external registered SQL writes, and object-upload begin, part and complete.
Each waits for a durable destination acknowledgement of its redacted intent before
the selected mutation is admitted or dispatched. Workload submission/retry also
rechecks current authority after the wait. Source writes recheck their current
connection approval. A pending intent alone is not proof that the mutation ran.

Read/export operations and already admitted workloads are outside this gate.
Cancellation, stop, lease renewal, output release, upload abort and reconciliation
remain available during destination failure. This is an explicit selection of
protected mutations, not a claim that every controller action is gated.

A missing provider or secret, failed TLS, invalid acknowledgement, backlog above
the configured threshold, or full admission queue refuses protected work. There
are at most 16 admission waiters and one delivery in flight. Requests wait at most
12 seconds; delivery attempts have a five-second overall network deadline. File
synchronization and secret resolution run in owned background work, outside the
controller database lock. Shutdown waits for owned disk operations; a stalled
filesystem can consequently delay shutdown but does not hold the node poll loop.

The local audit table retains 10000 events. If delivery falls behind retention,
FICC appends explicit gap ranges before continuing. Acknowledged gaps remain
visible as missing-event counts; they are not reconstructed records. Required
admission can resume after the gap report and retained backlog are acknowledged.
If history moves behind an existing checkpoint, delivery fails closed instead of
silently resetting its cursor.

To change enforcement while stopped:

```sh
ficc audit-mode --state-dir /private/ficc --best-effort
ficc audit-mode --state-dir /private/ficc --required
```

Best-effort mode continues automatic delivery and visible error reporting without
blocking selected mutations. Only local administrators can change this policy.

## Recovery and limits

Before sending, FICC atomically writes the exact pending batch into
`STATE/audit-private/`. After an exact durable acknowledgement, it atomically
advances its checkpoint. Lost acknowledgements and controller restarts resend the
same stream, sequence and canonical bytes. The collector accepts an exact repeat
and refuses a different batch at an existing sequence. This supports reconciliation
without an exactly-once claim for application mutations or all audit events.

Metadata backups exclude destination configuration/checkpoints and secret-store
custody. They preserve the required-policy marker: an isolated restore with
required auditing cannot silently resume protected mutations without destination
configuration. Preserve `audit-private/`, the encrypted secret records and key
custody separately if resuming the original controller after an ordinary restart
or loss of its disk. Do not run two controllers using the same stream/checkpoint.

For a restored or replaced controller, keep the original stream available for
investigation. Provision the destination secret and explicitly configure a new
stream under the destination administrator's authority. The new stream exports
retained history and reports any missing prefix. It does not establish continuity
with events omitted from the backup. Required enforcement stays enabled unless an
administrator explicitly changes it. Never delete a live pending checkpoint to
force an uncertain batch past a collector conflict.

The controller trusts the authenticated receiver's durability acknowledgement.
Qualify external receiver implementations against the [SDK](../sdk/audit.md),
including durable duplicate handling, partial writes and unavailable storage.
The shipped collector's local TLS checks exercise commit/replay behavior, not
power-loss behavior of a particular filesystem or storage controller.
