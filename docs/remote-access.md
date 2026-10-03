# Remote access

Remote mode is an explicit installation configuration. Local mode continues to
bind to loopback. Do not publish a local-mode listener through a proxy or tunnel.
Use the supplied [gateway and service profiles](../packaging/remote/README.md)
with a separate controller account and a valid HTTPS certificate.

The gateway connects through a protected Unix socket and a separate random
credential. It replaces client-address headers. Arbitrary forwarded headers
cannot establish trusted ingress. The remote controller exposes no network HTTP
listener. Its private owner control socket remains available during identity
service failures.

## Configure external sign-in

Install a trusted identity provider into the controller's Python environment.
The supplied [OIDC package](../identity-providers/oidc/README.md) is separate
from the controller and workspace modules. It implements authorization code
flow with S256 PKCE, a nonce, verified HTTPS and signed identity tokens.
Use its dependency lock. Identity providers run with controller authority;
ordinary module grants cannot install them.

The [Keycloak profile](../packaging/remote/keycloak/README.md) requires a password
and authenticator code. It supports a public IP address. WebAuthn passkeys need
a domain-based identity provider, which can serve an IP-addressed FICC controller.

Prepare a private configuration owned by the controller account:

```json
{
  "provider": "oidc",
  "configuration": {
    "issuer": "https://identity.example.com/auth/realms/ficc",
    "client_id": "ficc",
    "client_secret_file": "/var/lib/ficc-controller/identity-client-secret",
    "allowed_origins": ["https://identity.example.com"],
    "algorithms": ["RS256"],
    "required_acr": ["2"],
    "max_auth_age": 28800,
    "session_seconds": 28800
  }
}
```

Use mode `0600` for this file and the client secret. The issuer must exactly
match discovery. Configure the confidential client's exact redirect as
`https://CONTROLLER_ADDRESS/auth/callback`, without wildcards. An optional
`ca_file` adds private issuer trust without disabling certificate verification.

With the controller stopped, run as its installation account:

```sh
ficc remote-configure --state-dir /var/lib/ficc-controller \
  --origin https://CONTROLLER_ADDRESS \
  --socket /run/ficc-controller/gateway.sock \
  --gateway-secret-file /var/lib/ficc-controller/gateway-secret
ficc identity-provider-configure --state-dir /var/lib/ficc-controller \
  --input /path/to/private-identity-provider.json
```

Generate the gateway credential from at least 32 random bytes. Keep it separate
from the OIDC client secret. The socket directory belongs to the controller
account and permits no group writes or other-account access. The supplied
service uses mode `0750` with the gateway group and socket mode `0660`.
State remains mode `0700`; the owner control socket remains mode `0600`.

The controller profile permits `openat2`, which the registered-file adapter uses
to refuse links and mount crossings. `RestrictSUIDSGID=true` blocks this syscall
in systemd, so the supplied controller profile sets it to `false`. The dedicated
account still has no capabilities, uses `NoNewPrivileges=true`, and cannot write
outside its approved filesystem locations. FICC file-mode changes accept only
ordinary permission bits. Do not run this profile as root.

## Approve identities

An identity-service account does not grant FICC access. Create a local identity,
assign project capabilities and resources, then approve its exact issuer and
immutable external subject. Obtain that subject from trusted identity-service
administration. Email, display name and group claims never substitute for this
mapping. External identities cannot map to the local recovery owner.

Use **Access / External identity approvals** in an owner session, or the private CLI:

```sh
ficc identity-external-list --state-dir /var/lib/ficc-controller
ficc identity-external-set --state-dir /var/lib/ficc-controller \
  --issuer https://identity.example.com/auth/realms/ficc \
  --external-subject IMMUTABLE_SUBJECT --subject FICC_IDENTITY_ID --revision 0
```

New mappings use revision zero. Later changes require the returned revision.
Add `--disabled` to suspend a mapping. Re-enabling it does not revive old sessions.
Sign-in also requires an enabled local identity and current project membership.
Unknown identities see an approval-required message.

## Sessions and revocation

Login uses one-use state bound to the initiating browser. Session cookies are
Secure, HttpOnly, host-only and SameSite=Strict. The short callback-binding cookie
uses SameSite=Lax. The exact GET callback admits the external login return.
The public root document also permits its final top-level GET navigation.
Cross-site API requests remain blocked. Mutations need the exact origin and CSRF token. Stream tickets and current
project checks remain required.

**Access** shows session expiry. The supplied profile allows at most eight hours
from authentication. External authority is verified within 30 seconds; expired
verification denies further access without an offline grace period. Streams
apply their next authority check. Local approval and membership changes apply
without waiting for external verification. Dispatched commands can continue;
revocation is not process cancellation.

Project selection rotates the session and CSRF token without extending expiry.
External sessions use the selected project's current approved capabilities.
Locally delegated sessions retain their original scope ceiling. Machine, folder
and policy restrictions continue to apply. Use separate browser profiles for
independent concurrent identities or projects.

Signing out ends the FICC session and discards its external tokens. The provider
also attempts refresh-token revocation. Organisation SSO can remain active;
the supplied MFA flow requires its factor for a new sign-in. Controller restart
requires fresh remote login because external tokens remain in memory. Backups
exclude these tokens. Restore disables external mappings as well as its other
identity and grant suspension rules.

## Recovery and bounds

Owner CLI commands use private Unix sockets even during identity-service failure.
API-backed commands such as `ficc nodes` do not send their owner credentials
through the public network. Preserve administrator SSH access and backups.

The controller admits eight simultaneous login operations, 128 pending logins,
512 active credentials and 1,024 external approvals. Gateway and controller
settings bound headers, sign-in bodies, connections and ingress rate. These
protect the control interface; they are not dataset limits or a concurrent-user
capacity claim. Measure the complete installation under its intended workload.

Node enrollment, contributor isolation and data pipelines have separate
requirements. Browser login does not turn a managed SSH account into a sandbox.
See [managed jobs](jobs.md), [identities](identities.md) and the
[identity provider SDK](../sdk/identities.md).

For private SSH or database routes, use the optional
[WireGuard network profile](../packaging/remote/wireguard/README.md).
Its peer keys do not replace FICC identities, TLS or project permissions.
