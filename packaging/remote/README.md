# Remote gateway and controller

The base profile prepares HTTPS on a dedicated Linux server. Without optional
route files, application requests return HTTP 503. Unknown hosts receive HTTP 421.
FICC v0.2.5 provides an explicit remote mode and a private gateway socket.
Configure that mode and approved identity mappings before adding the application
route. The ordinary local listener remains for local access; do not expose it
through a public proxy.

The profile uses Caddy 2.11.4 or a later compatible security release and systemd.
Obtain Caddy from its signed package repository or verify an official release before installation.
Keep the gateway binary at `/usr/bin/caddy` and record its version.

## Address and certificates

Use one public IP address or DNS name. An IP address does not need a DNS record.
IP certificates require the Let's Encrypt `shortlived` profile and automated renewal.
Caddy stores its account and certificates under `/var/lib/ficc-gateway` and renews them automatically.
Keep that directory private and persistent. Monitor issuance failures and certificate expiry.
Allow inbound TCP 80 and 443 for certificate validation and HTTPS.

Review the [certificate service terms](https://letsencrypt.org/repository/) before enabling issuance.
Use the staging directory in `gateway.env.example` for the first issuance check.
Then select the production directory and reload the service.
Verify the production certificate with normal browser or operating-system trust.
Do not install the staging issuer in a client trust store or disable verification for application use.

References: [IP certificates](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability),
[Caddy TLS configuration](https://caddyserver.com/docs/caddyfile/directives/tls).

## Service installation

Inspect existing listeners, accounts, firewall rules and files first. Use a dedicated server for this profile.
Preserve SSH access and verify its host key through a trusted channel.
Do not replace an existing Caddy service, account or firewall configuration without reviewing its purpose.
On a fresh dedicated server, mask the packaged `caddy.service` and `caddy-api.service` before installing Caddy.
The supplied `ficc-gateway.service` owns ports 80 and 443. Keep the other units masked during package upgrades.

Create a system account named `ficc-gateway` with no login shell or password.
Create `/etc/ficc-gateway` with owner `root:ficc-gateway` and mode 0750.
Copy `Caddyfile` and a completed `gateway.env` into that directory with mode 0640 and the same owner.
The environment file contains the public address and ACME directory only. Do not put secrets there.
The administrator controls these files; the service account cannot change them.

Copy `ficc-gateway.service` to `/etc/systemd/system/` with owner `root:root` and mode 0644.
Systemd creates the private state and runtime directories.
The service uses a private Unix control socket. It does not expose the Caddy API over TCP.
The supplied memory and task limits are deployment settings and can be changed through a systemd override.

The dedicated contributor port has a separate `servers :8443` block.
Its SNI-to-Host comparison is disabled because IP clients omit SNI.
The named and fallback TLS policies both require verified client certificates.
Keep the supplied fallback policy and refuse unknown HTTP hosts.
Never share this port with a site that uses a different client trust policy.
The browser listener retains its own TLS and routing rules.

Validate the Caddyfile with the two environment values set, then verify the unit and start it:

```sh
caddy validate --config /etc/ficc-gateway/Caddyfile --adapter caddyfile
systemd-analyze verify /etc/systemd/system/ficc-gateway.service
systemctl daemon-reload
systemctl enable --now ficc-gateway.service
systemctl status ficc-gateway.service
```

The validation command must receive `FICC_PUBLIC_ADDRESS` and `FICC_ACME_DIRECTORY` from the reviewed environment file.
After a configuration change, validate it and use `systemctl reload ficc-gateway.service`.
Check an external HTTPS request, its certificate identity and expiry, the HTTP redirect and rejection of unknown hosts.
Check that controller, database and control sockets are unavailable from the network.
Enabling the gateway alone must not make any FICC action accessible.
Restart the gateway and check HTTPS again to verify that certificate state persists.

The global log filter removes request headers, request URLs and response headers.
This also protects error logs from CSRF tokens and identity callback query values.
Keep this filter when adding routes or access logging. Use status, method and error IDs for gateway diagnostics.
The controller routes retain idle upstream connections for one second, below the controller's five-second timeout.
Keep the proxy timeout shorter if either setting changes. Do not add retries for write requests.

Keep Caddy current through a trusted package source. Distribution repositories can contain older versions without public IP certificate support.
An individually installed release package needs an explicit update procedure; it does not add an update repository.

## Recovery

Retain the previous configuration before each change. Validate a restored configuration before reloading it.
Use `systemctl disable --now ficc-gateway.service` to close the gateway.
This retains certificates and account state for recovery. Remove firewall permissions separately if no longer required.
Do not delete private state as part of a routine stop, upgrade or rollback.

## Identity and controller services

Install the [Keycloak profile](keycloak/README.md) or configure another trusted
OIDC service. Only the supplied realm's login, protocol and resource routes are
public. Identity administration, master realm, health and metrics remain private.
The `Caddyfile` imports optional `/etc/ficc-gateway/routes/*.caddy` files. Keep
that directory root-owned, group `ficc-gateway`, mode `0750`; route files use
owner `root:ficc-gateway` and mode `0640`. An absent route leaves the service closed.

Prepare a root-owned Python environment at `/opt/ficc-controller/current`.
The v0.2.5 source installer and binary payload supply the controller and 17
separately built provider wheels with their locked dependencies. This includes
OIDC, policy, certificate, state, workload, data, secret, audit and inspection
providers. A host-only wheel installation must add the selected trusted provider
wheels separately; see the [package catalogue](../providers.json) and
[dependency guide](../../docs/dependencies.md#supplied-runtime-providers).
Installing those wheels does not provision the gateway, identity service, CA,
database, executors or their authority. Runtime code must be readable and
executable by the controller account. Keep credentials outside the installed
runtime and use the [encrypted secret store](../../docs/secrets.md) for source
and audit references, with its key under separate custody.
Create the system account `ficc-controller` without a login shell and the shared
group `ficc-ingress`. Install `ficc-controller.service` as root-owned mode `0644`.
Systemd creates `/var/lib/ficc-controller` as private state and
`/run/ficc-controller` for the gateway socket.

Configure [remote access](../../docs/remote-access.md) while the controller is
stopped. Run configuration commands as `ficc-controller`, using its private state
directory. Generate separate random gateway and OIDC client secrets. All private
controller files must belong to that account with mode `0600`.

Create a root-owned mode `0600` `/etc/ficc-gateway/controller.env` containing
`FICC_GATEWAY_SECRET`, equal to the private gateway credential. Load it and add
the socket group through `/etc/systemd/system/ficc-gateway.service.d/controller.conf`:

```ini
[Service]
EnvironmentFile=/etc/ficc-gateway/controller.env
SupplementaryGroups=ficc-ingress
```

Restart the gateway after changing its environment or supplementary groups;
an ordinary reload does not update the running process's environment. The gateway
account must not be able to change the service override or environment file.
The private Caddy configuration state can contain the gateway credential and
must receive the same protection as other credentials.

Start the controller and verify its private owner socket, configured remote
origin, identity-provider status and identity approvals. Keep `controller.caddy`
outside the imported route directory until these settings are correct. Copy it
into that directory to enable the reviewed application route, then validate and
reload Caddy with both environment files available. Test a real browser sign-in,
MFA, project permissions, logout and revocation. Do not bypass TLS verification
or use wildcard redirects to resolve configuration errors.

The service limits are deployment settings, not a concurrent-user capacity
claim. Default profiles provide one controller and one identity backend, without
automatic failover. Application data remains in the configured SQLite or
PostgreSQL store. Identity-service state has a separate backup procedure.

To close application access while retaining HTTPS and identity-service recovery,
move `controller.caddy` outside the imported directory and reload Caddy. Stop the
controller for maintenance without removing its private state. Retain the
previous runtime and the pre-upgrade backup for rollback; older controllers
cannot open a newer state schema.

## Optional policy evaluator

The [OPA provider](../../policy-providers/opa/README.md) uses the controller account's
systemd user manager. The base service hides `/run/user` through `ProtectHome=true`.
The evaluator needs that account's session bus and private systemd manager sockets.
`systemd-run --wait --pipe` uses the session bus; `systemctl` uses the manager socket.

Install Bubblewrap and the distribution's systemd user-session support. Keep the
distribution's restricted user-namespace policy enabled. Enable lingering for
`ficc-controller` and start its user manager. Confirm CPU, memory and process
controllers are available. Do not disable host security controls to pass this check.

Copy `ficc-controller-policy.conf.example` into the controller's service override
directory. Replace each `CONTROLLER_UID` with the numeric result of
`id -u ficc-controller`. Keep the file root-owned with mode `0644`. The override
hides home directories and all other user-runtime files. It exposes only the
controller account's two sockets through read-only bind mounts.

Create `/var/lib/ficc-controller/tmp` as `ficc-controller:ficc-ingress`, mode `0700`.
The controller and its separate user-manager services must see the same policy
temporary files. The private temporary directory in the base service stays enabled.
Reload systemd and restart the controller after installing the override.

Verify policy preview and activation through the running controller. A successful
standalone provider check does not verify the hardened service environment.
Check the actual evaluator's resource limits and cleanup. Restart the controller
if its user manager or either socket is replaced.

See [systemd filesystem isolation](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#ProtectHome=)
for the combined temporary-filesystem and bind-mount settings.

## Contributor connections

Install the separate [Smallstep certificate provider](../../certificate-providers/smallstep/README.md)
and its dedicated loopback CA before enabling contributor access. Its offline root,
encrypted intermediate, provisioning key and database have separate recovery duties.
Do not reuse the identity backend's certificate authority.

Complete `contributors.json.example` with the deployment ID and explicit issuer
configuration. Keep its root and a fresh node gateway credential in controller-owned
private files. Run `ficc contributors-configure --state-dir STATE --input FILE`
while the controller is stopped. Its HTTPS node origin must differ from the browser
origin, and its gateway credential must differ from `FICC_GATEWAY_SECRET`.

Copy the public node root to `/etc/ficc-gateway/node-ca.pem`, owned by
`root:ficc-gateway`, mode `0640`. Create a root-owned mode `0600`
`/etc/ficc-gateway/contributors.env` with `FICC_NODE_GATEWAY_SECRET`, matching
the controller's private node gateway file. Add that file to the gateway service's
`EnvironmentFile` settings. Restart the gateway when changing environment files.

Create `/etc/ficc-gateway/listeners` as `root:ficc-gateway`, mode `0750`.
Place `contributors.caddy` there as root-owned mode `0640`. This is a top-level
listener file; it must not go in the browser's `routes` directory. Validate the
complete Caddy configuration with all environment files available. Then allow
TCP 8443 and restart the gateway. TLS 1.3 and a verified client certificate are
required on that listener. The host separately checks exact registered authority
on every node request and message.

The node gateway removes incoming identity headers before it adds verified proof.
Keep that request-header operation before the reverse proxy. Caddy applies proxy
header deletions after proxy header assignments; combining a wildcard deletion
with those assignments would remove the verified proof.

Use the [contributor guide](../../docs/contributors.md) for invitation, independent
key approval, connection, rotation, revocation and removal. The service file
`ficc-contributor.service` runs an enrolled Linux node under a dedicated account.
Install its runtime first, create the account, and enroll into its private state
directory as that account before enabling the unit. A managed deployment controls
its service and state through the system administrator. Voluntary deployments
must give the machine owner a local stop control. Workload offers and execution
require the contributor executor in addition to this connection service.

Check an actual node through both persistent and polling modes. Verify certificate
rotation, live revocation, expiry, gateway loss and controller restart. A restored
controller suspends retained node identities and discards their certificates and
pending invitations. Re-enroll them explicitly after recovery.

## Optional private routes

The [WireGuard profile](wireguard/README.md) supplies an external management network
for approved SSH and data connections. Its individual peer routes preserve the
existing default route and DNS. Network enrollment does not grant FICC authority.
