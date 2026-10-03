# Private identity backend

This optional profile runs Keycloak for the separately installed FICC OIDC provider.
It supplies one private identity server and database, with selected login endpoints
behind the [remote gateway](../README.md). It is a single-host installation, without
high availability. The identity service authenticates people; FICC controls their
access grants. Identity accounts, system credential profiles and module capability
grants are separate records. An identity account alone grants no FICC access.

`ADDRESS` means the exact public IP address or DNS name, without a scheme or path.
Replace it in all examples. The public origin is `https://ADDRESS`; the issuer is
`https://ADDRESS/auth/realms/ficc`. DNS is optional. Use a normally trusted public
certificate, including automated short-lived certificate renewal for an IP address.
These instructions assume an administrator's root terminal on a dedicated Linux
server. Inspect existing accounts, files and database use before making changes.

## Prerequisites and verified packages

Use Keycloak **26.8.0**, OpenJDK **25**, PostgreSQL **18**, Python **3.12 or later**,
OpenSSL **3**, systemd and the gateway's compatible Caddy version. The supplied
paths and PostgreSQL unit name follow Debian or Ubuntu packaging. Adapt them
together on other distributions. Reserve memory for PostgreSQL and the gateway
in addition to the identity service's 2 GiB memory limit and 1 GiB Java heap.
Synchronize the server clock; OTP and token expiry depend on it.

Obtain Keycloak from its [official download page](https://www.keycloak.org/downloads.html).
Verify the release archive against the publisher's release metadata and signature
where supplied, with the signing key checked through a trusted channel. Record its
SHA-256 digest and version before extraction. A locally calculated hash alone does
not authenticate an archive. Install Java, PostgreSQL, Python and OpenSSL from
signed distribution repositories or their verified upstream package repositories.
Keep security updates current and check compatibility before changing versions.
The [supported configurations](https://www.keycloak.org/server/supported-configurations)
include Java 25 and PostgreSQL 18.

Keep TCP 5432, 8543, 9001 and cache listeners inaccessible from the network.
Only the reviewed SSH and public gateway ports need inbound access. Install the
gateway first, with its application route still closed. No instruction here
publishes the controller or the identity administration API.

## Account and filesystem

Create a system account without a password or login shell:

```sh
umask 077
useradd --system --user-group --home-dir /var/lib/ficc-identity \
  --shell /usr/sbin/nologin ficc-identity
install -d -o root -g root -m 0755 /opt/ficc-identity
install -d -o root -g ficc-identity -m 0750 /etc/ficc-identity /etc/ficc-identity/tls
install -d -o ficc-identity -g ficc-identity -m 0700 \
  /var/lib/ficc-identity /var/lib/ficc-identity/data /var/lib/ficc-identity/data/import
install -d -o root -g postgres -m 0750 /etc/postgresql/18/main/ficc-tls
chmod 0750 /etc/ficc-identity /etc/ficc-identity/tls /etc/postgresql/18/main/ficc-tls
chmod 0700 /var/lib/ficc-identity /var/lib/ficc-identity/data /var/lib/ficc-identity/data/import
```

Set directory modes explicitly after creation. A `mkdir` mode argument can be
reduced by `umask 077`, preventing service accounts from reading their TLS files.
Do not fix that problem by making a private key readable by another account.

Extract the verified archive into `/opt/ficc-identity/keycloak-26.8.0`, owned by
root. Keep distribution files readable and directories traversable by the service
account, but not writable by it. Preserve executable modes on `bin/*.sh`.
For a new installation, create these links only after confirming neither replaces
existing data:

```sh
ln -s /var/lib/ficc-identity/data /opt/ficc-identity/keycloak-26.8.0/data
ln -s /opt/ficc-identity/keycloak-26.8.0 /opt/ficc-identity/current
```

Only `/var/lib/ficc-identity` is writable by the server. Do not make the installation,
configuration, CA key or systemd units writable by `ficc-identity`.

## Private CA and backend certificates

Use a dedicated private root CA for this profile, independent of the public
gateway certificate. The supplied renewal helper requires this layout:

| File or directory | Owner | Mode |
| --- | --- | --- |
| `/etc/ficc-identity/tls` | `root:ficc-identity` | `0750` |
| `tls/ca.pem` | `root:root` | `0644` |
| `tls/ca.key` | `root:root` | `0600` |
| `tls/server.pem` | `root:ficc-identity` | `0644` |
| `tls/server.key` | `ficc-identity:ficc-identity` | `0600` |
| `/etc/postgresql/18/main/ficc-tls` | `root:postgres` | `0750` |
| Database `server.pem` | `root:postgres` | `0644` |
| Database `server.key` | `postgres:postgres` | `0600` |

Generate a self-signed root with critical `CA:TRUE` basic constraints and
`keyCertSign,cRLSign` key usage. Keep its unencrypted private key root-only for
unattended renewal. Use distinct **RSA3072** keys for the two backends. Sign
**90-day**, SHA-256 leaf certificates with these exact extensions:

```ini
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
```

With OpenSSL, create each private key with `genpkey`, create its CSR with `req`,
and sign it with `x509 -req -CA ... -CAkey ... -days 90 -sha256 -extfile ...`.
Assign a fresh random positive serial number to each certificate. Work in a
root-owned `0700` temporary directory with `umask 077`; install the resulting
files with the owners and modes above. Do not overwrite existing keys or reuse
one backend's key for the other. The CA must outlive each new leaf by at least
one day. Plan CA replacement before its remaining lifetime reaches 91 days.

Verify both leaf/key public keys match, both SANs match, and
`openssl verify -CAfile /etc/ficc-identity/tls/ca.pem -purpose sslserver ...`
succeeds. Copy **only the CA certificate** to
`/etc/ficc-gateway/identity-ca.pem`, with owner `root:ficc-gateway`, mode `0640`.
Neither the gateway nor the identity account may read the CA private key.
See [OpenSSL certificate commands](https://docs.openssl.org/3.0/man1/openssl-x509/).

## Database and secrets

Create database `ficc_identity` with owner `ficc_identity`. Give that login role
no superuser, database creation, role creation, replication or row-security bypass
rights. Limit it to eight connections, matching the application pool. Revoke
public connection rights to this database. The role needs schema ownership for
Keycloak's database migrations, but no access to FICC's controller database.

Generate independent random database and confidential-client secrets with at
least 256 bits of entropy. URL-safe base64 without padding fits the realm tool's
43-to-128-character client-secret format. Store them as regular, single-link,
root-owned files `/etc/ficc-identity/db-password` and
`/etc/ficc-identity/client-secret`, both mode `0600`. Use exclusive file creation;
never silently replace existing secrets. Set the role password through a private
administration tool, such as the `psql` `\password` prompt with
`password_encryption = 'scram-sha-256'`. Do not put passwords in SQL history,
command arguments, repository files or logs.

Configure PostgreSQL to listen on `127.0.0.1` and use its private leaf pair:

```ini
ssl = on
ssl_cert_file = '/etc/postgresql/18/main/ficc-tls/server.pem'
ssl_key_file = '/etc/postgresql/18/main/ficc-tls/server.key'
ssl_min_protocol_version = 'TLSv1.3'
password_encryption = 'scram-sha-256'
```

Put the specific TLS rule before broader rules in `pg_hba.conf`, then reject other
TCP connections for this role. Preserve unrelated local administration rules:

```text
hostssl ficc_identity ficc_identity 127.0.0.1/32 scram-sha-256
host all ficc_identity 0.0.0.0/0 reject
host all ficc_identity ::/0 reject
```

Reload after supported configuration changes; a changed listener requires a
restart. Verify a fresh connection with `sslmode=verify-full` and the private CA,
and verify plaintext access is rejected. If PostgreSQL already serves other
applications, coordinate its certificate and listener changes with their owners.
References: [PostgreSQL TLS](https://www.postgresql.org/docs/18/ssl-tcp.html),
[client verification](https://www.postgresql.org/docs/18/libpq-ssl.html) and
[authentication rules](https://www.postgresql.org/docs/18/auth-pg-hba-conf.html).

Create `/etc/ficc-identity/identity.env`, owned by `root:root`, mode `0600`.
It contains `KC_DB_PASSWORD=` followed by the database secret on the same line,
without a literal example value. Construct it from the private source file using
a tool that does not print the value. Systemd reads this file and supplies the
variable to the service. It is not a shell script; do not source it or enable shell
tracing. Keep bootstrap credentials out of this persistent environment file.

## Configuration, realm and service

Copy [keycloak.conf.example](keycloak.conf.example) to
`/opt/ficc-identity/current/conf/keycloak.conf`, owned by root, mode `0644`.
Replace `ADDRESS`. The JDBC URL uses `sslmode=verify-full` and the private CA.
The private HTTPS listener is `127.0.0.1:8543`, with prefix `/auth`;
management HTTPS is `127.0.0.1:9001/auth`. Cache traffic also binds to loopback.
Only the loopback proxy is trusted to supply forwarded headers. The fixed public
hostname does not expose administration: the proxy route restrictions do that.
Option names are in [Keycloak configuration](https://www.keycloak.org/server/all-config).

Generate the initial realm import as root, from this directory:

```sh
python3 realm.py --origin 'https://ADDRESS' \
  --client-secret-file /etc/ficc-identity/client-secret \
  --output /var/lib/ficc-identity/data/import/ficc-realm.json
chown ficc-identity:ficc-identity /var/lib/ficc-identity/data/import/ficc-realm.json
chmod 0600 /var/lib/ficc-identity/data/import/ficc-realm.json
/opt/ficc-identity/current/bin/kc.sh build \
  --db=postgres --health-enabled=true --metrics-enabled=true
install -o root -g root -m 0644 ficc-identity.service /etc/systemd/system/
systemd-analyze verify /etc/systemd/system/ficc-identity.service
systemctl daemon-reload
```

The generator refuses an existing output file. Its `ficc` realm disables public
registration and password reset, requires password plus OTP at ACR `2`, and sets
the brute-force reset interval through `maxDeltaTimeSeconds`. The confidential
client uses code flow, PKCE S256, exact redirect `https://ADDRESS/auth/callback`,
and refresh-token rotation with zero reuse. No users are bundled.

An explicit audience mapper includes `ficc` in access tokens, lightweight access
tokens and introspection responses. Keycloak requires the introspecting client
to be in the token's audience. Keep that check enabled; `fullScopeAllowed` remains
false. ID tokens keep their normal client audience. See the
[introspection audience requirement](https://www.keycloak.org/docs/26.8.0/upgrading/#token-introspection-now-validates-audience-claim).

The service starts with `--optimized --import-realm`. Existing realms are skipped;
editing the import file does not update an installed realm. Apply later changes
through authenticated private administration, with a database backup. After the
first successful import, move its secret-bearing JSON into protected backup storage
and remove it from the live import directory. See
[realm import behavior](https://www.keycloak.org/server/importExport).

The unit has a private state directory, a read-only installation, no capabilities,
restricted address families and explicit CPU, memory, task and file limits. Use
systemd overrides for deployment-specific resource changes. Keep the database pool
within its role limit. An optimized build contains build-time options; never pass
credentials as build options. See [server configuration](https://www.keycloak.org/server/configuration).

## Root-controlled administration and approved users

Before first start, or for recovery, stop every Keycloak instance that uses this
database. From the root terminal, run the bootstrap command with the same private
database environment. This transient unit runs the command as the service account
and prompts for temporary administrator credentials:

```sh
systemctl stop ficc-identity.service
systemd-run --unit=ficc-identity-bootstrap --pty --wait --collect \
  --property=User=ficc-identity --property=Group=ficc-identity --property=UMask=0077 \
  --property=WorkingDirectory=/opt/ficc-identity/current \
  --property=EnvironmentFile=/etc/ficc-identity/identity.env \
  /opt/ficc-identity/current/bin/kc.sh bootstrap-admin user --optimized
systemctl enable --now ficc-identity.service
```

Use the Admin CLI or Admin REST API from a root-controlled session against
`https://127.0.0.1:8543/auth`. Configure its trust store with the private public CA
certificate; keep TLS verification enabled. Use password prompts or private
environment inputs supported by the installed command's `--help`, never a literal
password argument. Store temporary token caches in a root-owned `0700` directory
under `/run`, with files `0600`. Do not run administration under the FICC controller
account or expose the master realm through the public proxy.

Create only approved realm users. Supply a temporary password privately and require
password change and OTP registration before FICC access. Bind each approved issuer
and immutable subject to a local FICC principal, then grant only the required FICC
permissions. Removing a user requires both identity disablement/session revocation
and removal of the relevant FICC access. Email addresses and group names are not
automatic grants. Reset a lost OTP only after the administrator verifies the owner.

Delete the temporary bootstrap administrator and its sessions after provisioning
or recovery. Remove temporary password files, token caches and exports. Keep a
protected recovery procedure and verify it before removing the last usable
administration path. If MFA prevents administrator recovery, Keycloak also supports
an offline temporary bootstrap service account; delete it after recovery. Do not
weaken the normal login flow. References:
[bootstrap recovery](https://www.keycloak.org/server/bootstrap-admin-recovery) and
[administration](https://www.keycloak.org/docs/26.8.0/server_admin/).

For a numeric public IP, use the supplied password-and-TOTP flow. Native WebAuthn
does not support an IP address as its relying-party identifier. A DNS-based,
separately configured and tested WebAuthn deployment is needed for passkeys; TOTP
does not provide phishing resistance. See [WebAuthn requirements](https://www.w3.org/TR/webauthn-3/).

## Restricted public route and FICC connection

Install `identity.caddy` as `/etc/ficc-gateway/routes/identity.caddy`, owned by
`root:ficc-gateway`, mode `0640`. Set `FICC_PUBLIC_ADDRESS` in the gateway's reviewed
environment. Validate the whole gateway configuration with that environment before
reloading `ficc-gateway.service`.

This route permits the `ficc` discovery document, OIDC protocol endpoints, login
actions and static resources. It verifies backend TLS with `identity-ca.pem`, sets
the expected forwarded headers and limits request bodies to 64 KiB. It does not
publish `/auth/admin`, `/auth/realms/master`, account administration, health or
metrics. Do not replace the allowlist with an unrestricted `/auth/*` proxy. Setting
`hostname-admin` alone does not protect the administration API; see
[hostname configuration](https://www.keycloak.org/server/hostname) and
[reverse proxy guidance](https://www.keycloak.org/server/reverseproxy).

Install the [OIDC provider](../../../identity-providers/oidc/README.md) in the
controller environment. Configure exact issuer `https://ADDRESS/auth/realms/ficc`,
client ID `ficc`, allowed origin `https://ADDRESS`, algorithm `RS256`, required ACR
`2`, and authentication/session age limits of `28800` seconds. Give the controller
its own `0600` copy of the client secret, owned by its service account in a protected
directory. Its identity configuration points to that copy. Do not grant it access
to `/etc/ficc-identity`, bootstrap credentials, the database password or the CA key.

Verify public certificate trust and discovery issuer, private readiness at
`https://127.0.0.1:9001/auth/health/ready`, listener bindings, and rejection of public
admin/master/management paths. Test approved-user first login, OTP, refresh,
revocation and denial when identity verification is unavailable through FICC.
Do not claim a working login from a successful discovery request alone.

## Daily backend certificate renewal

Install the root-owned helper and units, then enable the timer:

```sh
install -o root -g root -m 0644 renew_tls.py /opt/ficc-identity/renew_tls.py
install -o root -g root -m 0644 ficc-identity-tls.service ficc-identity-tls.timer /etc/systemd/system/
systemd-analyze verify /etc/systemd/system/ficc-identity-tls.service /etc/systemd/system/ficc-identity-tls.timer
systemctl daemon-reload
systemctl start ficc-identity-tls.service
systemctl enable --now ficc-identity-tls.timer
```

`https-certificates-reload-period=60s` in the supplied configuration enables
Keycloak PEM reload. Management inherits that period. Routine renewal does not
restart Keycloak or invalidate its sessions. The helper reloads PostgreSQL when
its certificate changes. See [Keycloak TLS reload](https://www.keycloak.org/server/enabletls).

Each day, with up to 30 minutes of random delay, the root-only helper checks both
pairs. It renews a leaf with at most 30 days remaining and validates the CA lifetime,
chain, names, server purpose, RSA3072 key and exact key match before publication.
It refuses malformed profiles and concurrent runs. Fresh pairs remain regular
files until their first renewal is due; a no-op does not migrate them.

At that first renewal, the helper saves the old pair in `versions/<id>`, points
`current` to it, and replaces `server.pem` and `server.key` with links to
`current/server.pem` and `current/server.key`. It saves the renewed pair in a new
version and atomically switches `current`, retaining `previous`. Every routine
renewal keeps the same private key. Thus even a reader opening files across the
switch receives a matching key and certificate. Separate identity and database
keys remain separate. Private-key and CA rotation require a coordinated procedure;
this helper does not perform them.

A durable `pending.json` records publication. Reload failure restores the prior
pairs. If interrupted, the next run restores the recorded prior pair and reloads
PostgreSQL as needed; that run performs recovery only. Run the service again after
successful recovery to renew a certificate that is still due. Preserve the version
directories and pending record until recovery succeeds; do not delete them to
silence a failed unit. Invalid recovery data requires private administrator repair.

The optional root-owned `0600` file `/etc/ficc-identity/tls-renew.env` can override
`FICC_TLS_CA_CERT`, `FICC_TLS_CA_KEY`, `FICC_TLS_IDENTITY_DIR`,
`FICC_TLS_DATABASE_DIR`, `FICC_TLS_IDENTITY_USER`, `FICC_TLS_DATABASE_USER` and
`FICC_TLS_POSTGRESQL_SERVICE`. Custom paths also require matching `ReadWritePaths`
overrides; custom services require matching unit ordering. The units bound runtime,
memory, CPU, tasks and file size. The root CA key stays root-only during all steps.

Monitor timer failures and all certificate expiry dates. A successful reload
command does not prove the new certificate is served: inspect fresh verified TLS
connections to both backends and compare their serials after the reload interval.
PostgreSQL can retain its prior TLS configuration after an invalid reload. Public
gateway certificate renewal is separate and remains Caddy's responsibility.

## Backups and recovery

Back up the identity database separately from the FICC controller database. It
contains users, password hashes, OTP material, realm signing keys, clients and
sessions. Keep encrypted, access-controlled database backups with tested restores.
Preserve the corresponding private configuration, client/database secrets, CA key,
certificates and renewal versions, plus verified distribution version and digest.
The initial realm JSON is not a complete backup. Do not put these artifacts in
source control or ordinary diagnostic bundles.

Test recovery in an isolated instance before returning it to service. Restore
ownership and modes, reconcile identity subjects with FICC mappings, and revoke
stale sessions or credentials as required by the incident. For a Keycloak upgrade,
retain a compatible database snapshot; switching the binary link back does not
undo a schema migration. Keep public administration closed throughout recovery.
Stopping this identity service leaves new login and lease renewal unavailable;
expired FICC identity leases must continue to deny access.
