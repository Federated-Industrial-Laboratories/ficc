# OpenSSH certificate trust

Existing enrolled machines keep their pinned host keys. An installation
administrator can select certificate trust for an approved SSH profile.
The browser cannot write SSH configuration or add a certificate authority.
OpenSSH performs the handshake, verifies signatures and checks host principals.

## Configure an authority

Create `ssh-trust.json` in the controller state directory. Use
[the example configuration](../examples/ssh-trust.json). The file must belong
to the controller account, have mode `0600` and contain no symbolic link.
Its directory must have mode `0700`. The version is `1`; at most 64 profiles
are allowed. The configuration file limit is 64 KiB.

Each profile selects these fields:

| Field | Purpose |
| --- | --- |
| `host_ca` | Absolute path to one approved OpenSSH CA public key. |
| `host_principal` | Exact principal required in the host certificate. Wildcards and certificates without principals are refused. |
| `revoked_keys` | Absolute path to an OpenSSH KRL. A missing or invalid list refuses access. |
| `user` | Optional user certificate, private identity file and exact user principal. |

Trust files must be private regular files owned by the controller account.
Use absolute paths without spaces, quotes or expansion characters. Public key
and certificate files have a 64 KiB limit. KRL files have a 4 MiB limit.
The CA private key does not belong in this configuration or controller state.

Keep the destination in the installation's approved SSH configuration:

```text
Host renderer-a
    HostName 192.0.2.15
    User ficc
    IdentityFile /var/lib/ficc/ssh-trust/renderer-a
    IdentitiesOnly yes
```

For a user certificate, the profile must select exactly its configured identity
file. Select the certificate in `ssh-trust.json`; omit `CertificateFile` from
the SSH profile. The configured private key must be an account-owned regular
file with private permissions. Certificate mode uses this file directly;
it does not use an SSH agent or offer raw-key authentication as a fallback.
An account-private temporary key alias supplies the approved public certificate
to OpenSSH. The controller does not copy the private key bytes.

Without `user`, the profile retains raw-key client authentication. It cannot
implicitly select a user certificate from a neighboring file. Host certificate
algorithms and client signature algorithms are selected from the installed
OpenSSH profile's allowed algorithms.

Configure the server's `HostCertificate`, `TrustedUserCAKeys` and
`AuthorizedPrincipalsFile` through its normal administrative process. Keep its
user KRL current with `RevokedKeys`. Separate a forced-command helper credential
from a credential intended for interactive terminals. Do not grant a shell to
a helper-only credential merely to enable the terminal panel.

Create an empty KRL with OpenSSH when no keys are revoked:

```sh
ssh-keygen -k -f revoked.next /dev/null
chmod 600 revoked.next
mv revoked.next revoked.krl
```

When adding revocations, copy the current KRL to a new file and use
`ssh-keygen -k -u -f` on that copy. Replace the live file atomically. Preserve
earlier revocations. OpenSSH supports certificate serials, certificate IDs,
public keys and CA key revocation.

## Enroll and use a machine

Create a normal machine preview using the approved profile. Certificate mode
shows the CA fingerprint and the required host principal. Compare the CA
fingerprint with the installation's independently approved value. Enrollment
and helper installation retain their existing explicit confirmation.

The configured principal is also the SSH `HostKeyAlias`. Only certificates
signed by the configured CA and valid for that principal can connect. FICC
records the exact certificate supplied to OpenSSH during the handshake;
an unauthenticated key scan cannot set the connection's trust or expiry.

A valid certificate renewal under the same CA and principal can connect
without re-enrollment. A changed CA, principal, destination or account requires
a new enrollment. Removing certificate configuration cannot downgrade an
enrolled certificate profile to a pinned key.

## Current trust and connection lifetime

Certificate connections check current trust before returned data and at
one-second guard intervals while idle. Current KRL changes, removed trust,
changed user certificates and certificate expiry stop cached observation
masters and active attachments. A KRL change that does not revoke a connection
keeps that connection usable. Certificate validity uses both wall-clock checks
and a monotonic deadline, so a backward clock adjustment cannot extend an
already bound lifetime. The controller and managed machines require reliable
system clocks.

These guards stop the FICC SSH attachment. They do not claim to terminate a
remote process that intentionally outlives its SSH session, such as a managed
job or persistent terminal. Its normal cancellation or stop procedure still
applies. Revocation also prevents new SSH operations through that certificate.

Connection state and captured public certificates occupy private temporary
directories. Normal cleanup removes them. A controller restart clears its
connection authority; retained node records must pass a new handshake.

For a host integration, preserve the object returned by `SSH.arguments()`.
It is list-compatible. Capture `SSH.connection_check(arguments)`, call the
guard before data delivery and at most one second apart while idle, and call
`SSH.release(arguments)` after the child process is closed. Release is
idempotent. Uncertified arguments have a no-op guard. Ordinary helper commands
and observation masters own this lifecycle internally.

Protocol references: [OpenSSH client configuration](https://man.openbsd.org/ssh_config.5)
and [OpenSSH key and KRL tools](https://man.openbsd.org/ssh-keygen.1).
