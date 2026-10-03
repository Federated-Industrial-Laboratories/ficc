# Certificate providers

Certificate providers are trusted installation components. They are not panel
modules and cannot be installed through an ordinary module capability grant.
The administrator installs a separate Python distribution, then selects its
`ficc.certificates` entry point in the private contributor configuration.

The host owns invitations, approval, immutable node identity, certificate
registration, channel authorization, rotation and audit. The provider only
adapts an established certificate authority. Its code must not be built into
the host. Private node keys never leave their node.

## Interface version 1

The entry point exports `API_VERSION = 1` and `create(configuration)`.
Configuration is a provider-specific JSON object. The returned object supplies
three synchronous methods. The host calls them on a bounded worker pool.

`issue(request)` accepts these exact fields:

```json
{
  "request_id": "0123456789abcdef0123456789abcdef",
  "node_id": "0123456789abcdef0123456789abcdef",
  "identity_uri": "urn:ficc:node:0123456789abcdef0123456789abcdef:0123456789abcdef0123456789abcdef",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "validity_seconds": 3600
}
```

Identifiers are 32 lowercase hexadecimal characters. The identity URI binds the
installation and node. A request contains one signed PKCS#10 request, at most
8192 bytes. The host verifies possession and the exact URI before issuance.
The provider repeats validation before contacting its authority. The certificate
has this URI as its only subject alternative name, the node ID as its common
name, client authentication extended usage and no certificate-signing authority.
Accepted node keys are Ed25519 and ECDSA P-256. No other CSR extension is accepted.

The return value is `{"certificate_chain": "...PEM..."}`. It contains the leaf
followed by its intermediate certificates, at most 16384 bytes. The host verifies
the chain against its configured public roots, the requested key and identity,
client usage and validity. The host never trusts provider-supplied identity fields.
Validity is 60 to 86400 seconds. The configured default is 3600 seconds.

`revoke(certificate_chain, reason)` returns `None` after the authority accepts
revocation. Reasons are `superseded`, `disabled` or `recovery`. Revocation must
be repeatable. A provider error does not reverse the host's immediate denial.
Passive CA revocation alone does not terminate an unexpired TLS session.

`close()` releases provider resources and is safe to repeat.

Calls finish or fail within 20 seconds. Responses, TLS verification and network
timeouts are bounded. No redirects, proxy environment, plaintext transport,
automatic mutation retry or diagnostic credential disclosure is permitted.
An uncertain issuance is not registered. Another explicit attempt may issue a
new certificate; only the exact certificate registered by the host can connect.

## Supplied authority

The separately installed Smallstep package uses a private step-ca HTTPS endpoint
and a restricted JWK provisioner. It signs short-lived, single-use authorization
tokens bound to the request. The provisioner's private signing credential is a
private file reference, never a database value or process argument.

Use an offline root and a separate online intermediate. The controller holds
the public trust chain and its restricted provisioner credential. It does not
hold the root or intermediate private key. The CA is a separate service.

An independent provider can implement this interface without importing a
Smallstep module. The maintained qualification must cover actual issuance,
wrong identity/key/usage, expiration, revocation, timeout, malformed responses,
and distinct nodes at batches of 1 and 64.
