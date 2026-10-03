# FICC OpenID Connect identity provider

This separately installed, trusted Python package implements the FICC
`ficc.identity` interface, version 1. It provides browser authentication through
an OpenID Connect service. The controller owns local access grants and mappings.
An external email address or group does not grant access.

## Installation

Use Python 3.12 or later. Install this package in the controller environment:

```sh
python -m pip install --require-hashes -r identity-providers/oidc/requirements.lock
python -m pip install --no-deps ./identity-providers/oidc
```

Select the `oidc` entry point in the private `identity-provider.json` file:

```json
{
  "provider": "oidc",
  "configuration": {
    "issuer": "https://identity.example/realms/operations",
    "client_id": "ficc",
    "client_secret_file": "/private/ficc/client-secret",
    "allowed_origins": ["https://identity.example"],
    "algorithms": ["RS256"],
    "required_acr": ["2"],
    "max_auth_age": 28800,
    "session_seconds": 28800
  }
}
```

An optional `ca_file` adds a trusted PEM CA bundle. TLS hostname verification is
always enabled. Files require absolute paths, trusted owners and safe parent
directories. The client secret must be a regular file with mode 0600 or stricter.
Links, shared hard links and writable file ancestors are rejected. Root-owned
sticky temporary directories are permitted. The controller supplies its exact
HTTPS callback URI to `create`.

Configure a confidential code-flow client with `client_secret_basic`, S256 PKCE,
token introspection and rotating refresh tokens. Every refresh response must
include a signed ID token and a new refresh token. The Keycloak client must enable
refresh-token revocation and set maximum reuse to zero. Use an authentication flow
that actually requires the configured ACR level; a static claim mapper does not
establish MFA. Configure only the exact controller callback, without wildcards.

Discovery must advertise the required endpoints and methods. All endpoint origins
must be explicitly listed. Metadata and endpoint URLs cannot contain credentials,
query parameters or fragments. Redirects, environment proxy settings, compressed
responses and token-supplied keys or key URLs are rejected. The supported signing
algorithms are RS256/384/512, PS256/384/512 and ES256/384/512. The administrator
selects the permitted subset; symmetric signatures and unsigned tokens are refused.

## Session behavior

The provider verifies the signature, issuer, subject, audience, authorized party,
nonce, authentication age and ACR. Introspection must return `active: true`, the
same subject, the configured `client_id` and a future `exp`. If present, its issuer
must also match. Each lease ends within 30 seconds, at token expiry or at the
absolute session deadline, whichever occurs first. Session limits are from 1 to
86400 seconds. The lease begins with its introspection request; a delayed
response or assertion cannot extend that verification interval. Token timestamps
allow at most 30 seconds of future clock skew.
Expired tokens never receive a lease.

Renewal accepts 1 to 64 distinct handles and returns results in the same order.
One unavailable or revoked identity does not change the other results. A failed
renewal removes its handle. An uncertain refresh result requires fresh login;
the provider never retries a possibly consumed refresh token. A refresh cannot
change the subject, original authentication time or original ACR value,
or extend the absolute session deadline. Refresh nonces, when present, must match.

Access tokens, refresh tokens and handles remain in memory. `forget` removes
local authority before attempting external revocation. `close` clears credentials
and token references and closes network resources. Python does not guarantee
physical erasure of released strings. Controller restart requires fresh login.

## Bounds and implementation

The provider permits at most 1024 sessions, four concurrent requests and one
renewal batch at a time. It uses four renewal workers; additional renewal callers
receive denied results. A response is limited to 256 KiB, a token to 16 KiB, and
a JWKS response to 32 keys. Signing keys are cached for five minutes. An unknown
or changed key can trigger a refresh at most once every five seconds.

Requests have a five-second checked elapsed budget and two-second pool, connect,
read and write timeouts. One blocked I/O operation can extend the elapsed budget
by up to its timeout. Admission, renewal and revocation use a twenty-second total
request budget; queued renewal work denies access when that budget expires.
The controller must continue to reject expired leases while renewal runs. A failed token
exchange is never replayed. Server response bodies do not enter provider errors
or logs.

`config.py` validates administrator input and private files. `transport.py`
contains HTTPS and discovery. `tokens.py` validates JWTs and introspection.
`provider.py` implements token storage and the public interface. Authlib validates
OIDC claims; joserfc validates signatures. HTTPX supplies the verified transport.

Run the maintained tests against the installed dependencies:

```sh
PYTHONPATH=src python -m pytest tests -q
```

The tests use an actual local HTTPS server, a temporary CA, signed JWTs and
rotating tokens. They cover distinct batches of 1 and 64 identities, including
late-row denials. A deployed identity service and browser workflow require the
controller integration tests.
