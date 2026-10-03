# Trusted identity providers

Identity providers are separately installed security components. They are not
ordinary workspace modules. A controller administrator installs their Python
distribution and selects exactly one `ficc.identity` entry point in the private
`identity-provider.json` file. A panel cannot register or configure this provider.

The host owns browser state, PKCE secrets, the nonce, local identity mappings,
session cookies, project permissions and audit. The provider owns its external
authentication protocol and external token handling. An external subject cannot
be mapped to the local recovery owner. Email addresses, groups and display names
do not grant local access.

## Interface version 1

The entry point exports `API_VERSION = 1` and
`create(configuration, callback_uri)`. The callback is an exact, administrator
configured HTTPS URI. The result has a canonical `issuer` string and these
synchronous, thread-safe methods:

- `authorization(state, nonce, challenge)` returns the authentication URL.
  `challenge` is the S256 PKCE challenge. Only code flow with query response
  mode is supported. The host retains the corresponding verifier.
- `complete(code, verifier, nonce)` exchanges one authorization code, validates
  the result and returns the assertion described below. It never returns an
  external access token or refresh token.
- `renew(handles)` accepts 1 to 64 distinct handles and returns one ordered
  result per handle. A successful result contains the assertion fields and
  `valid: true`. A denied or unavailable result contains exactly `handle` and
  `valid: false`. Missing, duplicated, reordered or malformed results deny access.
- `forget(handles)` removes 1 to 64 handles from memory and attempts external
  token revocation. Local access is already revoked and cannot depend on that
  network operation succeeding. Unknown handles are harmless.
- `close()` clears all tokens and releases network resources.

An assertion contains exactly `handle`, `issuer`, `subject`, `auth_time`,
`expires_at` and `valid_until`. The handle is a random opaque string of at least
32 characters. The issuer and subject are verified, stable identity identifiers.
The three times are finite Unix timestamps. `expires_at` is the absolute session
deadline established at login and cannot increase during renewal. `valid_until`
is at most 30 seconds after successful external verification, and no later than
the session deadline or current token expiry. Renewal cannot change the identity
or its original authentication time. Handles and tokens are memory-only; controller
restart requires fresh external login.

The host binds each session to the current local mapping revision. It rechecks
that mapping, identity, membership and grants on every request and stream action.
It renews external authority in bounded background batches, outside database
transactions. Expired leases deny access even if a worker is delayed or unavailable.
Local identity revocation is immediate. Identity-provider revocation is bounded
by the 30-second verification lease; stream loops also apply their documented
reauthorization interval. Queued actions recheck authority before dispatch.

## OIDC provider

The supplied `oidc` distribution uses verified HTTPS discovery, authorization
code flow, S256 PKCE, confidential client authentication, signed ID tokens,
token introspection and rotating refresh tokens. Required configuration fields:

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

An optional `ca_file` selects a trusted CA bundle without disabling hostname
verification. Each selected endpoint must be HTTPS and belong to an explicitly
allowed origin. Redirects, environment proxy settings and token-supplied key URLs
are refused. Responses, network concurrency and deadlines are bounded. Discovery
must advertise S256, code flow, the required endpoints and a supported confidential
client authentication method. The provider supports `client_secret_basic`.

The administrator selects asymmetric signing algorithms and accepted ACR values
that the identity service actually enforces. The supplied Keycloak profile uses
password and authenticator-code MFA with authentication level 2. A static ACR
claim is not evidence of MFA. Numeric IP addresses cannot serve as WebAuthn RP
domains; passkeys require a compatible domain-based identity service.

The provider validates signature, issuer, subject, audience, authorized party,
nonce, token lifetime, authentication age and required assurance. It introspects
the access token before admission and on renewal. A refresh response must retain
the same identity and assurance. An uncertain refresh result ends that handle;
the provider does not replay a possibly consumed rotating refresh token.

External tokens remain in provider memory and never enter controller state,
backups, browser storage, URLs or logs. FICC logout revokes its own session first
and attempts revocation of that provider handle. It does not promise to end every
session held by the external identity service.
