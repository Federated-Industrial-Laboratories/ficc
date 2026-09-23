# Security

FICC is in development. No stable release is supported yet.
Report a security issue privately to contact@federatedindustrial.com.
Do not include credentials, private keys or confidential logs in a public issue.

The current service supports one local Linux account. It listens on loopback
and requires authentication. Do not expose its port through a public proxy,
tunnel or network bind. Shared remote access is not supported.

The local account, its SSH configuration and its SSH agent are trusted.
A process with the same account can control FICC and use that account's keys.
The service does not isolate applications that share the local account.

Remote machine data is untrusted. The service validates data before storage.
The browser treats names, errors and resource labels as text. SSH connections
require a pinned, trusted host key. A changed host key prevents collection.

Only locally approved SSH profiles can be enrolled. Review their proxy commands
and executable configuration rules before approval. FICC does not accept SSH
configuration text from the browser or store SSH private keys.

Browser sessions use short-lived login credentials and HttpOnly cookies.
Origin, Host and CSRF checks apply to browser requests. API tokens have explicit
scope, node access and expiry. Revoke unused credentials in Access or the CLI.

The service stores inventory and audit data in its private state directory.
Do not put that directory in a repository or a shared filesystem. A private Git
repository is not a suitable secret store. Local audit data is not tamper-proof
against the account owner or system administrator.

Dependency checks and a source scan run before integration. These checks do not
replace code review or establish that software has no security defects.
