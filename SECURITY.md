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
scope, node/root access and expiry. Revoke unused credentials in Access or the CLI.

Managed execution has the full authority of the remote SSH account. Limits and
GPU visibility are resource controls, not a sandbox for hostile programs. Grant
jobs:execute only to callers permitted to use that account. Log output can carry
secrets and needs the separate jobs:logs scope. Command arguments and explicit
environment values are stored in durable job requests; avoid embedding secrets.

The CLI stores private submission credentials only in bounded recovery receipts
under the state directory. They expire after one hour and remain revocable.
Copy those receipts only with the same care as API credentials. Do not expose
one-use browser bootstrap URLs through desktop configuration or service logs.

The service stores inventory and audit data in its private state directory.
Do not put that directory in a repository or a shared filesystem. A private Git
repository is not a suitable secret store. Local audit data is not tamper-proof
against the account owner or system administrator.

Dependency checks and a source scan run before integration. These checks do not
replace code review or establish that software has no security defects.

File roots are object capabilities within the trusted local or remote account.
They refuse symlink traversal and bind registered directory identity. They do
not isolate another program with the same account: an opened directory remains
usable after external movement, and hard links can give an object other names.
Keep root namespaces operator-managed. Detected changes are refused; continuous
pathname confinement against a concurrent same-account writer is not promised.

Interactive terminal execution has full remote-account authority. Ticket,
Origin and current-grant checks protect attachment; revocation detaches the
client. Persistent tmux sessions require a separate confirmed stop. Terminal
bytes are untrusted, confined to the emulator and not recorded by FICC.

The browser content policy permits inline styles for xterm's generated font,
RGB color and contrast rules. Scripts remain restricted to local assets.
Application code constructs labels with text nodes and does not render remote
HTML. Terminal color values are parsed by the pinned emulator; remote terminal
data does not become arbitrary CSS or HTML.
