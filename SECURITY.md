# Security

The supported stable release is 0.2.0, published as 0.2.0-stable.
Report a security issue privately to contact@federatedindustrial.com.
Do not include credentials, private keys or confidential logs in a public issue.

The supported stable release uses local-mode loopback access. Do not expose
that release's listener through a public proxy, tunnel or network bind.
The development controller also provides explicit [remote mode](docs/remote-access.md):
verified HTTPS, a protected Unix gateway connection, approved external identities
and current project permissions. Adding a proxy to a local-mode listener does
not enable secure remote access.

The local account, its SSH configuration and its SSH agent are trusted.
A process with the same account can control FICC and use that account's keys.
The service does not isolate applications that share the local account.

Application identities separate project workspaces and operation receipts within that trusted account.
The owner controls membership and can issue credentials through the private socket.
The owner assigns project machines, folders and capabilities. Job and file
receipts remain project-bound; terminals also require their creating identity.
Job execution and shells have full remote-account authority. Provider and
installation administration remain owner-only. Remote identity approval is separate
from membership and cannot assign the local recovery owner.
See [identities and projects](docs/identities.md) for ownership and recovery limits.

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
not isolate another program with the same account. An opened directory remains
usable after external movement. Hard links can give an object other names.

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

Coding-agent launch and bus send have separate node-scoped permissions. Selecting
a runtime profile does not change provider login, model settings, sandbox settings
or approval policy. Direct delivery can start work under the recipient agent's
existing account. Bus messages are labeled participant testimony and carry no
FICC approval authority. Revocation prevents later admission but cannot undo
work that the runtime already accepted.

Nodes expose only the fixed SSH helper exchange and private local spool tools.
Controller credentials stay on the controller. An outbox cannot choose a different
sender, run or grant. Runtime submissions with uncertain outcomes are not
replayed automatically.

Ordinary same-account processes remain inside the trusted
account boundary. Spools reject links, unsafe ownership, unknown members and
capacity overflow. The native TUI owns runtime approval decisions.

Runtime modules have a separate containment boundary. Executable packages require
private namespaces, syscall filters and enforced cgroup limits. They receive no
SSH keys, controller database, host home, display socket or provider socket.
The host broker intersects current caller access, package-digest grants and panel
targets. Missing containment prevents execution; there is no unrestricted fallback.

Package inspection validates bounded contents and hashes. It does not authenticate
publishers. All current packages show an unverified publisher state and need
explicit source acceptance. New digests need new grants. Disabling a package
revokes its calls and streams while retaining recovery records and saved data.

Native displays use a separate verified runtime in their own bounded process.
Opaque references bind a display to the current actor, panel and VM identity.
Input is released on arrival and on focus or authority loss. Clipboard, file
transfer, console audio and microphone input are disabled. See [display controls](docs/viewer.md).

Workspace data has local-account file protection, not encryption at rest. Audio
uses an explicit browser-local file selection and revocable playback leases.
No module may place provider passwords in workspace state. Treat saved notes,
operation history and backups as private data.

## Policy packages

Signed policy archives contain Rego and JSON. Exact manifest signatures and
payload hashes bind them to an explicitly trusted Ed25519 publisher. Ordinary
workspace modules cannot establish that trust or install a security provider.
Providers are separately installed trusted Python components with controller
authority. The OPA provider requires a network-isolated process and verified
resource controls for both compilation and evaluation.

Policy input contains current host-established authority, with caller labels
kept separate. An allow can only narrow host grants. Invalid, missing, stale or
unavailable required decisions deny access. Unrestricted local owner policy
administration remains available for explicit recovery and generates audit
events. Restore disables policy execution and publisher trust. See
[policy operations](docs/policies.md) for the remaining managed-process limits.
