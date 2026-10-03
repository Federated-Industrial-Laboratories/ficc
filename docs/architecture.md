<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Architecture

[Contents](README.md) | [Project README](../README.md) | [Next: Installation](install.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

<details>
<summary>On this page</summary>

- [Connections](#connections)
- [State](#state)
- [Access](#access)
- [Demonstration mode](#demonstration-mode)
- [Coding agents and bus](#coding-agents-and-bus)
- [Runtime modules and workspaces](#runtime-modules-and-workspaces)

</details>

FICC connects a browser and CLI to Linux machines through OpenSSH.
One Python controller owns inventory, authentication, audit records and resource
snapshots in SQLite or an explicitly configured PostgreSQL database.
Each approved machine runs a small Python helper under its
remote account. The helper opens no network listener.

The browser uses local HTML, CSS and JavaScript. It does not execute code sent
by a managed machine. The wheel includes all web assets and font licenses.
Node.js is required to build and test these assets, not to serve the application.

Local mode uses a loopback listener and local owner recovery. Explicit remote mode
uses a private Unix socket behind a verified HTTPS gateway. A separately installed
identity provider verifies organization accounts. FICC binds approved external
subjects to local identities and checks their current project access. See
[remote access](remote-access.md) for the configuration and trust boundaries.

The installed service provides observation, access management and durable jobs.
Typed requests travel to the helper through SSH stdin. A fixed node runner reads
saved arguments and starts programs under bounded systemd user services. Durable
intent and node receipts support reconciliation after a controller restart.

Registered roots and verified file transfers use descriptor-relative helper
operations. Interactive terminals connect pinned OpenSSH through a supervised
PTY and an authenticated, flow-controlled WebSocket. Local xterm.js assets
render terminal bytes. Persistent sessions use a separate tmux namespace.

## Connections

The operator approves SSH aliases locally. A preview resolves the target account,
address and known host key. Enrollment confirms that fingerprint and any required
helper installation. Each enrolled machine keeps its own trusted key snapshot.
Every connection checks it. Host-key changes require a deliberate trust update.

Connections have deadlines and bounded output. Resource observation uses private,
FICC-owned SSH master connections for at most 300 seconds. A probe renews its
connection when fewer than 11 seconds remain for its 10-second deadline. Every probe resolves
its complete SSH configuration, checks its pinned key and checks current access.
Configuration changes, revocation and node removal close affected connections.

A finite supervisor ends each master even if the controller exits unexpectedly;
the maximum remaining lifetime after a crash is 302 seconds, including kill grace.
Jobs, files, helper installation and terminals use fresh SSH connections. FICC
never adopts external control sockets. Agent, X11 and port forwarding are disabled.
Authentication can use the local SSH agent without forwarding it to a node.

## State

Resource data carries a receipt time and visible age. An unsuccessful poll does
not replace an earlier sample with zeros. The browser shows stale samples and
the connection error. Unsupported GPU reporting is distinct from zero use.

SQLite stores local metadata on a local filesystem. An optional trusted driver
stores the same records in PostgreSQL with verified TLS and exclusive connection
ownership. Local module files and receipts remain in the private state directory.
See [controller state storage](state-storage.md) for installation and recovery.
Large external workloads
and their state remain under their own tools. FICC does not infer ownership of
a process from the fact that it is visible in a resource sample.

## Access

A private Unix socket checks the caller's account. In local mode it supplies a one-use browser
login credential. The credential is exchanged for a session cookie and removed
from the browser URL. Mutations also require a session CSRF value.

Remote mode uses a bound authorization-code exchange with PKCE. Identity tokens
remain in provider memory; the browser receives an opaque Secure, HttpOnly session
cookie. External authority expires within 30 seconds unless verified again.
Exact external-identity approval, project membership and resource grants are
checked independently. The remote browser cannot become the local recovery owner.
Controller restart invalidates all remote sessions.

Automation credentials have a scope, optional node list and expiry. Each API
request checks current grants. Revocation prevents later use. Local owner access
is separate from a token's restricted view of the inventory.

Schema 7 separates durable user identities from credential IDs and assigns each
credential to a project. Workspace contents are shared within that project;
views and window surfaces belong to their user. Membership limits are checked
when resolving credentials and before queued actions. Schema 8 adds project
resource assignments and durable job, file, transfer and terminal ownership.
Lists, direct access and queued actions use those boundaries; file chunks and
terminal frames also check current access. Provider and installation administration
remain local-owner capabilities. See [identities and projects](identities.md).

Schema 9 stores policy packages, role assignments and activation history. Schema 10
adds external-identity mappings. Restore suspends external mappings and non-owner
identities until the administrator reviews and explicitly enables them.

## Demonstration mode

Demonstration mode uses synthetic records and displays a simulation label.
It disables remote enrollment, managed-job mutation and SSH collection. Demonstration results do not
describe real machine health or resource capacity.

## Coding agents and bus

Schema4 adds bounded profiles, agents, runs, messages and delivery tables without
expanding existing grants. Agent launches create exact ordinary tmux terminal
records. A separate, host-initiated SSH exchange carries structured inbox items,
outbox replies and delivery receipts; terminal keyboard bytes are never a bus
control channel. Native OMP and Codex adapters remain version-gated; other runtimes
use a registered local inbox tool. Private node spools carry no controller secret.

Two relay exchanges run concurrently with per-agent coordination. Launch admission
has a separate lock; a blocked node does not hold the healthy-node stop lock.
Controller and node persistence precede acknowledgement. Runtime uncertainty is
retained until matching session evidence exists.

Closed-run archival publishes
controller evidence before moving exact quiescent node spools and releasing host
capacity. Backup and history maintenance include the combined schema and refuse
unresolved agent work. See [agents](agents.md) and [bus](bus.md).

## Runtime modules and workspaces

Schema5 adds installed package inventories, grants, workspaces, view layouts and provider receipts.
Schema6 adds separate Windows endpoints and immutable packaged adapter profiles and receipts.
The controller validates separate runtime archives after the application build.
Supplied modules use the same installation, trust and activation steps as other archives.
An archive digest identifies exact bytes; it does not authenticate a publisher.

Executable modules run in separate, bounded processes with private namespaces and no network access.
They receive framed JSON through private pipes. Ordinary modules receive no controller token, SSH key or provider socket.
The controller checks each broker request against the caller, package digest, panel and selected system grants.

Separate VM, container and administration providers validate their own resources and operations.
Ordinary panel modules request previews. The host confirms their lifecycle actions separately.

Provider adapter packages use separately registered transports and broad provider account grants.
The host supplies credential custody, transport limits, confirmations, journals and display components.
An adapter supplies provider parsing, resource identity and operation tracking.
Its account grant can change provider resources during any call; ordinary panel grants cannot restrict that account.
Declared consistency appears before confirmation and in retained receipts.

The browser renders validated component descriptions. It does not load module scripts, HTML or styles.
Dockview arranges module panels inside each workspace and workspace tiles inside each window.
Each window has separate layout identities; workspace data remains shared and uses revision checks.
The audio service shares preferences and issues one renewable playback lease per module instance.

The native viewer is a separate optional process with its own namespaces and resource limits.
The controller supplies a verified SSH or registered display stream and checks browser output and input bounds.
Provider connection details and temporary display credentials stay outside browser messages and saved layouts.
The viewer has no clipboard, file transfer or audio channel. Workspace sound has separate controls.

Durable intents and node receipts retain uncertain changes without automatic replay.
Retained operations prevent removal of their authority records until explicit cleanup succeeds.
Permission revocation and security disable remain available. Restored packages and provider profiles stay disabled.
Backup removes execution grants and refuses unresolved work. See [modules](modules.md), [workspaces](workspaces.md) and [backup](backup.md).


<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Next: Installation](install.md)
