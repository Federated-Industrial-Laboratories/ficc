<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Architecture

[Contents](README.md) | [Project README](../README.md) | [Next: Installation](install.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

The browser and CLI use one local HTTP API. A Python service owns inventory,
authentication, audit data and resource snapshots in SQLite. OpenSSH connects
to approved machine profiles. A small Python helper collects Linux resources.
The helper runs under the remote account and opens no network listener.

The browser uses local HTML, CSS and JavaScript. It does not execute code sent
by a managed machine. The wheel includes all web assets and font licences.
Node.js is required to build and test these assets, not to serve the application.

The installed service provides observation, access management and durable jobs.
Typed requests travel to the helper through SSH stdin. A fixed node runner reads
saved arguments and starts programs under bounded systemd user services. SQLite
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

SQLite stores local metadata on a local filesystem. Large external workloads
and their state remain under their own tools. FICC does not infer ownership of
a process from the fact that it is visible in a resource sample.

## Access

A private Unix socket checks the caller's account and supplies a one-use browser
login credential. The credential is exchanged for a session cookie and removed
from the browser URL. Mutations also require a session CSRF value.

Automation credentials have a scope, optional node list and expiry. Each API
request checks current grants. Revocation prevents later use. Local owner access
is separate from a token's restricted view of the inventory.

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
retained until matching session evidence exists. Closed-run archival publishes
controller evidence before moving exact quiescent node spools and releasing host
capacity. Backup and history maintenance include the combined schema and refuse
unresolved agent work. See [agents](agents.md) and [bus](bus.md).


<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Next: Installation](install.md)
