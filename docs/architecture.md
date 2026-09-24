# Architecture

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
File management and interactive terminals remain later development work.

## Connections

The operator approves SSH aliases locally. A preview resolves the target account,
address and known host key. Enrollment confirms that fingerprint and any required
helper installation. Each enrolled machine keeps its own trusted key snapshot.
Every connection checks it. Host-key changes require a deliberate trust update.

Connections have deadlines and bounded output. The current version uses fresh
SSH connections and does not reuse external control sockets. SSH agent and X11
forwarding are disabled. Authentication can use the local SSH agent without
forwarding it to a node.

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
