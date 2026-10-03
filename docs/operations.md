<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Operation and maintenance

[Contents](README.md) | [Project README](../README.md) | [Previous: Installation](install.md) | [Next: Managed jobs](jobs.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

<details>
<summary>On this page</summary>

- [User service](#user-service)
- [Trust changes](#trust-changes)
- [State copy and upgrades](#state-copy-and-upgrades)
- [Removal](#removal)
- [Agent operation](#agent-operation)

</details>

Use this guide to start the controller, change its service settings and maintain
enrolled machines. Run FICC under a normal local account. The private state
directory defaults to `$XDG_STATE_HOME/ficc`, or `~/.local/state/ficc` when
XDG_STATE_HOME is unset. That account must own the directory with mode 0700.
Keep the control socket, database and pinned host keys private. Use separate
state for demonstration and live work.

The foreground `ficc serve` process stops with Ctrl+C. Stopping the controller
does not cancel managed remote jobs. Their lifetime still depends on the node's
user manager and the limits shown when each job was submitted.

## User service

Install the wheel and runtime requirements in a virtual environment. Activate
that environment, then install the launcher with the intended profiles and state.
The generated service uses this environment's absolute executable path. Keep the
environment at that path while its launcher is installed.

```sh
ficc install-launcher --profile rack-01 --profile rack-02
ficc launch
```

Open **FICC Cluster Commander** from the desktop application menu thereafter.
It starts the local user service, waits for authenticated readiness and opens
the console. Repeated launches use the running service. Bootstrap credentials
are short-lived and are never written into the desktop entry or service file.

Installation starts nothing and does not enable login startup by default.
Add `--autostart` during installation to enable startup at sign-in. A previously
enabled service stays enabled when reinstalled; disable it explicitly with
`systemctl --user disable ficc.service` if that preference changes.

```sh
ficc start
ficc status
ficc stop
```

Use `--state-dir PATH` during installation to retain existing enrolled state,
plus its existing `--port`, approved `--profile` values and `--ssh-config` if used.
Stop an old foreground service first. Do not delete its state directory. Stop
the user service before reinstalling its launcher settings. Alternate launchers
require both `--name ficc-NAME` and a distinct `--launcher-config PATH`; also use
a distinct state directory and port. Pass that configuration path to each
startup command for the alternate launcher.

The default files are `$XDG_CONFIG_HOME/ficc/launcher.json`,
`$XDG_CONFIG_HOME/systemd/user/ficc.service` and
`$XDG_DATA_HOME/applications/ficc.desktop`, with the standard home-directory
defaults when those variables are unset. The configuration is private and holds
paths and approved aliases, not SSH keys or browser credentials. Existing files
from another application and systemd overrides are refused.

The service uses a private temporary directory under the account's runtime directory.
Systemd removes it when the service stops. Each launcher name has a separate directory.
The controller retains normal file ownership checks and cannot gain new privileges.
Program modules use separate mandatory namespace, syscall and resource limits.

Startup updates an older generated service when it is not ready.
This change preserves its executable, state, profiles and port. Custom service changes are refused.

If startup fails, run `ficc status` and
`journalctl --user -u ficc.service -n 40`. Check that the installed executable,
state permissions and port are available. Browser opening needs xdg-utils and
a configured default browser. `ficc open --print-url` is an explicit fallback;
its output contains a credential and must not be logged or shared.

The service must have access to the intended local SSH identity or agent.
It does not forward the agent to a node. A locked or unavailable identity causes
an authentication error; do not store a private key passphrase in service settings.

## Trust changes

A changed key blocks observation. Independently verify a replacement key and
the machine identity first. Forget the old local enrollment, update the trusted
local SSH configuration, and preview a new enrollment. Complete the explicit
[history archive](history.md) before forgetting a machine with retained work.

If its old identity is unavailable, preserve that state and reconcile it before
archival. A replacement key does not prove that the old work is finished.
Forgetting a machine does not remove its helper or affect other SSH clients.

## State copy and upgrades

Use the stopped-service [backup and restore commands](backup.md) for a verified
state bundle that removes credentials. Finish or reconcile remote work, stop
terminal sessions, and finish or discard transfers before backup. Registered
file trees and remote job output need separate backups.

Before an upgrade, retain the old wheel, dependency lock and stopped state copy.
Install the new wheel into a separate environment and read its compatibility
notes. Do not run two service processes against the same state directory.
Use a new empty state directory if a development schema is incompatible.

Version 0.2.5 uses controller schema 15, including identities, projects, policy,
contributors, datasets, data sources and inspection records. Existing local
state migrates under exclusive ownership. The existing local owner is retained;
older credentials do not acquire newly introduced capabilities. Sign in again
or deliberately issue a scoped credential. Remote access and contributor
execution still require their explicit deployment and authority setup.

Stop the service and keep a complete private pre-upgrade copy first.
An older controller cannot open the migrated schema. A downgrade needs its
pre-upgrade state copy; restoring that copy loses subsequent operation records and
must wait until those jobs are reconciled. Preserve the current state as well.

Restore only with the original service stopped and a compatible application
version. The restore command creates a new directory, removes credentials and
clears cached observations. Check remote work since the backup before confirming
restore. Never run both controller copies. A raw pre-upgrade directory copy still
contains credential material; keep it private and revoke old credentials after
using that separate downgrade procedure.

## Removal

Stop and disable the user service before removing the environment and unit file.
Remove its matching desktop entry and launcher configuration, then run
`systemctl --user daemon-reload`. These steps do not remove enrolled state.
Keep the state directory unless its deletion is explicitly intended.

The helper
remains at `~/.local/lib/ficc/node.pyz` on each enrolled node. Remove that exact
file through an ordinary authenticated SSH session if it is no longer required.
Do not delete unrelated files in the parent directory.


## Agent operation

Coding-agent profiles name installed executables and working directories; they
never install agent software or transfer provider credentials. Use the Agents
preview before launch and the Bus receipt view to distinguish storage from runtime
inclusion. A generic inbox works without a native adapter. See [agents](agents.md)
and [bus](bus.md) for direct delivery, scoped replies and explicit closed-run
archival. Agent spools remain on their node until that explicit archive operation.


## Operational status and recovery

Open **Operations** with an unrestricted local-owner identity and `audit:read`.
The view shows saved connection freshness, policy readiness, contributor authority
expiry, background errors, local audit retention and completed metadata recovery
operations. Select **Refresh** for a new observation.

**Download redacted diagnostics** exports an explicit allowlist of status and
counters. It excludes account and resource labels, hostnames, paths, source
configuration, query text, payloads, credentials and raw exception messages.
The export does not probe external systems or certify storage encryption.

**Export retained audit events** downloads NDJSON with actor, project and resource
identities. Treat it as operational data and review it before sharing. Its header
identifies the retained range and any earlier retention gap. The final record has
`complete: true` only after the selected range finishes. A disconnected or revoked
export without that final record is incomplete. API clients can use
`GET /api/v1/operational-status/audit?after=EVENT_ID` to export subsequent retained events.
Local retention and an exported checksum are not proof against an administrator
who can change or remove controller state.

[Durable audit delivery](audit.md) adds automatic acknowledged export to a
separately administered append-only destination. Operations reports its backlog
and retention gaps. Optional required mode gates new workload admission and
external source writes while preserving cancellation and lease maintenance.

The backup timestamp records successful completion of `ficc backup`. The restore
timestamp records a verified archive restored into a new private state directory.
Neither timestamp proves that external dataset storage or a database source has a
working backup. Back up those systems separately, protect their keys and perform
an isolated restore drill. A restored controller has no retained login credentials;
reconcile external work before granting execution again.

The contributor authority expiry comes from its configured public certificate.
The HTTPS gateway manages its own certificate and renewal. Use the gateway's
monitoring for that endpoint; this screen labels it as externally managed.

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Previous: Installation](install.md) | [Next: Managed jobs](jobs.md)
