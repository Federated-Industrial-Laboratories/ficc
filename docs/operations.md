# Operation and maintenance

Run FICC as a normal local account. Its state defaults to
`$XDG_STATE_HOME/ficc`, or `~/.local/state/ficc` when XDG_STATE_HOME is unset.
The directory must be owned by that account with mode 0700. The control socket,
database and pinned host keys stay private. Do not reuse demo state for live work.

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
local SSH configuration, and preview a new enrollment. Forgetting a machine does
not remove its helper or affect other SSH clients.

## State copy and upgrades

This development version has no online backup command. Stop the service before
copying its complete state directory. Preserve file ownership and permissions.
Treat the copy as confidential because it includes credential digests and audit
history. Keep it outside the source directory.

Before an upgrade, retain the old wheel, dependency lock and stopped state copy.
Install the new wheel into a separate environment and read its compatibility
notes. Do not run two service processes against the same state directory.
Use a new empty state directory if a development schema is incompatible.

The managed-job version migrates controller state from schema 1 to schema 2.
The older observation-only version refuses schema 2. A downgrade needs its
pre-upgrade state copy; restoring that copy loses subsequent job records and
must wait until those jobs are reconciled. Preserve the current state as well.

Restore only with the service stopped and a compatible application version.
After restore, revoke stale credentials and verify enrolled identities. Old
resource samples do not prove that a machine is currently reachable.

## Removal

Stop and disable the user service before removing the environment and unit file.
Remove its matching desktop entry and launcher configuration, then run
`systemctl --user daemon-reload`. These steps do not remove enrolled state.
Keep the state directory unless its deletion is explicitly intended. The helper
remains at `~/.local/lib/ficc/node.pyz` on each enrolled node. Remove that exact
file through an ordinary authenticated SSH session if it is no longer required.
Do not delete unrelated files in the parent directory.
