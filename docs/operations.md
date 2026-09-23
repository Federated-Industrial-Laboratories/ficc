# Operation and maintenance

Run FICC as a normal local account. Its state defaults to
`$XDG_STATE_HOME/ficc`, or `~/.local/state/ficc` when XDG_STATE_HOME is unset.
The directory must be owned by that account with mode 0700. The control socket,
database and pinned host keys stay private. Do not reuse demo state for live work.

The foreground `ficc serve` process stops with Ctrl+C. This observation version
does not own remote workloads. Stopping it does not stop their processes.

## User service

Install the wheel and runtime requirements in a virtual environment at
`~/.local/share/ficc/venv`. Copy packaging/ficc.service into
`~/.config/systemd/user/ficc.service`. Adjust ExecStart to use approved profiles
or an explicit trusted SSH configuration before starting the service.

```sh
systemctl --user daemon-reload
systemctl --user enable --now ficc
systemctl --user status ficc
```

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

Restore only with the service stopped and a compatible application version.
After restore, revoke stale credentials and verify enrolled identities. Old
resource samples do not prove that a machine is currently reachable.

## Removal

Stop and disable the user service before removing the environment and unit file.
Keep the state directory unless its deletion is explicitly intended. The helper
remains at `~/.local/lib/ficc/node.pyz` on each enrolled node. Remove that exact
file through an ordinary authenticated SSH session if it is no longer required.
Do not delete unrelated files in the parent directory.
