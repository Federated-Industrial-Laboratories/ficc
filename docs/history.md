# Archive completed history

FICC keeps completed operation receipts to make retries safe. The controller and
node histories have finite limits. Use an explicit archive to start a new
execution epoch after all work has stopped. FICC does not expire or delete
history automatically.

Before maintenance, upgrade and refresh every enrolled node helper. Complete or
cancel jobs and transfers, finish pending file cleanup, close terminals, and
explicitly stop persistent tmux sessions. A detached terminal is still open.
Stop FICC with `ficc stop`, then preview the archive:

```sh
ficc archive-history --state-dir "$HOME/.local/state/ficc" --output "$HOME/ficc-archive-001"
```

The preview lists controller record counts and every enrolled node's identity,
SSH profile, account, host and pinned fingerprint. The output must be a new
private directory outside controller state. It is not created by the preview.
Use the same command with `--confirm` to archive. If you use a separate SSH
configuration, pass its path with `--ssh-config` in both commands.

The confirmed command holds the controller's exclusive lock. It refuses active,
unknown or unreconciled work, prepared downloads, pending cleanup, unsafe files,
and nodes whose history cannot be verified. Every node must be reachable through
its retained pinned SSH identity. Nodes require `tmux` to prove their old terminal
namespace has no sessions. Each retained job's exact systemd unit must be absent
or inactive with its recorded identity and no populated cgroup.

## Archive contents

The local directory contains:

- `controller/`: a verified [portable backup](backup.md) of the stopped state,
  with credentials removed. It contains recorded history, trust, roots and file
  reference metadata, but no registered tree content or remote job output.
- `cli/`: command receipts with actor, command key, digest and operation identity.
  Credentials and local authentication grants are omitted.
- `retirement.json`: hashes that bind local receipt retirement to archived copies.
- `archive.json`: the archive identity, original and next controller identities,
  record counts, node identities and each node archive's path and manifest hash.

On each node, `~/.local/state/ficc/history/ARCHIVE_ID/` holds `manifest.json`, a
recovery journal, completed managed job requests and results, retained stdout and
stderr, and closed file and terminal receipts. All members have size bounds and
SHA-256 hashes. FICC moves only its own validated records; it never walks
registered file roots. Remote job output stays on that node. Back up completed
archives separately if you need copies elsewhere.

After all nodes confirm completion, one controller transaction rotates the job
and terminal controller identities, revokes all credentials, clears archived
execution records, and clears cached observations. Node IDs, enrolled SSH trust,
approved profiles, registered roots and file reference keys remain. Private lock
files remain at their original paths. Start FICC, refresh the nodes, obtain fresh
credentials and use new command keys before issuing work.

Archives continue to consume storage. New jobs still need sufficient physical
free space. There is no archive expiry or deletion command; retain and manage
completed archives through your normal backup policy.

## Resume after an interruption

If the command fails, keep the original state and output directories. Correct the
reported connectivity, storage, helper or closed-work issue, then repeat the
same command with the same `--output`, `--ssh-config` and `--confirm`. Do not remove
`archive.pending.json` from controller state. While that journal exists, FICC
refuses startup before opening or migrating its database.

After the first intent is published, retries retain the archive ID and next
controller identities. A lost node reply
resumes its existing archive. Each moved record must match its saved hash;
missing unarchived records, unexpected files or changed content stop recovery.
The controller changes its identities only after all nodes acknowledge their
archives. Local receipts are removed only after their archived copies verify.
A completed command can be repeated with its original output to show the same
result without retiring another epoch.

Archive journals use reserved `.archive-write-NAME.tmp` siblings. Under the
maintenance lock, a retry removes only the matching bounded, private regular
scratch file and recomputes that write from the last published journal. No later
effect can precede completion of a journal write. Other unexpected files or
unsafe scratch links are retained and cause refusal. Do not remove these files
manually. Directory entries through the node archive's parent chain are synced
before source records move or namespace ownership changes.

Restoring an earlier controller backup does not undo an archive on a node. Its
old controller identity cannot take ownership of the new node job namespace.
Keep the original controller stopped and reconcile archive and node identities
before using an earlier backup. Do not edit ownership files to force rollback.

Legacy history can reference a machine that was previously forgotten. Archival
refuses that history because it cannot safely establish every old remote
identity from the remaining records. Enrolling the same host again creates a
new node ID and does not repair this mismatch. Preserve the current state and
archives, and reconcile the original enrollment from a retained backup together
with the remote history before retrying. There is no automatic identity recovery
or deletion bypass. New node deletion requests require that node's retained
execution history to be archived first.
