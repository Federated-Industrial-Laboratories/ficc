# Controller backup and restore

FICC exports a stopped, quiescent controller into a private directory bundle.
The backup command holds the same exclusive state lock as service startup before
opening the database. A running controller or another maintenance command causes
an explicit refusal. This is an offline maintenance operation.

1. Finish or cancel managed jobs. Reconcile every unknown outcome.
2. Stop persistent terminals and close other terminal sessions.
3. Finish transfers or explicitly discard their retained partials. Discard prepared
   downloads and clean retained partials from completed transfers.
4. Stop FICC with `ficc stop`, or stop the process that runs `ficc serve`.
5. Export to a new directory outside the state directory:

```sh
ficc backup --state-dir "$HOME/.local/state/ficc" \
  --output "$HOME/ficc-backup"
```

The output parent must already exist. Use the state path configured for the
launcher if it differs from this example. Do not restart the controller until
the command completes. Any recorded active or unknown work, prepared download,
retained partial, or unresolved local receipt prevents export.

The bundle contains `manifest.json`, `state.sqlite3`, pinned SSH public host-key
files under `trust/`, and local file-operation receipts under `files/`. The
manifest records the format, application version, schema, controller identity,
and every member's size and SHA-256 digest. The database is copied with SQLite's
backup API and checked for integrity. Credentials, session digests, and CSRF
values are removed; secure deletion and database compaction remove their free-page
copies. No database journal or WAL enters the completed bundle.

Controller, node, registered-root, job, terminal, transfer and operation identities
are preserved, together with trust metadata, settings and bounded audit history.
Treat bundles as private: they contain host names, account names, paths, command
arguments, file names, reference-signing material, and operation history. File
hashes detect corruption; they are not a signature proving a bundle's origin.

Registered file-tree contents, remote job output, remote helper state, remote tmux
sessions, SSH private keys, external SSH configuration, launchers and systemd units
are excluded. Back up those resources separately. No external file tree is read,
copied or changed by this command. Existing node receipts remain on their nodes.
A snapshot does not contain work performed after it was made.

Credential-bearing CLI submission files under `cli-requests/` are excluded.
Each must match a retained, closed operation before export; unresolved submissions
cause refusal. The operation and its identity remain in the database and can be
read after restore. Use new request keys for new work after restore; do not retry
old submissions from a separate copy of their CLI receipts.

## Restore into a new state directory

Check the nodes with the original controller or ordinary SSH. Verify that all
remote work performed since the backup is idle and that no retained process or
partial needs recovery. Stop the original controller. Never run the original
and restored controller at the same time: they share controller identities.

```sh
ficc restore --backup "$HOME/ficc-backup" \
  --state-dir "$HOME/.local/state/ficc-restored" \
  --confirm-remote-idle
```

`--confirm-remote-idle` provides the operator's acknowledgement of that check.
Restore cannot determine later remote effects from a snapshot. It does not
contact nodes or dispatch work. It verifies the manifest, member paths, sizes,
hashes, database schema, integrity, and quiescent records before publishing a
new private directory. An existing destination is never replaced. Symbolic
links, hard-linked files, unexpected members and non-private member permissions
are refused. Keep bundle directories at mode 0700 and files at mode 0600 when
moving a bundle between accounts or machines; the restoring account must own them.

Credentials are removed again during restore. Cached observations and capabilities
are cleared, so restored inventory cannot appear fresh. Start the restored state
explicitly, refresh the machines, and issue new credentials as needed:

```sh
ficc serve --state-dir "$HOME/.local/state/ficc-restored"
# In another terminal:
ficc open --state-dir "$HOME/.local/state/ficc-restored"
```

Preserve the original approved SSH profiles and configuration, or provide the
matching `--ssh-config` when starting the restored service. Registered roots retain
their original absolute paths and object identities. A moved or recreated root
requires explicit registration; restore does not remap paths or override identity
checks. Reinstall the desktop launcher with the restored state path if it should
become the normal controller. Keep the original state stopped and retained until
the restored console has been checked.

## Format and limits

Bundle format 1 supports state schema 4 directly. Incompatible schemas are refused;
restore does not migrate an archive. For an older application, retain a complete
stopped copy of its private state before using the supported application upgrade
path. Then stop and export with the current schema. A portable export does not
replace the pre-upgrade copy used for application rollback.

The maximum database is 256 MiB, the total member data is 512 MiB, and the manifest
is 2 MiB. There are at most 8,194 regular members. Each local receipt is at most
256 KiB and each pinned host-key file is at most 16 KiB. Existing product limits
on nodes, roots and operation history also apply. SQLite work has a 60-second
progress deadline; a blocked filesystem operation can still wait for the kernel.
The command refuses excess data instead of producing a partial archive.

Each command stages new private files, flushes them, and publishes the completed
directory atomically without replacing another path. Handled failures remove the
staging directory. A process crash can leave a private `.ficc-maintenance-*`
directory beside the chosen destination; it is incomplete and must not be used
as a backup. Once no maintenance process remains, the owner can remove it. Keep
sufficient free disk for the bundle and SQLite compaction, which needs additional
temporary space. Normal service startup acquires state ownership before schema
creation or migration, so a second service cannot modify a live database.

Agent and bus tables are included. Active or uncertain coding agents and unresolved
bus deliveries prevent backup or restore. A restored closed agent record preserves
its identity and never restarts the agent. Export and archive its closed run before
retiring terminal history with `archive-history`.
