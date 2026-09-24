# Files and verified transfers

Files shows two independent locations. Each location selects the controller or
an enrolled machine, then a registered folder. The controller pane is server
storage; the Upload picker selects files from the browser's computer.

The local owner registers existing folders through the private CLI socket:

```sh
mkdir -m 700 "$HOME/ficc-workspace"
ficc root-add --label Workspace --path "$HOME/ficc-workspace"
ficc root-add --label Inputs --path /srv/cluster-inputs --node NODE_ID --read-only
ficc root-list
ficc root-remove ROOT_ID
```

Use actual node and root IDs. The remote path is evaluated on that node.
Registration requires a current helper. Upgrade it explicitly with the helper
upgrade action before registering a remote folder. No home folder or existing
project tree is registered automatically. A root cannot be removed while an
active or uncertain file operation refers to it.

A root keeps its directory identity. Replacing the directory makes the root
unavailable; register the intended replacement explicitly. Symbolic links in
paths and mount crossings below the root are refused. The file adapter requires
Linux openat2 on x86_64 or aarch64 and compatible filesystem rename semantics.
Unsupported platforms fail closed. Descriptor mode changes additionally require
Linux fchmodat2 with AT_EMPTY_PATH support (Linux 6.6 or later); unavailable
mode changes fail without using a pathname fallback.

## Browse and edit

Each pane has an address bar, an Up button and a separate scrollable table.
Select a column heading to sort the current page. Drag its divider to resize it;
focused dividers also accept arrow keys, Home and End. Sorting retains selection
by entry identity. The filter searches names on the current page, clears old
selection and limits Select page to the visible entries. It does not search the
whole directory or subsequent pages.

Click a row to select it. Ctrl or Command toggles a row; Shift selects a range.
Arrow keys move row focus, Space toggles selection and Enter opens a directory
or previews a supported file. Changing the machine, location, directory or page
clears selection and the page filter. The status bar shows the selection count.

Entries show type, byte size, modification time, numeric owner/group and mode.
Names with invalid UTF-8 or control bytes use escaped display text. Selection
uses an opaque identity, so changing a displayed name cannot redirect an action.
Listings contain at most 200 entries per page and refuse directories exceeding
10,000 entries. Changed cursors require a refresh. Text previews are at most
64 KiB. File content is never rendered as an HTML document.

Create directory, Rename, Change mode and Delete show the selected effects before
confirmation. Rename does not overwrite. Delete removes selected regular files,
links as links, or empty directories; it never recursively removes a directory.
Mode changes allow ordinary rwx bits on account-owned objects. Ownership, ACLs,
setuid/setgid/sticky modes and mode changes on multiply linked files are refused.
A batch contains at most 64 entries and retains individual results.

## Transfer and recover

Copy to the other pane prepares verified transfers. Node-to-node bytes pass
through the controller in bounded chunks. Existing destinations require explicit
overwrite consent. The destination is staged privately on its filesystem,
verified, synced and published atomically. A failed transfer does not advertise
success. An uncertain publish remains visible for recovery.

Upload selects browser files and uses bounded, SHA-256 checked chunks. Resume
requires the original file again and verifies its accepted prefix; matching
name and size alone are insufficient. Source changes require a new transfer.
Cancel and cleanup are separate from deleting a completed destination.

Download first prepares a verified private controller spool, then offers an
attachment to the browser. The displayed hash verifies the server's preparation;
FICC cannot confirm that the browser saved the file successfully. Ordinary
controller-root copies remain the durable option for controller storage.

Limits are 16 GiB per file, 64 GiB reserved partial/spool storage, 64 pending
items and four active file channels. Interrupted partials retain their storage
reservation until explicit cleanup. No automatic eviction removes recovery data.
Completed download spools retain their reservation until Discard download.
If a verified destination retains staging files, Clean retained partial removes only
those staging files. The committed destination remains intact. Retained artifacts
must be cleaned before their roots can be removed or helpers replaced.

## Access boundary

Scopes files:read, files:write, files:mode and files:delete are independent.
Transfer history requires read permission on each item's source and destination
roots, except the private download spool. Mutation responses include receipts
only for the items explicitly requested under the required action permissions.
Use repeated `--root ROOT_ID` options with token-create to restrict roots,
and repeated `--node NODE_ID` options for remote machines. A node-restricted
credential cannot use controller roots. Read-only roots refuse mutations even
for the owner. Current grants are checked again during transfer and publication.

Roots provide API access control inside a trusted operating-system account.
They are not a sandbox against other programs with that account. A descriptor
still refers to an opened object if another program moves its directory; an
external rename, hard link or privileged mount operation can change its pathname
or aliases. Detected changes are refused, but continuous pathname confinement
against such writers is not promised. Keep registered namespaces operator-managed.
Shell and managed-job execution have the full authority of the remote account.
