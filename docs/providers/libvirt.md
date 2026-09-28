# Libvirt VM module

The `org.ficc.libvirt` runtime package provides inventory, start, graceful shutdown
and a request for a host-owned VNC viewer. Install and enable the package, grant
its permissions for selected enrolled systems, then add it to a workspace. The
host must also configure one libvirt profile for each selected system.
Inventory requires `vm:read`. The package declares `vm:power` and `vm:console` as
optional permissions, so an inventory-only panel does not require either grant.
Their actions remain unavailable until explicitly granted for the selected system.

## System prerequisites

The enrolled Linux SSH account needs the current FICC node helper, the distribution
`python3-libvirt` package and permission to access the selected local libvirt
connection. A profile chooses only `system` (`qemu:///system`) or `session`
(`qemu:///session`). These are separate inventories. The helper does not run sudo,
install packages, start a daemon, accept an arbitrary URI or execute a shell command
from a module. Configure the account's libvirt access outside the module first.

Read/write libvirt access can confer broad administrative authority on that account.
Durable receipts require account-owned, non-symlink ancestors under `.local/state`;
group/world-writable ancestors are refused. The final receipt directory is private
with mode 0700 and regular receipt files have mode 0600. FICC reports this prerequisite
without changing existing directory permissions automatically.
See the official [connection URI](https://libvirt.org/uri.html),
[Python binding](https://libvirt.org/python.html) and
[authentication](https://libvirt.org/auth.html) documentation.

The host checks the current caller scope, exact installed package grant, workspace
instance authority, enrolled SSH destination and profile revision before dispatch.
`vm:read`, `vm:power` and `vm:console` are separate system grants and caller scopes.
Power previews also require read authority. Profile setup requires `nodes:write`.
Modules receive inventory data and opaque confirmation/viewer references, without
SSH keys, paths, libvirt XML, console addresses or credentials.

## Inventory and power actions

A VM resource ID consists of its profile ID and libvirt domain UUID. A VM name is
display text, never an execution identifier. The inventory is capped at 4096 VMs
per connection. A page contains at most 64 VMs. The supplied module divides
its 128-row table limit across one to 64 systems.

The result includes the total, next offset,
truncation flag and an inventory digest. Inventory is a live observation: if the
digest changes between pages, refresh from offset zero. Each request has a finite
deadline, so a large or slow batch can report a partial refusal or timeout.

Select VMs and request a start or graceful-shutdown preview. The host displays the
exact VM names, system IDs, states and action before confirmation. A preview expires
after 120 seconds. Confirmation freezes UUIDs, definition digests, observed states,
profile revisions, package authority and the caller.

The node rechecks each VM
before applying the selected fixed libvirt API. A state or definition change
refuses that target. Batches are not transactions; each target has its own outcome.

The controller saves an operation before dispatch, and the node saves and syncs an
intent receipt before each provider call. An idempotency key never repeats a
provider call. A transport loss produces `unknown`; reading the durable receipt
can recover a provider acknowledgement. Observing a desired VM state alone does
not turn an unknown action into success.

An acknowledged action becomes `observed`
when its requested active/off state is seen. This records observation, not proof
that this action caused the state. Graceful shutdown has no forced-power fallback.

The host can close an accepted or unknown outcome as `resolved` after explicit
operator inspection and confirmation. Accepted outcomes require a fresh state
observation. This does not establish success or change the original node receipt.
For example, a guest can ignore a shutdown request before its power handler starts.
Closing that record permits a new confirmed action; it does not replay the request.

Unfinished operations block new power actions on the same VM and backup. Receipt history is bounded
to 1024 operations on both controller and node. No automatic deletion or replay
occurs after restart. There is no snapshot, force-off, reset, migration, storage,
network or guest-command primitive in this initial libvirt adapter.

The host can explicitly remove an operation receipt after every target is
`observed`, `refused` or `resolved`. Removal requires current read and power grants.
It sends the original frozen intent and exact terminal outcomes to each enrolled
node, without calling a VM lifecycle API. The node saves the terminal proof before
removing its receipt.

The controller records each acknowledgement durably and
removes its history row only after every node acknowledges. A lost acknowledgement
leaves removal pending; retrying removal does not repeat a VM action. Pending
removal blocks backup and restore. Receipt removal does not delete a VM.

Remove every retained receipt before changing a profile's connection or removing
its profile, workspace panel or package. Security disable and grant revocation
remain available. Re-enable the same profile and restore its required grants to
resume receipt removal. Revision-only re-enablement can recover existing history;
new lifecycle requests still require a fresh confirmation. Profile removal requires
`nodes:write` and `vm:read` caller scopes. Committed previews are consumed, so
removing their history does not allow the original confirmation to dispatch again.

## Console contract

The first transport is VNC. The node finds a VNC graphics device in the selected
domain and calls `openGraphicsFD(index, 0)` on a local read/write libvirt connection.
The returned descriptor is bound to that domain's graphics backend. It avoids a
TCP-port lookup/rebind race and does not bypass VNC authentication. The host viewer
must handle or refuse the negotiated RFB authentication without exposing secrets to
the module. Password credential entry is not supplied by this package.

See the official [domain graphics APIs](https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainOpenGraphicsFD)
and [graphics configuration](https://libvirt.org/formatdomain.html#graphical-framebuffers).
SPICE, VMRC and RDP are different protocols and are not represented as VNC.
This descriptor reports `audio: false`; it does not imply VM audio support.

Only a host-controlled viewer reference reaches the module. A fresh attach checks
the caller, package, instance, profile and domain again. The fixed SSH stream helper
opens no listening socket and emits a bounded ready header before raw RFB data.
The host stream supervisor must continue checking authority, stop its SSH process
group on revoke/disconnect and enforce its viewer session limits. Console acquisition
has a six-second kernel deadline and the node relay has a one-hour maximum lifetime,
with at most 64 KiB queued in either direction. The common host viewer owns
fullscreen, focus escape, clipboard/file restrictions and reconnect behavior.

## Host integration interface

`VMs(service)` uses the service's store, SSH transport, authorization and module
registry. The host supplies a synchronous `check()` closure for current caller,
package revision and persisted workspace-instance authority. Keep that closure
active for the entire request and console lifetime.

| Method | Contract |
| --- | --- |
| `set_profile(actor, node_id, connection, enabled=True)` | Owner setup; returns the saved profile. |
| `remove_profile(actor, node_id)` | Async host removal after all referenced receipts are removed. |
| `profiles(actor)` | Returns profiles visible under nodes/read and VM/read scopes. |
| `broker(actor, call, instance_id)` | List, status, preview or operation reads; no commit, resolve or console address. |
| `preview_for_confirmation(actor, preview_id, check)` | Revalidates the retained preview for the host confirmation surface. |
| `commit(actor, preview_id, key, check)` | Async host-confirmed lifecycle request; returns public per-VM outcomes. |
| `operation(actor, operation_id, check)` | Async receipt/status reconciliation without replay. |
| `resolve(actor, operation_id, vm_ids, check)` | Async explicit host resolution of accepted or unknown targets. |
| `forget(actor, operation_id, check)` | Async host-confirmed terminal receipt removal; returns `{removed:true}`. |
| `console(actor, digest, instance_id, node_id, vm_id, check)` | Async private host descriptor; exchange it for an opaque viewer reference. |
| `console_command(descriptor, check)` | Async `(ssh_argv, header_bytes)` for the host stream supervisor. |

The console helper replies with `{"version":1,"ready":true}` followed by a newline
and the RFB byte stream. A nonzero exit or missing ready header is a failed attach.
The host must never treat descriptor fields supplied by a module as trusted input.

Broker parameters are `{offset?,limit?}` for `vm.libvirt.list`, `{vm_ids}` for
`vm.libvirt.status`, `{action,vm_ids}` for `vm.libvirt.preview`, and `{operation_id}`
for `vm.libvirt.operation`. Invocation targets are enrolled node IDs; selected VM
IDs must belong to those exact current profiles. The controller handles
`vm.libvirt.console` with exactly one selected VM and returns only `viewer_ref`.
Unknown fields are rejected. Destructive confirmation is not a module boolean.

Preview data is `{preview_id,expires_at,action,vms}`; each VM has `node_id`, `vm_id`,
`name` and `state`. Only the first target carries the complete VM array; later
targets carry empty arrays. Public operations have `id`, `action`, `instance_id`,
timestamps, `cleanup` and targets containing `node_id`, `vm_id`, `state`, optional `error`,
`observed_state` and `observed_at`. Only the first broker target carries the complete
operation, with null for later targets. This keeps batch responses bounded.
`cleanup` is null before removal, or `{acknowledged,total}` while removal is pending.

`module_vm_store.initialize(db)` creates the two tables listed in its `TABLES`
constant. `validate_records(profile_rows, operation_rows, node_ids)` checks exact
column identities, bounded JSON records, intent digests, retained node references
and quiescence. Terminal target states are `refused`, `observed`, `resolved`.
`queued`, `dispatching`, `accepted`, `unknown` and any pending cleanup block backup and restore.

Restore must disable every profile and increment its revision; module restore
separately disables packages and removes grants. No restored operation is replayed.
`Records.retained(node_id)` includes profiles and operation history for node-forget
checks. The host owns schema migration, backup integration and route composition.
