# System administration

Install the supplied System administration module through the module installer.
Register a systemd profile for an enrolled SSH account. Select its user or system manager.
The system needs systemd 248 or newer, busctl, journalctl and the current FICC node helper.
A user manager must already be active. The profile does not change system policy.

Grant `admin:read` to selected systems and `workspace:read` to the workspace.
Add `admin:logs`, `admin:services` or `admin:power` only when required.
The caller also needs the matching scopes. Each request checks current grants and system identity.

The table shows system uptime and available memory, or installed service states.
Select service rows to read logs or preview start, stop and restart actions.
Select system rows from system-manager profiles to preview reboot or poweroff.
Power actions use existing account policy and check inhibitors. The module cannot confirm an action.
The host shows the exact action, resources and effects before confirmation.

Service actions use the saved unit configuration. Dependencies and configured stop timeouts apply.
Systemd can terminate processes when those timeouts expire. The host adds no force option.
The helper checks the boot, definition and state immediately before dispatch.
External changes can occur after this check; the action is not an atomic compare-and-change.

A service receipt becomes observed only after a matching state is read.
Start and restart also require a new service invocation identity on the same boot.
A short-lived or oneshot service can require explicit inspection and resolution.

An accepted power request means queued, not complete. SSH loss does not prove a power state.
Power receipts require explicit owner resolution after inspection. Resolution does not establish success.

Retry an interrupted commit with the same idempotency key. FICC does not replay its durable intent.
Unknown outcomes block another action on the same resource until resolved.
Remove receipt deletes operation history after each node acknowledges cleanup; it does not delete services.
A partial cleanup retains its controller proof for retry.
A powered-off system must return online before its node receipt can be removed.

Profiles with receipt history cannot be removed.
Security disable and grant revocation remain available.

Receipt directories under the enrolled account's `.local/state/ficc/admins` must be private.
Their ancestors must be owned, direct directories without group or other write access.
FICC refuses unsafe existing directories and does not change their permissions.

Each action selects at most 64 distinct resources. Inventory returns at most 256 rows across profiles.
The default table requests 128 rows and displays an offset for more rows.
Logs use at most 200 lines per service and 256 KiB of source bytes across the selection.
The display limits logs further.

Provider reads share an eight-second broker deadline.
The node mutation limit is 20 seconds; the SSH envelope is 22 seconds.
There are at most 64 profiles, 64 previews and 1,024 retained operation receipts.

This provider supports Linux systemd. It has no arbitrary command, unit edit, enable, mask or force action.
