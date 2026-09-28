# Containers

Install and enable the supplied `org.ficc.containers` package. Select enrolled
Linux systems for its workspace panel. The host runs fixed provider requests
through each system's SSH account. Module processes cannot access provider
sockets, credentials or network endpoints.

## Connections

Open **Workspace**, then **Container providers**. Select an enrolled system and
provider. Choose the account socket or an explicit Kubernetes context and namespace.
Select **Probe and add profile**. The table shows the verified provider version.

Profile registration does not grant a module access. Grant the package its selected
systems separately, then add its panel to a workspace.

Use **Disable profile** to stop new provider requests. **Probe and enable** checks
the connection again. Remove all action receipts before removing its profile or
changing its connection.

| Provider | Registered connection | Supported operations |
| --- | --- | --- |
| Docker | Rootful `/run/docker.sock` or current-account `/run/user/UID/docker.sock` | Inventory, state, logs, start and stop existing containers |
| Podman | Current-account `/run/user/UID/podman/podman.sock` | Inventory, state, logs, start and stop existing containers |
| Kubernetes | Named context and namespace from the account's private `~/.kube/config` | Pod, Deployment and StatefulSet inventory; pod logs; Deployment and StatefulSet scale |

Install the current FICC node helper before registering a connection. Enable
the provider socket under that account. Docker rootful access gives the SSH
account substantial host authority. FICC does not expose that socket to modules.

Kubernetes uses verified HTTPS with embedded CA data. Use an embedded client
certificate and key, or one static bearer token. Authentication plugins,
impersonation, external credential files, proxies and TLS overrides are refused.
The configuration must be a private regular file, no larger than 256 KiB.

JSON works directly. YAML requires an installed `kubectl` for configuration
conversion only. Credentials remain in the node helper.

## Permissions and controls

`container:read` is required. Logs require `container:logs`. State changes
require `container:power`. Both are optional package grants. The caller must
also have the corresponding current system scopes. Revocation or package disable
blocks subsequent requests.

Changed SSH or provider identities require a new
profile check.

Select stable workload IDs in the table. Sorting, filtering and paging preserve
selection. Select a pod for Kubernetes logs. Enter a container name when the pod
has more than one container. Select Deployment or StatefulSet rows to scale.
Replica counts are limited to 0 through 64.

A preview freezes identity, configuration and observed state for 120 seconds.
Confirm it in the host. Docker and Podman stop allow 10 seconds for exit, then
force the container to stop. Other clients can race the pre-action state check.
Kubernetes scale tests UID, resource version and scale data in one JSON patch.

Batches are not transactions. FICC does not create, delete, prune or execute
commands in workloads.

Keep the same idempotency key when retrying a submitted confirmation. Closing
the HTTP waiter does not cancel its owned dispatch task. Accepted requests need
an observed result. A lost response remains unknown until a receipt proves its
outcome, or the operator explicitly resolves it. Matching current state alone
does not prove that an unknown request succeeded.

## Bounds and recovery

Requests select at most 64 workloads or systems. Inventory contains at most
256 rows across profiles; the supplied table requests 128. Logs have an aggregate
256 KiB source-byte limit and a smaller, visibly marked display limit. Broker
reads and previews have an eight-second host deadline within the module budget.
Refresh after a timeout. Profile probes use a separate host request.

Mutation requests allow 30 seconds for a provider HTTP response, within a
45-second helper and 47-second SSH deadline. Large or slow batches can complete
partially. Saved per-workload receipts retain the known results. Shutdown waits
for dispatch cleanup and retains uncertain outcomes.

The controller and each account retain at most 1024 operation receipts. Remove
completed history from **Container action history** in the workspace panel.
Select **Inspect operation**, then confirm **Remove operation receipt**. This removes history only;
it does not delete workloads. Active and unknown outcomes require observation
or explicit resolution first.

Interrupted receipt removal retains its proof and
must be retried. Remove a profile's receipts before removing the profile.
Backup requires all operations to be terminal and all receipt cleanup complete.
Restore disables profiles and removes package grants. Probe and enable each
profile, then grant the required package permissions again.

A panel, workspace or package with operation receipts cannot be removed. Rename
and security disable remain available. Regrant access to inspect and remove receipts.
History is available after a page reload. It never automatically repeats an action.

The provider contract supports Docker API 1.24 through 1.51 and Podman 4 or 5.
Negotiation also respects the server's minimum API. Qualification covers
rootless Docker 29.1.3, rootless Podman 5.7.0 and Kubernetes 1.34.0. Rootful Docker
and other provider versions require their own deployment checks.
