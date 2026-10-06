# Agent observations

[Contents](README.md) | [Coding agents](agents.md) | [Security](../SECURITY.md)

Use the observation interface to inspect permitted Linux SSH machines from a
continuing agent session. Each resource request names one machine. The agent
can inspect several machines without moving its runtime or changing its conversation.

This initial interface covers the controller's enrolled SSH inventory.
Contributor nodes and Windows provider catalogs use separate APIs and are not
included in these observation responses.

The interface provides JSON through the CLI and authenticated HTTP API.
It reads the controller's existing samples. It does not start a remote command,
refresh a machine, read files or retrieve logs.

## Approve access and disclosure

Choose an existing FICC identity and project. Assign the permitted machines
under **Access**, then grant `observations:read` and `observations:resources`
to that project's member. Grant only `observations:read` when resource
measurements are not needed. See [project access](identities.md).

These separate observation permissions approve release of the selected
fields to the receiving agent. Before granting them, establish that the agent
runtime and its inference provider may receive those fields. A machine label,
device identifier or resource sample can contain sensitive operational details.
Ordinary read access does not add this disclosure permission automatically.

If a runtime policy is active, use a package that permits these operations.
The supplied policy presets include an `agent-observer` role. Assign that role
explicitly. It restricts existing membership and credential permissions; it
cannot add a missing grant. An older active package may deny the new permission.
Follow [policy installation and activation](policies.md) when updating it.

As the controller owner, issue a short-lived, machine-limited token:

```sh
ficc token-create --subject USER_ID --project PROJECT_ID \
  --label 'Agent observations' --scope observations:read \
  --scope observations:resources --node NODE_ID \
  --lifetime 3600 --output /home/operator/.config/ficc/observation.token
```

Create the private parent directory first. Repeat `--node` for each approved
machine. Include only observation scopes. The observation endpoints reject
broader tokens and browser sessions. Save the returned credential ID for
revocation. The token file contains
the secret; never pass its contents in command arguments, a prompt or a log.
Provision that file privately on the machine that will run the observation CLI.
Do not give the agent access to the controller owner's private control socket.

## Configure the observation client

The operator creates a private JSON connection file:

```json
{
  "controller": "https://console.example.com",
  "token_file": "/home/operator/.config/ficc/observation.token"
}
```

Save it as `/home/operator/.config/ficc/observation.json` with mode `0600`.
The connection and token files must be regular files owned by the CLI account.
Use a protected directory and do not use symbolic links. HTTPS certificate
verification is required. For a local controller, an exact loopback HTTP origin
such as `http://127.0.0.1:8170` is supported. A remote controller needs FICC's
configured [HTTPS gateway](remote-access.md).

The connection fixes the controller and credential. Tool arguments select an
operation and, for readings, an explicit machine ID:

```sh
ficc observe --connection /home/operator/.config/ficc/observation.json nodes
ficc observe --connection /home/operator/.config/ficc/observation.json \
  resources --node NODE_ID
```

Register these commands with the agent runtime's normal tool interface. Preserve
the connection path and pass machine IDs as separate arguments. Successful
commands write JSON to standard output. A failed request returns a nonzero exit
status. The client does not obtain an owner credential or change credentials
when access is denied.

## Returned fields

Inventory contains permitted machine IDs, labels, states and sample freshness.
It excludes SSH destinations, accounts, profile configuration, host keys and
raw collection errors. Resource responses identify their machine and include
the saved resource measurements with freshness information.

Measurements include CPU usage/count/load, memory, uptime, storage mount names
and capacities, network interface names and counters, and GPU identifiers,
names, memory, utilization and temperature. Approve this complete field set;
the interface does not classify or redact individual labels automatically.

Missing values remain `null`. A stale sample retains its stale flag and age;
it must not be treated as current capacity. Resource access does not reserve
capacity. Machine labels, device names and other returned strings are untrusted
data, not instructions or approval.

## Authority and records

Each request checks the current identity, project, credential, machine limits
and runtime policy. Credentials expire and remain revocable:

```sh
ficc token-revoke CREDENTIAL_ID
```

The controller records authenticated observation access with the actor,
credential, project, operation and target. It does not put observation payloads
or credentials in those audit events. An authorized disclosure record does not
prove that the caller received or processed the response.

Revocation prevents later reads. It cannot recall output already received by
the agent or prevent its later disclosure. The interface governs operations
performed through FICC. The external runtime retains its tools, model settings,
conversation and approval behavior. Processes sharing the client account can
access that account's files and authority; this interface is not an account
sandbox or an inference gateway.

## HTTP endpoints

| Method and path | Required scopes | Result |
| --- | --- | --- |
| `GET /api/v1/observations/nodes` | `observations:read` | Permitted machine inventory |
| `GET /api/v1/observations/nodes/{node_id}/resources` | `observations:read`, `observations:resources` | One permitted machine's saved resource sample |

Observation-only credentials are restricted to these two GET endpoints.
They cannot retrieve general project or session metadata, inventory, refresh,
files, logs or execution results. Project machine assignments, credential
machine limits and current policy decisions apply to each observation request.

Use the existing bearer authentication and error contract in the
[API guide](api.md). A caller-supplied agent name or natural-language request
does not establish authority.
