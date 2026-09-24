<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Coding agents

[Contents](README.md) | [Project README](../README.md) | [Previous: Terminals](terminals.md) | [Next: Agent bus](bus.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

FICC launches an explicitly registered command on an enrolled Linux node. The
native agent interface appears in a managed tmux terminal in the Terminals page.
The controller owns the agent identity, run enrollment and bus delivery records.
An existing shell is never repurposed by typing launch commands into it.

Install and sign in to the selected agent on the node before registration. FICC
does not install coding agents, copy provider credentials or select a model.
Register an existing absolute executable and workspace from the local owner CLI:

```sh
ficc agent-profile-add --node NODE_ID --name 'Project agent' --adapter omp \
  --workspace /home/operator/project --argv-json '["/home/operator/.local/bin/omp"]'
ficc agent-profile-list
```

Use `--adapter codex` for Codex or `--adapter generic` for another command. An
explicit interpreter is also supported:

```json
["/usr/bin/node", "/home/operator/.local/bin/codex"]
```

The JSON array is passed as command arguments; message text never becomes shell
syntax. Keep adapter arguments compatible with the agent's native subcommands.
The profile preview shows the exact executable, arguments, account, workspace,
version and delivery method. Changed versions require a newly registered profile.
A missing executable produces a registration error rather than installing it.
Remove an unused profile with `ficc agent-profile-remove PROFILE_ID` after its
retained runs have been archived.

In Bus, create a run. In Agents, select that run and a registered profile, review
the preview and explicitly launch. The returned terminal ID names the same
session in Terminals. Closing a tile detaches its viewer. Stop Agent stops its
exact tmux session. An interrupted launch remains unknown; Reconcile only checks
the saved identity and never creates a replacement. Node forgetting and helper
upgrade refuse active or uncertain agent work.

## Runtime adapters

OMP 18.1.12 loads one packaged FICC extension through an explicit extension
argument. Its `ficc_bus` tool reads the registered inbox and submits explicitly
addressed replies. Direct messages use visible custom messages labelled with
sender, run, message and delivery IDs. The extension records submission separately
from an observed custom message inclusion event. Switching or branching a session
suspends direct admission until the operator explicitly rebinds the observed
session identity. Pending messages are not silently replayed after an interruption.

Codex 0.156.1 uses an owned private Unix app-server and attaches its native TUI to
the exact thread returned by `thread/start`. The bridge uses a bounded WebSocket
connection and the version-specific queue API. Queue admission can start agent
work. The native TUI handles runtime approval requests; FICC never answers them.
The queue's client message ID is correlation data, not an exactly-once guarantee.
FICC records a durable uncertain boundary before submission. A matching user
message ID and exact content in the same thread establishes session inclusion.
A disappeared queue entry does not. A changed TUI thread suspends direct delivery.
Confirmed rebinding validates the observed thread against the owned server. A
thread change is refused while old direct outcomes remain uncertain or submitted.
The bridge can reconcile those outcomes against the original thread while
suspended. It then follows the confirmed binding for all new submissions. A
read-side failure can be recovered by explicitly rebinding the same thread;
stale observations cannot replace a newer confirmed binding.

Other runtime versions retain the generic inbox capability and show that direct
integration is unavailable. A generic profile launches the exact command without
loading either native adapter. Each agent can use these separate environment
variables with correct shell quoting:

```sh
"$FICC_AGENT_PYTHON" "$FICC_AGENT_HELPER" --agent-tool list
"$FICC_AGENT_PYTHON" "$FICC_AGENT_HELPER" --agent-tool list --after DELIVERY_ID
"$FICC_AGENT_PYTHON" "$FICC_AGENT_HELPER" --agent-tool read DELIVERY_ID
"$FICC_AGENT_PYTHON" "$FICC_AGENT_HELPER" --agent-tool rejects
"$FICC_AGENT_PYTHON" "$FICC_AGENT_HELPER" --agent-tool rejected IDEMPOTENCY_KEY
printf '%s' '{"text":"Build checks passed."}' |
  "$FICC_AGENT_PYTHON" "$FICC_AGENT_HELPER" --agent-tool send \
  --recipient AGENT_ID --delivery inbox --reply-to MESSAGE_ID \
  --idempotency-key 0123456789abcdef0123456789abcdef
```

Codex receives these tool instructions as thread instructions without editing
workspace files. OMP exposes the same operations as its registered tool. Inbox
listing returns at most eight messages and a continuation ID. Reading an inbox
records tool access without starting a turn. `--delivery direct` is explicit and
requires a recipient with a supported direct adapter. Replies can name only
selected agents enrolled in the same run. FICC never automatically replies or
broadcasts messages.

Invalid message bodies are refused locally before outbox publication. Permanent
host refusals are retained separately from successful storage. The Agents page
shows the latest 16 refusal IDs, codes, details and times. Use `rejects` to list
node refusal receipts eight at a time, with `--after` for another page, and
`rejected KEY` to inspect the original message. OMP exposes these same actions
in its bus tool. Corrected content requires a new request key. Transient capacity
errors and expired or revoked launch grants leave pending messages in place.

## Authority and limits

Agent read, execute and stop permissions are distinct. Bus read and send are also
distinct, with node restrictions checked for each participant. Launch requires
both `agents:execute` and `bus:send`; terminal attachment additionally requires
`terminals:execute`. Existing credentials gain no scopes during schema migration.

Each launch binds the originating credential for agent outbox authority. Expiry
or revocation prevents further outbox publication. Reconcile does not transfer
that authority to the current viewer. Unacknowledged node outbox items remain
available for owner inspection; they are not silently imported under a new grant.
Already admitted runtime work cannot be unsent by later credential revocation.

There are at most 128 registered profiles and 512 retained agents. Agent launches
share the terminal limits: 16 active sessions total, four per node and 512
retained terminal records. Two background relay exchanges run concurrently,
leaving controller connection capacity for user actions. A slow sibling's relay
does not hold the global agent control lock.

Each node controller namespace holds up to 512 current agent spools. Each spool
has at most 256 retained inbox messages, 128 pending outbox messages, 1,024 files,
32 KiB per file and 8 MiB total. Closed-run archival moves eligible spools into
an explicit retained node archive, freeing current spool capacity. The node keeps
up to 8,192 archived agent namespaces. Nothing expires or disappears automatically.
Agents on the same Unix account share that account's authority; private files
protect against other accounts, not a hostile process running as the owner.


<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Previous: Terminals](terminals.md) | [Next: Agent bus](bus.md)
