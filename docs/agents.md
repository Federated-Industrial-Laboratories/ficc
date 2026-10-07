<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Coding agents

[Contents](README.md) | [Project README](../README.md) | [Previous: Terminals](terminals.md) | [Next: Agent bus](bus.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

<details>
<summary>On this page</summary>

- [Installed agent discovery](#installed-agent-discovery)
- [Register and launch an agent](#register-and-launch-an-agent)
- [Runtime adapters](#runtime-adapters)
- [Linux and macOS requirements](#linux-and-macos-requirements)
- [Authority and limits](#authority-and-limits)
- [External agent assistance](#external-agent-assistance)

</details>

Use Agents to launch a registered command in its own managed tmux terminal on
an enrolled Linux or macOS SSH machine. Its native interface appears in Terminals. The
controller records the agent identity, run membership and message deliveries.
Launch creates a dedicated session; FICC never types the launch command into
an existing shell.

FICC polls enrolled machines for installed coding agents and registers them
automatically. Install the selected agent on the machine; complete provider
sign-in in its terminal. Discovery does not install coding agents, copy provider
credentials or select a model. Custom commands and workspaces can also be
registered with an existing absolute executable through the local owner CLI:

## Installed agent discovery

The controller scans each enrolled machine about once a minute. The
`POST /api/v1/agent-profiles/refresh` API also requests discovery. Refresh returns
within two seconds while remaining scans continue; repeated requests share active
scans. The helper searches the enrolled account's command path and common local,
mise and Homebrew installation directories for Codex, Claude Code, Pi, OMP,
Kimi Code, OpenCode, GitHub Copilot, Gemini CLI, Grok and Cursor Agent. It skips
mise setup launchers in favor of existing installed executables. Custom command
names still use manual registration.

Codex and OMP use their existing native adapters and bounded version checks.
Other commands use the generic adapter, which verifies the installed command and
interpreter but does not probe its version. Discovery does not establish provider
sign-in or qualify new runtime versions for direct bus delivery.

New discovered profiles use the enrolled account's home directory as their
workspace. Matching manual registrations retain their custom workspace. Each
automatic registration keeps its identity across scans and runtime updates.
An uninstalled command becomes unavailable; a failed connection preserves the
last inventory and records the scan error. Upgrade an older node helper to
enable discovery. One unavailable machine does not block other results.

## Register and launch an agent

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
version and delivery method. Changed manual profiles require registration again;
discovered profiles update automatically and require a new launch preview.
A missing executable produces a registration error rather than installing it.
Remove an unused profile with `ficc agent-profile-remove PROFILE_ID` after its
retained runs have been archived.

In Bus, create a run. In Agents, select that run and a registered profile, review
the preview and explicitly launch. The returned terminal ID names the same
session in Terminals. Closing a tile detaches its viewer.

Stop Agent stops its
exact tmux session. An interrupted launch remains unknown; Reconcile only checks
the saved identity and never creates a replacement. Node forgetting and helper
upgrade refuse active or uncertain agent work.

## Runtime adapters

The same profile types and bus contract apply on Linux and macOS:

| Profile | Inbox and explicit reply tools | Native direct delivery |
| --- | --- | --- |
| `generic` | Yes, through the helper CLI | No |
| `omp` | Yes, including the registered `ficc_bus` tool at the supported version | OMP 18.1.12 only |
| `codex` | Yes, through the helper CLI described in thread instructions at supported versions | Codex 0.156.1 and 0.160.1 only |

An unsupported OMP or Codex version retains the helper CLI inbox baseline. It does
not load the native adapter or receive its tool registration/thread instructions.
Other coding agents use `generic`; their provider, model, login and native tool
compatibility remain the installed runtime's responsibility.

OMP 18.1.12 loads one packaged FICC extension through an explicit extension
argument. Its `ficc_bus` tool reads the registered inbox and submits explicitly
addressed replies. Direct messages use visible custom messages labelled with
sender, run, message and delivery IDs. The extension records submission separately
from an observed custom message inclusion event. Switching or branching a session
suspends direct admission until the operator explicitly rebinds the observed
session identity. Pending messages are not silently replayed after an interruption.
OMP 18.1.12 can print either a named or bare version when command flags are used;
both forms support the same native adapter. After upgrading the node helper,
re-register a profile previously recorded as inbox-only for this version. FICC
retains its existing runs and refuses a changed profile at the next launch preview.

Codex 0.156.1 and 0.160.1 use an owned private Unix app-server and attach the native TUI to
the exact thread returned by `thread/start`. The bridge uses a bounded WebSocket
connection and the version-specific queue API. Queue admission can start agent
work. The native TUI handles runtime approval requests; FICC never answers them.

The queue's client message ID is correlation data, not an exactly-once guarantee.
FICC records a durable uncertain boundary before submission. A matching user
message ID and exact content in the same thread establishes session inclusion.

A disappeared queue entry does not. A changed TUI thread suspends direct delivery.
Confirmed rebinding validates the observed thread against the owned server. A
thread change is refused while old direct outcomes remain uncertain or submitted.

Codex 0.160.1 names the new thread after its FICC agent ID to persist it before
the TUI resumes it, without starting a model turn. It uses legacy history so an
empty thread has a source rollout when the native client attaches.
Its ephemeral `thread_title` background thread does not change the registered
session binding. Other new threads retain
the suspension and explicit-rebind behavior.

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
records tool access without starting a turn.

`--delivery direct` is explicit and
requires a recipient with a supported direct adapter. Replies can name only
selected agents enrolled in the same run. FICC never automatically replies or
broadcasts messages.

Invalid message bodies are refused locally before outbox publication. Permanent
host refusals are retained separately from successful storage. The Agents page
shows the latest 16 refusal IDs, codes, details and times. Use `rejects` to list
node refusal receipts eight at a time, with `--after` for another page, and
`rejected KEY` to inspect the original message.

OMP exposes these same actions
in its bus tool. Corrected content requires a new request key. Transient capacity
errors and expired or revoked launch grants leave pending messages in place.

## Linux and macOS requirements

Install Python 3.12 or later, OpenSSH and tmux on the SSH node. On macOS, use a
current Homebrew Python; the system Python is insufficient. The SSH environment
must find both Python and tmux. See [macOS](macos.md) for installation and node
limits. Register the actual absolute runtime executable and workspace; Linux
`/home/operator` examples are not macOS installation paths. Interpreter-based profiles
must also name an installed absolute interpreter. FICC does not add Linux-only
runtime flags or change provider credentials, model settings or approval policy.

The portable agent contract covers managed launch, terminal identity, inbox
list/read, explicit replies with retry keys, receipts, confirmed stop and archive.
Native adapter checks additionally cover their pinned protocol and session
binding. The native OMP integration test uses the real extension/RPC loop with
scripted local model output and an empty runtime home. It verifies bus tools and
direct admission without contacting a model provider. This is not qualification
of every provider or model. The opt-in real Codex macOS test requires separate
operator authorisation because it uses the configured provider.

## Authority and limits

Agent read, execute and stop permissions are distinct. Bus read and send are also
distinct, with node restrictions checked for each participant. Launch requires
both `agents:execute` and `bus:send`; terminal attachment also requires
`terminals:execute`. Existing credentials gain no scopes during schema migration.

Each launch binds the originating credential for agent outbox authority. Expiry
or revocation prevents further outbox publication. Reconcile does not transfer
that authority to the current viewer. Unacknowledged node outbox items remain
available for owner inspection; they are not silently imported under a new grant.
Already admitted runtime work cannot be unsent by later credential revocation.

There are at most 1,024 registered profiles and 512 retained agents. Agent launches
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

## External agent assistance

The [agent observation interface](agent-observations.md) lets an existing agent
session inspect permitted machine inventory and resource readings. It uses
explicit disclosure permission and scoped API credentials. It does not require
a registered runtime profile or grant remote command execution.

The separate [ficc-harness](https://github.com/Federated-Industrial-Laboratories/ficc-harness)
companion provides portable skills, agent templates
and optional session hooks for coding agents that assist an operator with FICC
setup and operation. It includes local and remote administration guidance for
Codex, Claude Code, Gemini CLI, GitHub Copilot and Cursor. Consult the README,
provider guide and compatibility table shipped with the companion for supported
versions, installation methods and runtime qualification.

These instructions use FICC's existing CLI and browser interfaces. They do not
install coding-agent runtimes, grant system access or extend FICC's version-specific
native direct adapters. Controller-owner CLI access and scoped browser access
have different authority. Remote assistance preserves SSH host verification,
FICC's HTTPS gateway and individual sign-in requirements.

The companion is versioned separately. Its documentation and compatibility record
are reviewed with each FICC release. Download its source and provider archives from
[GitHub Releases](https://github.com/Federated-Industrial-Laboratories/ficc-harness/releases/latest).


<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Previous: Terminals](terminals.md) | [Next: Agent bus](bus.md)
