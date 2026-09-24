<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Cluster message bus

[Contents](README.md) | [Project README](../README.md) | [Previous: Coding agents](agents.md) | [Next: Backup and restore](backup.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

The controller database is the canonical bus. Nodes hold private inboxes, outboxes
and transport receipts. Only the controller initiates pinned SSH exchanges. Nodes
receive no controller API token or SSH identity, and need no public listener,
reverse tunnel or shared network filesystem.

Create a named run in Bus, then launch selected agents into that run. Messages
name explicit recipient agent IDs. Inbox delivery stores data for a tool read.
Direct delivery invokes the supported runtime adapter and can start agent work.
The confirmation applies to the displayed message and selected recipients only.
The fixed runtime wrapper identifies the sender and states that message content
is participant testimony, not an operator instruction or approval.

Stable request keys deduplicate host admission. A reused key with different run,
recipient or message content is refused. Sender identity, run and authority for
node replies come from the saved launch record, never from an outbox's claimed
sender. Each message has one delivery record per selected recipient. There are
no automatic broadcasts, replies or retry loops that start extra agent turns.

## Receipts

| State | Evidence |
| --- | --- |
| `host-stored` | Canonical message and delivery intent committed on the controller. |
| `host-uncertain` | SSH dispatch began; node persistence has not been confirmed. |
| `node-stored` | The node confirmed durable inbox storage. |
| `adapter-submitted` | The runtime accepted a submission; inclusion is not yet proved. |
| `session-included` | The bound runtime exposed the exact delivery in its session. |
| `tool-read` | The registered local inbox tool read the item. |
| `uncertain` | Runtime admission began without sufficient durable acknowledgement. |
| `failed` | A specific adapter operation was refused. |
| `cancelled` | Admission was prevented before runtime submission or tool access. |

These receipts do not mean the requested work completed. A lost SSH reply is
queried before another admission. A runtime submission is never blindly replayed.
An uncertain direct message stays unresolved unless the same runtime supplies
matching proof; reading it with the generic tool does not erase that uncertainty.
Outbox items stay on the node until a later exchange acknowledges canonical host
storage. Expired launch credentials prevent new outbox publication and are never
silently replaced by the current viewer's credential.

An outbox rejection is separate from these delivery receipts. For a permanently
invalid reply, the host durably records a `host-rejected` acknowledgement with
the exact request digest. The node retains the original outbox bytes in a
`rejected-ID.json` file and a separate refusal receipt, then permits later items
to progress. A lost acknowledgement is safe to repeat. Successful storage retains
a distinct sent record. Node tools expose the refusals; the public agent record
contains only the latest 16 summaries. Explicit closed-run archival includes all
retained refusal files and preserves their hashes.

## Portable runs and explicit archival

The JSONL envelope is version 1: `v`, `run`, `agent`, `seq`, `ts`, `type`, `body`.
Supported types are finding, rank, question, answer, handoff, note and cost.
Sequences are allocated per sender. Findings require claim and provenance; rank
and answer references must name an earlier permitted message in the same run.
The base envelope is compatible with agentbus JSONL tools. Optional extension
features and relation tokens are refused rather than silently discarded.
Transport receipts are exported separately from canonical messages.

Export and import require the service to be stopped so they hold exclusive state
ownership. Import reads only the explicitly named private file, validates the
whole run before committing it, and creates a closed historical run with no
recipients or delivery effects:

```sh
ficc stop
ficc bus-export --run RUN_ID --output /private/new-run-export
ficc bus-import --input /private/selected-run.jsonl
ficc start
```

To reclaim capacity, stop every enrolled agent and resolve every delivery outcome,
then close the run in Bus. With the service running, use the local owner command:

```sh
ficc bus-archive --run RUN_ID --output /private/new-run-archive --confirm
```

Archival first publishes a private, hash-described controller export. It then
moves each exact, quiescent node spool into a retained archive and verifies its
receipt before removing canonical host rows. The files include messages, run and
agent metadata, transport receipts, and node archive locations and hashes. An
interrupted operation can resume with the same run and output directory. Active
sessions, unknown states, unresolved deliveries and unacknowledged outboxes are
retained. Node archives preserve admission identities and cannot be relaunched.

The controller supports 128 retained runs, 16,384 messages, 32,768 delivery records
and 4,096 unresolved deliveries. Message bodies are limited to 8,192 UTF-8 bytes.
Each exchange carries at most eight inbox items, eight receipts and eight outbox
items. Capacity errors require explicit archival or resolution; no age-based
expiry deletes bus history. Node archive storage has its own finite retained cap.

State backup and restore include all agent and bus tables, preserve identities
and erase controller credentials. They refuse active or uncertain agents and
unresolved delivery outcomes. Archive closed agent runs before `archive-history`
retires terminal namespaces, so no retained agent record loses its terminal link.


<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Previous: Coding agents](agents.md) | [Next: Backup and restore](backup.md)
