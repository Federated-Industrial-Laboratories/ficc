# Project-fair workload scheduler

Install this trusted controller provider after installing FICC:

```sh
python -m pip install ./scheduler-providers/fair
```

Create a private `workload-provider.json` in the controller state directory:

```json
{
  "provider": "fair",
  "configuration": {"global_active": 16, "project_active": 4}
}
```

These example limits are administrator choices. The host has no default queue
order or project concurrency. Each call selects up to64 jobs by rotating among
projects, with oldest jobs first within each project. Active and unresolved
attempts consume the configured concurrency. Empty capacity returns no jobs.
Explicitly abandoned attempts from revoked nodes leave scheduler concurrency
accounting. Their unresolved storage and devices remain reserved on the old node.

The provider proposes an order. The controller checks current project rights,
node approval, policy, local consent, runtime identity and reserved capacity for
each placement. A scheduling result cannot grant those permissions.

This provider runs as trusted controller code. Install it only from an approved
source. It receives job and project identifiers, creation times and active attempt
identifiers. It receives no command, input contents or credential secrets.

See [workload operations](../../docs/workloads.md) and
[the scheduler interface](../../sdk/schedulers.md).
