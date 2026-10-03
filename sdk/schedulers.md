# Workload scheduler providers

A scheduler is a trusted installation package in the controller environment.
It proposes an ordering of queued project jobs. The host owns authorization,
resource reservations, durable attempt state, dispatch and lease renewal.
A scheduling proposal cannot grant access or select arbitrary runtime commands.

## Package entry point

Register one entry point in the `ficc.scheduler` group. Its name matches the
administrator's configured `provider` value. The loaded module exposes
`API_VERSION = 1` and `create(configuration)`. The returned object implements
`select(request)` and `close()`. Configuration belongs to the provider; validate
it before returning the instance.

The [supplied fair scheduler](../scheduler-providers/fair/README.md) is a separate
Python distribution. Installing FICC does not install or activate it implicitly.
The controller reads private `workload-provider.json` at startup. The
`workloads-configure` command validates configuration with the installed provider
and restores the previous configuration if validation fails.

## Selection protocol

`select` receives an object with exactly these fields:

| Field | Content |
| --- | --- |
| `version` | Integer `1`. |
| `pending` | Objects with `id`, `project_id` and `created_at` for queued, uncancelled jobs. |
| `active` | Objects with attempt `id`, `job_id` and `project_id` for held attempts. |

Return a list of at most 64 distinct pending job IDs. An empty list is valid.
Unknown, duplicate or malformed identities are refused before dispatch.
No payload, input contents, environment values or credentials enter this interface.

Active accounting includes prepared, running, completed and unknown attempts until
their resources are released. Explicitly abandoned attempts from revoked nodes
leave scheduler concurrency accounting, while the old node reservation remains.

The host can withhold temporarily refused jobs from the next selection call.
It rechecks each proposed job against fresh project authority, policy, local offer,
runtime identity, available capacity and independently bounded storage. One placement
per node snapshot forces fresh capacity observation before further admission.
New placements also require the executor's durable admission contract and bind
its current ledger identity. A replacement ledger cannot inherit held reservations.
The provider receives updated active records on later calls.

Keep selection bounded and deterministic for the supplied inputs. Do not perform
network requests or start jobs inside the scheduler. Selection failure leaves
jobs queued with a visible scheduler error. Closing the provider must release
its own resources and must not mutate workload execution state.

The supplied scheduler rotates across projects and orders jobs by age within each
project. Its explicit global and project concurrency limits are deployment choices.
Alternative scheduling and quota policies belong in other installed packages.

[Workload operations](../docs/workloads.md) | [Executor SDK](executors.md)
