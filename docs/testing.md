<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Testing

[Contents](README.md) | [Project README](../README.md) | [Previous: Local API](api.md) | [Next: Dependencies](dependencies.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

<details>
<summary>On this page</summary>

- [Remote identity checks](#remote-identity-checks)
- [Source and unit checks](#source-and-unit-checks)
- [SSH integration](#ssh-integration)
- [Browser checks](#browser-checks)
- [Installed packages](#installed-packages)
- [Contributor execution and data workflows](#contributor-execution-and-data-workflows)
- [Secret, inspection and audit boundaries](#secret-inspection-and-audit-boundaries)
- [Maintenance and operation checks](#maintenance-and-operation-checks)
- [Runtime modules and providers](#runtime-modules-and-providers)
- [State storage conformance](#state-storage-conformance)
- [Runtime policy qualification](#runtime-policy-qualification)

</details>

Select test sizes for the behavior under test. No fixed batch size is required
for every feature. Protocol batch limits remain unchanged. Run the relevant
focused checks after a change, then the applicable release checks on the assembled
candidate. Reuse unaffected results; a skipped prerequisite is not a passing check.

Expanded batch and repeated recovery cases carry the `scale` marker. They are
optional and excluded from the default run. Use `python -m pytest -m scale` for
that coverage, or `python -m pytest -m ''` to include it with the normal suite.
Use a short `--basetemp` path for tests that create Unix sockets; socket path
limits also apply inside a temporary directory.

Run commands from the project root with the development environment active.
Use isolated state, accounts and services. Each check establishes its own boundary;
a browser fixture does not establish that remote execution works on an installed
machine. This guide describes the checks, not the qualification status of a release.

Identity checks cover local-owner upgrades, migration rollback, distinct projects
and direct object access, private layouts, scope ceilings, revocation
and restore. Distinct unaffected credentials remain usable during authority changes.
SSH lifecycle checks verify that member session changes preserve owner connections.
Legacy restore checks include unsaved view references at the saved-view capacity.
Restored view and surface records must retain their exact content and owners.
Browser checks exercise owner membership controls, independent user
contexts, project switching and stale-window refusal. Resource checks cover
machine and folder assignments, credential limits, queued dispatch and durable
operation owners. Project file checks copy real files and verify their bytes.
Terminal checks revoke project grants after a real PTY read, before socket delivery.
The resource browser case uses real folder assignments, copies and revocation.
Remote login requires the separate identity, gateway and live browser checks.
PostgreSQL requires the real database checks below.

## Remote identity checks

The host checks private Unix ingress, owner recovery during identity-service
failure, one-use browser state, current approvals, project selection, expired
verification, queued work, real terminal revocation and restored mappings.
The separately installed OIDC provider uses real local HTTPS and signed-token
fixtures. Its suite checks introspection, refresh rotation,
issuer and audience validation, assurance, network bounds and lease expiry.

`FICC_TEST_HTTPS_GATEWAY` selects an isolated live gateway for the maintained
endpoint and path-confusion checks. The real browser test uses
`FICC_TEST_REMOTE_SEED`, a private mode `0600` fixture containing two disposable
Keycloak identities and approved FICC project IDs, and `FICC_TEST_REMOTE_CONTROL`,
an executable fixture helper. The helper reads a JSON `operation` on stdin:
`identity-logout`, `mapping-disable` or `mapping-enable`; it returns `ok: true`
and that operation after making the change through private administration.
It must never print credentials. Keep fixture credentials outside the repository.

The browser checks MFA setup and login, refusal before approval, project rights,
workspace persistence, real token refresh, external revocation and sign-out.
Disable traces and authentication-page screenshots. Capture only the FICC
application after it has removed authentication parameters. These checks require
the real identity service and do not run against a browser mock.

## Source and unit checks

The source installer and binary payload supply 17 separately built provider
wheels. A development environment with only the host installed also needs the
providers used by its checks. Build and install the supplied set into that
environment with a new output directory:

```sh
python tools/runtime_packages.py --output /path/to/new-provider-wheels --install
```

This installs locked Python dependencies and trusted runtime code. It does not
start external services or approve sources, policy, contributors or inspection.
Focused dataset regressions cover project isolation, changed-source refusal,
manifest authentication, delegated reads and metadata recovery. Transfer checks
exercise whole-source commitments and real block reservations with small files;
large-file integration must transfer a complete file larger than 16 GiB within
measured storage headroom and independently verify the result. A sparse offset
fixture does not establish that transfer result.

```sh
bash tools/check.sh
python -m pip_audit -r requirements.lock --disable-pip --no-deps
python -m build --no-isolation
```

The source check detects common credential formats, private infrastructure text,
missing license identifiers and oversized source files. Its negative fixtures
must fail when restricted content is present. A clean source scan is not proof
that all possible secrets are absent.

Python tests cover the API, authentication, token revocation, batched requests,
SSH trust and resource schema. Managed-job checks cover batch routing,
durable deduplication, revoked grants, unknown outcomes,
resource controls, cancellation, output bounds and CLI recovery. Launcher checks
cover path quoting, service identity and readiness.

## SSH integration

Run actual SSH integration with a distribution
OpenSSH server binary and tmux. The test server listens on a temporary loopback port and
uses generated keys, a temporary home and a private configuration.

```sh
FICC_TEST_SSHD=/usr/sbin/sshd python -m pytest tests/integration
```

If the server binary is unavailable, the integration test reports a skip.
Set FICC_REQUIRE_SSH=1 to make a missing prerequisite fail instead. A skipped
SSH check is not evidence of a successful SSH connection.

## Browser checks

Run browser checks against an isolated service. The test obtains its login
credential through the local CLI and does not retain it in the report.

```sh
ficc serve --demo --state-dir /tmp/ficc-browser-state --port 8171
```

In a second terminal:

```sh
FICC_STATE_DIR=/tmp/ficc-browser-state FICC_URL=http://127.0.0.1:8171 \
  npm test --prefix web
```

The actual contributor-workload fixture also requires `FICC_WORKLOAD_PYTHON`
and the qualified `FICC_TEST_OPA` evaluator. Its Python path must include
`src`, `node` and `tests/python`. Without these explicit fixture settings, the
checks report a skip. A configured fixture that fails still fails the check.

Set `FICC_TEST_LIVE_RESOURCES=1` to run the real project-folder workflow against
an isolated live service. It requires live mode; the ordinary demo service cannot
register or copy real files. Remote stream checks require the explicit lab
configuration described in [the remote stream fixture](../tests/integration/remote_streams/README.md).

Browser checks are headless by default. For a visible check, set `FICC_HEADED=1`.
Set `FICC_BROWSER_WINDOW_POSITION=x,y` to place its windows on another monitor.
Use a separate X server, such as `xvfb-run`, for unattended checks that require
windowed rendering without taking desktop focus.

Keep captures outside the repository. Check narrow and wide layouts, browser
zoom, keyboard operation, focus, stale data, errors, access limits and logout.
Inspect the rendered result as well as the assertions. Job browser fixtures cover
preview and confirmation, permission separation, output following, recovery and
cancellation. These fixtures do not qualify a remote systemd implementation.
Exercise installed helpers on supported machines with bounded CPU jobs before
claiming job execution, effective limits or desktop startup support.

## Installed packages

Package checks install the wheel in a fresh environment. Verify that the node
helper and web assets are present without access to the source checkout. Install
the provider wheels after the host and check runtime discovery against
`packaging/providers.json` and `runtime-packages/index.json`. Check a missing or
incompatible provider explicitly; installation must not fabricate readiness for
an unconfigured external service. Inspect a built binary payload as well as the
host wheel, including its provider inventories, dependency notices and sources.
Record source revision, exact artifact hashes, commands, skips and exit status for each
qualification. Performance limits require separate measured evidence.

## Contributor execution and data workflows

Use disposable approved Linux contributors and independently bounded storage
slots for actual execution. Exercise CPU work and, where supported, an explicitly
selected GPU. Verify local consent, resource enforcement, pause/drain/stop, lease
loss, controller/executor restart, retained output and explicit release. An
authenticated connection or accepted job does not establish successful execution.

Dataset checks bind complete digests and manifest identity to jobs. Delay a source
read while node maintenance continues, revoke source authority, interrupt staging
and resume only the same valid attempt. The runtime must not start before complete
input verification. Run a dataset-backed workload, publish its complete output
through Files, and select the resulting dataset for another job. Check current
permissions, no-overwrite conflicts, cancellation and uncertain commit recovery.
Measure process memory and real allocated storage separately from file length.

Source checks use real registered files and disposable SQL/object services with
verified TLS and separately provisioned read/write credentials. Exercise catalogue,
schema, bound parameters, preview, export, dataset registration and multipart
publication. Use the maintained `test_source_servers.py` and `test_source_s3.py`
fixture contracts for live services. Never point destructive fixtures at an
operator's database or bucket. Test lost acknowledgments and publication after
rename; recovery must retain unknown outcomes rather than replay writes.

The [data provider SDK](../sdk/data-sources.md) describes installed-extension
checks. SQL dialects, server versions, object checksums and conditional multipart
completion need evidence for the actual service. Sharing a protocol name does
not establish compatibility. Current dataset and output paths relay through the
controller; measure that route when reporting throughput.

## Secret, inspection and audit boundaries

Secret checks cover encrypted round trips, revision conflicts, tampering, missing
keys, explicit plaintext migration and exclusion from metadata backups. Provision
only synthetic values through private files or non-terminal stdin. Keep key
custody separate from test state, and never print credentials or include them in
captures. A successful round trip does not establish protection from the account
that owns both the running service and its key.

Inspection checks use the actual approved local engine and assets. Exercise
detection, incomplete coverage, unavailable assets, cancellation, source changes,
quarantine, inherited restrictions, exemptions and restore. Inspect engine and
rule receipts, not only the aggregate status. A bounded `no_detection` result
cannot establish that uninspected or encrypted content is safe.

Audit checks use a disposable TLS append destination and real durable records.
Exercise acknowledgment loss, exact replay after restart, conflict refusal,
retention gaps and backpressure. Required admission must wait outside controller
locks while cleanup and lease maintenance progress. Rotate a source credential
or revoke authority during the wait and verify refusal before dispatch. A memory
filesystem can support functional checks but cannot establish crash durability;
the destination's custody and acknowledgment guarantees need separate assessment.

## Maintenance and operation checks

Maintenance checks use isolated histories. They cover
exclusive state ownership, consistent credential-free backup, restore integrity,
WAL recovery, interrupted archive publication and idempotent resume. Active or
unknown work, unsafe paths and changed identities must prevent retirement.
Archive integration also runs the owner CLI through an isolated SSH server and
checks real systemd unit absence. Use separate synthetic state for these checks;
do not retire an operator's history as a test fixture.

GPU collector checks run with `python -m pytest tests/python/test_gpu_metrics.py
tests/python/test_gpu_apple.py tests/python/test_macos.py`. Run `gpu.spec.mjs`,
`jobs.spec.mjs` and `states.spec.mjs` against the isolated browser service.
Fixtures do not establish hardware support. Compare actual packaged-helper
samples with native driver counters and validate them against `node-v1.json`.
See [GPU observations](gpu-observations.md) for the hardware checks and limits.

Observation checks exercise owned connection reuse, renewal before expiry,
changed SSH configuration, pinned identity and process cleanup. Count controller
and child CPU together for performance measurements. A dedicated Linux cgroup's
cumulative CPU counter includes terminated child processes; sampling only live
processes can miss their cost. Measure browser memory separately.

File checks cover root and entry identity, hostile names, permissions,
previews, verified transfers, interruption, explicit cleanup and multi-entry
selections. Terminal checks use real PTYs and an isolated SSH
server for binary bytes, resize, tmux detach/reattach and exact stop. Permission,
ticket and bounded acknowledgement checks also cover active revocation.
A private tmux fixture installation can use FICC_TEST_EXTRA_PATH for the SSH
server PATH; production does not read this test setting.

Exercise the complete installed browser workflow with synthetic files before
claiming file transfer or interactive terminal support. Compare source and
retrieved hashes independently, and test revocation while a terminal is open.

Explorer browser checks cover sorting, filtering, keyboard column resizing,
opaque selection identities and obsolete listing replies. Terminal workspace
checks use local xterm rendering for machine tabs, split geometry, focus, hidden
output, explicit attachment, fullscreen and disposal. Session routing checks
reuse the bounded concurrent attachment capacity.

Agent and bus browser checks cover exact launch previews, explicit recipients,
multi-agent selections, lost-response retries, permission loss, literal
message rendering and receipt stages. Browser fixtures do not establish native
agent protocol behavior. Test the installed adapter version separately, with
its actual extension or Unix endpoint, and exercise an isolated node workflow.
An accepted message is not evidence of completed agent work.

Operational checks exercise redacted diagnostics, bounded audit exports with a
completion marker, backup/restore receipts and current project permissions.
Browser workflows share and apply workspace/workload templates through the real
API, then submit with current authority. Retained usage is project accounting for
reserved and observed resources; check exact bytes and isolation without treating
those counters as hardware metering or billing evidence.

## Runtime modules and providers

The VM provider guides record the supported behavior and deployment limits:

| Provider | Behavior | Limit |
| --- | --- | --- |
| KVM/libvirt | Real inventory, power actions and interactive display through FICC. | Requires a configured provider profile and compatible native viewer. |
| Proxmox VE | Real inventory, power actions and authenticated display through FICC. | Requires a supported provider version, grants and native viewer. |
| Hyper-V | Real inventory, confirmed start and graceful shutdown, interactive VMConnect, revocation and retained outcomes. | Windows Server 2025; HTTPS WinRM, fixed JEA endpoint and separately pinned display account required. |
| VirtualBox | Real inventory, confirmed start and graceful shutdown, interactive private display and revocation. | VirtualBox 7.2.20r175154 on Ubuntu 26.04 x86_64; account sandbox and matching free display extension required. |
| VMware vSphere | None. | Not included. |

Hyper-V checks cover distinct lightweight VM definitions, confirmed starts and
observed outcomes. A bootable Linux guest supplies graceful shutdown and
interactive VMConnect checks. Inventory scale does not establish loaded-guest capacity.
Inventory and commits have finite deadlines; lost acknowledgements remain unknown until explicitly reconciled.
See [Windows endpoint requirements](windows-endpoints.md).

VirtualBox checks use distinct VM definitions for inventory, status, previews and
stale-action refusal. Those checks do not establish concurrent guest or display
capacity. A bootable guest supplies a separate real power and console workflow.
See [VirtualBox requirements and limits](providers/virtualbox.md).

Module checks cover archive validation, exact digest grants, malformed protocol messages and cancellation.
Workspace checks cover revision conflicts, missing packages, independent windows, geometry recovery and nested fullscreen.
Editor checks retain conflicting copies and refuse unsafe roots or changed file identities.
Audio checks cover local playback, master controls, lease loss and competing windows.
Keep executable-module and native-viewer checks enabled in their supported host environment:

```sh
FICC_MODULE_HOST_TESTS=1 python -m pytest tests/python/test_module_host_integration.py
FICC_VIEWER_HOST_TESTS=1 FICC_VIEWER_RUNTIME=/path/to/verified-viewer \
  python -m pytest tests/python/test_viewer_host.py
```

Build all six SDK variants and run their protocol conformance checks.
Also run them through the real controller with mandatory isolation and selected grants.
See [SDK build and qualification](../sdk/README.md) for the required commands.
A direct executable test does not qualify its sandbox or host broker.

Actual provider tests are explicit opt-ins because they change disposable resources.
Use dedicated accounts, pinned SSH configurations and fixtures matching each test's documented names.
Do not point these tests at production resources. Read the test's setup and cleanup requirements first.
Provider tests cover inventory, lifecycle, revocation, unknown outcomes and exact receipt removal.
Inventory fixtures do not establish concurrent display or running-guest capacity.

The real browser display check uses an isolated controller with a prepared, running disposable VM.
Set `FICC_URL`, `FICC_STATE_DIR`, and `FICC_CLI` for that controller.
Set `FICC_VIEWER_FIXTURE=1` and select `libvirt`, `proxmox`, `hyperv`, or `virtualbox` with `FICC_VIEWER_PROVIDER`.
Use `FICC_VIEWER_WORKSPACE`, `FICC_VIEWER_PANEL`, and `FICC_VIEWER_MACHINE` to select the exact fixture.
Packaged providers also require the registered profile ID in `FICC_VIEWER_PROFILE`.

Run `viewer.spec.mjs` with the browser configuration above and `FICC_HEADED=1`.
The check covers display output, input release, nested fullscreen, small-window restoration, and grant revocation.
It restores the module's previous activation and grants after the check.
Do not run concurrent operations against that module during this check.
Confirm guest input separately by observing the guest's response to a harmless console command.

Administration service fixtures use a dedicated user manager.
Power tests require a separate disposable guest and an independent observer of boot and shutdown.
A power acknowledgment or lost connection cannot establish that the requested state was reached.
Restore fixture baselines and retain any uncertain receipts for explicit inspection.

Installed checks include every supplied archive, runtime discovery and the complete native display process boundary.
Verify copied licenses, corresponding sources and the package inventory after extraction.
Test an incompatible native runtime: implicit discovery disables display, while an invalid explicit selection refuses startup.
Visible browser workflows must exercise actual provider connections as well as isolated UI fixtures.


## State storage conformance

The default test run exercises SQLite. PostgreSQL cases explicitly skip when no
qualification configuration is supplied. A skip does not qualify the driver.
Install `state-providers/postgresql/requirements.lock` with hash checking, then
install the driver package without dependency resolution.

Prepare a dedicated disposable PostgreSQL 18 database, TLS certificate and
account-private provider configuration as described in [state storage](state-storage.md).
The database name must start with `ficc_test_`. These tests delete and recreate
its public schema. Close all other connections first. Never use production state.

```sh
FICC_TEST_POSTGRES=/path/to/private-test-provider.json \
  python -m pytest tests/python/test_state_storage.py tests/python/test_state_postgresql.py
FICC_TEST_POSTGRES=/path/to/private-test-provider.json \
  python -m pytest tests/python/test_resource_access.py tests/python/test_resource_jobs.py \
    tests/python/test_resource_files.py tests/python/test_resource_recovery.py
```

The shared cases use independent records. They cover real project
workspaces, module manifests, private layouts, sound preferences, restart,
rollback and portable restore. Network cases exercise second-owner refusal,
wrong certificates, terminated database connections, committed-import recovery
and interrupted history archival. Configuration tests reject unsafe files and
ambiguous or incompatible driver registrations. Run the workspace and project
browser checks against an isolated controller using this driver as well.
The resource checks also cover earlier-schema upgrades, durable operation ownership,
migration rollback and portable restore on both databases. Include schema 15
dataset safety, lineage and inspection receipts in current recovery checks.
Queued dispatch uses
an isolated SSH response fixture; real SSH qualification remains separate.

## Runtime policy qualification

Install the separate OPA provider into the development environment and verify
the OPA 1.21.1 static binary before enabling real evaluator checks. Linux user
namespaces, Bubblewrap and the systemd user resource controls must work.

```sh
FICC_TEST_OPA=/opt/opa/opa python -m pytest tests/python/test_policy_*.py
FICC_TEST_OPA=/opt/opa/opa FICC_TEST_POSTGRES=/path/to/private-test-provider.json \
  python -m pytest tests/python/test_policy_workflow.py tests/python/test_policy_recovery.py \
  tests/python/test_policy_revocation.py
```

The default run verifies signing and injected failure boundaries. Real evaluator
cases skip unless FICC_TEST_OPA is supplied. Database tests use the disposable
fixture described above. Run only one process against that database at a time.
These checks cover signed installation, host grant ceilings, role changes,
stale/malformed decisions, queued dispatch, actual terminal output revocation,
restart, suspended restore and transactional schema upgrades.

For the browser check, start a separate live controller with its evaluator
configured. Supply FICC_TEST_OPA, FICC_STATE_DIR, FICC_URL, FICC_CLI and
FICC_PYTHON, then select policies.spec.mjs. It creates disposable signing keys,
packages, identities and roles; never point it at a normal controller state.
The browser exercises trust, uploads, effective access, activation, a member
workspace, rollback and publisher recovery. Capture outside the repository.

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Previous: Local API](api.md) | [Next: Dependencies](dependencies.md)

## Native platform CI

The `Native platforms` workflow checks an installed wheel on Ubuntu 24.04,
Apple Silicon macOS 15 and Intel macOS 15. It covers process and credential
contracts, SSH helper installation, terminals, generic agents and the pinned
OMP/Codex runtimes. macOS also exercises a real isolated launchd controller.
See [native macOS](macos.md#shared-agent-and-ci-checks) for the exact scope.
Linux sandbox, workload and package checks remain separate; macOS does not
claim Linux-only capabilities. Provider model calls and physical GPU
qualification require their separate explicitly configured checks.
