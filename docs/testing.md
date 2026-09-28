<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Testing

[Contents](README.md) | [Project README](../README.md) | [Previous: Local API](api.md) | [Next: Dependencies](dependencies.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

<details>
<summary>On this page</summary>

- [Source and unit checks](#source-and-unit-checks)
- [SSH integration](#ssh-integration)
- [Browser checks](#browser-checks)
- [Installed packages](#installed-packages)
- [Maintenance and operation checks](#maintenance-and-operation-checks)
- [Runtime modules and providers](#runtime-modules-and-providers)

</details>

Run the checks below from the project root with the development environment
active. Use isolated state, accounts and SSH services for tests. Each check
qualifies its own boundary; a browser fixture does not establish that a remote
operation works on an installed machine.

## Source and unit checks

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
SSH trust and resource schema. Managed-job checks cover distinct 1-node and
64-node batches, durable deduplication, revoked grants, unknown outcomes,
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

Keep captures outside the repository. Check narrow and wide layouts, browser
zoom, keyboard operation, focus, stale data, errors, access limits and logout.
Inspect the rendered result as well as the assertions. Job browser fixtures cover
preview and confirmation, permission separation, output following, recovery and
cancellation. These fixtures do not qualify a remote systemd implementation.
Exercise installed helpers on supported machines with bounded CPU jobs before
claiming job execution, effective limits or desktop startup support.

## Installed packages

Package checks install the wheel in a fresh environment. Verify that the node
helper and web assets are present without access to the source checkout.
Record source revision, commands, case counts, skips and exit status for each
qualification. Performance limits require separate measured evidence.

## Maintenance and operation checks

Maintenance checks use distinct 1-record and 64-record histories. They cover
exclusive state ownership, consistent credential-free backup, restore integrity,
WAL recovery, interrupted archive publication and idempotent resume. Active or
unknown work, unsafe paths and changed identities must prevent retirement.
Archive integration also runs the owner CLI through an isolated SSH server and
checks real systemd unit absence. Use separate synthetic state for these checks;
do not retire an operator's history as a test fixture.

Observation checks exercise owned connection reuse, renewal before expiry,
changed SSH configuration, pinned identity and process cleanup. Count controller
and child CPU together for performance measurements. A dedicated Linux cgroup's
cumulative CPU counter includes terminated child processes; sampling only live
processes can miss their cost. Measure browser memory separately.

File checks cover root and entry identity, hostile names, permissions,
previews, verified transfers, interruption, explicit cleanup and distinct
1-entry/64-entry selections. Terminal checks use real PTYs and an isolated SSH
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
output, explicit attachment, fullscreen and disposal. Distinct 1-session and
64-session routing checks reuse the bounded concurrent attachment capacity.

Agent and bus browser checks cover exact launch previews, explicit recipients,
1-agent and 64-agent selections, lost-response retries, permission loss, literal
message rendering and receipt stages. Browser fixtures do not establish native
agent protocol behavior. Test the installed adapter version separately, with
its actual extension or Unix endpoint, and exercise an isolated node workflow.
An accepted message is not evidence of completed agent work.

## Runtime modules and providers

Current VM provider qualification is:

| Provider | Verified behavior | Limit |
| --- | --- | --- |
| KVM/libvirt | Real inventory, power actions and interactive display through FICC. | Requires a configured provider profile and compatible native viewer. |
| Proxmox VE | Real inventory, power actions and authenticated display through FICC. | Requires a supported provider version, grants and native viewer. |
| Hyper-V | Package protocol, sandbox and component fixtures. | Real Windows lifecycle and VMConnect are not qualified. |
| VirtualBox | No complete provider package. | Local IPC execution remains disabled. |
| VMware vSphere | None. | Not included. |

Hyper-V and VirtualBox are not supported for operational use in this source state.
Their unit checks do not establish working VM management or display.

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
Distinct one-resource and 64-resource tests do not imply 64 concurrent VM displays or running guests.

Administration service fixtures use a dedicated user manager.
Power tests require a separate disposable guest and an independent observer of boot and shutdown.
A power acknowledgment or lost connection cannot establish that the requested state was reached.
Restore fixture baselines and retain any uncertain receipts for explicit inspection.

Installed checks include every supplied archive, runtime discovery and the complete native display process boundary.
Verify copied licenses, corresponding sources and the package inventory after extraction.
Test an incompatible native runtime: implicit discovery disables display, while an invalid explicit selection refuses startup.
Visible browser workflows must exercise actual provider connections as well as isolated UI fixtures.


<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Previous: Local API](api.md) | [Next: Dependencies](dependencies.md)
