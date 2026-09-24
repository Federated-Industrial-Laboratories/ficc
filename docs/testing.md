<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Testing

[Contents](README.md) | [Project README](../README.md) | [Previous: Local API](api.md) | [Next: Dependencies](dependencies.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

Run checks from the project root with the development environment active.

```sh
bash tools/check.sh
python -m pip_audit -r requirements.lock --disable-pip --no-deps
python -m build --no-isolation
```

The source check detects common credential formats, private infrastructure text,
missing licence identifiers and oversized source files. Its negative fixtures
must fail when restricted content is present. A clean source scan is not proof
that all possible secrets are absent.

Python tests cover the API, authentication, token revocation, batched requests,
SSH trust and resource schema. Managed-job checks cover distinct 1-node and
64-node batches, durable deduplication, revoked grants, unknown outcomes,
resource controls, cancellation, output bounds and CLI recovery. Launcher checks
cover path quoting, service identity and readiness.

Run actual SSH integration with a distribution
OpenSSH server binary and tmux. The test server listens on a temporary loopback port and
uses generated keys, a temporary home and a private configuration.

```sh
FICC_TEST_SSHD=/usr/sbin/sshd python -m pytest tests/integration
```

If the server binary is unavailable, the integration test reports a skip.
Set FICC_REQUIRE_SSH=1 to make a missing prerequisite fail instead. A skipped
SSH check is not evidence of a successful SSH connection.

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

Package checks install the wheel in a fresh environment. Verify that the node
helper and web assets are present without access to the source checkout.
Record source revision, commands, case counts, skips and exit status for each
qualification. Performance limits require separate measured evidence.

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


<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Previous: Local API](api.md) | [Next: Dependencies](dependencies.md)
