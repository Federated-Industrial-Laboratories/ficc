# Testing

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
