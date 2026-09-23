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
SSH trust and resource schema. Run actual SSH integration with a distribution
OpenSSH server binary. The test server listens on a temporary loopback port and
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
Inspect the rendered result as well as the assertions.

Package checks install the wheel in a fresh environment. Verify that the node
helper and web assets are present without access to the source checkout.
Record source revision, commands, case counts, skips and exit status for each
qualification. Performance limits require separate measured evidence.
