# Contributor TLS tests

These tests run the controller, node client, installed certificate provider,
Smallstep authority, and Caddy gateway. Each case has private temporary state.
Both HTTPS listeners and the authority bind to the loopback address.
The tests use new local keys and an explicit private test root. They do not
change system trust or contact a remote controller.

Install the FICC development dependencies and the Smallstep provider wheel.
Obtain verified step-ca 0.30.2, step 0.31.0, and Caddy 2.11.4 binaries.
Set these environment variables to absolute paths:

| Variable | Required path |
| --- | --- |
| `FICC_TEST_HOST_SOURCE` | Fixed FICC source copy |
| `FICC_TEST_CERTIFICATE_SOURCE` | Fixed Smallstep provider source, with `deployment/profile.py` |
| `FICC_TEST_STEP` | `step` binary |
| `FICC_TEST_STEP_CA` | `step-ca` binary |
| `FICC_TEST_CADDY` | `caddy` binary |
| `FICC_TLS_LOG_DIRECTORY` | Optional private output directory for redacted process logs |

Use the selected host's `src` and `node` directories on `PYTHONPATH`, followed
by this integration directory. The provider must load from its installed wheel.
Use an empty `PATH` for CPU-only resource collection. All service binaries have
explicit paths. Run the tests with the development environment's Python:

```sh
/path/to/environment/bin/python -m pytest -q --tb=short tests/integration/test_contributor_tls*.py
```

Missing fixture paths produce explicit skips in the general integration suite.
Invalid configured fixtures still fail. The cases run serially, with one
controller, authority, and gateway at a time. Normal runs create one node;
`-m scale` selects the optional 64-node cases. A node has a five-second
lease and sends a heartbeat each second. The automatic rotation case uses
60-second certificates. Other cases use one-hour certificates.

The suite checks pending approval, real TLS activation, persistent and polling
connections, key rotation, replay, revocation, and recovery after gateway loss.
It also checks trusted header replacement, client certificate checks, server
trust, and rejection of TLS 1.2. An unregistered certificate from the trusted
authority must also fail. No case permits job execution.
These checks do not establish external network or physical-node operation.
