<!-- SPDX-License-Identifier: Apache-2.0 -->
# Remote stream checks

These checks start a private controller, a Caddy HTTPS gateway, an HTTPS identity
service and an OpenSSH node. Each user completes the real authorization-code,
PKCE, signed-token and introspection path. The identity service is a test fixture;
it does not test human MFA. All listeners bind to loopback. Each run deletes its
private state, keys and synthetic data when it ends.

Use a frozen source copy. Install the host development dependencies and the OIDC
provider wheel in the test environment. Add `tests/integration`, `src` and `node`
from that copy to `PYTHONPATH`. The fixture uses the maintained TLS helpers in
`contributor_tls` and the OIDC provider's HTTPS issuer fixture.

Set these paths before running a check:

| Variable | Content |
| --- | --- |
| `FICC_TEST_HOST_SOURCE` | Absolute path to the frozen FICC source |
| `FICC_TEST_CADDY` | Verified Caddy2.11.4 executable |
| `FICC_TEST_SSHD` | OpenSSH server executable |
| `FICC_REQUIRE_SSH` | `1` to fail if the server is absent |
| `FICC_STREAM_LOG_DIRECTORY` | Optional private destination for bounded process logs |

Missing fixture paths produce explicit skips in the general integration suite.
Invalid configured fixtures still fail. Run the HTTP and terminal cases with
`python -m pytest -q tests/integration/test_remote_streams.py`. Normal runs use
one project user and a healthy control; `-m scale` selects the optional 64-user
cases. The 64-user case uses bounded cohorts within
the shipped terminal limits. It does not claim 64 simultaneous SSH shells.
The cases use actual polling, binary terminal input/output, terminal resize,
one-use tickets, streamed downloads, file digests and persisted workspaces.
Late-user revocation must cut an active download and terminal while a peer
remains usable. Gateway loss must close and release the affected shell.
Download preparation has a 60-second setup wait with bounded progress details.
This setup wait does not define a production transfer deadline.

The viewer cases also require libvirt, QEMU, GNU assembler/linker, system Python
with libvirt bindings, the installed OPA provider and a valid native viewer
runtime. Set `FICC_TEST_OPA` and `FICC_TEST_VIEWER_RUNTIME`. Run
`python -m pytest -q tests/integration/test_remote_streams_viewer.py`.
The fixture creates a private libvirt session and a 64 MiB, one-vCPU TCG VM. A small
boot image draws text and echoes keyboard input. No operating-system media,
external account, existing libvirt instance or hardware virtualization is used.
The installed default VM module creates each real host-owned descriptor. A
signed managed policy, project membership, assigned node and module grants all
apply. Distinct users attach in bounded cohorts; a control remains connected.
Each attached client reads and acknowledges frames continuously.

Run these process checks from the normal test account. A confined launcher can
prevent libvirt from passing a graphics file descriptor. An ordinary same-user
transient service can contain the run with finite memory, task and time limits.
Do not change host security policy to make a fixture pass.

For the browser, use an isolated Xvfb display and Chrome. The runner starts and
cleans the real services. Example arguments to `python -m remote_streams.browser`:

```text
--browser-source /path/to/frozen/tests/browser/remote-streams.spec.mjs
--node-modules /path/to/web/node_modules
--display
```

Set `FICC_PYTHON` to the test Python executable and optionally set
`FICC_STREAM_CAPTURES` to a private output directory. The browser has a new
temporary profile. Its launch pins the exact two generated certificate public
keys; it does not change the account or system trust store. This browser check
qualifies the pinned transport and UI, not browser CA-chain acceptance. HTTPX
and WebSocket clients use ordinary verified TLS with the private fixture roots.
The browser does not use request or WebSocket mocks. It checks real sign-in,
observation polling, a downloaded file, notes and layout persistence, VM target
selection, the module console, input release, nested fullscreen, resize and
revocation. These checks do not replace provider-specific VM lifecycle tests.
