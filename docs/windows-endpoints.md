# Windows endpoints

The Hyper-V provider is experimental and is not supported for operational use.
Real Windows lifecycle and VMConnect remain unqualified.
See [provider support](testing.md#runtime-modules-and-providers).

A Windows endpoint is separate from an enrolled SSH system. FICC runs on Linux.
Register a Windows HTTPS WinRM endpoint and a fixed JEA configuration. Use the
certificate PEM trust chain and the SHA-256 fingerprint of its leaf certificate.
HTTP, Basic authentication, redirects, environment proxies and arbitrary scripts
are not supported.

NTLM uses TLS channel binding. The account must have access
to the selected JEA configuration.

The Windows endpoint ID is a system target for caller scopes. Reading endpoint
metadata requires `nodes:read`. Endpoint changes require unrestricted
`nodes:write`. A provider adapter also requires its separate digest-bound
`provider:admin` grant. Ordinary workspace VM permissions do not restrict the
provider account itself. Grant provider access only to a trusted adapter.

Register one to sixteen command names with exact parameter names. Include
`Get-FICCEndpointIdentity` with no parameters. It must return one JSON string
with `machine_identity`, a stable SHA-256 identity. Each command returns one
bounded JSON string. The host sends command names and literal parameters through
PSRP `AddCommand` and `AddParameter`; it does not evaluate a command script.

The optional Windows transport has its own interpreter and current locked
libraries. It requires its recorded Linux build platform. The controller keeps
its separate platform baseline. Build and install with:

```sh
python3 tools/windows_runtime.py build --cache /tmp/windows-cache \
  --work /tmp/windows-build --output /tmp/windows-runtime
python3 tools/windows_runtime.py install --source /tmp/windows-runtime \
  --destination /approved/new/windows-runtime
```

The destination must be new. Place the runtime beside the controller's Python
prefix or inside that prefix. The host checks its inventory and platform before
starting each helper. A hash inventory verifies local files; it does not identify
or authenticate the publisher. Approve the source before installation.

The build
requires a maintained Python, `zstd` and the pinned HTTPS inputs. It installs no
host packages.

The runtime includes dependency notices, Python build metadata,
CPython and Berkeley DB corresponding source, and build code.

The helper accepts at most64 literal commands and eight concurrent requests. The
host deadline is at most20 seconds; ordinary read calls use the adapter's shorter
deadline. JSON output is at most1 MiB, each HTTP response at most2 MiB. The helper
has a 512 MiB address limit and a 20-second CPU limit. Revocation, endpoint changes,
timeout and service shutdown terminate its process group.

A lost response does
not prove that a remote change failed. The adapter keeps that operation unknown
until the operator inspects its outcome; it does not dispatch it again.

Credentials and certificate trust are private local files outside the database
and backup archive. Restore disables endpoint records and increments their
revisions. Re-enter missing accounts and trust before enabling a restored
endpoint. The host probes identity before enabling and before command dispatch.
Connection or credential replacement and removal are refused while adapter
profiles or receipts retain the endpoint. Disable remains available.

VMConnect uses a separate display account, registered port and certificate pin.
It does not inherit the management password. A registered reference is opaque to
runtime packages and browser components. The host passes credentials only to its
private native display process. Actual provider and display support must pass
its integration checks before it is listed as qualified.
