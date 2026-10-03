# OPA policy provider

This optional package implements FICC policy interface version 1.
Install it into the controller's Python environment after the host is built:

```sh
python -m pip install ./policy-providers/opa
```

The installed entry point is `ficc.policy`, name `opa`.
System services also need the [user-manager socket override](../../packaging/remote/README.md#optional-policy-evaluator)
and a shared private temporary directory. Verify activation inside the running service.
This Python package has controller authority. Install it only from a trusted
source. It is separate from ordinary workspace modules and panel permissions.
Policy archives contain Rego and data, not Python provider code.

The provider requires Linux, Python 3.12 or later, Bubblewrap, a systemd user
manager and delegated cgroup v2 memory, CPU and process controls. It also requires
the host's `ficc.modules.sandbox` and `ficc.modules.watcher` helpers.
The evaluator must be a trusted static OPA binary. OPA 1.21.1 is the supported
version. Obtain it from the official OPA release and verify its published digest.
The binary is supplied separately; it is not included in this package.

Configuration has exactly two fields:

```json
{"binary":"/opt/opa/opa","sha256":"<64 hexadecimal digits>"}
```

The binary must be a regular executable file owned by the controller account or
root. It must have no group or other write access and no set-ID bits. The provider
copies and hashes its exact bytes before execution. Additional arguments and
environment settings are not accepted.

`prepare(configuration, source, run)` compiles the policy and returns a runner.
The host verifies package signatures and payload hashes before this call. It
supplies an immutable source directory and an empty run directory with mode 0700.
Both directories must belong to the controller account. Source files and
directories must have no group or other write access. Source files are Rego
files and `data.json` files. Limits are 256 files, eight path levels and 16 MiB.
The run path must fit a Linux Unix socket path with `/work/opa.sock` appended.

The runner has synchronous `evaluate(envelope)` and `close()` methods. Calls are
serialized. They also work when the caller already has an active async loop.
Use a worker thread if the application must keep that loop responsive.
The envelope has `version: 1`, an integer `revision`, and 1 to 64 requests.
Each request has a unique `id`, an `action`, an `authority` object and a `labels`
object. IDs and actions have at most 128 characters. Request JSON is limited to
256 KiB. The host must keep credentials and workload contents out of this input.

Only `data.ficc.decisions` is queried. The result is an ordered list with one
decision per request: `id`, Boolean `allow` and a `reason` code. A reason starts
with a lowercase letter and contains lowercase letters, digits, underscores,
periods or hyphens. Its length is 1 to 80 characters. Response JSON is limited
to 64 KiB.
Undefined results, invalid responses and unavailable services raise `ValueError`.
Errors contain no policy output. The host must still validate current authority,
revision and the full result before it uses a decision. The provider adds no
authentication or authorization rules.

Compilation and serving both require a network and filesystem namespace. The
process sees readonly policy, binary and capability files plus private writable
storage. It receives no controller environment or home directory. The service
drops capabilities and requires these kernel limits before admission:

| Control | Limit |
| --- | --- |
| Memory | 512 MiB |
| Swap | 0 |
| CPU | One CPU |
| Processes and threads | 64 |
| Written file size | 16 MiB |

The bundled capability list contains 62 explicit deterministic builtins from
OPA 1.21.1. It permits no HTTP, network, runtime, time, random, print or external
data functions. `allow_net` is empty. Compilation uses this list inside the
sandbox. Serving uses the resulting bundle, a private socket with mode 0600 and
no TCP listener. The version check is disabled. Go's 256 MiB memory target is
additional to the required kernel memory limit.

Resource admission and socket startup each have a five-second deadline. Each
compiler command has a ten-second deadline and a 15-second service lifetime.
Each HTTP exchange has a two-second total deadline, including headers and body.
Waiting for another decision has a two-second limit. Close waits at most 15
seconds for a decision to release the runner. Each process stream is limited to
64 KiB. Service management calls have a
three-second deadline. Cleanup adds bounded service-stop and process-reap time.
Evaluator, transport and malformed-result failures stop the service. Invalid
caller envelopes are rejected before execution and preserve a healthy service.
There is no fallback without isolation.
`close()` confirms that the service has no live processes and is safe to repeat.
The watcher also stops the sandbox when the controller exits.

The source layout separates file validation, sandbox commands, process control
and the decision protocol. `capabilities.json` contains the permitted type
declarations. `admit.py` waits for verified kernel controls before execution.
The host owns removal of the private run directory after close.

Run maintained checks from this directory in a FICC development environment:

```sh
PYTHONPATH=../../src:src python -m pytest -q tests
FICC_TEST_OPA=/opt/opa/opa PYTHONPATH=../../src:src python -m pytest -q -s tests
```

Without `FICC_TEST_OPA`, real evaluator tests are explicitly skipped. With it,
the tests require the official 1.21.1 Linux AMD64 static binary and active kernel
controls. They use private temporary directories and owned systemd user units.
They do not install a system service or change controller configuration.
