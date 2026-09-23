# Federated Industrial Cluster Commander

FICC is a local console for Linux clusters. It connects through OpenSSH and
provides a web interface and a local API for machine status and resource use.
The interface uses white and silver panels with orange controls. All assets
are local, including fonts.

This development version provides authenticated access, explicit machine
enrollment, CPU/RAM/storage/network observations, optional NVIDIA reporting,
scoped API tokens and audit history. It distinguishes old samples, unavailable
metrics, authentication failures and changed host keys.

Managed jobs add bounded CPU/RAM use, durable output and recovery after a local
controller restart. GPU reservations are advisory. File management, interactive
terminals and shared remote access remain outside this development version.
Existing SSH tools continue to work.

## Requirements

Use Linux, Python 3.12 or later and OpenSSH on the controller. Nodes require
OpenSSH server and Python 3.12 or later. NVIDIA reporting uses a bounded,
structured nvidia-smi query when available. Missing GPU support does
not prevent CPU and memory observation.

Node.js 20 or later is a build and browser-test dependency. It is not needed
to run an installed wheel. The initial qualification targets Ubuntu 24.04 and
26.04. Other systems require separate checks.

## Build and install

From the source directory:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.lock
npm ci --prefix web
npm run build --prefix web
python -m pip install --no-deps --no-build-isolation -e .
```

For a distributable package, run `python -m build --no-isolation` after building
the web assets. Install the wheel with requirements.lock in a clean environment.
Keep state, credentials and captures outside the source directory.

## Try the interface

```sh
ficc serve --demo --state-dir /tmp/ficc-demo --port 8171
```

In another terminal with the environment active:

```sh
ficc open --state-dir /tmp/ficc-demo
```

The browser signs in with a short-lived, one-use credential. Demonstration mode
shows synthetic machines and disables live SSH collection and enrollment.
Use a different state directory for live operation.

## Connect a machine

First establish working key authentication and verify the machine's SSH host
fingerprint independently. Save that trusted key in the local known-hosts file.
Prepare an SSH alias such as `rack-01`. Review any executable SSH configuration
before approving it for use.

```sh
ficc serve --profile rack-01
```

The default address is `http://127.0.0.1:8170`. In another terminal:

```sh
ficc open
ficc nodes
```

Select Enroll node in the browser. Review the resolved account, host and
fingerprint. Confirm installation if the node helper is absent. The helper is
installed under the remote account at `~/.local/lib/ficc/node.pyz`. It runs only
when requested over SSH and opens no network listener.

Use repeated `--profile` options to approve more aliases. `--ssh-config PATH`
selects a separate trusted local SSH configuration. Untrusted or changed host
keys are refused. Do not turn off host verification to resolve that refusal.

The CLI can show the same enrollment preview:

```sh
ficc enroll --profile rack-01 --name 'Rack 01'
```

After reviewing the preview, repeat with `--fingerprint SHA256:...` and, when
required, `--install-helper`. Use the actual independently verified fingerprint.

## Start from the desktop

After installation, stop the foreground service and retain its state directory.
Install a launcher with the same approved profiles and settings:

```sh
ficc install-launcher --profile rack-01
ficc launch
```

Select **FICC Cluster Commander** in the application menu to start the service
and open the console. It starts on demand by default. Use `ficc status` to check
it and `ficc stop` to stop the local service. See [operations](docs/operations.md)
for existing state, alternate configurations and optional sign-in startup.

## Access and operation

The local owner can create an expiring token in a protected file:

```sh
ficc token-create --label monitor --scope nodes:read --scope resources:read \
  --lifetime 3600 --output /tmp/ficc-monitor-token
```

Add `--node ID` to restrict it to specific machines. Revoke a token in Access
or with `ficc token-revoke ID`. Keep the output file private and delete it when
no longer needed. Never put token values in shell arguments or source files.

See [managed jobs](docs/jobs.md), [API](docs/api.md), [operations](docs/operations.md),
[architecture](docs/architecture.md), [security](SECURITY.md),
[testing](docs/testing.md) and [contribution procedure](CONTRIBUTING.md).

The software uses the Apache License, Version 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE). Font files retain their included OFL licences.
