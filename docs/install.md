<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Installation and first connection

[Contents](README.md) | [Project README](../README.md) | [Previous: Architecture](architecture.md) | [Next: Operation](operations.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

Install a [Linux package](releases.md), try a separate demo, then enroll trusted machines.
Keep live state and credentials outside the source checkout.

## Requirements

Binary packages include Python. The source installer downloads a private Python
and requires an updated system Python 3.10 or later to bootstrap it. Manually
managed source and wheel installations need Python 3.12 or later. All controllers
need Linux, OpenSSH and GNU coreutils `timeout`. Nodes require
OpenSSH server and Python 3.12 or later. NVIDIA reporting uses a bounded,
structured nvidia-smi query when available. Missing GPU support does
not prevent CPU and memory observation.

Node.js 20 or later is a build and browser-test dependency. It is not needed
to run an installed wheel. The [package guide](releases.md) lists native controller formats.
Actual node checks use Ubuntu 26.04 and Python 3.14.
These are separate platform roles; other controller/node combinations require
their own checks. See [testing](testing.md) for qualification boundaries.

## Install a cloned repository

Run as your normal desktop account on Linux x86_64. On Ubuntu, install the
system prerequisites if they are absent:

```sh
sudo apt update
sudo apt install python3 openssh-client coreutils systemd xdg-utils ca-certificates
```

From the clone, run:

```sh
./install.sh
~/.local/bin/ficc
```

The installer verifies pinned Python and Node downloads, installs hash-locked
Python dependencies, builds the frontend with the npm lockfile and installs a
wheel. No system Python packages are changed. Internet access is required for
downloads. Python and Node need not be installed at the application's required
versions beforehand. Bootstrap Python must include maintained tar extraction
filters; apply distribution security updates if this check fails.

The runtime lives under `~/.local/share/ficc/source-installs/` and the command is
`~/.local/bin/ficc`. XDG_DATA_HOME and XDG_CACHE_HOME are respected. The checkout
can be moved or removed after installation. A desktop entry and on-demand user
service are installed; nothing starts automatically at sign-in. Opening `ficc`
starts the service and signs the browser in. A graphical session with a working
systemd user manager is required for desktop startup.

If `ficc` is not on PATH yet, run the line printed by the installer:

```sh
export PATH="$HOME/.local/bin:$PATH"
ficc
```

The default is live mode with no approved aliases. For first installation with a
trusted SSH alias, use `./install.sh --profile rack-01`; repeat `--profile` for
more aliases. Existing launcher profiles, state, mode and port are preserved.
Stop an existing service before rerunning the installer. Changed profiles must
be set explicitly with `ficc install-launcher` after stopping it.

For a terminal-only setup, use `./install.sh --no-desktop`, then `ficc serve`
and `ficc open --print-url` in separate terminals. This installs the command
without changing any existing launcher; it does not require a user service manager.

## Update or remove a source installation

Back up the stopped controller, close other FICC commands, update the checkout,
and rerun `./install.sh`. An existing unrelated `~/.local/bin/ficc` is never
replaced. Old private runtime directories remain available for recovery. Remove
an old runtime only after checking that no launcher or process uses it.

To remove the installation, stop FICC, disable its user service, remove its
generated service and desktop files and run `systemctl --user daemon-reload`.
Then remove the generated `~/.local/bin/ficc` command and unused directories
under `source-installs`. Keep your state directory and backups unless you intend
to delete recorded data. See [package removal](releases.md#upgrade-and-remove).

## Development environment

For editable development with Python 3.12 or later and Node.js 20 or later:

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
it and `ficc stop` to stop the local service. See [operations](operations.md)
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



<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Previous: Architecture](architecture.md) | [Next: Operation](operations.md)
