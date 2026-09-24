# Contributing

Use a working branch for each coherent change. Submit a pull request to master.
Do not update master directly after the initial repository setup. Repository
visibility is private. Branch policy is maintained manually on the current
hosting plan; GitHub does not enforce protection for this private repository.

Stage files explicitly. Use a short imperative commit subject that states the
change. Pull requests describe the resulting behavior and relevant validation.
Do not put local development records, credentials or private machine details in
source, tests, screenshots, commit messages or pull requests.

Substantial code receives one independent review after author checks pass.
Resolve findings and run the affected checks again. The repository owner merges
the pull request. A code review performed outside GitHub does not count as a
GitHub account approval. No automatic merge is configured.

## Development

Use Linux, Python 3.12 or later, Node.js 20 or later, and OpenSSH.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.lock
npm ci --prefix web
npm run build --prefix web
python -m pip install --no-deps --no-build-isolation -e .
bash tools/check.sh
```

Run browser checks against a separate demonstration service. Keep its state and
captures outside the source directory. See [testing](docs/testing.md).

Use small modules, explicit limits and typed API contracts. Target fewer than
400 lines per source file; the source ceiling is 1,000 lines. Add an Apache-2.0
SPDX identifier to source files. Keep third-party code and licence notices intact.
Use short technical sentences and consistent terms in product text.

Test batched contracts with one and 64 distinct items. Include denied access,
stale state and interrupted connections. SSH integration tests use a real
isolated server. A mock response cannot establish remote connection behavior.

## Dependency updates

Update the declared versions in pyproject.toml and rebuild both locks with
pip-compile and --generate-hashes. Run source, type, Python, browser, package
and dependency checks. Update package-lock.json with the same care. Pin CI
actions to verified commit IDs. Runtime assets must not use a CDN.

Build the wheel after the web assets. Install it into a clean environment and
check the installed CLI, helper package, API and web assets. Do not publish an
artifact from an unchecked working tree.
