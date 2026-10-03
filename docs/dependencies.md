<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Dependency notices

[Contents](README.md) | [Project README](../README.md) | [Previous: Testing](testing.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

<details>
<summary>On this page</summary>

- [Python runtime](#python-runtime)
- [Supplied runtime providers](#supplied-runtime-providers)
- [State driver dependencies](#state-driver-dependencies)
- [Data provider dependencies](#data-provider-dependencies)
- [Browser assets](#browser-assets)
- [System and build dependencies](#system-and-build-dependencies)
- [Package notices](#package-notices)

</details>

FICC is licensed under Apache-2.0. Its dependencies retain their own licenses
and notices. The runtime lock pins exact Python package versions and artifact
hashes. The tables below use license identifiers from those pinned distributions.

## Python runtime

| Python runtime distribution | Version | License |
| --- | --- | --- |
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| certifi | 2026.7.22 | MPL-2.0 |
| cffi | 2.1.1 | MIT-0 |
| click | 8.5.0 | BSD-3-Clause |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| fastapi | 0.141.1 | MIT |
| h11 | 0.16.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httpx | 0.28.1 | BSD-3-Clause |
| idna | 3.20 | BSD-3-Clause |
| pycparser | 3.0 | BSD-3-Clause |
| pydantic | 2.13.5 | MIT |
| pydantic-core | 2.46.5 | MIT |
| starlette | 1.7.0 | BSD-3-Clause |
| typing-extensions | 4.16.0 | PSF-2.0 |
| typing-inspection | 0.4.4 | MIT |
| uvicorn | 0.53.0 | BSD-3-Clause |
| websockets | 17.1 | BSD-3-Clause |

Installed Python distributions retain their license files under their
`.dist-info/` directories. Preserve those files when distributing an offline
environment. In particular, certifi retains its MPL-2.0 certificate-source notice.

## Supplied runtime providers

The v0.2.5 source installer and binary payload supply 17 separately built provider
wheels, installed after the host wheel. The package catalogue is
[`packaging/providers.json`](../packaging/providers.json); each installation
retains the wheels and their hashed `runtime-packages/index.json` inventory.
These packages use the same runtime interfaces as independently installed
extensions. A host-only wheel does not contain them.

| Capability | Supplied provider packages | Additional setup |
| --- | --- | --- |
| Controller state | PostgreSQL | Dedicated database, account, verified TLS and explicit backend selection. |
| Identity | OIDC | Identity service, MFA policy, client credentials and approved mappings. |
| Contributor certificates | Smallstep | CA service, protected issuer keys and contributor approval. |
| Policy | OPA | Verified native evaluator, isolation controls, publisher trust and policy activation. |
| Contributor execution | Podman | Contributor installation, bounded storage slots, approved images and local consent. |
| Scheduling | Fair | Controller scheduler configuration and eligible contributor offers. |
| Artifacts | Filesystem | Registered roots, project access and immutable source selection. |
| Data sources and formats | SQLite, CSV, PostgreSQL, MySQL/MariaDB, Arrow/Parquet, S3, DuckDB | Approved files or servers, schemas, TLS and separate read/write accounts as applicable. |
| Secret storage | Local encrypted store | Private provider configuration, an external encryption key and provisioned references. |
| Audit delivery | HTTPS | Separately administered TLS append destination, append credential and delivery policy. |
| Inspection | ClamAV | Native engine, approved signature assets and inspection policy. |

All FICC provider packages retain Apache-2.0 licensing. Their upstream libraries
retain their own notices. Installed code alone neither starts external services
nor grants authority. The [operator manuals](README.md) describe configuration,
custody and failure behavior for each capability.

## State driver dependencies

The PostgreSQL state driver has a separate hashed runtime lock at
`state-providers/postgresql/requirements.lock`. It uses SQLAlchemy 2.1.1 (MIT),
psycopg 3.3.6 and psycopg-binary 3.3.6 (LGPL-3.0-only). The standard installer
supplies these dependencies; a host-only SQLite installation does not require
the driver. Preserve each distribution's license files and the bundled
native-library notices when distributing an offline driver.

## Data provider dependencies

Data providers have their own hashed runtime lock at
`data-providers/requirements.lock`. These add psycopg, PyMySQL, PyArrow, boto3/botocore
and DuckDB. Their exact versions, installation and licenses are listed
in [data runtime packages](../data-providers/README.md). Preserve bundled native
library notices with offline packages. They do not replace the controller state
driver and do not bundle database or object servers.

## Browser assets

The browser bundles xterm.js 6.0.0 and FitAddon 0.11.0 under MIT. Their license
files are included under `ficc/static/vendor/` in the wheel. Fonts retain OFL-1.1:
Michroma 1.100, Barlow Semi Condensed 1.408, and JetBrains Mono 2.304. Their
original notices are under `ficc/static/fonts/`; see [NOTICE](../NOTICE).

Dockview core 8.3.1 supplies workspace layout under MIT.
The browser uses Guacamole common JavaScript 1.6.0 under Apache-2.0 for remote displays.
Both bundles and their licenses are local assets; no external script host is required.

## System and build dependencies

The supplied OIDC identity package uses separately locked Authlib, joserfc and
HTTPX dependencies through the `ficc.identity` entry-point interface.
See its [dependency and license notes](../identity-providers/oidc/README.md).
The supplied remote profile uses Caddy, Keycloak, Java and PostgreSQL as separate
services. Contributor issuance also needs a separately configured CA service.
These services are not embedded in the controller wheel or binary payload.
Preserve their upstream notices and update them through verified installation
sources.

OPA, Podman and OCI images, ClamAV and its signature collection are external
deployment assets. Their provider wheels do not supply or configure those assets.
The [secret store](secrets.md) uses the locked cryptography library for authenticated
encryption; the key remains under explicit administrator custody outside state
backups. The [audit collector](audit.md) is supplied by its runtime package but
needs its own service, TLS identity, storage and append authorization.

OpenSSH, GNU coreutils, systemd, tmux and optional NVIDIA tools are external
system dependencies. They are not bundled in the FICC wheel. Build and test
dependencies are pinned separately in requirements-dev.lock and web/package-lock.json.

Executable modules require Bubblewrap, a working user systemd manager and effective cgroup resource controls.
The host checks these requirements before enablement. There is no unrestricted fallback.
The SDK's native examples have separate pinned JSON dependencies and notices in [SDK third-party notices](../sdk/THIRD-PARTY.md).

## Package notices

Binary formats also include CPython 3.12.14 from the pinned standalone build.
Their licenses/python directory retains native dependency notices and build
metadata. AppImage adds its separate runtime and licenses/appimage notices.
The release includes corresponding source archives and THIRD-PARTY.md.
See [Linux packages](releases.md) for the distribution contents.

An optional [native viewer runtime](viewer-runtime.md) adds Guacamole, patched LibVNCClient and their recursive library dependencies.
It retains exact platform requirements, an inventory, licenses, build records and corresponding sources.
Its components also appear in the binary package SBOM when that runtime is included.
The linked viewer retains GPL-3.0-or-later terms; the separate controller retains Apache-2.0.

A release inventory identifies the exact host and provider wheels, runtime dependency
artifacts and all bundled browser/font components. Include a CycloneDX SBOM and
SHA-256 checksums with the distribution artifacts. Package-level inventories do
not describe every native implementation detail inside dependency extensions.
Generate these records from the final built package; a source version alone
does not prove the installed artifact contents.


<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Previous: Testing](testing.md)
