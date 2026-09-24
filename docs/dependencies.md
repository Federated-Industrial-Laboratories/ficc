<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Dependency notices

[Contents](README.md) | [Project README](../README.md) | [Previous: Testing](testing.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

FICC uses Apache-2.0. Dependencies retain their own licences and notices.
The runtime lock records exact Python package versions and artifact hashes.
Licence identifiers below come from the pinned distribution metadata and files.

| Python runtime distribution | Version | Licence |
| --- | --- | --- |
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| certifi | 2026.7.22 | MPL-2.0 |
| click | 8.5.0 | BSD-3-Clause |
| fastapi | 0.141.1 | MIT |
| h11 | 0.16.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httpx | 0.28.1 | BSD-3-Clause |
| idna | 3.20 | BSD-3-Clause |
| pydantic | 2.13.5 | MIT |
| pydantic-core | 2.46.5 | MIT |
| starlette | 1.7.0 | BSD-3-Clause |
| typing-extensions | 4.16.0 | PSF-2.0 |
| typing-inspection | 0.4.4 | MIT |
| uvicorn | 0.53.0 | BSD-3-Clause |
| websockets | 17.1 | BSD-3-Clause |

Installed Python distributions retain their licence files under their
`.dist-info/` directories. Preserve those files when distributing an offline
environment. In particular, certifi retains its MPL-2.0 certificate-source notice.

The browser bundles xterm.js 6.0.0 and FitAddon 0.11.0 under MIT. Their licence
files are included under `ficc/static/vendor/` in the wheel. Fonts retain OFL-1.1:
Michroma 1.100, Barlow Semi Condensed 1.408, and JetBrains Mono 2.304. Their
original notices are under `ficc/static/fonts/`; see [NOTICE](../NOTICE).

OpenSSH, GNU coreutils, systemd, tmux and optional NVIDIA tools are external
system dependencies. They are not bundled in the FICC wheel. Build and test
dependencies are pinned separately in requirements-dev.lock and web/package-lock.json.

A release inventory should identify the exact wheel, its runtime dependency
artifacts and all bundled browser/font components. Include a CycloneDX SBOM and
SHA-256 checksums with the distribution artifacts. Package-level inventories do
not describe every native implementation detail inside dependency extensions.
Generate these records from the final built package; a source version alone
does not prove the installed artifact contents.


<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Project README](../README.md) | [Previous: Testing](testing.md)
