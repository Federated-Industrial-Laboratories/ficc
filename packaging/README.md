# Linux release assembly

Build x86_64 AppImage, Debian amd64, Arch Linux and portable archives from one
isolated CPython payload. Assembly and publication are separate commands.

Use Linux x86_64, Python 3.12 or later, Node.js 22 or later, npm, dpkg-deb, zstd,
SquashFS tools and Docker or Podman. Native modules also require C/C++ compilers
and OpenSSL development files. Install requirements-dev.lock in a build
virtual environment. Use the same interpreter for the commands below.

```sh
python tools/release.py --cache /tmp/ficc-inputs \
  --work /tmp/ficc-build --output /tmp/ficc-release
```

Work and output directories must be new and outside the source checkout.
The input cache may be reused; every input is checked against inputs.json.
Native module dependencies use their declared hashes and a separate cache subdirectory.
`--allow-dirty` marks an uncommitted qualification build. Such a build is not a
publication candidate. A source archive includes release-source.json and can
be rebuilt with this same command after extracting it and installing build tools.

Runtime downloads use exact lengths and SHA-256 digests. AppImage assembly uses
the numbered appimagetool 1.9.1 release. Continuous AppImage
upstream assets can be replaced. The pinned runtime is preserved in the published
FICC 0.1.0 AppImage. Assembly reads its bounded runtime prefix and clears the
embedded AppImage checksum field before checking the original runtime SHA-256.
The executable bytes and corresponding source revision remain unchanged.

Retain the verified build cache. Other changed inputs fail their pinned checks.
The runtime source and build instructions are also distributed for rebuilding.

## Arch package

Build the container from a small context that contains only its Containerfile.
Use a dedicated container store if the local store contains unrelated work.
The recipe uses the verified portable archive and makepkg under an unprivileged
account. The generated package must then pass the native lifecycle check.

```sh
docker build -t ficc-package-arch -f packaging/Containerfile.arch packaging
docker run --rm --network=none \
  -v /tmp/ficc-release:/release \
  ficc-package-arch bash -ec '
    mkdir /build
    cp -a /release/arch /build/arch
    chown -R builder:builder /build
    cd /build/arch
    runuser -u builder -- makepkg --nodeps --noconfirm
    cp *.pkg.tar.zst /release/
  '
python tools/finalize_release.py --output /tmp/ficc-release \
  --arch-package /tmp/ficc-release/ficc-bin-0.2.6.post2-1-x86_64.pkg.tar.zst
```

## Qualification

Add `--viewer-runtime /path/to/verified-viewer-runtime` to include the native display decoder.
Add `--windows-runtime /path/to/verified-windows-runtime` to include the Windows transport helper.
Both are optional, separately validated directories. Their files, notices and source records enter the payload inventory.
The corresponding components also enter the combined SBOM. Each runtime retains its recorded platform requirements.
Their build and extraction paths must have trusted owners and no group-writable or world-writable parent directories.
Use a private build directory; the system temporary directory's sticky-bit exception remains permitted.

The payload also includes optional sandbox and power policy instructions under `tools/`.
Package installation does not apply these policies.

See [native displays](../docs/viewer-runtime.md) and [Windows management](../docs/windows-endpoints.md) for reproducible build commands.

Build the Windows transport from the same source used for the controller package.
Release assembly and installed checks reject helper files that differ from the selected controller source.
An older transport can have valid checksums and still lack the current command contract.

`tools/qualify_package.py` checks every payload file and link, the embedded
helper archive, a real terminal child, local HTTP authentication, one-use login,
static assets and clean shutdown. Point it at the installed command and payload.
It creates separate temporary state and never contacts an enrolled node.

`tools/qualify_native.sh` requires `FICC_DISPOSABLE_CONTAINER=1`. Run it only in a
disposable container with that script and qualify_package.py mounted at /checks.
It installs the package, runs the payload checks as an unprivileged account,
proves active upgrade/removal refusal, then checks stopped upgrade, removal and
preserved user state. Never run it on a workstation installation.

Run normal AppImage and explicit extraction checks separately. Check desktop
first use, repeated startup and stop on a graphical Linux session with its
systemd user manager. Use an isolated launcher name, configuration and state.
The browser and SSH regression suites use synthetic agents and fixtures.

Run the generated-service check on the supported desktop host:

```sh
python tools/qualify_launcher.py --command /path/to/installed/ficc \
  --require-sandbox --report /tmp/ficc-launcher-check.json
```

This check creates a temporary named launcher with separate demonstration state.
It checks private temporary storage, enforced module isolation, repeat startup,
stopped reinstall and retained state. It then removes its service and desktop entry.
It does not open the browser or contact enrolled systems. Check browser opening separately.

Before publication, inspect current source, reachable history, expanded packages
and metadata for secrets and local machine identifiers. Keep deny lists and
qualification logs outside the repository and release directory. Check the final
SHA256SUMS, SBOM, source correspondence and notices. Ship both source archives
alongside the binary formats. Release checks must pass before publication.

The SBOM records each supplied module archive with its exact identity and digest.
The package check refuses changed, unlisted or missing module inventory entries.

## Runtime providers

`providers.json` declares the separately built infrastructure packages and pinned
dependency locks. Both release assembly and the source installer install the host
first, then these provider wheels. They remain independent distributions, with
the wheels and build inventory retained under `runtime-packages/`. The SBOM and
payload manifest include their installed code and dependencies. Installation does
not configure an identity issuer, policy authority, node executor, source account,
scanner or audit destination, and does not create grants.

The source installation retains its private Python environment and pip for
administrator-managed provider additions and upgrades. Stop the controller before
changing trusted provider packages; inspect their source and dependency locks.
An AppImage or native release payload is a fixed distribution. Use the source
installation or a dedicated controller virtual environment for custom privileged
providers. Ordinary workspace modules use the module manager in every format.
Never treat a wheel's SHA-256 as its publisher identity.

Remote deployment presets are under `remote/` in the payload, with the provider
SDK and manuals beside them. External services and tools such as OPA, Podman,
ClamAV and an identity server retain their documented installation requirements;
the Python adapter wheel is not the external service.

The payload retains `python/bin/ficc-audit-collector` as a relocatable command.
Run it under separately administered custody as described in the audit manual.
The supplied policy sources are under `policy-packs/`; their activation uses
separate policy publisher trust and never follows package installation implicitly.

## Sign the release

Finish all formats before signing. Select a dedicated Ed25519 release key and
retain its public key through an independent trusted channel. The signing tool
does not generate keys, select an SSH login key or change publisher trust.
It uses OpenSSH SSHSIG with namespace `ficc-release-v1` to sign the exact
`SHA256SUMS` bytes. Those checksums bind the packages, source, SBOM and build record.

```sh
python tools/release_signatures.py sign --output /tmp/ficc-release \
  --key /private/release-signing-key --trusted-key /trusted/ficc-release.pub
python tools/release_signatures.py verify --output /tmp/ficc-release \
  --trusted-key /trusted/ficc-release.pub
```

The two added files are `RELEASE.pub` and `SHA256SUMS.sig`. The included public key
is informational; verification must use the separately trusted key. Replacing a
downloaded public key and checksum file must not establish a new publisher.
Release signatures authenticate bytes, not feature qualification or installation
permission. A key rotation requires an independently authenticated new public key.
Policy-package trust and module capability grants remain separate decisions.

## Publish a version

Merge the reviewed source, check out that exact default-branch commit, and build
and qualify all formats above. Change the project version for each new release;
never replace published assets. GitHub CLI must be signed in with repository
release access. Keep review evidence and private configuration out of the output.

```sh
python tools/publish_release.py --output /tmp/ficc-release \
  --notes /tmp/ficc-release-notes.md --trusted-key /trusted/ficc-release.pub
```

This verifies the publisher signature before any GitHub operation, then creates
or resumes a versioned draft in GitHub Releases. It uploads all fourteen
assets and verifies their sizes and SHA-256 digests against GitHub's API. It
requires a complete, clean build of the current default branch. Existing tags
must resolve to the same commit. Unexpected or changed assets are refused.

After review, repeat with `--publish` to publish the verified draft. Repository
visibility is unchanged. Published versions cannot be replaced by this command.
CI artifacts are temporary qualification output; they are not release downloads.

For `0.2.6r2-stable`, package metadata uses `0.2.6.post2`.
Pass `--tag v0.2.6r2-stable` to `publish_release.py` for the stable release tag.
