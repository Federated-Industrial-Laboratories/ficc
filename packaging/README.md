# Linux release assembly

Build x86_64 AppImage, Debian amd64, Arch Linux and portable archives from one
isolated CPython payload. No command in this procedure publishes a release.

Use Linux x86_64, Python 3.12 or later, Node.js 20 or later, npm, dpkg-deb, zstd,
SquashFS tools and Docker or Podman. Install requirements-dev.lock in a build
virtual environment. Use the same interpreter for the commands below.

```sh
python tools/release.py --cache /tmp/ficc-inputs \
  --work /tmp/ficc-build --output /tmp/ficc-release
```

Work and output directories must be new and outside the source checkout.
The input cache may be reused; every input is checked against inputs.json.
`--allow-dirty` marks an uncommitted qualification build. Such a build is not a
publication candidate. A source archive includes release-source.json and can
be rebuilt with this same command after extracting it and installing build tools.

Runtime downloads use exact lengths and SHA-256 digests. Continuous AppImage
upstream assets can be replaced: retain the verified build cache. A changed
upstream asset fails closed and requires an explicitly reviewed lock update.
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
  --arch-package /tmp/ficc-release/ficc-bin-0.1.0rc1-1-x86_64.pkg.tar.zst
```

## Qualification

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

Before publication, inspect current source, reachable history, expanded packages
and metadata for secrets and local machine identifiers. Keep deny lists and
qualification logs outside the repository and release directory. Check the final
SHA256SUMS, SBOM, source correspondence and notices. Ship both source archives
alongside the binary formats. Release checks must pass before publication.
