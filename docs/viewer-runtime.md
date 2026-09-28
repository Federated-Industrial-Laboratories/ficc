# Native viewer runtime

The native viewer is a separate runtime. It does not install a host service.
The runtime uses Apache Guacamole 1.6.0 and LibVNCClient at the fixed revision in its source lock.
The default build includes VNC. Use `--rdp` to add the pinned FreeRDP client libraries and native RDP decoder.

SSH and direct device services are not included. VNC does not use native TLS.
FICC supplies the authenticated display transport through its isolated viewer service.
RDP uses TLS with an exact certificate fingerprint for the registered endpoint.
The host disables clipboard, audio, microphone, printer and drive redirection.

## Build

Use a private Linux x86_64 build directory. The current builder requires Debian package metadata.
Install standard development tools before the build: C/C++, Make, CMake, pkg-config and binutils.
The build also requires the cairo, libpng, libjpeg and libuuid development libraries.
An RDP build also requires the OpenSSL development library.
The tool does not install these packages or change host configuration.

```sh
python3 tools/viewer_runtime.py build --cache /tmp/viewer-inputs \
  --work /tmp/viewer-build --output /tmp/viewer-runtime \
  --platform-sources /tmp/viewer-platform-sources --jobs 2
python3 tools/viewer_runtime.py verify /tmp/viewer-runtime
```

Add `--rdp` to the build command when the required provider uses native VMConnect.
The runtime manifest records either `vnc` or `vnc, rdp` and requires each declared protocol library.
Runtime support does not prove that a specific provider or console transport is configured.

Work and output paths must be new. Cache entries require their pinned length and SHA-256.
The source lock is `packaging/viewer-inputs.json`. Retain verified input archives for repeat builds.
The Guacamole source hash corresponds to its verified Apache release signature.

The optional RDP input is FreeRDP 3.32.1, with its pinned release size and SHA-256.
The installer does not download or accept arbitrary viewer binaries.

The VNC input includes the upstream Tight row-count, Tight gradient and UltraZip bounds fixes.
The unpatched 0.9.15 release archive is not a valid replacement.
See the [upstream security advisories](https://github.com/LibVNC/libvncserver/security/advisories)
and [fixed source revision](https://github.com/LibVNC/libvncserver/commit/42494999e6492aaab9c1db785ecd293ef10b3aed).

`--platform-sources` contains exact source packages for the copied distribution libraries.
Use the distribution's authenticated source repository to obtain each required `.dsc` and its source archives.
The builder reports the exact missing source package and version.
It checks archive hashes against the source control file and requires matching installed package identities.
It also refuses installed libraries that differ from their package checksum inventory.
Source control hashes verify local correspondence; they do not authenticate a repository or publisher.

The runtime includes the recursive ELF dependency chain, except glibc and its loader.
Each copied library retains its distribution copyright notice and corresponding source archives.
The runtime also includes native source archives, build scripts, a build record and a CycloneDX SBOM.

For a rebuild, use the distributed FICC source tools with these archives as the input cache and source directory.
Use the same development packages, compiler, build options and source epoch from `sources/build.json`.
The build record uses `/build` in place of the private work directory.
FreeRDP records the fixed `/viewer` install prefix. Installation uses a separate private staging prefix.

Guacamole retains visible upstream deprecation warnings for the current FreeRDP headers; other warnings remain errors.
Inspect the resulting file inventory before distribution. Different build platforms can produce different bytes.

## Install

Only install runtimes from trusted sources. The manifest checks file integrity, not publisher identity.
The local path is an explicit trust choice. Symlinks, hard links and writable runtime files are refused.
An install uses a new private directory and never replaces an existing directory.

```sh
./install.sh --viewer-runtime /tmp/viewer-runtime
python tools/release.py --cache /tmp/release-inputs --work /tmp/release-build \
  --output /tmp/release-output --viewer-runtime /tmp/viewer-runtime
```

The source installer copies the runtime below its virtual environment.
Release assembly copies it beside the bundled Python directory and includes its components in the release SBOM.
All runtime notices and corresponding sources remain inside the distribution.
Omitting this option leaves the native viewer unavailable until a runtime is supplied.

Discovery checks an explicit runtime first, then adjacent installation directories. It never searches PATH.
The manifest records the exact Linux distribution, version, architecture and glibc version.
A different platform requires a separate build and qualification. A local manifest edit does not prove compatibility.
The controller's base platform support does not imply support for an incompatible native viewer bundle.

An invalid automatically discovered runtime must disable the viewer without stopping the controller.
Use `--viewer-runtime` with `ficc serve` for an explicit selection.

Guacamole remains Apache-2.0. LibVNCClient retains its GPL-2.0-or-later terms.
FreeRDP and WinPR retain Apache-2.0 and their bundled component notices.
The linked native viewer is distributed under GPL-3.0-or-later, using LibVNCClient's later-version option.
The runtime includes that license and the common license texts referenced by its package notices.
The separate FICC controller retains its Apache-2.0 license.

See each bundled license and source notice for the terms that apply to that component.
The runtime's process boundary does not remove its source distribution requirements.

The RDP build applies the pinned Apache GUACAMOLE-2328 repair to Guacamole1.6.0.
FreeRDP3.31 and later create the connection cache after `PreConnect`. The repair
moves GDI initialization and its dependent callbacks to `PostConnect`, as in
upstream commit `ab36756b596520ae2a94cd4d25e406e0b5aa820b`. The exact backport,
checksum and upstream links are retained in the runtime source inventory.
The builder requires `patch` and applies the repair with no context fuzz.
