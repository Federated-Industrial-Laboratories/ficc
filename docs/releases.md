<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Linux packages

[Contents](README.md) | [Project README](../README.md) | [Installation](install.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

<details>
<summary>On this page</summary>

- [Debian and Ubuntu](#debian-and-ubuntu)
- [Arch Linux](#arch-linux)
- [AppImage](#appimage)
- [Portable archive](#portable-archive)
- [Upgrade and remove](#upgrade-and-remove)
- [Release contents](#release-contents)

</details>

Download FICC from [GitHub Releases](https://github.com/Federated-Industrial-Laboratories/ficc/releases).
Use a Linux x86_64 package below. The examples use version 0.2.6.post4.
Check the published release version before downloading. These manuals also cover the current source version.

The revision release designation is `0.2.6r4-final`, with tag `v0.2.6r4-final`.
Application and package versions use `0.2.6.post4` for Python and native package compatibility.
This version sorts after `0.2.6`; the public release name retains the `r4` designation.
This is the final revision of the 0.2.6 series. Subsequent changes use a new version.
Select the matching release and verify its signed `SHA256SUMS` file.

VM providers require their documented host versions, transports and explicit grants.
See [provider support](testing.md#runtime-modules-and-providers) before installing VM modules.

Each package includes Python and
application dependencies. Nodes need their own Python and SSH setup. The
controller needs OpenSSH, GNU coreutils and xdg-utils; desktop startup also
requires a systemd user manager. Installation does not start a root service.

| Format | Use |
| --- | --- |
| Debian `.deb` | Ubuntu 24.04 and Debian 12 package installation. |
| Arch `.pkg.tar.zst` | Arch Linux x86_64, installed with pacman. |
| AppImage | A movable executable with FUSE, or explicit extraction below. |
| Portable `.tar.gz` | An extracted directory with its own `ficc` command. |
| Wheel and source | Development and independently managed Python environments. |

Download `SHA256SUMS`, `SHA256SUMS.sig` and the selected packages from the same
release. Save the [publisher's public key from the FICC website](https://ficc.federatedindustrial.com/docs/source/packaging/ficc-release.pub)
as `ficc-release.pub`. The [repository copy](../packaging/ficc-release.pub) contains
the same Ed25519 key. Confirm its fingerprint through an independently trusted
channel before first use:

```text
SHA256:Z8IL7pkS9IT5uHTv+YUsQnN4GE1N8CQPTVUNq+QLYlU
```

Use `ssh-keygen -lf ficc-release.pub` to display the downloaded key's fingerprint.
The release asset `RELEASE.pub` alone does not establish publisher identity.
After confirming the key, verify the signature and package checksums:

```sh
printf 'ficc-release namespaces="ficc-release-v1" ' > allowed-signers
cat ficc-release.pub >> allowed-signers
ssh-keygen -Y verify -f allowed-signers -I ficc-release \
  -n ficc-release-v1 -s SHA256SUMS.sig < SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

Run the checksum command only after signature verification succeeds, and confirm
that it reports the exact package you intend to install. A checksum alone detects
corruption; the pinned signing key establishes which publisher signed those bytes.
Key rotation requires independent confirmation before replacing the trusted key.

## Debian and Ubuntu

```sh
sudo apt install ./ficc_0.2.6.post4_amd64.deb
ficc desktop
```

## Arch Linux

```sh
sudo pacman -U ./ficc-bin-0.2.6.post4-1-x86_64.pkg.tar.zst
ficc desktop
```

The recipe archive also contains a PKGBUILD and its verified portable input.
Extract it and run `makepkg` as a regular user to build the package locally.

## AppImage

Run the executable from a directory owned by the desktop account.

```sh
chmod +x FICC-0.2.6.post4-x86_64.AppImage
./FICC-0.2.6.post4-x86_64.AppImage
```

On first desktop use, FICC verifies and copies the bundled runtime into
`~/.local/share/ficc/runtimes/` (or XDG_DATA_HOME). The on-demand service and
desktop entry use that private copy, so service startup needs no FUSE mount.
The service keeps its privilege restrictions. Each release has a separate
content-addressed runtime; existing launcher settings remain authoritative.

Opening the AppImage requires a working FUSE installation. Without FUSE, extract once
into the directory where FICC will remain:

```sh
./FICC-0.2.6.post4-x86_64.AppImage --appimage-extract
./squashfs-root/AppRun desktop
```

Do not use `--appimage-extract-and-run` or `APPIMAGE_EXTRACT_AND_RUN`. The upstream
runtime shares a temporary directory between invocations; a second command can
remove files still used by the service. FICC refuses that mode. The explicit
extraction directory must remain available while its launcher is installed.

## Portable archive

```sh
tar -xzf ficc-0.2.6.post4-linux-x86_64.tar.gz
./ficc-0.2.6.post4-linux-x86_64/ficc desktop
```

The first desktop start creates a private on-demand user service and opens the
browser with a one-use sign-in. It approves no SSH aliases. Follow
[machine enrollment](install.md#connect-a-machine) to configure trusted profiles.
An existing launcher configuration remains authoritative. Stop the service before
changing formats or moving a portable or extracted directory. Then reinstall
the launcher with the same state and approved profiles.

## Upgrade and remove

Back up the stopped controller before an upgrade. Each account using the native
package must stop its service with `ficc stop` and close other bundled commands.
Debian and Arch transactions refuse replacement of an active bundled interpreter.
Install the new package normally, then open FICC. AppImage users must stop the service and run the new image with `install-launcher`
and their existing settings to select the new verified runtime. Portable users
must stop the service before replacing their extracted directory.

An upgrade from 0.2.0 migrates local state into the identity/project model with
the existing local owner. It does not enable remote access, enroll contributors,
activate policies or grant new source permissions. Retain the stopped 0.2.0
backup and old runtime together for rollback; do not open migrated state with
the older version. Restore into a separate directory and follow the
[recovery procedure](backup.md) before resuming external work.

Use `sudo apt remove ficc` or `sudo pacman -R ficc-bin` to remove a native package.
Removal preserves private state and user launcher files. To retire the launcher,
run `systemctl --user disable --now ficc.service`, remove its generated service
and desktop entry, then run `systemctl --user daemon-reload`. Use the configured
service name if it differs.

AppImage installations also retain versioned runtime
directories under `~/.local/share/ficc/runtimes/` (or XDG_DATA_HOME). After stopping
all launchers that use a runtime, its directory can be removed. Keep the runtime
selected by any retained launcher configuration. Remove private state only when
it is no longer needed.

## Release contents

Each release includes SHA256SUMS and its OpenSSH signature, RELEASE.pub, build.json,
a CycloneDX inventory, complete FICC
source and a third-party source archive. The payload's bundle.json binds its
files and links to the source and build inputs. THIRD-PARTY.md describes licenses
and source correspondence. The AppImage runtime's native dependency versions are
only listed where upstream provides evidence; its remaining build dependencies
are named without a claimed binary version.

Supplied infrastructure providers remain separate wheels under `runtime-packages/`
in the payload. Their installed packages, hashes and dependencies enter the SBOM
and payload inventory. SDK documentation, remote deployment presets and policy
sources are included. Provider installation does not configure its external
service or grant authority. Use a dedicated Python environment or the source
installation for administrator-managed provider extensions after build.

See [dependency notices](dependencies.md), [testing](testing.md) and the
[maintainer build procedure](../packaging/README.md).

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Installation](install.md)
