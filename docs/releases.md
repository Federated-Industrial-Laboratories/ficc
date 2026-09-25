<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Linux packages

[Contents](README.md) | [Project README](../README.md) | [Installation](install.md)

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

Download [FICC 0.1.0 from GitHub Releases](https://github.com/Federated-Industrial-Laboratories/ficc/releases/tag/v0.1.0).
This release supports Linux x86_64. Packages include Python
and application dependencies. Nodes still need their own Python and SSH setup.
The controller needs OpenSSH, GNU coreutils, xdg-utils and a systemd user manager
for desktop startup. Package installation does not start a service as root.

| Format | Use |
| --- | --- |
| Debian `.deb` | Ubuntu 24.04 and Debian 12 package installation. |
| Arch `.pkg.tar.zst` | Arch Linux x86_64, installed with pacman. |
| AppImage | A movable executable with FUSE, or explicit extraction below. |
| Portable `.tar.gz` | An extracted directory with its own `ficc` command. |
| Wheel and source | Development and independently managed Python environments. |

Download SHA256SUMS from the same release and verify the downloaded files with
`sha256sum --check --ignore-missing SHA256SUMS`. Checksums detect corruption;
obtain the files and checksum list from the trusted project release page.

## Debian and Ubuntu

```sh
sudo apt install ./ficc_0.1.0_amd64.deb
ficc desktop
```

## Arch Linux

```sh
sudo pacman -U ./ficc-bin-0.1.0-1-x86_64.pkg.tar.zst
ficc desktop
```

The recipe archive also contains a PKGBUILD and its verified portable input.
Extract it and run `makepkg` as a regular user to build the package locally.

## AppImage

Run the executable from a directory owned by the desktop account.

```sh
chmod +x FICC-0.1.0-x86_64.AppImage
./FICC-0.1.0-x86_64.AppImage
```

On first desktop use, FICC verifies and copies the bundled runtime into
`~/.local/share/ficc/runtimes/` (or XDG_DATA_HOME). The on-demand service and
desktop entry use that private copy, so service startup needs no FUSE mount.
The service keeps its privilege restrictions. Each release has a separate
content-addressed runtime; existing launcher settings remain authoritative.

Opening the AppImage requires a working FUSE installation. Without FUSE, extract once
into the directory where FICC will remain:

```sh
./FICC-0.1.0-x86_64.AppImage --appimage-extract
./squashfs-root/AppRun desktop
```

Do not use `--appimage-extract-and-run` or `APPIMAGE_EXTRACT_AND_RUN`. The upstream
runtime shares a temporary directory between invocations; a second command can
remove files still used by the service. FICC refuses that mode. The explicit
extraction directory must remain available while its launcher is installed.

## Portable archive

```sh
tar -xzf ficc-0.1.0-linux-x86_64.tar.gz
./ficc-0.1.0-linux-x86_64/ficc desktop
```

The first desktop start creates a private on-demand user service and opens the
browser with a one-use sign-in. It approves no SSH aliases. Follow
[machine enrollment](install.md#connect-a-machine) to configure trusted profiles.
An existing launcher configuration remains authoritative. Changing formats or
moving a portable or explicitly extracted directory requires reinstalling that launcher after
stopping the previous service, with the same state and approved profiles.

## Upgrade and remove

Back up the stopped controller before an upgrade. Each account using the native
package must stop its service with `ficc stop` and close other bundled commands.
Debian and Arch transactions refuse replacement of an active bundled interpreter.
Install the new package normally, then open FICC. AppImage users must stop the service and run the new image with `install-launcher`
and their existing settings to select the new verified runtime. Portable users
must stop the service before replacing their extracted directory.

Use `sudo apt remove ficc` or `sudo pacman -R ficc-bin` to remove a native package.
Removal preserves private state and user launcher files. To retire the launcher,
run `systemctl --user disable --now ficc.service`, remove its generated service
and desktop entry, then run `systemctl --user daemon-reload`. Use the configured
service name if it differs. AppImage installations also retain versioned runtime
directories under `~/.local/share/ficc/runtimes/` (or XDG_DATA_HOME). After stopping
all launchers that use a runtime, its directory can be removed. Keep the runtime
selected by any retained launcher configuration. Remove private state only when
it is no longer needed.

## Release contents

Each release includes SHA256SUMS, build.json, a CycloneDX inventory, complete FICC
source and a third-party source archive. The payload's bundle.json binds its
files and links to the source and build inputs. THIRD-PARTY.md describes licences
and source correspondence. The AppImage runtime's native dependency versions are
only listed where upstream provides evidence; its remaining build dependencies
are named without a claimed binary version.

See [dependency notices](dependencies.md), [testing](testing.md) and the
[maintainer build procedure](../packaging/README.md).

<p align="center"><img src="../.github/assets/divider.svg" width="720" alt=""></p>

[Contents](README.md) | [Installation](install.md)
