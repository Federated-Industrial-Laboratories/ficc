# SPDX-License-Identifier: Apache-2.0
"""Wrap the same payload in AppImage, Debian and Arch distribution formats."""

import os
import shutil
from pathlib import Path

from .common import archive_tree, digest, normalize_tree, run


def executable(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o755)


def install_tree(payload: Path, root: Path) -> None:
    shutil.copytree(payload, root / "opt/ficc", symlinks=True)
    for folder in ("usr/bin", "usr/share/applications", "usr/share/icons/hicolor/scalable/apps", "usr/share/doc/ficc"):
        (root / folder).mkdir(parents=True, exist_ok=True)
    (root / "usr/bin/ficc").symlink_to("../../opt/ficc/ficc")
    shutil.copy2(payload / "ficc.desktop", root / "usr/share/applications/ficc.desktop")
    shutil.copy2(payload / "ficc.svg", root / "usr/share/icons/hicolor/scalable/apps/ficc.svg")
    (root / "usr/share/doc/ficc/copyright").write_text((payload / "NOTICE").read_text() + "\n" + (payload / "LICENSE").read_text())


def deb(payload: Path, work: Path, output: Path, version: str, epoch: int) -> Path:
    root = work / "deb"
    install_tree(payload, root)
    control = root / "DEBIAN"
    control.mkdir()
    deb_version = version.replace("rc", "~rc")
    size = sum(p.stat().st_size for p in payload.rglob("*") if p.is_file()) // 1024 + 1
    (control / "control").write_text(
        f"Package: ficc\nVersion: {deb_version}\nArchitecture: amd64\nSection: admin\nPriority: optional\n"
        "Maintainer: Federated Industrial Laboratories <contact@federatedindustrial.com>\n"
        f"Installed-Size: {size}\n"
        "Depends: libc6 (>= 2.28), openssh-client, coreutils, systemd, xdg-utils\n"
        "Recommends: libnotify-bin\n"
        "Homepage: https://github.com/Federated-Industrial-Laboratories/ficc\n"
        "Description: Local Linux cluster administration console\n"
        " Manage trusted nodes, jobs, files, terminals and coding agents through\n"
        " a local browser interface and pinned OpenSSH connections.\n")
    guard = (payload / "package-guard.sh").read_text()
    executable(control / "preinst", guard)
    executable(control / "prerm", guard)
    normalize_tree(root, epoch)
    target = output / f"ficc_{deb_version}_amd64.deb"
    run(["dpkg-deb", "--root-owner-group", "-Zxz", "--build", str(root), str(target)],
        env=dict(os.environ, SOURCE_DATE_EPOCH=str(epoch)))
    return target


def appimage(payload: Path, source: Path, work: Path, output: Path,
             inputs: dict[str, Path], version: str, epoch: int) -> Path:
    appdir = work / "FICC.AppDir"
    shutil.copytree(payload, appdir / "usr/lib/ficc", symlinks=True)
    shutil.copy2(source / "packaging/AppRun", appdir / "AppRun")
    (appdir / "AppRun").chmod(0o755)
    (appdir / "ficc.desktop").write_text((payload / "ficc.desktop").read_text().replace("Exec=ficc desktop", "Exec=AppRun"))
    shutil.copy2(payload / "ficc.svg", appdir / "ficc.svg")
    (appdir / ".DirIcon").symlink_to("ficc.svg")
    normalize_tree(appdir, epoch)
    tool_dir = work / "appimagetool"
    tool_dir.mkdir()
    tool = inputs["appimagetool"]
    tool.chmod(0o755)
    run([str(tool), "--appimage-extract"], cwd=tool_dir)
    target = output / f"FICC-{version}-x86_64.AppImage"
    run([str(tool_dir / "squashfs-root/AppRun"), "--no-appstream", "--runtime-file", str(inputs["runtime"]),
         "--mksquashfs-opt", "-processors", "--mksquashfs-opt", "2", str(appdir), str(target)],
        env=dict(os.environ, ARCH="x86_64", VERSION=version, SOURCE_DATE_EPOCH=str(epoch)))
    target.chmod(0o755)
    return target


def arch_recipe(payload: Path, portable: Path, output: Path, version: str, epoch: int) -> Path:
    recipe = output / "arch"
    recipe.mkdir()
    shutil.copy2(portable, recipe / portable.name)
    (recipe / "PKGBUILD").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "# Package the verified upstream runtime for the native package manager.\n"
        "pkgname=ficc-bin\n"
        f"pkgver={version}\npkgrel=1\n"
        "pkgdesc='Local Linux cluster administration console'\n"
        "arch=('x86_64')\n"
        "url='https://github.com/Federated-Industrial-Laboratories/ficc'\n"
        "license=('Apache-2.0')\n"
        "depends=('glibc>=2.28' 'openssh' 'coreutils' 'systemd' 'xdg-utils')\n"
        "optdepends=('libnotify: desktop startup errors')\n"
        "provides=('ficc')\nconflicts=('ficc')\n"
        "options=('!strip' '!debug')\n"
        f"source=('{portable.name}')\nsha256sums=('{digest(portable)}')\n\n"
        "package() {\n"
        "  install -d \"$pkgdir/opt\" \"$pkgdir/usr/bin\" \"$pkgdir/usr/share/applications\"\n"
        "  cp -a \"$srcdir/ficc-$pkgver-linux-x86_64\" \"$pkgdir/opt/ficc\"\n"
        "  ln -s ../../opt/ficc/ficc \"$pkgdir/usr/bin/ficc\"\n"
        "  install -Dm644 \"$pkgdir/opt/ficc/ficc.desktop\" \"$pkgdir/usr/share/applications/ficc.desktop\"\n"
        "  install -Dm644 \"$pkgdir/opt/ficc/ficc.svg\" \"$pkgdir/usr/share/icons/hicolor/scalable/apps/ficc.svg\"\n"
        "  install -Dm644 \"$pkgdir/opt/ficc/LICENSE\" \"$pkgdir/usr/share/licenses/ficc-bin/LICENSE\"\n"
        "  install -Dm644 \"$pkgdir/opt/ficc/ficc-runtime.hook\" \"$pkgdir/usr/share/libalpm/hooks/00-ficc-runtime.hook\"\n"
        "}\n")
    archive_tree(recipe, output / f"ficc-{version}-arch-recipe.tar.gz", epoch)
    return recipe
