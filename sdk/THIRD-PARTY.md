# SDK dependency licenses

FICC SDK source and examples use Apache-2.0, as stated in the source headers and
root LICENSE. Every generated package includes the FICC license and NOTICE file.
Third-party terms remain separate.

| Dependency | Use | Source and terms |
| --- | --- | --- |
| cJSON 1.7.19 | C/C++ JSON parsing and encoding; compiled into the native examples | [Official repository](https://github.com/DaveGamble/cJSON/tree/v1.7.19), MIT. The original license is included in each native package. |
| serde_json 1.0.145 | Rust JSON parsing and encoding | [Versioned source](https://docs.rs/crate/serde_json/1.0.145/source/), MIT or Apache-2.0. Cargo.lock pins all dependencies; their original license files and the lockfile are included in the Rust package. |
| TypeScript 5.9.3 | Build-time compiler only | [Official compiler](https://github.com/microsoft/TypeScript), Apache-2.0. The compiler is downloaded to the build cache, not shipped as runtime code. Its license is included with the compiled example. |
| VirtualBox SDK 7.2.20 revision 175154 | C API glue and declarations for the supplied VirtualBox adapter | [Pinned upstream SDK](https://download.virtualbox.org/virtualbox/7.2.20/VirtualBoxSDK-7.2.20-175154.zip). VBoxCAPIGlue.c/.h are MIT; VBoxCAPI_v7_2.h is LGPL-2.1-only. Original notices, complete selected source/header files and COPYING.LIB are included in the adapter archive. |
| Python and Node.js | Host-provided language runtimes and standard JSON libraries | Runtimes are not included in the module archives. Their own distribution licenses apply. |

Downloaded dependency source is kept in the build cache. No third-party source
is copied into the maintained SDK source tree. Dependency cache entries are
verified before use. Review dependency changes and regenerate pins or Cargo.lock
explicitly; the packer does not update versions in the background.

The VirtualBox SDK archive is pinned to 14889127 bytes and SHA256
`d94e4dddd5b99c84b2e328e8a19faff906168ad1d51e9545376f638108c0edc8`
in the module's `build.json`. The installed VirtualBox provider libraries remain
external runtime prerequisites; the module loads their C API dynamically.

The same provider package includes a GPL-3.0-only Unix-listener modification to
the free VirtualBox VNC extension, its full license, and a build script. That
separate build uses checksum-pinned upstream VirtualBox source and installed
LibVNCServer. It produces an administrator-installed provider extension with
complete corresponding source and notices. It is not built or installed during
FICC module activation. See the [extension source and license guide](../modules/virtualbox-adapter/payload/README.md).
