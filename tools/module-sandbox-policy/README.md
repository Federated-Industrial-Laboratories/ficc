<!-- SPDX-License-Identifier: Apache-2.0 -->
# AppArmor prerequisite for executable modules

This optional administrator action prepares Ubuntu hosts that restrict
unprivileged user namespaces and lack a working Bubblewrap profile. It does not
enable a module. FICC still requires its exact namespace, syscall and cgroup
probe to succeed before executable activation.

The profile attaches to `/usr/bin/bwrap`, so it also applies to other applications
that execute that binary. Its bootstrap may use capabilities needed to construct
the isolated environment. Every executed child receives a stacked profile that
denies capabilities. The profile alone does not restrict arbitrary file paths.
FICC's read-only mounts, hidden home and sockets, private namespaces, seccomp
rules and resource controls provide the rest of the execution boundary.

This is a scoped executable policy, not a change to the global user-namespace
sysctl. Do not disable AppArmor, use a complain-mode profile or give a module a
general unconfined profile to make the probe pass. The installer refuses known
conflicting bwrap policies and never replaces a different policy file. An
administrator must review any existing policy or attachment ambiguity first.

The rule structure comes from the AppArmor project's
[ABI 4.0 bwrap profile](https://gitlab.com/apparmor/apparmor/-/raw/apparmor-4.0/profiles/apparmor/profiles/extras/bwrap-userns-restrict),
with FICC-specific profile names and optional local overrides removed. This
separate policy is GPL-2.0-only under the upstream
[license](https://gitlab.com/apparmor/apparmor/-/raw/apparmor-4.0/LICENSE);
the full license is in `COPYING`. The installer and this document are Apache-2.0.

Ubuntu describes the restricted namespace capability transition and recommends
a purpose-built bwrap profile with constrained children in its
[security explanation](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007).
Its [AppArmor documentation](https://ubuntu.com/server/docs/how-to/security/apparmor/)
describes loading and removing individual profiles.

## Review, install and qualify

Read `ficc-module-bwrap` and `install.sh`. The `check` action compiles policy
without loading it or writing the parser cache. It needs no administrator access.

```sh
bash tools/module-sandbox-policy/install.sh check
```

Only after administrator review, install from a trusted checkout:

```sh
sudo bash tools/module-sandbox-policy/install.sh install
```

The command writes only `/etc/apparmor.d/ficc-module-bwrap` and loads its two
profiles. It requires ABI 4.0 support and the namespace restriction to be enabled.
It does not restart AppArmor or change other profile files. The installed file
loads through the normal AppArmor startup mechanism. Loading failures trigger
removal; a failed rollback retains the file and reports the recovery requirement.

Run this command as the ordinary FICC owner in the desktop session, outside
another tool sandbox. Do not run the FICC controller as root:

```sh
.venv/bin/python -c 'import asyncio; from ficc.modules.sandbox import Sandbox; print(asyncio.run(Sandbox().probe()).public())'
```

Require `available: True`, then run real installed-module isolation and lifecycle
tests before claiming the platform is qualified. A syntax check is not a security
qualification. Other applications using Bubblewrap need a smoke check because the
child capability restriction can affect their existing workflows.

## Rollback

Disable executable modules and stop the FICC controller and other active bwrap
jobs. The removal command refuses while a process uses these profiles or if the
installed file differs from the reviewed source:

```sh
sudo bash tools/module-sandbox-policy/install.sh remove
```

It unloads only `ficc_module_bwrap` and `ficc_module_payload`, then removes the
matching policy file. The namespace sysctl and unrelated profiles remain intact.
On a host requiring this prerequisite, executable activation will fail closed
again after removal. Declarative workspace components do not launch a process.
