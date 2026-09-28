#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Install only the reviewed bwrap policy; never alter global AppArmor settings.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
policy_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_file="$policy_dir/ficc-module-bwrap"
target=/etc/apparmor.d/ficc-module-bwrap
profiles=/sys/kernel/security/apparmor/profiles
action=${1:-check}

fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# -le 1 ]] || fail 'Use check, install or remove.'
[[ $action == check || $action == install || $action == remove ]] || fail 'Use check, install or remove.'
[[ -f $source_file && ! -L $source_file ]] || fail 'The reviewed policy source is missing or linked.'
[[ -x /usr/sbin/apparmor_parser && -f /etc/apparmor.d/abi/4.0 ]] || fail 'AppArmor with policy ABI 4.0 is required.'
/usr/sbin/apparmor_parser -Q -K "$source_file"
if [[ $action == check ]]; then
    printf '%s\n' 'Policy syntax passed. No policy was installed or loaded.'
    exit 0
fi
[[ $EUID == 0 ]] || fail 'An administrator must run install or remove after reviewing README.md.'
[[ -r $profiles ]] || fail 'The active AppArmor profile list is unavailable.'
[[ ! -L $target ]] || fail 'The policy target is a link. Refusing to replace it.'

if [[ $action == remove ]]; then
    [[ -f $target ]] || fail 'This policy is not installed.'
    cmp -s -- "$source_file" "$target" || fail 'The installed policy changed. Review it before removal.'
    for current in /proc/[0-9]*/attr/current; do
        if grep -qE 'ficc_module_(bwrap|payload)' "$current" 2>/dev/null; then
            fail 'Stop all processes using this policy before removal.'
        fi
    done
    if grep -qE '^ficc_module_(bwrap|payload)( |//)' "$profiles"; then
        /usr/sbin/apparmor_parser -R -K "$target"
    fi
    rm -- "$target"
    printf '%s\n' 'Removed the FICC bwrap policy. Executable modules require a new successful sandbox check.'
    exit 0
fi

[[ $(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns) == 1 ]] || fail 'This prerequisite applies only with restricted unprivileged user namespaces enabled.'
if [[ -e $target ]]; then
    [[ -f $target ]] && cmp -s -- "$source_file" "$target" || fail 'A different policy already occupies the target.'
    /usr/sbin/apparmor_parser -r -K "$target"
    printf '%s\n' 'Reloaded the identical FICC bwrap policy. Run the sandbox qualification check.'
    exit 0
fi
if grep -qiE '(^|[ /])(bwrap|bubblewrap|unpriv_bwrap|ficc_module_bwrap|ficc_module_payload)( |/|$)' "$profiles"; then
    fail 'A bwrap-related policy is already loaded. Review the existing policy instead of installing another.'
fi
for existing in /etc/apparmor.d/*; do
    [[ -f $existing ]] || continue
    if grep -qE '^[[:space:]]*(profile[[:space:]]+[^[:space:]]+[[:space:]]+)?/?usr/bin/bwrap([[:space:]]|$)' "$existing"; then
        fail 'An existing policy attaches to /usr/bin/bwrap. Review it before installation.'
    fi
done
stage=$(mktemp /etc/apparmor.d/.ficc-module-bwrap.XXXXXXXX)
trap 'rm -f -- "$stage"' EXIT
install -o root -g root -m 0644 -- "$source_file" "$stage"
# A hard link publishes without replacing a file created after the checks.
ln -- "$stage" "$target"
rm -- "$stage"
if ! /usr/sbin/apparmor_parser -a -K "$target"; then
    if /usr/sbin/apparmor_parser -R -K "$target"; then
        rm -- "$target"
    else
        printf '%s\n' 'Policy load or rollback failed. The file was retained for administrator recovery.' >&2
    fi
    exit 1
fi
printf '%s\n' 'Installed the FICC bwrap policy. Run the sandbox qualification check before enabling modules.'
