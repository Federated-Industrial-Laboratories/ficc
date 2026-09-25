#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test a native package only inside a disposable qualification container.
# Inputs: package type and file. Exit: zero when install and lifecycle checks pass.
set -eu
[ "${FICC_DISPOSABLE_CONTAINER:-}" = 1 ] || {
    echo 'This check requires an explicitly disposable container.' >&2
    exit 1
}
kind=$1
package=$2
case "$kind" in
    deb)
        install_package() { dpkg -i "$package"; }
        remove_package() { dpkg --purge ficc; }
        ;;
    arch)
        install_package() { pacman -U --noconfirm "$package"; }
        remove_package() { pacman -R --noconfirm ficc-bin; }
        ;;
    *) exit 2 ;;
esac
install_package
/usr/bin/ficc --version
test -x /opt/ficc/python/bin/python3
test ! -e /usr/lib/systemd/system/ficc.service
test ! -e /etc/systemd/system/ficc.service
id package-user >/dev/null 2>&1 || useradd -m -U package-user
runuser -u package-user -- /opt/ficc/python/bin/python3 -I -B /checks/qualify_package.py \
    --command /usr/bin/ficc --payload /opt/ficc
state=$(getent passwd package-user | cut -d: -f6)/.local/state/ficc
mkdir -p "$state"
printf '%s\n' retained-user-state > "$state/package-check"
chown -R package-user:package-user "$(dirname "$(dirname "$state")")"
/opt/ficc/python/bin/python3 -I -B -c 'import time; time.sleep(90)' &
child=$!
trap 'kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true' EXIT
# The process may not have completed exec when the package manager starts.
attempt=0
while [ "$(readlink "/proc/$child/exe" 2>/dev/null || true)" != /opt/ficc/python/bin/python3.12 ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 100 ] || exit 1
    sleep 0.05
done
if install_package; then echo 'Upgrade accepted an active runtime.' >&2; exit 1; fi
test -x /opt/ficc/python/bin/python3
if remove_package; then echo 'Removal accepted an active runtime.' >&2; exit 1; fi
test -x /opt/ficc/python/bin/python3
kill "$child"
wait "$child" 2>/dev/null || true
trap - EXIT
install_package
/usr/bin/ficc --version
remove_package
test ! -e /opt/ficc
test ! -e /usr/bin/ficc
test "$(cat "$state/package-check")" = retained-user-state
echo 'Native package: install, API/PTY/auth, active guards, stopped upgrade, removal and retained state pass.'
