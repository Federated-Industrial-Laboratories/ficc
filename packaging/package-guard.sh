#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Refuse package replacement while its interpreter is in use; preserve user state.
set -eu
for process_exe in /proc/[0-9]*/exe; do
    target=$(readlink -- "$process_exe" 2>/dev/null) || continue
    case "$target" in
        /opt/ficc/python/bin/python*)
            echo 'Stop FICC and its bundled commands before upgrading or removing this package.' >&2
            echo 'Each desktop account can run: ficc stop' >&2
            exit 1
            ;;
    esac
done
