#!/bin/sh
# Emit the path of a cargo-build-sbf with platform-tools >= v1.52 / rustc 1.89,
# needed to parse edition2024 transitive deps. Checks $CARGO_BUILD_SBF, then
# $PATH, then installed solana releases. Exit 1 if nothing qualifies.

set -u

MIN_MAJOR=1
MIN_MINOR=52

check_bin() {
    bin="$1"
    [ -x "$bin" ] || return 1
    ver=$("$bin" --version 2>/dev/null | awk '/platform-tools/ {print $2}' | tr -d 'v')
    [ -z "$ver" ] && return 1
    maj=${ver%%.*}
    rest=${ver#*.}
    min=${rest%%.*}
    case "$maj$min" in
        *[!0-9]*) return 1 ;;
    esac
    if [ "$maj" -gt "$MIN_MAJOR" ]; then
        echo "$bin"; return 0
    fi
    if [ "$maj" -eq "$MIN_MAJOR" ] && [ "$min" -ge "$MIN_MINOR" ]; then
        echo "$bin"; return 0
    fi
    return 1
}

if [ "${CARGO_BUILD_SBF-}" != "" ]; then
    check_bin "$CARGO_BUILD_SBF" && exit 0
fi

if bin=$(command -v cargo-build-sbf 2>/dev/null); then
    check_bin "$bin" && exit 0
fi

for bin in "$HOME"/.local/share/solana/install/releases/*/solana-release/bin/cargo-build-sbf; do
    check_bin "$bin" && exit 0
done

exit 1
