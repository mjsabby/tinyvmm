#!/usr/bin/env bash
set -euo pipefail

recipe=$(cd "$(dirname "$0")" && pwd)
source=$(realpath "${1:?usage: build.sh SOURCE_DIR [BUILD_DIR]}")
build=$(realpath -m "${2:-$source/build-tinyvmm}")

make -s -C "$source" O="$build" allnoconfig KCONFIG_ALLCONFIG="$recipe/tinyvmm.config"

bad=0
while IFS= read -r line; do
    if [[ $line =~ ^CONFIG_[A-Za-z0-9_]+= ]]; then
        grep -qxF -- "$line" "$build/.config" || { echo "not applied: $line" >&2; bad=1; }
    elif [[ $line =~ ^"# "(CONFIG_[A-Za-z0-9_]+)" is not set"$ ]]; then
        if grep -q "^${BASH_REMATCH[1]}=" "$build/.config"; then
            echo "not applied: $line" >&2
            bad=1
        fi
    fi
done < "$recipe/tinyvmm.config"
[[ $bad == 0 ]]

make -s -C "$source" O="$build" -j"${JOBS:-$(nproc)}" vmlinux
objcopy --strip-debug "$build/vmlinux" "$build/vmlinux.tinyvmm"
size "$build/vmlinux"
ls -l "$build/vmlinux.tinyvmm"
