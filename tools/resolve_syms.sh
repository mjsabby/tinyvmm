#!/bin/bash
nm /mnt/c/tinyvmm/vmlinux 2>/dev/null | sort > /tmp/syms.txt
for a in "$@"; do
  echo "-- $a --"
  grep ' T ' /tmp/syms.txt | awk -v t="$a" '$1 <= t' | tail -3
  echo "    -- next --"
  grep ' T ' /tmp/syms.txt | awk -v t="$a" '$1 >= t' | head -1
done
