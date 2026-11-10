#!/bin/busybox sh
# /init of the PoC guest. The kernel command line names the PoC:
#   poc=<name> [pocargs=key=value,key=value,...]
# It runs /bin/vhostile <name> key=value ... and powers off. Everything a PoC
# reports is a "[poc] ..." line on /dev/kmsg, which the kernel prints on hvc0.
bb=/bin/busybox
$bb mount -t proc proc /proc
$bb mount -t sysfs sys /sys
$bb mount -t devtmpfs dev /dev
$bb mount -t tmpfs -o mode=1777 tmp /tmp

log() { echo "[poc] $*" > /dev/kmsg; }

poc=""
args=""
for w in $($bb cat /proc/cmdline); do
    case "$w" in
        poc=*) poc="${w#poc=}" ;;
        pocargs=*) args="${w#pocargs=}" ;;
    esac
done

if [ -z "$poc" ]; then
    log "ERROR no poc= on the kernel command line"
else
    log "init: running $poc"
    # shellcheck disable=SC2046
    /bin/vhostile "$poc" $(echo "$args" | $bb tr ',' ' ')
    log "init: vhostile exited rc=$?"
fi
$bb sync
$bb poweroff -f
# poweroff -f does not return; if it did, park.
exec $bb sleep 3600
