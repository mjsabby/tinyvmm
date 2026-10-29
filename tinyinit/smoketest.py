"""Boot tinyinit in the unchanged tinyvmm and check it from Windows over SSH."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import socket
import statistics
import subprocess
import threading
import time

HERE = Path(__file__).resolve().parent
OUT = HERE / "out" / "smoke"


def check(condition, message, detail=None):
    if not condition:
        raise AssertionError(f"{message}: {detail!r}")
    print(f"PASS {message}", flush=True)


def keygen(path):
    if not path.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True)


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class VM:
    def __init__(self, args, config, name):
        self.name = name
        self.port = unused_port()
        self.log = OUT / f"{name}.log"
        self.known_hosts = OUT / f"{name}.known_hosts"
        self.known_hosts.unlink(missing_ok=True)
        bootstrap = OUT / name
        bootstrap.mkdir(exist_ok=True)
        (bootstrap / "init.json").write_text(json.dumps(config), encoding="utf-8")
        (bootstrap / "caller.pub").write_bytes((OUT / "caller.pub").read_bytes())
        self.lines = []
        self.events = {}
        self.boot_ready = threading.Event()
        argv = [
            str(args.vmm), "--pvh-run", "--vcpus", str(args.vcpus), "--ram-mb", "1536", "--rng",
            "--net", "--portfwd", f"{self.port}:22",
            "--virtio-9p-share", f"bootstrap={bootstrap},ro",
            "--virtio-9p-share", f"apps={args.apps},ro",
        ]
        if args.external_rootfs:
            argv += ["--virtio-9p-share", f"rootfs={args.external_rootfs.resolve()},ro"]
        if not args.embedded:
            argv += ["--initrd", str(OUT / "initrd.cpio"), str(OUT / "vmlinux")]
        argv += ["--", "console=hvc0", "pci=conf1,nocrs,lastbus=0", "idle=halt",
                 f"tinyinit.epoch={int(time.time())}"]
        if args.external_rootfs:
            argv += ["tinyinit.rootfs=9p:rootfs"]
        self.started_at = time.perf_counter()
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.reader = threading.Thread(target=self.read_log, daemon=True)
        self.reader.start()

    def read_log(self):
        pending = b""
        with self.log.open("wb") as log:
            while chunk := self.proc.stdout.read1(65536):
                log.write(chunk)
                log.flush()
                self.lines.append(chunk)
                pending += chunk
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    elapsed = (time.perf_counter() - self.started_at) * 1000
                    if b"tinyinit boot:" in line:
                        self.events.setdefault("host_to_pid1_first_log_ms", elapsed)
                    if b"event=supervisor-ready" in line:
                        self.events.setdefault("host_to_supervisor_ready_ms", elapsed)
                        self.boot_ready.set()

    def ssh(self, command=None, user="root", key="caller", pty=False, input=None, timeout=15):
        argv = [
            "ssh", "-p", str(self.port), "-i", str(OUT / key),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={self.known_hosts}", "-o", "ConnectTimeout=3",
        ]
        if pty:
            argv.append("-tt")
        argv.append(f"{user}@127.0.0.1")
        if command is not None:
            argv.append(command)
        return subprocess.run(argv, input=input, capture_output=True, timeout=timeout)

    def ready(self, poll_interval=0.3):
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline and self.proc.poll() is None:
            result = self.ssh("echo SSH_READY", timeout=5)
            if result.returncode == 0 and b"SSH_READY" in result.stdout:
                check(True, f"{self.name}: PID 1 boot and key-authenticated SSH")
                return (time.perf_counter() - self.started_at) * 1000
            time.sleep(poll_interval)
        raise AssertionError("VM did not become SSH-ready:\n" + self.text()[-12000:])

    def text(self):
        return b"".join(self.lines).decode(errors="replace")

    def finished(self):
        self.proc.wait(timeout=15)
        self.reader.join(timeout=3)
        check("=== tinyvmm shutdown requested ===" in self.text(), f"{self.name}: orderly VM shutdown")

    def close(self):
        if self.proc.poll() is None:
            subprocess.run(["powershell", "-NoProfile", "-Command", f"Stop-Process -Id {self.proc.pid} -Force"],
                           capture_output=True, timeout=10)
            self.proc.wait(timeout=10)
        self.reader.join(timeout=3)


def configuration(args):
    apps = []
    for name in ("a", "b"):
        if args.dotnet:
            argv = ["/usr/share/dotnet/dotnet", "/mnt/apps/TinyinitProbe.dll", name]
        else:
            argv = ["/bin/sh", "-c",
                    f"while :; do id > /home/app/{name}.txt; sleep 0.2; done"]
        apps.append({
            "name": name, "user": "app", "argv": argv, "cwd": "/home/app",
            # The Windows test SDK is .NET 10; explicitly opt its probe into the .NET 11 RC runtime.
            "env": {"DOTNET_ROLL_FORWARD": "Major", "DOTNET_ROLL_FORWARD_TO_PRERELEASE": "1",
                    "TINYINIT_TEST_VALUE": "from-init-json"},
            "limits": {"memory_max": 536870912, "pids_max": 128, "cpu_percent": 100},
        })
    return {
        "mounts": [{"tag": "apps", "target": "/mnt/apps", "readonly": True}],
        "users": [{"name": "app", "uid": 1000, "gid": 1000, "home": "/home/app"}],
        "network": {"interface": "eth0", "address": "10.0.0.2/24", "gateway": "10.0.0.1", "dns": ["1.1.1.1"]},
        "apps": apps,
        "ssh": {"logins": [
            {"user": "root", "public_keys_file": "/mnt/bootstrap/caller.pub"},
            {"user": "app", "public_keys_file": "/mnt/bootstrap/caller.pub"},
        ]},
    }


def benchmark(args, config, package_ms):
    samples = []
    for index in range(args.benchmark + 1):
        name = "bench-warmup" if index == 0 else f"bench-{index:02}"
        vm = VM(args, config, name)
        try:
            if not vm.boot_ready.wait(timeout=40):
                raise AssertionError("supervisor did not become ready:\n" + vm.text()[-12000:])
            ssh_ms = vm.ready(poll_interval=0.02)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                status = vm.ssh("cat /home/app/a.txt /home/app/b.txt")
                if status.returncode == 0 and status.stdout.count(b"uid=1000") == 2:
                    break
                time.sleep(0.02)
            else:
                raise AssertionError(f"both apps did not become ready: {status!r}")
            apps_ms = (time.perf_counter() - vm.started_at) * 1000
            snapshot = vm.ssh(
                "cat /run/log/boot.log; echo ===SSHD===; cat /run/log/sshd.log; "
                "echo ===MOUNTS===; cat /proc/self/mountinfo; "
                "echo ===DIRECTORIES===; ls -la /; "
                "echo ===SPACE===; df -B1 / /run /tmp /dev/shm; "
                "echo ===MEMORY===; cat /proc/meminfo"
            )
            check(snapshot.returncode == 0, f"{name}: capture boot diagnostics")
            text = snapshot.stdout.decode(errors="replace")
            (OUT / f"{name}.snapshot").write_text(text, encoding="utf-8")
            stages = {
                match[0]: float(match[1]) for match in re.findall(
                    r"stage=(\S+) event=complete duration_ms=([\d.]+)", text
                )
            }
            supervisor = re.search(r"elapsed_ms=([\d.]+) event=supervisor-ready", text)
            listener = re.search(r"event=listener-ready startup_ms=([\d.]+)", text)
            check(supervisor is not None and listener is not None
                  and ("root-unpack" in stages or "stage=root-unpack event=skipped" in text),
                  f"{name}: complete guest boot timings")
            sample = {
                **vm.events,
                "host_to_ssh_command_ms": ssh_ms,
                "host_to_both_apps_observed_ms": apps_ms,
                "guest_pid1_to_supervisor_ms": float(supervisor[1]),
                "guest_sshd_startup_ms": float(listener[1]),
                "stages_ms": stages,
            }
            if args.dotnet:
                # Guest timestamps exclude SSH's authentication delay and client polling.
                app_times = re.findall(rb"ready_uptime_ms=(\d+)", status.stdout)
                pid1 = re.search(r"event=begin kernel_uptime_ms=([\d.]+)", text)
                listener_uptime = re.search(r"event=listener-ready.*kernel_uptime_ms=([\d.]+)", text)
                check(len(app_times) == 2 and pid1 is not None and listener_uptime is not None,
                      f"{name}: guest application/listener readiness timestamps")
                sample["guest_pid1_to_both_apps_ready_ms"] = max(map(float, app_times)) - float(pid1[1])
                sample["guest_pid1_to_ssh_listener_ms"] = float(listener_uptime[1]) - float(pid1[1])
            if index:
                samples.append(sample)
            print(f"{name}: unpack={stages.get('root-unpack', 0):.1f} ms; "
                  f"bind-init={stages['root-bind-init']:.3f} ms; "
                  f"PID1={sample['guest_pid1_to_supervisor_ms']:.1f} ms; "
                  f"host-to-SSH={ssh_ms:.1f} ms; apps-observed={apps_ms:.1f} ms", flush=True)
            vm.ssh("poweroff")
            vm.finished()
        finally:
            vm.close()
    metrics = {key: [sample[key] for sample in samples] for key in samples[0] if key != "stages_ms"}
    for stage in samples[0]["stages_ms"]:
        metrics[f"stage:{stage}"] = [sample["stages_ms"][stage] for sample in samples]
    summary = {
        key: {"min_ms": min(values), "median_ms": statistics.median(values), "max_ms": max(values)}
        for key, values in metrics.items()
    }
    report = {
        "runs": args.benchmark, "warmup_runs": 1, "vcpus": args.vcpus, "ram_mib": 1536,
        "workload": "dotnet-probe" if args.dotnet else "shell",
        "image": json.loads((HERE / "rootfs.lock.json").read_text()),
        "binary_bytes": None if args.embedded else args.binary.stat().st_size,
        "vmm_bytes": args.vmm.stat().st_size,
        "embedded_boot": args.embedded,
        "external_rootfs": args.external_rootfs is not None,
        "initrd_package_ms": package_ms,
        "notes": "Warm host cache; host timings include VMM/kernel/client overhead. "
                 "SSH uses 20ms retry sleeps; apps readiness is an upper bound observed after SSH. "
                 "Guest app readiness uses /proc/uptime (10ms resolution), excluding SSH observation overhead. "
                 "Supervisor-ready means spawned, not application-ready.",
        "summary": summary, "samples": samples,
    }
    (OUT / "benchmark.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("BENCHMARK SUMMARY (milliseconds; min / median / max)", flush=True)
    for key, values in summary.items():
        print(f"{key}: {values['min_ms']:.3f} / {values['median_ms']:.3f} / {values['max_ms']:.3f}")
    print(f"Report: {OUT / 'benchmark.json'}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--vmm", type=Path, default=HERE.parent / "target/release/tinyvmm.exe")
    parser.add_argument("--binary", type=Path, default=HERE / "target/x86_64-unknown-linux-musl/release/tinyinit")
    parser.add_argument("--rootfs", type=Path)
    parser.add_argument("--embedded", action="store_true", help="use only the VMM executable's embedded kernel/initramfs")
    parser.add_argument("--external-rootfs", type=Path, help="directory containing trusted rootfs.tar.zst or rootfs.tar.gz, shared read-only for early extraction")
    parser.add_argument("--apps", type=Path)
    parser.add_argument("--dotnet", action="store_true", help="run tests/DotnetApp DLLs from --apps using embedded ASP.NET")
    parser.add_argument("--benchmark", type=int, metavar="RUNS", help="benchmark RUNS boots after one warm-up, instead of the smoke suite")
    parser.add_argument("--vcpus", type=int, default=2, help="guest vCPUs (default 2)")
    args = parser.parse_args()
    if args.benchmark is not None and args.benchmark < 1:
        parser.error("--benchmark must be at least 1")
    if args.vcpus < 1:
        parser.error("--vcpus must be at least 1")
    OUT.mkdir(parents=True, exist_ok=True)
    if not args.embedded and args.kernel is None:
        parser.error("--kernel is required without --embedded")
    if args.embedded and args.rootfs:
        parser.error("--rootfs is an extra initramfs payload; use --external-rootfs with --embedded")
    for path in ([args.vmm] if args.embedded else [args.kernel, args.vmm, args.binary]):
        if not path.is_file():
            parser.error(f"missing {path}")
    if args.external_rootfs and not any((args.external_rootfs / name).is_file() for name in ("rootfs.tar.zst", "rootfs.tar.gz")):
        parser.error("--external-rootfs must contain rootfs.tar.zst or rootfs.tar.gz")
    if args.apps is None:
        args.apps = OUT / "apps"
        args.apps.mkdir(exist_ok=True)
    (args.apps / "share-marker.txt").write_text("WINDOWS_SHARE_OK", encoding="utf-8")
    if not args.embedded:
        shutil.copyfile(args.kernel, OUT / "vmlinux")
    keygen(OUT / "caller")
    keygen(OUT / "wrong")
    spec = importlib.util.spec_from_file_location("make_initrd", HERE / "make-initrd.py")
    pack = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pack)
    package_ms = 0
    if not args.embedded:
        package_started = time.perf_counter()
        pack.build(args.binary, OUT / "initrd.cpio", args.rootfs)
        package_ms = (time.perf_counter() - package_started) * 1000
    config = configuration(args)
    if args.benchmark is not None:
        benchmark(args, config, package_ms)
        return
    vm = VM(args, config, "services")
    try:
        vm.ready()
        check(vm.ssh("true", key="wrong").returncode != 0, "reject unauthorized public key")
        check(vm.ssh("true", user="unknown").returncode != 0, "reject unknown SSH user")
        result = vm.ssh("id")
        check(result.returncode == 0 and b"uid=0(root)" in result.stdout, "authorized root administration")
        result = vm.ssh("id; touch /home/app/login.txt; touch /root/forbidden", user="app")
        check(b"uid=1000(app)" in result.stdout and result.returncode != 0, "ordinary login cannot access root home")
        result = vm.ssh("cat /mnt/apps/share-marker.txt")
        check(result.stdout.strip() == b"WINDOWS_SHARE_OK", "read Windows 9p deployment share")
        result = vm.ssh("touch /mnt/apps/forbidden", user="app")
        check(result.returncode != 0, "share stays read-only for applications")
        result = vm.ssh("cat", input=b"STDIN_ROUNDTRIP\n")
        check(result.stdout == b"STDIN_ROUNDTRIP\n", "SSH stdin and EOF")
        result = vm.ssh("echo normal; echo separate >&2; exit 37")
        check(result.returncode == 37 and result.stdout == b"normal\n" and b"separate\n" in result.stderr,
              "SSH stdout, stderr and command exit status", result)
        result = vm.ssh("printf '%s\\n' c a b | sort; echo $((6 * 7))")
        check(result.returncode == 0 and result.stdout == b"a\nb\nc\n42\n", "Brush pipelines/arithmetic and uutils")
        result = vm.ssh("tty; stty size", pty=True)
        check(result.returncode == 0 and b"/dev/pts/" in result.stdout, "SSH PTY and terminal utilities")
        result = vm.ssh(pty=True, input=b"echo INTERACTIVE_SHELL_OK\nexit\n")
        check(result.returncode == 0 and b"\r\nINTERACTIVE_SHELL_OK\r\n" in result.stdout, "interactive Brush login")
        result = vm.ssh("readlink /dev/fd; cat /proc/1/comm; cat /proc/self/mountinfo")
        check(b"/proc/self/fd\n" in result.stdout and b" - tmpfs tmpfs " in result.stdout,
              "dev/fd links and real tmpfs root switch")
        result = vm.ssh("date +%s")
        check(abs(int(result.stdout.strip()) - time.time()) < 30, "guest clock initialized from host")
        result = vm.ssh("cat /run/log/boot.log /run/log/sshd.log")
        check(result.returncode == 0
              and (b"stage=root-unpack event=complete duration_ms=" in result.stdout
                   or b"stage=root-unpack event=skipped" in result.stdout)
              and b"stage=root-bind-init event=complete duration_ms=" in result.stdout
              and b"event=supervisor-ready" in result.stdout
              and b"event=listener-ready startup_ms=" in result.stdout,
              "boot timings persist early stages and distinguish spawned services from SSH listener readiness")
        result = vm.ssh("stat -Lc '%d:%i' /proc/1/exe /bin/tinyinit")
        inodes = result.stdout.splitlines()
        check(result.returncode == 0 and len(inodes) == 2 and inodes[0] == inodes[1],
              "PID 1 and multicall tools share one init inode instead of copying the ELF")
        result = vm.ssh("cat /sys/fs/cgroup/a/memory.max /sys/fs/cgroup/a/pids.max /sys/fs/cgroup/a/cpu.max")
        check(result.stdout == b"536870912\n128\n100000 100000\n", "per-application cgroup limits")
        if args.dotnet:
            result = vm.ssh("dotnet --list-runtimes; cat /etc/os-release; cat /etc/resolv.conf")
            check(result.returncode == 0 and b"Microsoft.AspNetCore.App " in result.stdout
                  and b"Microsoft.NETCore.App " in result.stdout
                  and b"nameserver 1.1.1.1" in result.stdout, "selected runtimes, OS metadata and DNS config")
            result = vm.ssh(
                "test -s /etc/ssl/certs/ca-certificates.crt && "
                "test -s /usr/share/zoneinfo/America/Los_Angeles && echo ROOTFS_DATA_OK"
            )
            check(result.returncode == 0 and result.stdout == b"ROOTFS_DATA_OK\n", "CA trust and timezone database")
        result = vm.ssh("cat /home/app/a.txt /home/app/b.txt")
        if args.dotnet:
            check(b"uid=1000" in result.stdout and b"from-init-json" in result.stdout, "both Windows-published .NET applications running")
            check(result.stdout.count(b"runtime=.NET ") == 2
                  and result.stdout.count(b"icu=ok tz=ok trust=ok aspnet=ok") == 2,
                  "both apps exercise selected .NET runtime, ICU, timezones, CA trust and ASP.NET")
            result = vm.ssh(
                "env DOTNET_ROLL_FORWARD=Major DOTNET_ROLL_FORWARD_TO_PRERELEASE=1 "
                "dotnet /mnt/apps/TinyinitProbe.dll --network-check",
                user="app", timeout=40,
            )
            check(result.returncode == 0 and b"DNS_HTTPS_OK" in result.stdout,
                  "unprivileged .NET DNS and trusted HTTPS using embedded OpenSSL/CA data", result)
        else:
            check(result.stdout.count(b"uid=1000(app)") == 2, "both applications stay unprivileged")
        result = vm.ssh("for p in $(cat /sys/fs/cgroup/a/cgroup.procs); do cat /proc/$p/status; done")
        check(b"CapEff:\t0000000000000000" in result.stdout and b"NoNewPrivs:\t1" in result.stdout,
              "application capability drop and no_new_privs")
        # A shell that exits with an orphaned child must not kill the appliance.
        check(vm.ssh("sleep 0.2 >/dev/null 2>&1 & exit 0").returncode == 0, "orphan-producing SSH command exits normally")
        time.sleep(0.5)
        check(vm.ssh("echo STILL_ALIVE").stdout == b"STILL_ALIVE\n", "session exits do not trigger appliance death")
        # Brush's kill builtin only accepts one target; use uutils for a cgroup's PID list.
        vm.ssh("/bin/kill -TERM $(cat /sys/fs/cgroup/a/cgroup.procs)")
        vm.finished()
        check("essential service a exited" in vm.text(), "application exit is fatal with no restart")
    finally:
        vm.close()

    vm = VM(args, config, "sshd-exit")
    try:
        vm.ready()
        vm.ssh("/bin/kill -TERM $(cat /sys/fs/cgroup/sshd/cgroup.procs)", timeout=10)
        vm.finished()
        check("essential service sshd exited" in vm.text(), "SSH listener exit is fatal")
    finally:
        vm.close()

    config["apps"][0]["argv"] = ["/bin/sleep", "0.5"]
    vm = VM(args, config, "clean-exit")
    try:
        vm.finished()
        check("essential service a exited (wait status 0)" in vm.text(), "even successful service exit is fatal")
    finally:
        vm.close()
    config["ssh"]["logins"][0]["public_keys"] = ["not a valid key"]
    vm = VM(args, config, "invalid-config")
    try:
        vm.finished()
        check("invalid SSH public key" in vm.text() and "started a pid=" not in vm.text(), "invalid authorization fails closed before apps start")
        check("stage=ssh-authorization event=failed duration_ms=" in vm.text(),
              "failed boot stage and duration are logged")
    finally:
        vm.close()
    print(f"ALL PASS; logs: {OUT}", flush=True)


if __name__ == "__main__":
    main()
