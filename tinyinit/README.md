# tinyinit

One **Linux** Rust/std binary: PID 1, a key-only Russh server, a Brush shell,
and 30 selected [uutils/coreutils](https://github.com/uutils/coreutils) applets.
No systemd, OpenSSH, BusyBox, modules, udev, passwords, sudo, or respawning.
The applet crates (`uu_cat`, etc.) come from the uutils/coreutils project.

## Build on Windows

One-time setup (Rust/Cargo, Zig and Python 3.14+ must be on PATH):

```powershell
rustup target add x86_64-unknown-linux-musl
cargo install cargo-zigbuild --locked
```

```powershell
cd D:\tinyvmm\tinyinit
.\build.ps1
```

This cross-compiles on Windows, including native dependencies, to a static
Linux ELF at `target\x86_64-unknown-linux-musl\release\tinyinit`.
The nested crate is independent of tinyvmm's Windows workspace.

The default build embeds the official ASP.NET **11.0 RC3**, Ubuntu Resolute
**chiseled-extra**, Linux x86-64 filesystem. `rootfs.lock.json` pins the image's
immutable manifest digest. `build.rs` runs `fetch-rootfs.py`, which downloads
and SHA-256-verifies the manifest/layers directly from Microsoft Container
Registry and applies them in order at build time: whiteouts and opaque
directories remove lower-layer paths, upper entries replace lower ones, and
the result is one flat tree with each path exactly once. The guest never sees
layers. No Docker, WSL, administrator rights, or Windows symlink support is
needed for this step. Downloads and the packed archive are cached under
`out\rootfs-cache`; unchanged builds reuse them. The first build needs internet
access.

The packed `rootfs.tar.zst` starts with a zstd skippable marker frame, then one
frame of directories and symlinks, then frames of whole regular-file tar entries
cut near 8 MiB in path order (21 frames for the pinned image; zstd level 19 with
checksums). Decompressed in order, it is one ordinary tar stream, so standard
`zstd`/`tar` tools can inspect it. Tinyinit extracts the directory/symlink frame
first, then the file frames largest-first across every guest vCPU. The pack is
56.7 MB versus 71.5 MB for the previous gzip tar.

The fetcher is deliberately small and uses only the Python standard library,
not an OCI library. It supports Docker v2/OCI manifests and indexes, gzip or
zstd layers, regular files, directories, symlinks, hardlinks (materialized as
copies, since flattening must not depend on link targets) and OCI whiteouts.
Absolute symlinks are rewritten as equivalent relative links. It fails closed:
an ambiguous platform, a digest mismatch, device nodes, escaping paths/links,
or an unsupported manifest stops the build rather than producing a different
rootfs. Pinned digests mean a changed image only arrives through `-RootfsImage`
or `-UpdateRootfs`. If a future image needs something the fetcher lacks, build a
trusted tarball with another tool and use it as an external rootfs.
For the pinned image, extracting the pack with tinyinit's code matched an
independent flattening (`crane export` from go-containerregistry, extracted by
GNU tar) on all 1,709 paths: type, mode bits, numeric owner, content hash, file
mtime and xattrs; the eight absolute symlinks resolve to the same targets.

The embedded base includes CoreCLR, ASP.NET, matching glibc/loader and native
dependencies, OpenSSL, ICU, CA certificates, timezone data, and OS metadata.
Updating `rootfs.lock.json` and rebuilding updates this base; the guest has no
package manager or automatic trust/timezone updates. Linux license/copyright
files supplied by the image remain in the embedded filesystem.

Choose an image or refresh it with one build command:

```powershell
.\build.ps1 -RootfsImage mcr.microsoft.com/dotnet/aspnet:11.0.0-rc.3-resolute-chiseled-extra
.\build.ps1 -UpdateRootfs
```

`-RootfsImage` resolves the tag's **Linux amd64** manifest, validates the image
architecture, and updates `rootfs.lock.json`. Both architecture-specific and
multi-architecture tags work. `-UpdateRootfs` refreshes the configured tag;
ordinary builds do not check for tag changes. To follow the .NET 11 servicing
line rather than staying on RC3, select
`mcr.microsoft.com/dotnet/aspnet:11.0-resolute-chiseled-extra`, then use
`-UpdateRootfs` when desired. Keep `rootfs.lock.json` with the source so builds
remain reproducible. Different images must still supply the native runtime/data
your applications need; the ASP.NET smoke probe requires an ASP.NET extra image.
The build prints rootfs preparation/cache verification and cross-build timings.

`.\build.ps1 -NoRootfs` builds the small init/shell/SSH binary without downloading
or embedding a rootfs (unless image selection/update was explicitly requested).
At boot it can create an empty tmpfs for shell-only workloads, or extract a trusted
external rootfs using `tinyinit.rootfs=9p:TAG`; that read-only 9p share must contain
`rootfs.tar.zst` (a pack from `fetch-rootfs.py`, extracted in parallel) or
`rootfs.tar.gz` (streamed sequentially). The share is mounted early and
unmounted after extraction.
This explicit boot argument also overrides an embedded base when one exists.
The parent repository's `build-appliance.ps1` packages these two init variants
with a kernel into `tinyvmm-init.exe` and `tinyvmm-dotnet.exe`.

## Run

Build tinyvmm normally, then create a bootstrap directory containing
`init.json` (start with `init.example.json`) and the caller's OpenSSH **public**
key as `caller.pub`. Never provide the caller's private key to the guest.

```powershell
.\run.ps1 -Kernel C:\kernels\vmlinux.tinyvmm -Bootstrap C:\vm\bootstrap `
    -Shares 'apps=C:\vm\published,ro'
ssh -p 10022 -i $HOME\.ssh\id_ed25519 root@127.0.0.1
```

No separate rootfs file/share is needed. The example uses the embedded runtime
to execute DLLs from the apps share, with ICU globalization enabled.
You can publish Linux .NET output on Windows; Windows apphosts and Windows
native libraries don't run in Linux. Target the embedded .NET version, or
explicitly configure compatible roll-forward for older applications.

`-Rootfs` remains an optional extra tar payload overlaid on the embedded base.
Do not mix incompatible libc/runtime versions through this overlay.
For a **shell-only workload demo**, replace the two example `argv` arrays
with `["/bin/sleep", "infinity"]`.

The launcher copies the kernel to a local Windows path, passes the host's
current Unix time, and supplies `idle=halt` for the current WHP idle issue.
It exposes SSH only on the VMM's loopback port forward. This legacy launcher
uses the plain VMM with external boot files; the appliance variants embed them.

## Boot and configuration

Top-down startup is in `src\boot.rs`: decompress the embedded filesystem into
a tmpfs root, bind-mount the original `/init` at `/usr/bin/tinyinit`, and move off initramfs,
mount proc/sys/dev/devpts/shm/run/tmp/cgroup2, create `/dev/fd` links and applet
links, mount the read-only bootstrap share, read JSON, apply tmpfs limits and
sysctls, mount workload shares,
load public keys, create identities/homes, set static IPv4/DNS, create cgroups,
then spawn the apps and another process using the same executable inode in `sshd` mode.

Kernel requirements: built-in virtio PCI/net/console/RNG and 9p/9p-virtio,
proc/sysfs/tmpfs/devtmpfs/devpts, IPv4, cgroup v2 with cpu/memory/pids controllers.
Namespaces need their kernel options, but no additional namespaces are created.
The root switch is a real mount move, not just chroot.
This is an ordinary writable, RAM-backed Linux filesystem, not a direct mount
of ELF memory segments. The compressed bytes stay in the executable and the
expanded files occupy tmpfs memory; there is no guest disk dependency.
The current build is approximately 73 MiB, with about 162 MiB of expanded
regular-file contents, before applications and the kernel. The init ELF is
shared through a read-only, nosuid bind mount, not copied into the new root.
The `-NoRootfs` binary is approximately 19 MiB.

Init gives applications and SSH sessions `PATH=/bin:/usr/bin`, `HOME`, `USER`,
`LOGNAME` and `SHELL`. Everything image-specific comes from `init.json`:
top-level `env` supplies defaults for applications and SSH sessions, and
application `env` overrides them. The ASP.NET base expects `DOTNET_ROOT`,
`ASPNETCORE_HTTP_PORTS` and `LANG`, as in `init.example.json`. The container
image's configuration (entrypoint, user, environment, working directory) is not
applied: init.json controls identities and services. Init supplies
DNS/hosts/NSS configuration and the host-derived clock. Timezone data is
present; set `TZ` to choose a local timezone rather than the default UTC.

Boot arguments:

- `tinyinit.bootstrap=bootstrap`: initial 9p tag, default `bootstrap`.
- `tinyinit.config=/mnt/bootstrap/init.json`: configuration path, default shown.
- `tinyinit.epoch=SECONDS`: set guest wall time before applications start.
- `tinyinit.rootfs=9p:TAG`: extract `rootfs.tar.zst` or `rootfs.tar.gz` from an
  early read-only share into the new root instead of using the embedded base.

## Trusted rootfs metadata policy

Rootfs archives are trusted executable inputs: they control native libraries,
programs, and privileged guest startup. Both embedded/external bases and the
optional `-Rootfs` overlay are unpacked by Linux, not by Windows. The extractor
explicitly preserves numeric UID/GID, ordinary and special mode bits, symlinks,
and supported PAX `SCHILY.xattr.*` extended attributes (including file capabilities
when represented in that format and supported by the guest kernel/filesystem).
Failures restoring requested attributes fail the boot rather than silently
discarding them. Standalone ACL extensions are not a separately implemented
archive feature. Init subsequently replaces its own identity/network files
and sets configured home ownership; this is intentional.

Applications always receive `no_new_privs` and only explicitly configured
capabilities, so preserved setuid/file-capability metadata does not grant those
apps privilege escalation.
Mount permissions such as nosuid/read-only remain separate from inode modes.
Direct 9p shares use synthetic Unix metadata by default, with configurable
`uid=`/`gid=` ownership. Shares using `,metadata` persist owners and modes in
WSL-compatible NTFS attributes. Extracting an archive restores metadata from
inside the archive regardless of the transport share's metadata policy.

JSON rejects unknown fields and invalid users/service names. `users` contains
non-root accounts; root exists implicitly. Applications **must** use a non-root
account and always get `no_new_privs`; supplementary groups and capabilities
are granted only when configured. `env`, `cwd`, and optional cgroup limits are
per application. `cpu_percent=100` means one CPU's worth of time; values above
100 allow multiple CPUs.
Applications must stay in the foreground: exit, including exit code zero,
means appliance death. Failed boot setup also shuts the VM down.

Optional process and memory settings:

- `rlimits`, top level and per application, use `ulimit` names such as `nofile`,
  `nproc`, `core`, `memlock` and `stack`. A number or `"unlimited"` sets both
  limits; `{"soft": 4096, "hard": 65536}` sets each. Top-level limits apply to
  applications and sshd, so SSH sessions inherit them; an application's entry
  replaces the same resource. Init itself is unaffected. Linux otherwise starts
  with a `nofile` soft limit of 1024 and a hard limit of 4096 (.NET raises its
  soft limit to the hard limit); values above 1048576 also need a larger
  `fs.nr_open`.
- `groups`: supplementary numeric GIDs for an application, never 0. Init names
  only users' primary groups in `/etc/group`, so tools such as `id` warn about
  other GIDs.
- `umask`: an octal string such as `"0027"`; the default is `0022`.
- `capabilities`: opt-in Linux capabilities for an application, for example
  `["CAP_NET_BIND_SERVICE"]`. They become ambient capabilities, so they survive
  the switch to the application's user while `no_new_privs` still blocks
  setuid and file-capability escalation. Each one is real privilege; prefer a
  sysctl such as `net.ipv4.ip_unprivileged_port_start` when that is enough.
- `sysctls`: values written to `/proc/sys` before services start, for example
  `{"net.core.somaxconn": 4096}`. Any failure stops the boot.
- `tmpfs`: `size=` limits for `/`, `/run`, `/tmp` and `/dev/shm`: bytes with an
  optional `k`, `m` or `g` suffix, or a percentage of guest RAM. They are applied
  by remounting after the config is read, so a size below current use fails the
  boot. Mounts left unset keep the kernel default of half of guest RAM each.
- `logs.max_bytes` (default 8 MiB): PID 1 drains each service's output into
  `/run/log/<name>.log` and rotates it to `<name>.log.1`, so a stream holds at
  most twice this much RAM. Output keeps draining even if a log cannot be
  written, so a full tmpfs never blocks a service.

Settings are recorded in `/run/log/boot.log`, except environment values.

SSH `logins` maps each configured Unix user (including root) to `public_keys`
and/or a `public_keys_file`. The file is read once after shares mount. Use
distinct users/keys when you want distinct access; an explicitly authorized
root login is full guest administration without sudo. Ordinary logins have
no escalation mechanism. Plain OpenSSH public keys only, no authorized_keys
options or certificates.

SSH supports interactive PTYs, resizing, non-interactive commands, stdin,
stderr, and exit status; not SFTP/SCP subsystems or port/agent forwarding.
Brush supplies shell syntax and builtins; selected uutils applets supply
external tools, not an entire distro. `poweroff` signals PID 1.

By default the SSH host key is ephemeral, so its fingerprint changes each boot.
For a stable identity, set `ssh.host_key` to a protected persistent Linux
private-key file. Never bake one shared host private key into every instance.
Bootstrap configuration is copied to root-only `/run/tinyinit.json`.

Without share options, tinyvmm presents 9p files as root-owned 0644/0444.
Use `,uid=1000,gid=1000` to grant the configured app account ownership on a
writable share, or `,metadata` to persist chmod/chown and executable modes
using WSL-compatible NTFS attributes. The examples deliberately use read-only
shares; ownership changes do not override `,ro`. Guest-local homes/state are
writable but ephemeral; use an appropriately configured writable share or
Linux disk for persistent data. No DAC-override workaround is granted.
Root SSH can modify any writable host share: expose only directories you
intend to grant it.

PID 1 alone reaps its children/adopted orphans. The SSH process waits for its
own shell children; shells wait for commands. Login/command exits don't kill
the appliance. Shutdown sends TERM, waits briefly, sends KILL, syncs, then
prints tinyvmm's shutdown marker and requests kernel poweroff. No restarts.
Logs are `/run/log/<app-name>.log` and `/run/log/sshd.log`, each with one rotated
`.1` file; a fatal service exit also prints the last 4 KiB of its log.

## Diagnostics and boot benchmark

PID 1 emits monotonic `elapsed_ms`, named stage begin/complete/failed events,
and per-stage `duration_ms` to the serial console and `/run/log/boot.log`.
The early root extraction/bind-mount logs are buffered until `/run` is mounted.
Mount/share targets, actual mountinfo, service UID/GID/executable/cwd/log paths,
and boot-stage errors are recorded; argv, environment values and key contents
are not dumped. `supervisor-ready` means every essential process was spawned,
not that the apps are accepting requests. `/run/log/sshd.log` separately records
host-key work, actual listener readiness and configured authentication delays.
Boot logs are ephemeral; capture the VMM console if a failed boot shuts down.

```powershell
python .\smoketest.py --embedded --vmm ..\out\deploy\tinyvmm-dotnet.exe --apps .\out\dotnet-apps --dotnet --benchmark 5
```

This runs one warm-up and five measured boots, and
writes `out\smoke\benchmark.json`, per-boot console logs and `.snapshot` files.
Snapshots include mountinfo, top-level directories, tmpfs usage and meminfo.
Each VM is powered off after measurement. Without `--dotnet`, the workload is
two shell loops. The non-embedded mode packages the binary once before timing.
`--vcpus N` (default 2) sets the guest vCPU count.
The .NET probe records readiness after ICU, timezone, trust-store
and ASP.NET loopback checks; this is not a benchmark of your production apps.

Measured on this Windows/WHP host with Linux 7.3, 1536 MiB guest RAM, warm host
caches, logging enabled, and the standalone embedded .NET deployment (medians of
five boots; the first column is the earlier gzip/single-copy build at 2 vCPUs):

| Metric | Before | 1 vCPU | 2 vCPUs | 4 vCPUs |
|---|---:|---:|---:|---:|
| Rootfs extraction into tmpfs | 674 ms | 436 ms | 216 ms | 115 ms |
| VMM launch to PID 1 first log | 348 ms | 197 ms | 163 ms | 163 ms |
| PID 1 entry to SSH listener ready | 693 ms | 452 ms | 236 ms | 132 ms |
| PID 1 entry to both .NET probes ready | 935 ms | 1017 ms | 492 ms | 381 ms |
| VMM launch to authenticated SSH command completion | 2083 ms | 692 ms | 449 ms | 341 ms |

Rootfs extraction is the boot stage that scales with vCPUs; .NET startup also
benefits because both probes start at once. Linux itself reached PID 1 in about
80 ms of guest uptime with two or four vCPUs and about 118 ms with one.

The old executable-copy step took 26.7 ms and duplicated the init executable.
The bind mount eliminates that copy and tests verify identical device/inode
numbers for `/proc/1/exe` and `/bin/tinyinit`.
Mounting the root tmpfs itself takes about 0.02 ms; eager decompression/file
creation is the dominant init cost. Guest app timestamps have 10 ms resolution.
Host timings also include VMM/kernel startup and SSH client overhead. The SSH
server rejects clients' initial `none` probe immediately; rejected keys and
other failed authentication attempts keep Russh's 1000 ms delay.
The host observation of app readiness occurs after SSH and is only an upper
bound; the report also contains the apps' own guest readiness timestamps.

## Filesystem layout and tmpfs tradeoffs

The measured mount layout is:

| Mountpoint | Type | Purpose |
|---|---|---|
| `/` | tmpfs | Writable in-memory ASP.NET base |
| `/usr/bin/tinyinit` | read-only file bind mount | Original initramfs executable, shared by PID 1 and multicall processes |
| `/proc` | proc | Processes and kernel interfaces |
| `/sys` | sysfs | Kernel/device interfaces |
| `/dev` | devtmpfs | Kernel-created device nodes |
| `/run`, `/tmp` | separate tmpfs mounts | Runtime state/logs and temporary files |
| `/dev/pts` | devpts | SSH pseudo-terminals |
| `/dev/shm` | tmpfs | Shared-memory files |
| `/sys/fs/cgroup` | cgroup2 | Application and SSH resource groups |
| `/mnt/bootstrap`, `/mnt/apps` | read-only 9p | Config/public keys and Windows-published apps |

The example's `/etc`, `/home`, `/root`, `/usr`, `/var`, and `/mnt` are ordinary
directories on the root tmpfs, not additional filesystems. `/bin`, `/sbin`,
`/lib`, and `/lib64` are symlinks into `/usr`. Share mountpoints vary with config.

Tmpfs is appropriate for this simple diskless, disposable appliance: it supplies
normal Linux file/permission/exec semantics and a real root mount for namespaces.
It is not a zero-copy compressed filesystem. The root currently uses about
165 MiB, plus the single original init executable (about 73 MiB with the embedded
base) retained by the bind mount. Compared with the old copy-based boot, this
avoids a second copy of that executable in guest memory. The minimal-init variant's executable
is about 19 MiB and its external archive is unmounted after extraction.
Optional initramfs overlay archives are not explicitly reclaimed yet.
No guest swap is configured.
Unless `tmpfs` sets a size, each tmpfs has the kernel's default limit (roughly
half guest memory), not a reserved allocation; combined growth can exhaust guest
RAM. Application cgroup `memory_max` also counts tmpfs pages an application writes.
Separate `/run`, `/tmp` and `/dev/shm` mounts are conventional isolation/lifecycle
boundaries, not a way to make an already-RAM-backed root faster.

For a tighter production memory/boot budget, a read-only SquashFS/EROFS base
with writable tmpfs state/overlay is a possible later design. It avoids eager
whole-image expansion, but needs appropriate kernel/filesystem/image tooling.
That is not implemented here. Persist anything important through an explicitly
supported persistent storage mechanism, not this root filesystem.

Tinyinit is a separate userspace ELF, not kernel code. The launcher supplies a
separate initramfs containing `/init`; Linux creates PID 1 and executes that
file. Preloading an initramfs into guest RAM is supported by this boot path,
but directly jumping to tinyinit's physical address is not: Linux must establish
its process/address space and load the ELF. Building the initramfs into the
kernel is another packaging option, not what this project currently does.
The durable [future-PR list](../README.md#requested-follow-up-prs-reducing-memory-copies)
tracks direct GPA backing/COW, DAX, compressed-rootfs mounting and archive reclamation.

## Tests

```powershell
.\build.ps1 -Tests
# Run the generated Linux test executable in WSL:
wsl -d Ubuntu-26.04 --exec /mnt/d/tinyvmm/tinyinit/target/x86_64-unknown-linux-musl/release/deps/tinyinit-<hash> --test-threads=1
python .\smoketest.py --kernel C:\kernels\vmlinux.tinyvmm
```

The smoke test boots the real VMM and authenticates from Windows.
It needs Python, Windows OpenSSH (`ssh`, `ssh-keygen`), and the built VMM/binary.
No external Linux rootfs is required for the basic smoke test.

To also test two instances of an actual Windows-published .NET application:

```powershell
dotnet publish .\tests\DotnetApp\TinyinitProbe.csproj -c Release -r linux-x64 --self-contained false -o .\out\dotnet-apps
python .\smoketest.py --kernel C:\kernels\vmlinux.tinyvmm --apps .\out\dotnet-apps --dotnet
python -m unittest discover -s .\tests -p test_rootfs.py
```

To test the two standalone deployment paths instead of supplying boot files:

```powershell
python .\smoketest.py --embedded --vmm ..\out\deploy\tinyvmm-dotnet.exe --apps .\out\dotnet-apps --dotnet
python .\smoketest.py --embedded --vmm ..\out\deploy\tinyvmm-init.exe --external-rootfs .\out\rootfs-cache --apps .\out\dotnet-apps --dotnet
python .\smoketest.py --embedded --vmm ..\out\deploy\tinyvmm-init.exe
```

The Linux unit test for archive ownership/special modes/xattrs should also be
run as root (e.g. WSL `--user root`) to exercise restoration of different numeric
owners; it uses only a dedicated temporary test directory.

Rust and .NET compilation happen on Windows. The probe targets the installed
.NET 10 SDK and explicitly opts into major/prerelease roll-forward for testing
the embedded .NET 11 RC3 runtime. No WSL libraries or external rootfs are used.
The two unprivileged probes test ICU formatting, timezone/DST rules, trusted
root certificates, and real ASP.NET loopback HTTP. The suite also checks DNS
and trusted external HTTPS; that check requires guest internet access.
Clippy can cross-check without WSL:

```powershell
cargo-zigbuild clippy --locked --target x86_64-unknown-linux-musl --release --all-targets -- -D warnings
cargo fmt --check
```
