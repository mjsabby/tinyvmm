"""Run in Linux/WSL after Windows publishes tests/DotnetApp.

python3 tests/make-dotnet-rootfs.py out/dotnet-apps out/dotnet-rootfs.tar

The app's DLL/config are symlinked to 9p; its Linux apphost/runtime and Linux
OS libraries are local, with executable permissions preserved in the tar.
"""
import io
from pathlib import Path
import sys
import tarfile

published, output = map(Path, sys.argv[1:])
with tarfile.open(output, "w", dereference=True) as archive:
    for path in sorted(published.iterdir()):
        if not path.is_file():
            continue
        name = f"runtime/{path.name}"
        if path.name in ("TinyinitProbe.dll", "TinyinitProbe.deps.json", "TinyinitProbe.runtimeconfig.json"):
            link = tarfile.TarInfo(name)
            link.type = tarfile.SYMTYPE
            link.linkname = f"/mnt/apps/{path.name}"
            archive.addfile(link)
        else:
            data = path.read_bytes()
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o755 if path.name == "TinyinitProbe" else 0o644
            archive.addfile(member, io.BytesIO(data))
    for name in ("libc.so.6", "libm.so.6", "libdl.so.2", "libpthread.so.0",
                 "librt.so.1", "libgcc_s.so.1", "libstdc++.so.6", "libz.so.1"):
        path = Path("/lib/x86_64-linux-gnu") / name
        archive.add(path.resolve(strict=True), arcname=f"lib/x86_64-linux-gnu/{name}")
    archive.add(Path("/lib64/ld-linux-x86-64.so.2").resolve(strict=True),
                arcname="lib64/ld-linux-x86-64.so.2")
print(output)
