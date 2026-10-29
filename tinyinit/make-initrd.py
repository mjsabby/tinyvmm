"""Package the static Linux binary and optional native userland into a newc initramfs."""
import argparse
import io
from pathlib import Path, PurePosixPath
import stat


def build(binary: Path, output: Path, rootfs: Path | None = None) -> None:
    archive = io.BytesIO()
    inode = 0
    directories = set()

    def entry(name, mode, data=b""):
        nonlocal inode
        inode += 1
        name = name.encode() + b"\0"
        fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
        archive.write(b"070701" + b"".join(f"{n:08x}".encode() for n in fields))
        archive.write(name)
        archive.write(b"\0" * (-archive.tell() % 4))
        archive.write(data)
        archive.write(b"\0" * (-archive.tell() % 4))

    def directory(name):
        if name not in ("", ".") and name not in directories:
            directory(str(PurePosixPath(name).parent))
            entry(name, stat.S_IFDIR | 0o755)
            directories.add(name)

    for name in ("dev", "proc", "sys", "newroot"):
        directory(name)
    entry("init", stat.S_IFREG | 0o755, binary.read_bytes())
    if rootfs:
        entry("rootfs-payload", stat.S_IFREG | 0o400, rootfs.read_bytes())
    entry("TRAILER!!!", 0)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(archive.getvalue())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(__file__).parent / "target/x86_64-unknown-linux-musl/release/tinyinit")
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "out/initrd.cpio")
    parser.add_argument("--rootfs", type=Path, help="optional tar of Linux runtimes/libraries, preserving Unix modes/symlinks")
    args = parser.parse_args()
    build(args.binary, args.out, args.rootfs)
    print(f"initramfs: {args.out} ({args.out.stat().st_size:,} bytes)")
