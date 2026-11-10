#!/usr/bin/env python3
"""Fetch libslirp for `--net-backend slirp`: MSYS2's ucrt64 build of
libslirp-0.dll and the DLLs it loads (GLib and what GLib needs).

The packages are pinned: tools\\libslirp.lock.json names each package file
and its SHA-256, and only those bytes are accepted, from whichever mirror
(--repo) serves them. These DLLs run inside tinyvmm, so what a build fetches
must not depend on what the repository offers that day. MSYS2 keeps only
current versions online; when a pinned file is gone, or to take an update,
run with --update-lock: that follows the DLLs' import tables through the
MSYS2 package database, as before, and rewrites the lock for review.

tinyvmm loads libslirp-0.dll at run time from the path in TINYVMM_LIBSLIRP
if that is set, else from the directory of tinyvmm.exe, and from nowhere
else (never the current directory or PATH); its dependencies load from the
directory it is in. So by default this writes into target\\release, next to
tinyvmm.exe. The license files of each package used go to
<out>\\licenses\\<package>.

Needs Python 3.14+ (compression.zstd) and access to repo.msys2.org.

Usage:
  python tools\\fetch_libslirp.py [--out target\\release] [--repo URL] [--update-lock]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

try:
    from compression import zstd
except ImportError:  # pragma: no cover - older Pythons
    sys.exit("fetch_libslirp.py needs Python 3.14+ (for compression.zstd)")

REPO = Path(__file__).resolve().parent.parent
LOCK = Path(__file__).resolve().parent / "libslirp.lock.json"
DEFAULT_URL = "https://repo.msys2.org/mingw/ucrt64/"
PREFIX = "mingw-w64-ucrt-x86_64-"
ROOT_DLL = "libslirp-0.dll"


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "tinyvmm-fetch-libslirp"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def untar_zst(data: bytes) -> tarfile.TarFile:
    return tarfile.open(fileobj=io.BytesIO(zstd.decompress(data)))


def read_db(db: tarfile.TarFile, entry: str) -> dict[str, dict[str, list[str]]]:
    """`<pkg>-<ver>/<entry>` records of a pacman database, by package name."""
    out: dict[str, dict[str, list[str]]] = {}
    for m in db.getmembers():
        if not m.name.endswith("/" + entry):
            continue
        fields: dict[str, list[str]] = {}
        key = None
        for line in db.extractfile(m).read().decode().splitlines():
            if line.startswith("%") and line.endswith("%"):
                key = line.strip("%")
                fields[key] = []
            elif line and key:
                fields[key].append(line)
        out[m.name.split("/")[0]] = fields
    return out


def pe_imports(dll: bytes) -> list[str]:
    """The DLL names a PE image imports (normal and delay-load tables)."""
    pe = struct.unpack_from("<I", dll, 0x3C)[0]
    nsec, opt_size = struct.unpack_from("<H12xH", dll, pe + 6)
    opt = pe + 24
    pe32_plus = struct.unpack_from("<H", dll, opt)[0] == 0x20B
    dirs = opt + (112 if pe32_plus else 96)
    sections = [struct.unpack_from("<8xIIII", dll, opt + opt_size + 40 * i)
                for i in range(nsec)]

    def off(rva: int) -> int:
        for vsize, va, rsize, raw in sections:
            if va <= rva < va + max(vsize, rsize):
                return raw + rva - va
        raise ValueError(f"RVA {rva:#x} outside the sections")

    def cstr(rva: int) -> str:
        o = off(rva)
        return dll[o:dll.index(b"\0", o)].decode()

    names = []
    for index, size, name_at in ((1, 20, 12), (13, 32, 4)):
        rva = struct.unpack_from("<I", dll, dirs + 8 * index)[0]
        if not rva:
            continue
        o = off(rva)
        while any(dll[o:o + size]):
            names.append(cstr(struct.unpack_from("<I", dll, o + name_at)[0]))
            o += size
    return names


def package(url: str, fname: str, sha256: str) -> tarfile.TarFile:
    """Download the package file `fname` and open it, if it is the pinned one."""
    try:
        data = fetch(url + fname)
    except urllib.error.HTTPError as e:
        sys.exit(f"fetch_libslirp: {url}{fname}: HTTP {e.code}. MSYS2 keeps only current versions "
                 f"online: rerun with --update-lock and review the change to {LOCK.name}")
    if hashlib.sha256(data).hexdigest() != sha256:
        sys.exit(f"fetch_libslirp: {fname}: SHA-256 mismatch")
    print(f"[fetch-libslirp] {fname}")
    return untar_zst(data)


def dll_bytes(tar: tarfile.TarFile, dll: str) -> tuple[str, bytes]:
    member = next(m for m in tar.getmembers()
                  if m.isfile() and m.name.lower().endswith("/bin/" + dll))
    return Path(member.name).name, tar.extractfile(member).read()


def resolve(url: str) -> tuple[dict[str, dict], dict[str, tarfile.TarFile]]:
    """What libslirp-0.dll needs as the repository offers it today: each
    package's file, SHA-256 and the DLLs taken from it, found by following
    import tables through the package database. Also the opened packages."""
    print(f"[fetch-libslirp] reading the package database at {url}")
    desc = {d["NAME"][0]: d for d in read_db(untar_zst(fetch(url + "ucrt64.db")), "desc").values()}
    files = read_db(untar_zst(fetch(url + "ucrt64.files")), "files")
    # Which package ships each DLL (ucrt64/bin/<name>.dll).
    owner: dict[str, str] = {}
    for dirname, f in files.items():
        name = next(n for n in desc if dirname.startswith(n + "-")
                    and desc[n]["FILENAME"][0].startswith(dirname))
        for path in f.get("FILES", []):
            parts = path.split("/")
            if len(parts) == 3 and parts[1] == "bin" and parts[2].lower().endswith(".dll"):
                owner.setdefault(parts[2].lower(), name)

    tars: dict[str, tarfile.TarFile] = {}
    pinned: dict[str, dict] = {}
    todo = [ROOT_DLL.lower()]
    seen: set[str] = set()
    while todo:
        dll = todo.pop()
        if dll in seen:
            continue
        seen.add(dll)
        pkg = owner.get(dll)
        if pkg is None:
            sys.exit(f"fetch_libslirp: no MSYS2 package ships {dll}")
        if pkg not in tars:
            fname, sha256 = desc[pkg]["FILENAME"][0], desc[pkg]["SHA256SUM"][0]
            tars[pkg] = package(url, fname, sha256)
            pinned[pkg] = {"file": fname, "sha256": sha256, "dlls": []}
        name, image = dll_bytes(tars[pkg], dll)
        pinned[pkg]["dlls"].append(name)
        # Imports no package ships are Windows' own (KERNEL32, WS2_32, the
        # UCRT api sets, ...).
        todo.extend(i.lower() for i in pe_imports(image) if i.lower() in owner)
    for entry in pinned.values():
        entry["dlls"].sort()
    return dict(sorted(pinned.items())), tars


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=REPO / "target" / "release")
    ap.add_argument("--repo", default=DEFAULT_URL, help="MSYS2 ucrt64 repository URL")
    ap.add_argument("--update-lock", action="store_true",
                    help="take what the repository offers today and rewrite the lock file")
    a = ap.parse_args()
    url = a.repo.rstrip("/") + "/"

    if a.update_lock:
        pinned, tars = resolve(url)
        LOCK.write_text(json.dumps({"packages": pinned}, indent=2) + "\n", encoding="utf-8")
        print(f"[fetch-libslirp] wrote {LOCK}: review the change before committing it")
    else:
        if not LOCK.is_file():
            sys.exit(f"fetch_libslirp: {LOCK} is missing; run with --update-lock to create it")
        pinned = json.loads(LOCK.read_text(encoding="utf-8"))["packages"]
        tars = {pkg: package(url, e["file"], e["sha256"]) for pkg, e in pinned.items()}

    a.out.mkdir(parents=True, exist_ok=True)
    done: dict[str, str] = {}
    for pkg, entry in pinned.items():
        for dll in entry["dlls"]:
            name, image = dll_bytes(tars[pkg], dll.lower())
            (a.out / name).write_bytes(image)
            done[name] = pkg
    if ROOT_DLL not in done:
        sys.exit(f"fetch_libslirp: the lock names no package with {ROOT_DLL}")

    for pkg, tar in tars.items():
        for m in tar.getmembers():
            parts = m.name.split("/")
            if m.isfile() and parts[1:3] == ["share", "licenses"]:
                dest = a.out / "licenses" / pkg.removeprefix(PREFIX) / parts[-1]
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(tar.extractfile(m).read())
    print(f"[fetch-libslirp] {len(done)} DLLs in {a.out}: "
          + ", ".join(f"{d} ({p.removeprefix(PREFIX)})" for d, p in sorted(done.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
