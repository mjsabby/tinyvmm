"""Fetch a digest-pinned MCR image and flatten its layers without Docker or WSL."""
import argparse
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import tarfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
MANIFEST_TYPES = ", ".join([
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
])


def registry_json(repository, kind, reference):
    request = urllib.request.Request(
        f"https://mcr.microsoft.com/v2/{repository}/{kind}/{reference}",
        headers={"Accept": MANIFEST_TYPES},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read()
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if reference.startswith("sha256:") and reference != digest:
        raise ValueError(f"digest mismatch: {reference}")
    return json.loads(data), digest


def resolve_image(reference):
    match = re.fullmatch(r"mcr\.microsoft\.com/([a-z0-9._/-]+):([\w][\w.-]{0,127})", reference, re.ASCII)
    if match is None:
        raise ValueError("use an explicit MCR image:tag, e.g. mcr.microsoft.com/dotnet/aspnet:11.0.0-rc.3-resolute-chiseled-extra")
    repository, tag = match.groups()
    if any(part in ("", ".", "..") for part in repository.split("/")):
        raise ValueError("invalid MCR repository")
    manifest, digest = registry_json(repository, "manifests", tag)
    if "manifests" in manifest:
        candidates = [
            item for item in manifest["manifests"]
            if item.get("platform", {}).get("os") == "linux"
            and item.get("platform", {}).get("architecture") == "amd64"
        ]
        if len(candidates) != 1:
            raise ValueError("image must provide exactly one Linux amd64 manifest")
        manifest, digest = registry_json(repository, "manifests", candidates[0]["digest"])
    config, _ = registry_json(repository, "blobs", manifest["config"]["digest"])
    if config.get("os") != "linux" or config.get("architecture") != "amd64":
        raise ValueError("tinyinit requires a Linux amd64 image")
    return {"image": f"mcr.microsoft.com/{repository}", "tag": tag, "digest": digest}


def update_lock(reference=None):
    path = HERE / "rootfs.lock.json"
    previous = json.loads(path.read_text())
    if reference is None:
        reference = f"{previous['image']}:{previous['tag']}"
    lock = resolve_image(reference)
    if lock != previous:
        temporary = path.with_suffix(".partial")
        temporary.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
    print(f"Rootfs image: {reference} -> {lock['digest']}", flush=True)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download(repository, kind, digest, cache):
    algorithm, expected = digest.split(":")
    if algorithm != "sha256" or len(expected) != 64:
        raise ValueError(f"unsupported digest: {digest}")
    path = cache / expected
    if path.exists() and sha256(path) == expected:
        return path
    print(f"Downloading {kind} {digest}", flush=True)
    started = time.perf_counter()
    request = urllib.request.Request(
        f"https://mcr.microsoft.com/v2/{repository}/{kind}/{digest}",
        headers={"Accept": MANIFEST_TYPES},
    )
    temporary = path.with_suffix(".partial")
    try:
        with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as target:
            while chunk := response.read(1024 * 1024):
                target.write(chunk)
        if sha256(temporary) != expected:
            raise ValueError(f"digest mismatch: {digest}")
        temporary.replace(path)
        print(f"Verified {digest}: bytes={path.stat().st_size} duration_ms={(time.perf_counter() - started) * 1000:.1f}", flush=True)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def relative_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe image path: {name}")
    return str(path)


def merge_layer(entries, layer):
    members = [(relative_path(member.name), member) for member in layer.getmembers()]
    # Whiteouts apply to lower layers, not to files added in this layer.
    for name, member in members:
        path = PurePosixPath(name)
        if path.name == ".wh..wh..opq":
            prefix = str(path.parent)
            for old in list(entries):
                if prefix == "." or old.startswith(prefix + "/"):
                    del entries[old]
        elif path.name.startswith(".wh."):
            victim = str(path.with_name(path.name[4:]))
            for old in list(entries):
                if old == victim or old.startswith(victim + "/"):
                    del entries[old]
    for name, member in members:
        if name == "." or PurePosixPath(name).name.startswith(".wh."):
            continue
        member = copy.copy(member)
        member.name = name
        member.pax_headers = {
            key: value for key, value in member.pax_headers.items()
            if key not in ("path", "linkpath")
        }
        if member.isreg():
            data = layer.extractfile(member).read()
        elif member.islnk():
            target = relative_path(member.linkname)
            target_member, data = entries[target]
            if not target_member.isreg():
                raise ValueError(f"non-regular hardlink target: {target}")
            member.type = tarfile.REGTYPE
            member.linkname = ""
            member.size = len(data)
        elif member.issym():
            data = b""
            target = posixpath.normpath(posixpath.join(posixpath.dirname(name), member.linkname))
            if member.linkname.startswith("/"):
                target = member.linkname.lstrip("/")
            if target == ".." or target.startswith("../"):
                raise ValueError(f"escaping symlink: {name}")
            member.linkname = posixpath.relpath(target, posixpath.dirname(name) or ".")
        elif member.isdir():
            data = b""
        else:
            raise ValueError(f"unsupported image entry: {name}")
        if not member.isdir():
            for old in list(entries):
                if old.startswith(name + "/"):
                    del entries[old]
        entries[name] = (member, data)


def build():
    started = time.perf_counter()
    lock = json.loads((HERE / "rootfs.lock.json").read_text())
    if not lock["image"].startswith("mcr.microsoft.com/"):
        raise ValueError("only official MCR images are supported")
    repository = lock["image"].removeprefix("mcr.microsoft.com/")
    cache = HERE / "out" / "rootfs-cache"
    cache.mkdir(parents=True, exist_ok=True)
    output = cache / "rootfs.tar.gz"
    receipt = cache / "rootfs.json"
    recipe = sha256(Path(__file__))
    if output.exists() and receipt.exists():
        previous = json.loads(receipt.read_text())
        if (previous.get("lock") == lock and previous.get("recipe") == recipe
                and previous.get("sha256") == sha256(output)):
            print(f"Rootfs cache verified: bytes={output.stat().st_size} duration_ms={(time.perf_counter() - started) * 1000:.1f}", flush=True)
            return output
    manifest_path = download(repository, "manifests", lock["digest"], cache)
    manifest = json.loads(manifest_path.read_bytes())
    entries = {}
    for index, layer in enumerate(manifest["layers"], 1):
        layer_started = time.perf_counter()
        path = download(repository, "blobs", layer["digest"], cache)
        with tarfile.open(path, "r:*") as archive:
            merge_layer(entries, archive)
        print(f"Rootfs layer={index}/{len(manifest['layers'])} merged_entries={len(entries)} duration_ms={(time.perf_counter() - layer_started) * 1000:.1f}", flush=True)
    temporary = output.with_suffix(".partial")
    try:
        with temporary.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                # Directories precede their children; Linux symlinks remain symlinks.
                for name in sorted(entries):
                    member, data = entries[name]
                    archive.addfile(member, io.BytesIO(data) if member.isreg() else None)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    receipt.write_text(json.dumps({"lock": lock, "recipe": recipe, "sha256": sha256(output)}, indent=2) + "\n")
    print(f"Embedded rootfs prepared: {output} bytes={output.stat().st_size} duration_ms={(time.perf_counter() - started) * 1000:.1f}", flush=True)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", help="select an MCR image:tag and update rootfs.lock.json")
    parser.add_argument("--update", action="store_true", help="refresh the configured tag's pinned digest")
    args = parser.parse_args()
    if args.image or args.update:
        update_lock(args.image)
    build()
