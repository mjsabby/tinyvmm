import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("fetch_rootfs", Path(__file__).resolve().parents[1] / "fetch-rootfs.py")
rootfs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rootfs)


def merge(entries, files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, value in files:
            member = tarfile.TarInfo(name)
            if isinstance(value, tuple):
                member.type, member.linkname = value
                archive.addfile(member)
            else:
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))
    buffer.seek(0)
    with tarfile.open(fileobj=buffer) as archive:
        rootfs.merge_layer(entries, archive)


class LayerTests(unittest.TestCase):
    def test_whiteouts_only_remove_lower_layer_files(self):
        entries = {}
        merge(entries, [("etc/old", b"old"), ("etc/tree/file", b"old")])
        merge(entries, [("etc/old", b"new"), ("etc/.wh.old", b""), ("etc/.wh.tree", b"")])
        self.assertEqual(entries["etc/old"][1], b"new")
        self.assertNotIn("etc/tree/file", entries)

    def test_opaque_directory_preserves_new_files(self):
        entries = {}
        merge(entries, [("etc/old", b"old"), ("usr/keep", b"keep")])
        merge(entries, [("etc/new", b"new"), ("etc/.wh..wh..opq", b"")])
        self.assertEqual(set(entries), {"etc/new", "usr/keep"})

    def test_linux_links_without_host_extraction(self):
        entries = {}
        merge(entries, [
            ("usr/lib/data", b"data"),
            ("usr/lib/copy", (tarfile.LNKTYPE, "usr/lib/data")),
            ("etc/data", (tarfile.SYMTYPE, "/usr/lib/data")),
            ("bin", (tarfile.SYMTYPE, "usr/bin")),
        ])
        self.assertEqual(entries["usr/lib/copy"][1], b"data")
        self.assertTrue(entries["usr/lib/copy"][0].isreg())
        self.assertEqual(entries["etc/data"][0].linkname, "../usr/lib/data")
        self.assertEqual(entries["bin"][0].linkname, "usr/bin")

    def test_reject_escaping_paths_and_links(self):
        for name, value in [
            ("../escape", b"bad"),
            ("/absolute", b"bad"),
            ("etc/link", (tarfile.SYMTYPE, "../../escape")),
        ]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                merge({}, [(name, value)])


class ImageTests(unittest.TestCase):
    def test_select_linux_amd64_from_multiarch_tag(self):
        with patch.object(rootfs, "registry_json", side_effect=[
            ({"manifests": [
                {"digest": "arm", "platform": {"os": "linux", "architecture": "arm64"}},
                {"digest": "linux", "platform": {"os": "linux", "architecture": "amd64"}},
                {"digest": "windows", "platform": {"os": "windows", "architecture": "amd64"}},
            ]}, "index"),
            ({"config": {"digest": "config"}}, "pinned"),
            ({"os": "linux", "architecture": "amd64"}, "config"),
        ]) as registry:
            lock = rootfs.resolve_image("mcr.microsoft.com/dotnet/aspnet:preview")
        self.assertEqual(lock, {"image": "mcr.microsoft.com/dotnet/aspnet", "tag": "preview", "digest": "pinned"})
        self.assertEqual(registry.call_args_list[1].args, ("dotnet/aspnet", "manifests", "linux"))

    def test_reject_incompatible_image(self):
        with patch.object(rootfs, "registry_json", side_effect=[
            ({"config": {"digest": "config"}}, "pinned"),
            ({"os": "linux", "architecture": "arm64"}, "config"),
        ]), self.assertRaisesRegex(ValueError, "Linux amd64"):
            rootfs.resolve_image("mcr.microsoft.com/dotnet/aspnet:arm64")

    def test_reject_non_mcr_or_untagged_image(self):
        for reference in ("docker.io/dotnet/aspnet:11", "mcr.microsoft.com/dotnet/aspnet"):
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                rootfs.resolve_image(reference)

    def test_update_refreshes_configured_tag_and_persists_digest(self):
        previous = {"image": "mcr.microsoft.com/dotnet/aspnet", "tag": "preview", "digest": "old"}
        updated = {**previous, "digest": "new"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rootfs.lock.json"
            path.write_text(json.dumps(previous))
            with patch.object(rootfs, "HERE", Path(directory)), patch.object(
                rootfs, "resolve_image", return_value=updated
            ) as resolve:
                rootfs.update_lock()
            resolve.assert_called_once_with("mcr.microsoft.com/dotnet/aspnet:preview")
            self.assertEqual(json.loads(path.read_text()), updated)

    def test_registry_rejects_mismatched_digest(self):
        with patch.object(rootfs.urllib.request, "urlopen", return_value=io.BytesIO(b"{}")):
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                rootfs.registry_json("dotnet/aspnet", "manifests", "sha256:incorrect")


if __name__ == "__main__":
    unittest.main()
