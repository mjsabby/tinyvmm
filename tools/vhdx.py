"""Create VHDX test disks and optionally prefill their virtual sectors."""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
from pathlib import Path
import subprocess
import uuid


class Guid(c.Structure):
    _fields_ = [("bytes", c.c_ubyte * 16)]


class Storage(c.Structure):
    _fields_ = [("device", w.DWORD), ("vendor", Guid)]


class OpenParameters(c.Structure):
    _fields_ = [("version", w.DWORD), ("info_only", w.BOOL),
                ("readonly", w.BOOL), ("resiliency", Guid)]


class Overlapped(c.Structure):
    _fields_ = [("internal", c.c_size_t), ("internal_high", c.c_size_t),
                ("offset", w.DWORD), ("offset_high", w.DWORD), ("event", w.HANDLE)]


def _guid(value: uuid.UUID) -> Guid:
    return Guid((c.c_ubyte * 16).from_buffer_copy(value.bytes_le))


def make_vhdx(path: Path, size_bytes: int, tinyvmm: Path | str,
              fill: int | None = None) -> None:
    if size_bytes <= 0 or size_bytes % (1024 * 1024):
        raise ValueError("VHDX test disk size must be a positive whole MiB")
    path.unlink(missing_ok=True)
    subprocess.run([str(tinyvmm), "--create-vhdx", str(path),
                    str(size_bytes // (1024 * 1024))], check=True)
    if fill is None:
        return

    kernel = c.WinDLL("kernel32", use_last_error=True)
    virtual = c.WinDLL("virtdisk", use_last_error=True)
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CreateEventW.argtypes = [c.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR]
    kernel.CreateEventW.restype = w.HANDLE
    kernel.WriteFile.argtypes = [w.HANDLE, c.c_void_p, w.DWORD,
                                c.POINTER(w.DWORD), c.POINTER(Overlapped)]
    kernel.GetOverlappedResult.argtypes = [w.HANDLE, c.POINTER(Overlapped),
                                         c.POINTER(w.DWORD), w.BOOL]
    kernel.FlushFileBuffers.argtypes = [w.HANDLE]
    virtual.OpenVirtualDisk.argtypes = [
        c.POINTER(Storage), w.LPCWSTR, w.DWORD, w.DWORD,
        c.POINTER(OpenParameters), c.POINTER(w.HANDLE)]
    virtual.AttachVirtualDisk.argtypes = [
        w.HANDLE, c.c_void_p, w.DWORD, w.DWORD, c.c_void_p, c.c_void_p]
    storage = Storage(3, _guid(uuid.UUID("ec984aec-a0f9-47e9-901f-71415a66345b")))
    parameters = OpenParameters(2, 0, 0, _guid(uuid.uuid4()))
    handle = w.HANDLE()
    error = virtual.OpenVirtualDisk(c.byref(storage), str(path.resolve()),
                                   0, 8, c.byref(parameters), c.byref(handle))
    if error:
        raise c.WinError(error)
    event = None
    try:
        error = virtual.AttachVirtualDisk(handle, None, 8, 0, None, None)
        if error:
            raise c.WinError(error)
        event = kernel.CreateEventW(None, True, False, None)
        if not event:
            raise c.WinError(c.get_last_error())
        chunk = bytes([fill & 0xff]) * min(size_bytes, 1024 * 1024)
        data = c.create_string_buffer(chunk, len(chunk))
        for offset in range(0, size_bytes, len(chunk)):
            length = min(len(chunk), size_bytes - offset)
            ov = Overlapped(offset=offset & 0xffffffff,
                            offset_high=offset >> 32, event=event)
            done = w.DWORD()
            if not kernel.WriteFile(handle, data, length, c.byref(done), c.byref(ov)):
                error = c.get_last_error()
                if error != 997:
                    raise c.WinError(error)
            if not kernel.GetOverlappedResult(handle, c.byref(ov), c.byref(done), True):
                raise c.WinError(c.get_last_error())
            if done.value != length:
                raise OSError("Short VHDX prefill write")
        if not kernel.FlushFileBuffers(handle):
            raise c.WinError(c.get_last_error())
    finally:
        if event:
            kernel.CloseHandle(event)
        kernel.CloseHandle(handle)
