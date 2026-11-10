"""Host-side PoCs: attacks that need no hostile driver in the guest. A boot
image tinyvmm parses, a DLL in the directory it is started from, a save that
is interrupted, input for a guest that isn't reading, and a guest that opens
flows through the gVisor backend. Each module's `run(exe, work, ...)` returns
{"vulnerable": bool | None, "evidence": str} (None: could not be judged, or
with "skipped": True, a prerequisite is missing). `poc/run.py` runs them.
"""
