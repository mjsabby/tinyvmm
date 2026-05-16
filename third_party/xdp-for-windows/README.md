# XDP for Windows — vendored public headers

This directory contains the public include surface from
**[microsoft/xdp-for-windows]** at tag **v1.3.0**
(commit `d59e6ad683cffa76764b63926d032149c5e91983`).

Only the contents of `published/external/` are vendored, plus the
upstream `LICENSE` file. No driver, no kernel-mode code, no
build system.

## Files

- `published/external/xdpapi.h`, `afxdp.h`, `afxdp_helper.h`,
  `xdpapi_experimental.h`, `afxdp_experimental.h`, `xdpddi.h` —
  user-mode API headers.
- `published/external/xdp/*.h` — supporting types and details.
- `LICENSE` — MIT (upstream).

## Refreshing

```powershell
git clone --depth 1 -b v<VERSION> https://github.com/microsoft/xdp-for-windows /tmp/xdp
robocopy /tmp/xdp/published/external third_party/xdp-for-windows/published/external /MIR
Copy-Item /tmp/xdp/LICENSE third_party/xdp-for-windows/LICENSE -Force
```

Then update the version string above and commit.

[microsoft/xdp-for-windows]: https://github.com/microsoft/xdp-for-windows
