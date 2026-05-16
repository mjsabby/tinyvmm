# wintunumapi (vendored, C++ session client)

Source: https://github.com/<owner>/wintunumapi (clean-room MIT)
Local mirror used: `C:\wintunumapi`

Files vendored here:
* `cpp/wintun_session.hpp`
* `cpp/wintun_session.cpp`

These implement the runtime (non-admin) wintun protocol: `TUN_IOCTL_REGISTER_RINGS`
(0xCA6CE5C0) + producer/consumer ring access via shared memory. **The session
is unprivileged on its own** — what requires admin is *adapter create/delete*,
which we handle via `wintun.dll` (admin path) or the `wintunsvc` named pipe
(non-admin path) outside this code. Both paths funnel into this single session.

License: MIT. SPDX-License-Identifier: MIT.

Do not edit these files locally; sync upstream by re-copying.
