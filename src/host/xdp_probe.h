#pragma once

namespace tinyvmm::host {

// --xdp-probe diagnostic.
//
// With ifindex == 0 (no arg): enumerates every host NIC, opens it via
// XdpInterfaceOpen, queries RSS capabilities (queue count, hash types) via
// XdpRssGetCapabilities, and tries XskBind on queue 0 with NATIVE and GENERIC
// flags. One summary line per NIC.
//
// With a specific ifindex: deep-dive on one NIC -- prints RSS caps in detail
// and tries each bind mode verbosely (full HRESULT + hint text on failure).
//
// Returns 0 on success / 1 if XDP is unavailable globally (driver not
// installed, access denied to the device, etc).
int RunXdpProbe(int ifindex);

}  // namespace tinyvmm::host
