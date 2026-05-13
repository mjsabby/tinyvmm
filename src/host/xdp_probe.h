#pragma once

namespace tinyvmm::host {

// --xdp-probe diagnostic. With ifindex == 0, lists every host NIC and reports
// XDP attachment (Generic + Native) for each. With a specific ifindex, opens
// an XSK, attempts to bind with Native first then Generic, and reports the
// outcome along with any error codes. Returns 0 on success / 1 on any failure
// the user should know about (e.g. XDP not installed).
int RunXdpProbe(int ifindex);

}  // namespace tinyvmm::host
