//! The destination policy of the backends whose TCP/IP stack isn't tinyvmm's
//! (libslirp, gVisor): the NAT's (`nat::host_dest`), applied to the guest's
//! frames before the stack sees them.
//!
//! Left to themselves both stacks connect, as the host, to whatever the guest
//! addresses. libslirp takes every address on the guest's link but its
//! nameserver for the host's loopback, and gVisor's shim takes the gateway
//! for it and dials any other address as it is: 127.0.0.1, the host's own
//! addresses, the link-local address where a cloud serves instance metadata
//! and identity tokens. Neither knows the host's addresses, and neither is
//! code tinyvmm can change at run time, so the guest's frames are sorted
//! here, by the rules the NAT applies to its own flows:
//!
//! * the gateway is the host's loopback on the DNS port only (and answers
//!   pings and DHCP itself); `--nat-host-local` opens its other ports. What
//!   is refused there is opening a connection: the stacks' own connections
//!   to the guest come from the gateway (a `--portfwd` client's), and the
//!   guest's side of those passes;
//! * what a router wouldn't forward (multicast, broadcast, the guest's own
//!   link) stays on the guest's link, DHCP's broadcasts excepted;
//! * host-local destinations beyond the link (127/8, the host's addresses,
//!   cloud metadata) are refused unless `--nat-host-local`.
//!
//! A fragment carries no ports, so one for a destination where only some
//! ports pass is refused: a DNS query fits in a packet. Frames that are
//! neither ARP nor IPv4 are dropped, as neither stack is set up to relay
//! anything else.

use crate::net::dhcp;
use crate::net::nat::{DNS_PORT, HostAddrs, host_dest, relayable};
use crate::net::wire::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct GuestFilter {
    gw: [u8; 4],
    /// An address on the guest's link, besides the gateway, where the stack
    /// serves DNS (libslirp's forwarder).
    dns_alias: Option<[u8; 4]>,
    /// `--nat-host-local`.
    host_local: bool,
    host_addrs: Mutex<HostAddrs>,
    refused: AtomicU64,
}

impl GuestFilter {
    pub fn new(gw: [u8; 4], dns_alias: Option<[u8; 4]>, host_local: bool) -> Self {
        GuestFilter {
            gw,
            dns_alias,
            host_local,
            host_addrs: Mutex::new(HostAddrs::default()),
            refused: AtomicU64::new(0),
        }
    }

    /// IPv4 packets from the guest that the stack was not given.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Whether the stack may have this frame from the guest. If not, and the
    /// frame opens a TCP connection, `reply` is the frame to give the guest
    /// in answer: a reset, so its `connect()` is refused at once rather than
    /// timing out. Otherwise `reply` is left empty.
    pub fn admits(&self, frame: &[u8], reply: &mut Vec<u8>) -> bool {
        reply.clear();
        let Some(eth) = parse_eth(frame) else {
            return false;
        };
        match eth.ethertype {
            ETHERTYPE_ARP => true,
            ETHERTYPE_IPV4 => {
                let admitted = self.admits_ipv4(&eth, reply);
                if !admitted {
                    self.refused.fetch_add(1, Ordering::Relaxed);
                }
                admitted
            }
            _ => false,
        }
    }

    fn admits_ipv4(&self, eth: &EthView, reply: &mut Vec<u8>) -> bool {
        let p = eth.payload;
        if p.len() < 20 || p[0] >> 4 != 4 {
            return false;
        }
        let ihl = usize::from(p[0] & 0x0F) * 4;
        let end = usize::from(be16(&p[2..4])).min(p.len());
        if ihl < 20 || end < ihl {
            return false;
        }
        let src = [p[12], p[13], p[14], p[15]];
        let dst = [p[16], p[17], p[18], p[19]];
        let proto = p[9];
        let l4 = &p[ihl..end];
        // More-Fragments set, or a fragment offset.
        let fragment = be16(&p[6..8]) & 0x3FFF != 0;
        // The TCP or UDP destination port, where the packet has one to read.
        let port = match proto {
            IP_PROTO_TCP | IP_PROTO_UDP if !fragment && l4.len() >= 4 => Some(be16(&l4[2..4])),
            _ => None,
        };
        let dhcp = proto == IP_PROTO_UDP && port == Some(dhcp::SERVER_PORT);
        // A TCP segment that opens no connection: anything but a bare SYN.
        // Only a SYN has either stack connect somewhere for the guest; any
        // other segment belongs to a connection that exists, or is answered
        // with a reset.
        let continues = proto == IP_PROTO_TCP
            && !fragment
            && l4.len() >= 14
            && l4[13] & (TCP_SYN | TCP_ACK | TCP_RST) != TCP_SYN;

        let admitted = if dst == self.gw {
            // The stack answers the gateway's pings (and libslirp DHCP)
            // itself. The gateway's ports are the host's loopback, which the
            // guest may open a connection to on the DNS port only. But the
            // gateway is also where the stack's own connections to the guest
            // come from (a `--portfwd` client's), and the guest's segments
            // on those must pass: they open nothing.
            self.host_local || proto == IP_PROTO_ICMP || dhcp || port == Some(DNS_PORT) || continues
        } else if Some(dst) == self.dns_alias {
            self.host_local || port == Some(DNS_PORT)
        } else if dst == dhcp::BROADCAST_IP {
            dhcp
        } else if !relayable(dst, self.gw) {
            false
        } else {
            // Without a port to read, the packet passes only where every
            // port would (0 is no service's port).
            self.host_dest(dst, port.unwrap_or(0)).is_some()
        };

        if !admitted
            && proto == IP_PROTO_TCP
            && !fragment
            && let Some(tcp) = parse_tcp(l4)
            && tcp.flags & (TCP_SYN | TCP_ACK | TCP_RST) == TCP_SYN
        {
            let mut rst = Vec::new();
            build_tcp_rst_for_syn_into(&mut rst, src, tcp.src_port, dst, tcp.dst_port, tcp.seq);
            let ip = build_ipv4(dst, src, IP_PROTO_TCP, &rst);
            // From the MAC the guest addressed (the gateway's) back to it.
            *reply = build_eth(eth.src, eth.dst, ETHERTYPE_IPV4, &ip);
        }
        admitted
    }

    /// `nat::host_dest` for a destination beyond the guest's link.
    fn host_dest(&self, ip: [u8; 4], port: u16) -> Option<[u8; 4]> {
        let host_owned = !self.host_local && self.host_addrs.lock().unwrap().contains(ip);
        host_dest(ip, port, self.gw, self.host_local, host_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GW: [u8; 4] = crate::net::GATEWAY_IP;
    const GUEST: [u8; 4] = crate::net::GUEST_IP;
    const ALIAS: [u8; 4] = [172, 29, 255, 3];
    /// One of the host's own addresses, in these tests.
    const OWN: [u8; 4] = [192, 168, 1, 10];
    const GW_MAC: [u8; 6] = [0x02, 0x53, 0x54, 0, 0, 1];
    const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];

    fn filter(host_local: bool) -> GuestFilter {
        let f = GuestFilter::new(GW, Some(ALIAS), host_local);
        *f.host_addrs.lock().unwrap() = HostAddrs::fixed(vec![[127, 0, 0, 1], OWN]);
        f
    }

    fn eth(ip: &[u8]) -> Vec<u8> {
        build_eth(GW_MAC, GUEST_MAC, ETHERTYPE_IPV4, ip)
    }

    fn udp(dst: [u8; 4], port: u16) -> Vec<u8> {
        let l4 = build_udp(GUEST, dst, 40000, port, b"query");
        eth(&build_ipv4(GUEST, dst, IP_PROTO_UDP, &l4))
    }

    fn tcp(dst: [u8; 4], port: u16, flags: u8) -> Vec<u8> {
        let l4 = build_tcp(GUEST, dst, 40000, port, 0x1000, 0, flags, 64240);
        eth(&build_ipv4(GUEST, dst, IP_PROTO_TCP, &l4))
    }

    fn ping(dst: [u8; 4]) -> Vec<u8> {
        eth(&build_ipv4(
            GUEST,
            dst,
            IP_PROTO_ICMP,
            &[ICMP_ECHO_REQUEST, 0, 0, 0, 0, 1, 0, 1],
        ))
    }

    /// `frame` as the first fragment of a longer datagram.
    fn fragmented(mut frame: Vec<u8>) -> Vec<u8> {
        frame[ETH_HDR + 6] |= 0x20; // More-Fragments
        frame
    }

    fn admits(f: &GuestFilter, frame: &[u8]) -> bool {
        f.admits(frame, &mut Vec::new())
    }

    /// The gateway is the host's loopback on the DNS port alone; it answers
    /// pings and DHCP itself. `--nat-host-local` opens the rest.
    #[test]
    fn the_gateway_is_the_hosts_loopback_for_dns_only() {
        let f = filter(false);
        assert!(admits(&f, &udp(GW, 53)));
        assert!(admits(&f, &tcp(GW, 53, TCP_SYN)));
        assert!(admits(&f, &ping(GW)));
        assert!(admits(&f, &fragmented(ping(GW))), "a big ping");
        assert!(admits(&f, &udp(GW, 67)), "a DHCP renewal");
        assert!(admits(&f, &udp(dhcp::BROADCAST_IP, 67)), "DHCP discovery");
        for port in [22, 80, 445, 3389, 8080] {
            assert!(!admits(&f, &tcp(GW, port, TCP_SYN)), "tcp {port}");
            assert!(!admits(&f, &udp(GW, port)), "udp {port}");
        }
        assert!(!admits(&f, &tcp(GW, 67, TCP_SYN)), "DHCP is UDP");
        assert!(!admits(&f, &fragmented(udp(GW, 53))), "no port to go by");
        assert_eq!(f.refused(), 12);

        let open = filter(true);
        for port in [22, 53, 80, 8080] {
            assert!(admits(&open, &tcp(GW, port, TCP_SYN)), "tcp {port}");
            assert!(admits(&open, &udp(GW, port)), "udp {port}");
        }
        assert!(admits(&open, &fragmented(udp(GW, 8080))));
        assert_eq!(open.refused(), 0);
    }

    /// A `--portfwd` client reaches the guest as a connection from the
    /// gateway, so the guest's side of it is addressed to the gateway, at a
    /// port that is no service's: those segments pass. Opening a connection
    /// to that port does not, whatever else the SYN carries.
    #[test]
    fn the_guests_side_of_a_forwarded_connection_passes() {
        let f = filter(false);
        for flags in [
            TCP_SYN | TCP_ACK,
            TCP_ACK,
            TCP_ACK | 0x08,
            TCP_FIN | TCP_ACK,
            TCP_RST,
            TCP_RST | TCP_ACK,
        ] {
            assert!(admits(&f, &tcp(GW, 51234, flags)), "flags {flags:#04x}");
        }
        assert_eq!(f.refused(), 0);
        // A SYN opens a connection, also with ECN's bits or a FIN on it.
        for flags in [TCP_SYN, TCP_SYN | 0xC0, TCP_SYN | TCP_FIN, TCP_SYN | 0x20] {
            assert!(!admits(&f, &tcp(GW, 51234, flags)), "flags {flags:#04x}");
        }
        // No flags to go by in a fragment, or in a segment cut short.
        assert!(!admits(&f, &fragmented(tcp(GW, 51234, TCP_ACK))));
        let mut short = tcp(GW, 51234, TCP_ACK);
        short.truncate(ETH_HDR + 20 + 13);
        short[ETH_HDR + 2..ETH_HDR + 4].copy_from_slice(&33u16.to_be_bytes());
        assert!(!admits(&f, &short));
        // Only the gateway is where the stack's connections come from: the
        // other host-local destinations stay shut to every segment.
        for dst in [[127, 0, 0, 1], ALIAS, OWN, [169, 254, 169, 254]] {
            assert!(!admits(&f, &tcp(dst, 51234, TCP_ACK)), "{dst:?}");
            assert!(!admits(&f, &tcp(dst, 51234, TCP_SYN | TCP_ACK)), "{dst:?}");
        }
    }

    /// libslirp's nameserver address forwards every port to the host's
    /// resolver, which may be on its loopback: DNS only.
    #[test]
    fn the_dns_alias_serves_dns_only() {
        let f = filter(false);
        assert!(admits(&f, &udp(ALIAS, 53)));
        assert!(admits(&f, &tcp(ALIAS, 53, TCP_SYN)));
        assert!(!admits(&f, &tcp(ALIAS, 80, TCP_SYN)));
        assert!(!admits(&f, &ping(ALIAS)));
        assert!(!admits(&f, &fragmented(udp(ALIAS, 53))));
        assert!(admits(&filter(true), &tcp(ALIAS, 80, TCP_SYN)));
        // Without such an address, it is one more on the guest's link.
        let none = GuestFilter::new(GW, None, true);
        assert!(!admits(&none, &udp(ALIAS, 53)));
    }

    /// What a router wouldn't forward stays on the guest's link, whatever
    /// the opt-in: other addresses there (which libslirp would take for the
    /// host's loopback), multicast, broadcast.
    #[test]
    fn the_guests_link_and_multicast_are_not_relayed() {
        for host_local in [false, true] {
            let f = filter(host_local);
            for dst in [
                [172, 29, 255, 4],
                [172, 29, 255, 6],
                [172, 29, 255, 7],
                GUEST,
                [224, 0, 0, 251],
                [239, 255, 255, 250],
                [240, 0, 0, 1],
                [0, 0, 0, 0],
            ] {
                assert!(!admits(&f, &udp(dst, 5353)), "{dst:?}");
                assert!(!admits(&f, &tcp(dst, 80, TCP_SYN)), "{dst:?}");
                assert!(!admits(&f, &ping(dst)), "{dst:?}");
            }
            assert!(!admits(&f, &udp(dhcp::BROADCAST_IP, 5353)));
            assert!(!admits(&f, &tcp(dhcp::BROADCAST_IP, 67, TCP_SYN)));
        }
    }

    /// Beyond the link the guest reaches what a router's clients reach, not
    /// the host's loopback, its own addresses or cloud metadata.
    #[test]
    fn host_local_destinations_need_the_opt_in() {
        let f = filter(false);
        for dst in [[1, 1, 1, 1], [10, 0, 9, 121], [192, 168, 1, 11]] {
            assert!(admits(&f, &tcp(dst, 443, TCP_SYN)), "{dst:?}");
            assert!(admits(&f, &udp(dst, 53)), "{dst:?}");
            assert!(admits(&f, &ping(dst)), "{dst:?}");
            assert!(admits(&f, &fragmented(udp(dst, 4000))), "{dst:?}");
        }
        for dst in [
            [127, 0, 0, 1],
            [127, 9, 9, 9],
            [169, 254, 169, 254],
            [100, 100, 100, 200],
        ] {
            for port in [53, 80] {
                assert!(!admits(&f, &tcp(dst, port, TCP_SYN)), "{dst:?}:{port}");
                assert!(!admits(&f, &udp(dst, port)), "{dst:?}:{port}");
            }
            assert!(!admits(&f, &ping(dst)), "{dst:?}");
            assert!(!admits(&f, &fragmented(udp(dst, 53))), "{dst:?}");
        }
        // The host's own address, and Azure's: a resolver there, no more.
        for dst in [OWN, [168, 63, 129, 16]] {
            assert!(admits(&f, &udp(dst, 53)), "{dst:?}");
            assert!(admits(&f, &tcp(dst, 53, TCP_SYN)), "{dst:?}");
            for port in [80, 445, 3389] {
                assert!(!admits(&f, &tcp(dst, port, TCP_SYN)), "{dst:?}:{port}");
                assert!(!admits(&f, &udp(dst, port)), "{dst:?}:{port}");
            }
            assert!(!admits(&f, &ping(dst)), "{dst:?}");
            assert!(!admits(&f, &fragmented(udp(dst, 53))), "{dst:?}");
        }

        let open = filter(true);
        for dst in [
            [127, 0, 0, 1],
            [169, 254, 169, 254],
            OWN,
            [168, 63, 129, 16],
        ] {
            assert!(admits(&open, &tcp(dst, 80, TCP_SYN)), "{dst:?}");
            assert!(admits(&open, &fragmented(udp(dst, 80))), "{dst:?}");
        }
    }

    /// A refused connection attempt is answered with a reset from the
    /// address the guest tried, so `connect()` fails at once. Nothing else
    /// refused is answered.
    #[test]
    fn a_refused_syn_is_reset() {
        let f = filter(false);
        let mut reply = Vec::new();
        assert!(!f.admits(&tcp([127, 0, 0, 1], 8080, TCP_SYN), &mut reply));
        let e = parse_eth(&reply).expect("an Ethernet frame");
        assert_eq!(
            (e.dst, e.src, e.ethertype),
            (GUEST_MAC, GW_MAC, ETHERTYPE_IPV4)
        );
        let ip = parse_ipv4(e.payload).expect("an IPv4 packet");
        assert_eq!(
            (ip.src, ip.dst, ip.proto),
            ([127, 0, 0, 1], GUEST, IP_PROTO_TCP)
        );
        let t = parse_tcp(ip.payload).expect("a TCP segment");
        assert_eq!((t.src_port, t.dst_port), (8080, 40000));
        assert_eq!(t.flags, TCP_RST | TCP_ACK);
        assert_eq!(t.ack, 0x1001, "acknowledges the SYN");

        for frame in [
            tcp([127, 0, 0, 1], 8080, TCP_ACK),
            tcp([127, 0, 0, 1], 8080, TCP_SYN | TCP_ACK),
            tcp([127, 0, 0, 1], 8080, TCP_RST),
            fragmented(tcp([127, 0, 0, 1], 8080, TCP_SYN)),
            udp([127, 0, 0, 1], 8080),
            ping([127, 0, 0, 1]),
        ] {
            reply.extend_from_slice(b"stale");
            assert!(!f.admits(&frame, &mut reply));
            assert!(reply.is_empty());
        }
        // An admitted frame leaves no reply either.
        reply.extend_from_slice(b"stale");
        assert!(f.admits(&tcp([1, 1, 1, 1], 443, TCP_SYN), &mut reply));
        assert!(reply.is_empty());
    }

    /// ARP passes; frames that aren't ARP or IPv4, and IPv4 too malformed to
    /// tell where it is going, never reach the stack.
    #[test]
    fn only_arp_and_wellformed_ipv4_pass() {
        let f = filter(true);
        assert!(admits(
            &f,
            &build_eth([0xFF; 6], GUEST_MAC, ETHERTYPE_ARP, &[0; 28])
        ));
        assert!(
            !admits(&f, &build_eth(GW_MAC, GUEST_MAC, 0x86DD, &[0x60; 40])),
            "IPv6"
        );
        assert!(
            !admits(&f, &build_eth(GW_MAC, GUEST_MAC, 0x8100, &[0; 40])),
            "a VLAN tag"
        );
        assert!(!admits(&f, &[0u8; 10]), "no Ethernet header");

        let good = udp([1, 1, 1, 1], 53);
        assert!(admits(&f, &good));
        let mut short = good.clone();
        short.truncate(ETH_HDR + 19);
        assert!(!admits(&f, &short), "a cut-off header");
        let mut v6 = good.clone();
        v6[ETH_HDR] = 0x65;
        assert!(!admits(&f, &v6), "not version 4");
        let mut ihl = good.clone();
        ihl[ETH_HDR] = 0x44;
        assert!(!admits(&f, &ihl), "a 16-byte header");
        let mut long_ihl = good.clone();
        long_ihl[ETH_HDR] = 0x4F;
        long_ihl[ETH_HDR + 2..ETH_HDR + 4].copy_from_slice(&40u16.to_be_bytes());
        assert!(!admits(&f, &long_ihl), "a header longer than the packet");
    }
}
