//! Wire-format helpers for the user-mode NAT: Ethernet / ARP / IPv4 / ICMP /
//! UDP / TCP parse + build + checksums. Big-endian on the wire. Shares the
//! conventions of src/virtio/net_l2.h.

pub const ETH_HDR: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;

pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;

pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_REPLY: u8 = 0;

// TCP flag bits.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

#[inline]
pub fn be16(b: &[u8]) -> u16 {
    ((b[0] as u16) << 8) | b[1] as u16
}
#[inline]
fn put_be16(b: &mut [u8], v: u16) {
    b[0] = (v >> 8) as u8;
    b[1] = (v & 0xFF) as u8;
}
#[inline]
pub fn be32(b: &[u8]) -> u32 {
    ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | b[3] as u32
}
#[inline]
fn put_be32(b: &mut [u8], v: u32) {
    b[0] = (v >> 24) as u8;
    b[1] = (v >> 16) as u8;
    b[2] = (v >> 8) as u8;
    b[3] = (v & 0xFF) as u8;
}

/// RFC 1071 ones-complement checksum.
pub fn checksum16(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut leftover: Option<u8> = None;
    for part in parts {
        let mut data = *part;
        if let Some(hi) = leftover.take() {
            if !data.is_empty() {
                sum += ((hi as u32) << 8) | data[0] as u32;
                data = &data[1..];
            } else {
                leftover = Some(hi);
            }
        }
        let mut i = 0;
        while i + 1 < data.len() {
            sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
            i += 2;
        }
        if i < data.len() {
            leftover = Some(data[i]);
        }
    }
    if let Some(hi) = leftover {
        sum += (hi as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ---------------------------------------------------------------------------
// Ethernet
// ---------------------------------------------------------------------------

pub struct EthView<'a> {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
    pub payload: &'a [u8],
}

pub fn parse_eth(f: &[u8]) -> Option<EthView<'_>> {
    if f.len() < ETH_HDR {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&f[0..6]);
    src.copy_from_slice(&f[6..12]);
    Some(EthView {
        dst,
        src,
        ethertype: be16(&f[12..14]),
        payload: &f[14..],
    })
}

pub fn build_eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ETH_HDR + payload.len());
    build_eth_into(&mut out, dst, src, ethertype, payload);
    out
}

/// Write an Ethernet frame into `out` (cleared first). No allocation when `out`
/// already has capacity — the hot-path form.
pub fn build_eth_into(out: &mut Vec<u8>, dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) {
    out.clear();
    out.extend_from_slice(&dst);
    out.extend_from_slice(&src);
    out.push((ethertype >> 8) as u8);
    out.push((ethertype & 0xFF) as u8);
    out.extend_from_slice(payload);
}

// ---------------------------------------------------------------------------
// ARP (RFC 826, IPv4-over-Ethernet)
// ---------------------------------------------------------------------------

pub struct ArpView {
    pub op: u16,
    pub sha: [u8; 6],
    pub spa: [u8; 4],
    pub tpa: [u8; 4],
}

pub fn parse_arp(p: &[u8]) -> Option<ArpView> {
    if p.len() < 28 {
        return None;
    }
    // htype=1, ptype=0x0800, hlen=6, plen=4.
    if be16(&p[0..2]) != 1 || be16(&p[2..4]) != ETHERTYPE_IPV4 || p[4] != 6 || p[5] != 4 {
        return None;
    }
    let mut sha = [0u8; 6];
    let mut spa = [0u8; 4];
    let mut tpa = [0u8; 4];
    sha.copy_from_slice(&p[8..14]);
    spa.copy_from_slice(&p[14..18]);
    tpa.copy_from_slice(&p[24..28]);
    Some(ArpView {
        op: be16(&p[6..8]),
        sha,
        spa,
        tpa,
    })
}

/// ARP reply payload: `sender`=gateway, `target`=the asking guest.
pub fn build_arp_reply(
    sender_mac: [u8; 6],
    sender_ip: [u8; 4],
    target_mac: [u8; 6],
    target_ip: [u8; 4],
) -> [u8; 28] {
    let mut p = [0u8; 28];
    put_be16(&mut p[0..2], 1); // htype Ethernet
    put_be16(&mut p[2..4], ETHERTYPE_IPV4); // ptype IPv4
    p[4] = 6;
    p[5] = 4;
    put_be16(&mut p[6..8], 2); // op = reply
    p[8..14].copy_from_slice(&sender_mac);
    p[14..18].copy_from_slice(&sender_ip);
    p[18..24].copy_from_slice(&target_mac);
    p[24..28].copy_from_slice(&target_ip);
    p
}

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

pub struct Ipv4View<'a> {
    pub proto: u8,
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub payload: &'a [u8],
    /// The full IP datagram (header + payload), clamped to total_len.
    pub datagram: &'a [u8],
}

pub fn parse_ipv4(p: &[u8]) -> Option<Ipv4View<'_>> {
    if p.len() < 20 {
        return None;
    }
    if p[0] >> 4 != 4 {
        return None;
    }
    let ihl = (p[0] & 0x0F) as usize * 4;
    if ihl < 20 || p.len() < ihl {
        return None;
    }
    let total_len = be16(&p[2..4]) as usize;
    let end = total_len.min(p.len()).max(ihl);
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&p[12..16]);
    dst.copy_from_slice(&p[16..20]);
    Some(Ipv4View {
        proto: p[9],
        src,
        dst,
        payload: &p[ihl..end],
        datagram: &p[..end],
    })
}

/// Build a 20-byte IPv4 header + payload (header checksum filled).
pub fn build_ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + payload.len());
    build_ipv4_into(&mut out, src, dst, proto, payload);
    out
}

/// Hot-path form of [`build_ipv4`]: writes into `out` (cleared first).
pub fn build_ipv4_into(out: &mut Vec<u8>, src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) {
    out.clear();
    let total = 20 + payload.len();
    let mut h = [0u8; 20];
    h[0] = 0x45;
    put_be16(&mut h[2..4], total as u16);
    // id=0, flags: DF set
    h[6] = 0x40;
    h[8] = 64; // TTL
    h[9] = proto;
    h[12..16].copy_from_slice(&src);
    h[16..20].copy_from_slice(&dst);
    let csum = checksum16(&[&h]);
    put_be16(&mut h[10..12], csum);
    out.extend_from_slice(&h);
    out.extend_from_slice(payload);
}

// ---------------------------------------------------------------------------
// ICMP
// ---------------------------------------------------------------------------

/// If `icmp` is an echo request, return the echo-reply ICMP message.
pub fn build_icmp_echo_reply(icmp: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    if build_icmp_echo_reply_into(&mut out, icmp) {
        Some(out)
    } else {
        None
    }
}

/// Hot/cold-path form: writes the echo reply into `out` (cleared first).
/// Returns false if `icmp` isn't an echo request.
pub fn build_icmp_echo_reply_into(out: &mut Vec<u8>, icmp: &[u8]) -> bool {
    if icmp.len() < 8 || icmp[0] != ICMP_ECHO_REQUEST {
        return false;
    }
    out.clear();
    out.extend_from_slice(icmp);
    out[0] = ICMP_ECHO_REPLY;
    out[2] = 0;
    out[3] = 0;
    let csum = checksum16(&[&out[..]]);
    put_be16(&mut out[2..4], csum);
    true
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

pub struct UdpView<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp(p: &[u8]) -> Option<UdpView<'_>> {
    if p.len() < 8 {
        return None;
    }
    let len = be16(&p[4..6]) as usize;
    let end = len.clamp(8, p.len());
    Some(UdpView {
        src_port: be16(&p[0..2]),
        dst_port: be16(&p[2..4]),
        payload: &p[8..end],
    })
}

/// Build a UDP datagram (header + data) with checksum, ready as an IP payload.
pub fn build_udp(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + data.len());
    build_udp_into(&mut out, src_ip, dst_ip, src_port, dst_port, data);
    out
}

/// Hot-path form of [`build_udp`]: writes into `out` (cleared first).
pub fn build_udp_into(
    out: &mut Vec<u8>,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    data: &[u8],
) {
    out.clear();
    let ulen = 8 + data.len();
    let mut h = [0u8; 8];
    put_be16(&mut h[0..2], src_port);
    put_be16(&mut h[2..4], dst_port);
    put_be16(&mut h[4..6], ulen as u16);
    // Pseudo-header: src, dst, zero, proto, udp_len.
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip);
    pseudo[4..8].copy_from_slice(&dst_ip);
    pseudo[9] = IP_PROTO_UDP;
    put_be16(&mut pseudo[10..12], ulen as u16);
    let mut csum = checksum16(&[&pseudo, &h, data]);
    if csum == 0 {
        csum = 0xFFFF; // 0 means "no checksum"; use all-ones instead.
    }
    put_be16(&mut h[6..8], csum);
    out.extend_from_slice(&h);
    out.extend_from_slice(data);
}

// ---------------------------------------------------------------------------
// TCP (header peek only -- payload handled by tcp-sans-io)
// ---------------------------------------------------------------------------

pub struct TcpView {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub flags: u8,
}

pub fn parse_tcp(p: &[u8]) -> Option<TcpView> {
    if p.len() < 20 {
        return None;
    }
    Some(TcpView {
        src_port: be16(&p[0..2]),
        dst_port: be16(&p[2..4]),
        seq: be32(&p[4..8]),
        flags: p[13],
    })
}

/// Build a 20-byte TCP segment (no options, no payload) with the pseudo-header
/// checksum filled, ready as an IPv4 payload. Used for the conn-cap RST that
/// refuses a guest SYN we can't service.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    build_tcp_into(
        &mut out, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, window,
    );
    out
}

/// Hot/cold-path form of [`build_tcp`]: writes into `out` (cleared first).
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_into(
    out: &mut Vec<u8>,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
) {
    out.clear();
    let mut h = [0u8; 20];
    put_be16(&mut h[0..2], src_port);
    put_be16(&mut h[2..4], dst_port);
    put_be32(&mut h[4..8], seq);
    put_be32(&mut h[8..12], ack);
    h[12] = 0x50; // data offset = 5 words (20 bytes), no options
    h[13] = flags;
    put_be16(&mut h[14..16], window);
    // Pseudo-header: src, dst, zero, proto, tcp_len.
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip);
    pseudo[4..8].copy_from_slice(&dst_ip);
    pseudo[9] = IP_PROTO_TCP;
    put_be16(&mut pseudo[10..12], h.len() as u16);
    let csum = checksum16(&[&pseudo, &h]);
    put_be16(&mut h[16..18], csum);
    out.extend_from_slice(&h);
}

/// Build the RST that refuses a guest SYN (src/dst swapped so it appears to
/// come from the destination) into `out`. RFC 793: for a SYN (no ACK) the
/// response is `seq=0, ack=seg.seq+1, flags=RST|ACK`.
pub fn build_tcp_rst_for_syn_into(
    out: &mut Vec<u8>,
    guest_ip: [u8; 4],
    guest_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    syn_seq: u32,
) {
    build_tcp_into(
        out,
        dst_ip,
        guest_ip,
        dst_port,
        guest_port,
        0,
        syn_seq.wrapping_add(1),
        TCP_RST | TCP_ACK,
        0,
    );
}
