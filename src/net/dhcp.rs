//! DHCP server (RFC 2131/2132) for the NAT's one-guest network, so stock
//! distributions configure their network with no help. Every client gets the
//! same lease: the guest address, the gateway as router and server, and the
//! host's DNS servers. With one possible answer there is no lease state.

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;
pub const BROADCAST_IP: [u8; 4] = [255; 4];
pub const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const HTYPE_ETHERNET: u8 = 1;
const HLEN_ETHERNET: u8 = 6;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// Options start after the fixed BOOTP fields and the magic cookie.
const OPTIONS: usize = 240;
/// BOOTP's minimum message size; some clients drop shorter replies.
const MIN_REPLY: usize = 300;
/// resolv.conf uses at most three name servers.
const MAX_DNS: usize = 3;

// Message types (option 53).
const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const ACK: u8 = 5;
const NAK: u8 = 6;
const INFORM: u8 = 8;

const OPT_PAD: u8 = 0;
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_END: u8 = 255;

/// The one lease this server hands out.
pub struct Lease {
    /// The gateway: router and server identifier.
    pub server: [u8; 4],
    pub client: [u8; 4],
    pub netmask: [u8; 4],
    pub dns: Vec<[u8; 4]>,
    pub lease_secs: u32,
}

/// Where a reply goes.
#[derive(Debug, PartialEq, Eq)]
pub struct Destination {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
}

#[derive(Default)]
struct RequestOptions {
    message_type: Option<u8>,
    requested_ip: Option<[u8; 4]>,
    server_id: Option<[u8; 4]>,
}

fn parse_options(mut opts: &[u8]) -> RequestOptions {
    let mut out = RequestOptions::default();
    while let Some((&code, rest)) = opts.split_first() {
        match code {
            OPT_PAD => {
                opts = rest;
                continue;
            }
            OPT_END => break,
            _ => {}
        }
        let Some((&len, rest)) = rest.split_first() else {
            break;
        };
        let Some(data) = rest.get(..len as usize) else {
            break;
        };
        match (code, data) {
            (OPT_MESSAGE_TYPE, &[t]) => out.message_type = Some(t),
            (OPT_REQUESTED_IP, &[a, b, c, d]) => out.requested_ip = Some([a, b, c, d]),
            (OPT_SERVER_ID, &[a, b, c, d]) => out.server_id = Some([a, b, c, d]),
            _ => {}
        }
        opts = &rest[len as usize..];
    }
    out
}

fn push_option(out: &mut Vec<u8>, code: u8, data: &[u8]) {
    out.push(code);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
}

/// Build the reply to the client message `req` into `out`. `None` if `req`
/// isn't a DHCP request or needs no answer (DECLINE, RELEASE, or a REQUEST
/// for another server).
pub fn reply(req: &[u8], lease: &Lease, out: &mut Vec<u8>) -> Option<Destination> {
    if req.len() < OPTIONS
        || req[0] != BOOTREQUEST
        || req[1] != HTYPE_ETHERNET
        || req[2] != HLEN_ETHERNET
        || req[236..OPTIONS] != MAGIC_COOKIE
    {
        return None;
    }
    let opts = parse_options(&req[OPTIONS..]);
    let ciaddr = [req[12], req[13], req[14], req[15]];
    let chaddr = [req[28], req[29], req[30], req[31], req[32], req[33]];
    let message_type = opts.message_type?;
    let (kind, yiaddr) = match message_type {
        DISCOVER => (OFFER, lease.client),
        REQUEST => {
            if opts.server_id.is_some_and(|id| id != lease.server) {
                return None;
            }
            let wanted = opts.requested_ip.or((ciaddr != [0; 4]).then_some(ciaddr));
            if wanted.is_some_and(|ip| ip != lease.client) {
                (NAK, [0; 4])
            } else {
                (ACK, lease.client)
            }
        }
        INFORM => (ACK, [0; 4]),
        _ => return None,
    };

    out.clear();
    out.resize(OPTIONS, 0);
    out[..3].copy_from_slice(&[BOOTREPLY, HTYPE_ETHERNET, HLEN_ETHERNET]);
    out[4..8].copy_from_slice(&req[4..8]); // xid
    out[10..12].copy_from_slice(&req[10..12]); // flags
    if kind == ACK {
        out[12..16].copy_from_slice(&ciaddr);
    }
    out[16..20].copy_from_slice(&yiaddr);
    out[24..28].copy_from_slice(&req[24..28]); // giaddr
    out[28..44].copy_from_slice(&req[28..44]); // chaddr
    out[236..OPTIONS].copy_from_slice(&MAGIC_COOKIE);
    push_option(out, OPT_MESSAGE_TYPE, &[kind]);
    push_option(out, OPT_SERVER_ID, &lease.server);
    if kind != NAK {
        // An INFORM client configured its own address: no lease for it.
        if message_type != INFORM {
            push_option(out, OPT_LEASE_TIME, &lease.lease_secs.to_be_bytes());
        }
        push_option(out, OPT_SUBNET_MASK, &lease.netmask);
        push_option(out, OPT_ROUTER, &lease.server);
        if !lease.dns.is_empty() {
            let dns: Vec<u8> = lease.dns.iter().take(MAX_DNS).flatten().copied().collect();
            push_option(out, OPT_DNS, &dns);
        }
    }
    out.push(OPT_END);
    if out.len() < MIN_REPLY {
        out.resize(MIN_REPLY, OPT_PAD);
    }

    // RFC 2131 4.1: a client that has an address gets a unicast; NAKs, and
    // clients without an address yet, get a broadcast, which every client
    // accepts whether or not it set the broadcast flag.
    Some(if ciaddr != [0; 4] && kind != NAK {
        Destination {
            ip: ciaddr,
            mac: chaddr,
        }
    } else {
        Destination {
            ip: BROADCAST_IP,
            mac: BROADCAST_MAC,
        }
    })
}

/// The host DNS servers a guest behind the NAT can use, at most three. The
/// host's own 127.0.0.1 (a local resolver) is offered as the gateway, whose
/// ports the NAT relays there; other loopback, link-local, unspecified and
/// broadcast addresses are dropped, as is any address on the guest's own
/// subnet other than the gateway (the guest would look for it on the link).
pub fn usable_dns(host: &[[u8; 4]], gateway: [u8; 4], netmask: [u8; 4]) -> Vec<[u8; 4]> {
    let on_subnet = |ip: [u8; 4]| (0..4).all(|i| ip[i] & netmask[i] == gateway[i] & netmask[i]);
    let mut out = Vec::new();
    for &ip in host {
        let ip = if ip == [127, 0, 0, 1] { gateway } else { ip };
        let unusable = ip == [0; 4]
            || ip == BROADCAST_IP
            || ip[0] == 127
            || ip[..2] == [169, 254]
            || (on_subnet(ip) && ip != gateway);
        if !unusable && !out.contains(&ip) && out.len() < MAX_DNS {
            out.push(ip);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];

    fn lease() -> Lease {
        Lease {
            server: [10, 0, 0, 1],
            client: [10, 0, 0, 2],
            netmask: [255, 255, 255, 0],
            dns: vec![[8, 8, 8, 8], [1, 1, 1, 1]],
            lease_secs: 86400,
        }
    }

    fn request(message_type: u8, ciaddr: [u8; 4], options: &[(u8, &[u8])]) -> Vec<u8> {
        let mut m = vec![0u8; OPTIONS];
        m[..3].copy_from_slice(&[BOOTREQUEST, HTYPE_ETHERNET, HLEN_ETHERNET]);
        m[4..8].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        m[12..16].copy_from_slice(&ciaddr);
        m[28..34].copy_from_slice(&MAC);
        m[236..OPTIONS].copy_from_slice(&MAGIC_COOKIE);
        push_option(&mut m, OPT_MESSAGE_TYPE, &[message_type]);
        m.push(OPT_PAD);
        for (code, data) in options {
            push_option(&mut m, *code, data);
        }
        m.push(OPT_END);
        m
    }

    /// A decoded reply.
    struct Answer {
        to: Destination,
        yiaddr: [u8; 4],
        opts: HashMap<u8, Vec<u8>>,
    }

    /// Run `req` and decode the reply.
    fn exchange(req: &[u8]) -> Option<Answer> {
        let mut out = Vec::new();
        let to = reply(req, &lease(), &mut out)?;
        assert!(out.len() >= MIN_REPLY);
        assert_eq!(out[0], BOOTREPLY);
        assert_eq!(out[4..8], [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(out[28..34], MAC);
        let mut opts = HashMap::new();
        let mut rest = &out[OPTIONS..];
        while let [code, len, tail @ ..] = rest {
            if *code == OPT_END {
                break;
            }
            opts.insert(*code, tail[..*len as usize].to_vec());
            rest = &tail[*len as usize..];
        }
        Some(Answer {
            to,
            yiaddr: [out[16], out[17], out[18], out[19]],
            opts,
        })
    }

    fn broadcast() -> Destination {
        Destination {
            ip: BROADCAST_IP,
            mac: BROADCAST_MAC,
        }
    }

    #[test]
    fn discover_then_request_gets_the_lease() {
        let offer = exchange(&request(DISCOVER, [0; 4], &[])).unwrap();
        assert_eq!(offer.to, broadcast());
        assert_eq!(offer.yiaddr, [10, 0, 0, 2]);
        assert_eq!(offer.opts[&OPT_MESSAGE_TYPE], [OFFER]);
        assert_eq!(offer.opts[&OPT_SERVER_ID], [10, 0, 0, 1]);
        assert_eq!(offer.opts[&OPT_ROUTER], [10, 0, 0, 1]);
        assert_eq!(offer.opts[&OPT_SUBNET_MASK], [255, 255, 255, 0]);
        assert_eq!(offer.opts[&OPT_DNS], [8, 8, 8, 8, 1, 1, 1, 1]);
        assert_eq!(offer.opts[&OPT_LEASE_TIME], 86400u32.to_be_bytes());

        let req = request(
            REQUEST,
            [0; 4],
            &[
                (OPT_REQUESTED_IP, &[10, 0, 0, 2]),
                (OPT_SERVER_ID, &[10, 0, 0, 1]),
            ],
        );
        let ack = exchange(&req).unwrap();
        assert_eq!((ack.to, ack.yiaddr), (broadcast(), [10, 0, 0, 2]));
        assert_eq!(ack.opts[&OPT_MESSAGE_TYPE], [ACK]);
    }

    #[test]
    fn renew_inform_nak_and_ignored_messages() {
        // Renewing: the client has the address, so the ACK is unicast.
        let renew = exchange(&request(REQUEST, [10, 0, 0, 2], &[])).unwrap();
        assert_eq!(
            renew.to,
            Destination {
                ip: [10, 0, 0, 2],
                mac: MAC
            }
        );
        assert_eq!(renew.opts[&OPT_MESSAGE_TYPE], [ACK]);
        // A remembered address from another network is refused.
        let req = request(REQUEST, [0; 4], &[(OPT_REQUESTED_IP, &[192, 168, 1, 7])]);
        let nak = exchange(&req).unwrap();
        assert_eq!((nak.to, nak.yiaddr), (broadcast(), [0; 4]));
        assert_eq!(nak.opts[&OPT_MESSAGE_TYPE], [NAK]);
        assert!(!nak.opts.contains_key(&OPT_ROUTER));
        // INFORM: configuration but no address or lease.
        let inform = exchange(&request(INFORM, [10, 0, 0, 2], &[])).unwrap();
        assert_eq!(inform.yiaddr, [0; 4]);
        assert!(inform.opts.contains_key(&OPT_DNS) && !inform.opts.contains_key(&OPT_LEASE_TIME));
        // No reply: another server chosen, RELEASE, or not a DHCP request.
        let other = request(REQUEST, [0; 4], &[(OPT_SERVER_ID, &[10, 0, 0, 9])]);
        assert!(exchange(&other).is_none());
        assert!(exchange(&request(7, [10, 0, 0, 2], &[])).is_none());
        let mut bootreply = request(DISCOVER, [0; 4], &[]);
        bootreply[0] = BOOTREPLY;
        assert!(exchange(&bootreply).is_none());
        assert!(exchange(&request(DISCOVER, [0; 4], &[])[..239]).is_none());
    }

    #[test]
    fn only_reachable_host_dns_servers_are_offered() {
        let host = [
            [127, 0, 0, 53],
            [169, 254, 1, 1],
            [10, 0, 0, 7],
            [8, 8, 8, 8],
            [8, 8, 8, 8],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            [9, 9, 9, 9],
        ];
        assert_eq!(
            usable_dns(&host, [10, 0, 0, 1], [255, 255, 255, 0]),
            [[8, 8, 8, 8], [10, 0, 0, 1], [1, 1, 1, 1]]
        );
        // A resolver on the host's 127.0.0.1 is reached at the gateway.
        assert_eq!(
            usable_dns(
                &[[127, 0, 0, 1], [8, 8, 8, 8]],
                [10, 0, 0, 1],
                [255, 255, 255, 0]
            ),
            [[10, 0, 0, 1], [8, 8, 8, 8]]
        );
    }
}
