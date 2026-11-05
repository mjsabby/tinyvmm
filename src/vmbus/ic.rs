//! Hyper-V integration components (ICs; Linux's `hv_utils`): small services
//! offered as message-mode VMBus pipes. A message is a pipe header, an IC
//! header and a body. Every exchange is a transaction the host starts and the
//! guest answers in place, flipping the request flag to a response; the first
//! one negotiates the framework and message versions.

use super::protocol::{u16_at, u32_at};

/// A version: major, minor.
pub type Version = (u16, u16);
/// The framework version; Linux takes 3.0 or 1.0 and prefers 3.0.
pub const FRAMEWORK: Version = (3, 0);
pub const TYPE_NEGOTIATE: u16 = 0;
pub const TYPE_TIMESYNC: u16 = 4;
const FLAG_TRANSACTION: u8 = 1;
const FLAG_REQUEST: u8 = 2;
const FLAG_RESPONSE: u8 = 4;
/// The pipe header's packet type for data.
const PIPE_DATA: u32 = 1;
const PIPE_HEADER_LEN: usize = 8;
const HEADER_LEN: usize = 20;
/// Where the body starts.
pub const BODY: usize = PIPE_HEADER_LEN + HEADER_LEN;

fn put_version(m: &mut Vec<u8>, (major, minor): Version) {
    m.extend(major.to_le_bytes());
    m.extend(minor.to_le_bytes());
}

/// A request of type `kind` at `versions` (framework, message) with `body`.
pub fn request(kind: u16, versions: (Version, Version), body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(BODY + body.len());
    m.extend(PIPE_DATA.to_le_bytes());
    m.extend(((HEADER_LEN + body.len()) as u32).to_le_bytes());
    put_version(&mut m, versions.0);
    m.extend(kind.to_le_bytes());
    put_version(&mut m, versions.1);
    m.extend((body.len() as u16).to_le_bytes());
    m.extend(0u32.to_le_bytes()); // status
    m.push(0); // transaction ID
    m.push(FLAG_TRANSACTION | FLAG_REQUEST);
    m.extend([0, 0]);
    m.extend(body);
    m
}

/// The version negotiation request: [`FRAMEWORK`] and `versions` of the
/// service's own protocol.
pub fn negotiate(versions: &[Version]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(1u16.to_le_bytes()); // framework versions
    body.extend((versions.len() as u16).to_le_bytes());
    body.extend(0u32.to_le_bytes());
    put_version(&mut body, FRAMEWORK);
    for &v in versions {
        put_version(&mut body, v);
    }
    request(TYPE_NEGOTIATE, ((0, 0), (0, 0)), &body)
}

/// A response's message type and body; None for anything else.
pub fn response(packet: &[u8]) -> Option<(u16, &[u8])> {
    if u32_at(packet, 0)? != PIPE_DATA || packet.get(PIPE_HEADER_LEN + 17)? & FLAG_RESPONSE == 0 {
        return None;
    }
    let kind = u16_at(packet, PIPE_HEADER_LEN + 4)?;
    let size = usize::from(u16_at(packet, PIPE_HEADER_LEN + 10)?);
    let body = packet.get(BODY..)?;
    Some((kind, &body[..size.min(body.len())]))
}

/// The framework and service versions a negotiation response settled on, or
/// None if the guest takes none of those offered.
pub fn negotiated(body: &[u8]) -> Option<(Version, Version)> {
    if u16_at(body, 0)? != 1 || u16_at(body, 2)? != 1 {
        return None;
    }
    let version = |at| Some((u16_at(body, at)?, u16_at(body, at + 2)?));
    Some((version(8)?, version(12)?))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// What Linux's `vmbus_prep_negotiate_resp` does to a negotiation request
    /// it receives, for a guest taking `framework` and `service`: picks the
    /// versions in place and turns the request into a response.
    pub fn guest_answers(request: &mut [u8], framework: Version, service: Version) {
        let neg = BODY;
        let frameworks = usize::from(u16_at(request, neg).unwrap());
        let services = usize::from(u16_at(request, neg + 2).unwrap());
        let at = |i: usize| {
            (
                u16_at(request, neg + 8 + 4 * i),
                u16_at(request, neg + 10 + 4 * i),
            )
        };
        let has = |range: std::ops::Range<usize>, (major, minor): Version| {
            range
                .into_iter()
                .any(|i| at(i) == (Some(major), Some(minor)))
        };
        let found =
            has(0..frameworks, framework) && has(frameworks..frameworks + services, service);
        request[PIPE_HEADER_LEN + 10..PIPE_HEADER_LEN + 12].copy_from_slice(&16u16.to_le_bytes());
        let count = u16::from(found).to_le_bytes();
        request[neg..neg + 2].copy_from_slice(&count);
        request[neg + 2..neg + 4].copy_from_slice(&count);
        for (i, (major, minor)) in [framework, service].into_iter().enumerate() {
            let v = neg + 8 + 4 * i;
            request[v..v + 2].copy_from_slice(&major.to_le_bytes());
            request[v + 2..v + 4].copy_from_slice(&minor.to_le_bytes());
        }
        request[PIPE_HEADER_LEN + 17] = FLAG_TRANSACTION | FLAG_RESPONSE;
    }

    #[test]
    fn a_negotiation_settles_on_the_versions_both_sides_take() {
        let mut m = negotiate(&[(4, 0)]);
        assert_eq!(response(&m), None, "a request isn't a response");
        guest_answers(&mut m, (3, 0), (4, 0));
        let (kind, body) = response(&m).unwrap();
        assert_eq!(kind, TYPE_NEGOTIATE);
        assert_eq!(negotiated(body), Some(((3, 0), (4, 0))));

        let mut m = negotiate(&[(4, 0)]);
        guest_answers(&mut m, (3, 0), (3, 0));
        assert_eq!(negotiated(response(&m).unwrap().1), None);
    }

    #[test]
    fn requests_carry_their_header_fields() {
        let m = request(TYPE_TIMESYNC, ((3, 0), (4, 0)), &[0xAA; 24]);
        assert_eq!(m.len(), BODY + 24);
        assert_eq!(u32_at(&m, 0), Some(PIPE_DATA));
        assert_eq!(
            u32_at(&m, 4),
            Some(20 + 24),
            "pipe payload: IC header + body"
        );
        assert_eq!(u16_at(&m, 8), Some(3), "framework major");
        assert_eq!(u16_at(&m, 12), Some(TYPE_TIMESYNC));
        assert_eq!(u16_at(&m, 14), Some(4), "message major");
        assert_eq!(u16_at(&m, 18), Some(24), "icmsgsize");
        assert_eq!(m[25], FLAG_TRANSACTION | FLAG_REQUEST);
    }
}
