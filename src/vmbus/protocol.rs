//! Wire formats of the VMBus channel-management protocol, as Linux's
//! `include/linux/hyperv.h` defines them: the messages the guest posts with
//! HvPostMessage and the ones the host posts back to its SynIC message page.
//! Every message starts with an 8-byte header holding its type.

use crate::whp::synic::MESSAGE_SIZE;

/// The SINT the guest takes VMBus messages and channel interrupts on.
pub const SINT: u8 = 2;
/// The connections the guest posts messages to: 1 before protocol 5.0, then 4
/// for the first message and whatever the version response names after it.
pub const MESSAGE_CONNECTION_ID: u32 = 1;
pub const MESSAGE_CONNECTION_ID_4: u32 = 4;
/// The SynIC message type of VMBus messages.
pub const MESSAGE_TYPE_CHANNEL: u32 = 1;
/// The most an `HV_MESSAGE` carries after its 16-byte header.
pub const MAX_PAYLOAD: usize = 240;
const HEADER_LEN: usize = 16;

pub const fn version(major: u16, minor: u16) -> u32 {
    (major as u32) << 16 | minor as u32
}

/// The protocol versions tinyvmm speaks: Windows 10's 5.x, through 5.3 (what
/// Windows 11 gives WSL). 6.0 adds only confidential channels.
pub const VERSION_5_0: u32 = version(5, 0);
pub const VERSION_5_3: u32 = version(5, 3);

pub const OFFERCHANNEL: u32 = 1;
pub const REQUESTOFFERS: u32 = 3;
pub const ALLOFFERS_DELIVERED: u32 = 4;
pub const OPENCHANNEL: u32 = 5;
pub const OPENCHANNEL_RESULT: u32 = 6;
pub const CLOSECHANNEL: u32 = 7;
pub const GPADL_HEADER: u32 = 8;
pub const GPADL_BODY: u32 = 9;
pub const GPADL_CREATED: u32 = 10;
pub const GPADL_TEARDOWN: u32 = 11;
pub const GPADL_TORNDOWN: u32 = 12;
pub const INITIATE_CONTACT: u32 = 14;
pub const VERSION_RESPONSE: u32 = 15;
pub const UNLOAD: u32 = 16;
pub const UNLOAD_RESPONSE: u32 = 17;
pub const MODIFYCHANNEL: u32 = 22;
pub const MODIFYCHANNEL_RESPONSE: u32 = 24;

/// Where the GPADL header's first PFN sits: after the message header, the
/// child relid, the GPADL handle, range_buflen, rangecount, and the range's
/// byte count and offset. Linux fits 26 PFNs there, and 28 in each body.
pub const GPADL_HEADER_PFNS: usize = 28;
/// Where a GPADL body's PFNs start: after the message header, msgnumber and
/// the GPADL handle.
pub const GPADL_BODY_PFNS: usize = 16;

/// An offer's `chn_flags` bit for a named pipe, and the message-mode pipe
/// type in its user-defined bytes: how integration components are offered.
const CHANNEL_NAMED_PIPE_MODE: u16 = 0x10;
const PIPE_TYPE_MESSAGE: u32 = 4;

/// A Windows GUID in its in-memory layout (`guid_t`, `GUID_INIT`).
pub const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5],
        d4[6], d4[7],
    ]
}

pub fn u16_at(p: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(p.get(off..off + 2)?.try_into().ok()?))
}

pub fn u32_at(p: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(p.get(off..off + 4)?.try_into().ok()?))
}

pub fn u64_at(p: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(p.get(off..off + 8)?.try_into().ok()?))
}

/// An `HV_MESSAGE` carrying the VMBus message `msgtype` with `body` after its
/// header.
pub fn message(msgtype: u32, body: &[u8]) -> [u8; MESSAGE_SIZE] {
    let payload_len = 8 + body.len();
    assert!(payload_len <= MAX_PAYLOAD);
    let mut m = [0u8; MESSAGE_SIZE];
    m[0..4].copy_from_slice(&MESSAGE_TYPE_CHANNEL.to_le_bytes());
    m[4] = payload_len as u8;
    m[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&msgtype.to_le_bytes());
    m[HEADER_LEN + 8..HEADER_LEN + payload_len].copy_from_slice(body);
    m
}

fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// `VERSION_RESPONSE`: whether the version is supported, the connection state
/// (0: connected) and the connection to post later messages to.
pub fn version_response(supported: bool) -> [u8; MESSAGE_SIZE] {
    let mut body = vec![u8::from(supported), 0, 0, 0];
    body.extend(MESSAGE_CONNECTION_ID.to_le_bytes());
    message(VERSION_RESPONSE, &body)
}

/// The fields of an `OFFERCHANNEL` the host chooses.
pub struct Offer {
    pub interface: [u8; 16],
    pub instance: [u8; 16],
    pub relid: u32,
    pub connection_id: u32,
}

/// `OFFERCHANNEL` (`vmbus_channel_offer_channel`) for a message-mode pipe with
/// no monitor page and no dedicated interrupt.
pub fn offer(o: &Offer) -> [u8; MESSAGE_SIZE] {
    let mut body = [0u8; 188];
    body[0..16].copy_from_slice(&o.interface);
    body[16..32].copy_from_slice(&o.instance);
    // reserved1, reserved2 (32..48) stay 0.
    body[48..50].copy_from_slice(&CHANNEL_NAMED_PIPE_MODE.to_le_bytes());
    // mmio_megabytes (50..52) stays 0; the pipe's user-defined bytes follow.
    body[52..56].copy_from_slice(&PIPE_TYPE_MESSAGE.to_le_bytes());
    // sub_channel_index, reserved3 (172..176) stay 0.
    body[176..180].copy_from_slice(&o.relid.to_le_bytes());
    // monitorid, monitor_allocated, is_dedicated_interrupt (180..184) stay 0.
    body[184..188].copy_from_slice(&o.connection_id.to_le_bytes());
    message(OFFERCHANNEL, &body)
}

pub fn all_offers_delivered() -> [u8; MESSAGE_SIZE] {
    message(ALLOFFERS_DELIVERED, &[])
}

/// `GPADL_CREATED`; Linux takes any nonzero status as a failure.
pub fn gpadl_created(relid: u32, gpadl: u32, ok: bool) -> [u8; MESSAGE_SIZE] {
    message(GPADL_CREATED, &words(&[relid, gpadl, u32::from(!ok)]))
}

pub fn gpadl_torndown(gpadl: u32) -> [u8; MESSAGE_SIZE] {
    message(GPADL_TORNDOWN, &words(&[gpadl]))
}

pub fn open_result(relid: u32, openid: u32, ok: bool) -> [u8; MESSAGE_SIZE] {
    message(OPENCHANNEL_RESULT, &words(&[relid, openid, u32::from(!ok)]))
}

pub fn modify_channel_response(relid: u32, ok: bool) -> [u8; MESSAGE_SIZE] {
    message(MODIFYCHANNEL_RESPONSE, &words(&[relid, u32::from(!ok)]))
}

pub fn unload_response() -> [u8; MESSAGE_SIZE] {
    message(UNLOAD_RESPONSE, &[])
}

/// Up to `max` of the PFNs a GPADL message carries from byte `at` on.
pub fn pfns(payload: &[u8], at: usize, max: usize) -> Vec<u64> {
    let n = (payload.len().saturating_sub(at) / 8).min(max);
    (0..n).filter_map(|i| u64_at(payload, at + 8 * i)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_lay_out_like_guid_init() {
        // HV_TS_GUID: GUID_INIT(0x9527e630, 0xd0ae, 0x497b, ad ce e8 0a b0 17 5c af)
        assert_eq!(
            guid(
                0x9527e630,
                0xd0ae,
                0x497b,
                [0xad, 0xce, 0xe8, 0x0a, 0xb0, 0x17, 0x5c, 0xaf]
            ),
            [
                0x30, 0xe6, 0x27, 0x95, 0xae, 0xd0, 0x7b, 0x49, 0xad, 0xce, 0xe8, 0x0a, 0xb0, 0x17,
                0x5c, 0xaf
            ]
        );
    }

    #[test]
    fn messages_carry_their_exact_struct_size() {
        // Linux drops a message shorter than its struct (channel_message_table's
        // min_payload_len), so payload_size must be each struct's sizeof.
        let o = offer(&Offer {
            interface: [1; 16],
            instance: [2; 16],
            relid: 7,
            connection_id: 0x2007,
        });
        assert_eq!(u32_at(&o, 0), Some(MESSAGE_TYPE_CHANNEL));
        assert_eq!(o[4], 196, "sizeof(vmbus_channel_offer_channel)");
        let body = &o[HEADER_LEN + 8..];
        assert_eq!(u32_at(&o, HEADER_LEN), Some(OFFERCHANNEL));
        assert_eq!(&body[0..16], &[1; 16]);
        assert_eq!(&body[16..32], &[2; 16]);
        assert_eq!(u16_at(body, 48), Some(0x10), "named pipe");
        assert_eq!(u32_at(body, 52), Some(4), "message mode");
        assert_eq!(u32_at(body, 176), Some(7), "child_relid");
        assert_eq!(
            &body[180..184],
            &[0; 4],
            "no monitor, no dedicated interrupt"
        );
        assert_eq!(u32_at(body, 184), Some(0x2007), "connection_id");

        assert_eq!(version_response(true)[4], 16);
        assert_eq!(gpadl_created(1, 2, true)[4], 20);
        assert_eq!(open_result(1, 1, true)[4], 20);
        assert_eq!(gpadl_torndown(2)[4], 12);
        assert_eq!(modify_channel_response(1, true)[4], 16);
        assert_eq!(all_offers_delivered()[4], 8);
        assert_eq!(unload_response()[4], 8);
    }

    #[test]
    fn statuses_are_zero_on_success() {
        let ok = version_response(true);
        assert_eq!(ok[HEADER_LEN + 8], 1, "version_supported");
        assert_eq!(u32_at(&ok, HEADER_LEN + 12), Some(MESSAGE_CONNECTION_ID));
        assert_eq!(version_response(false)[HEADER_LEN + 8], 0);
        assert_eq!(u32_at(&gpadl_created(1, 2, true), HEADER_LEN + 16), Some(0));
        assert_ne!(
            u32_at(&gpadl_created(1, 2, false), HEADER_LEN + 16),
            Some(0)
        );
        assert_eq!(u32_at(&open_result(1, 9, true), HEADER_LEN + 12), Some(9));
        assert_ne!(u32_at(&open_result(1, 9, false), HEADER_LEN + 16), Some(0));
    }
}
