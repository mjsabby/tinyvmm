//! VMBus ring buffers (Linux's `drivers/hv/ring_buffer.c`) in guest memory. A
//! channel has two, both in the GPADL the guest opened it with: the guest
//! writes the first and reads the second. Each starts with a control page
//! holding the write and read indices (byte offsets into the data) and the
//! reader's interrupt mask; the data after it is a circular buffer of packets.
//! A packet is a 16-byte descriptor (type, payload offset and length in 8-byte
//! units, flags, transaction ID), the payload padded to 8 bytes, and an 8-byte
//! trailer the reader skips.
//!
//! The writer signals the reader only when the reader may be idle: its
//! interrupt mask is clear and it had read up to where the new packet starts.
//! tinyvmm doesn't do the optional flow control (`pending_send_sz`): it
//! drops a packet that doesn't fit, and reads the guest's packets as they come.

use crate::whp::GuestMemory;
use std::sync::atomic::{Ordering, fence};

const PAGE: u64 = 4096;
const WRITE_INDEX: u64 = 0;
const READ_INDEX: u64 = 4;
const INTERRUPT_MASK: u64 = 8;
const DESCRIPTOR_LEN: u64 = 16;
const TRAILER_LEN: u64 = 8;
/// `VM_PKT_DATA_INBAND`: a packet whose payload follows its descriptor.
pub const PACKET_INBAND: u16 = 6;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// An index or packet the guest wrote makes no sense, or a page isn't RAM.
    Corrupt,
    /// The packet doesn't fit.
    Full,
}

#[derive(Clone, Debug)]
pub struct Ring {
    /// The control page's GPA, then the data pages'.
    pages: Vec<u64>,
}

impl Ring {
    /// The ring in these pages (PFNs): a control page and at least one of data.
    pub fn new(pfns: &[u64]) -> Option<Self> {
        if pfns.len() < 2 || pfns.len() > 1 << 16 {
            return None;
        }
        let pages = pfns
            .iter()
            .map(|&pfn| pfn.checked_mul(PAGE))
            .collect::<Option<_>>()?;
        Some(Ring { pages })
    }

    fn size(&self) -> u64 {
        (self.pages.len() as u64 - 1) * PAGE
    }

    fn control(&self, field: u64) -> u64 {
        self.pages[0] + field
    }

    /// The write and read indices, which must lie in the data and be 8-byte
    /// aligned, as every packet is a multiple of 8 bytes.
    fn indices(&self, mem: &GuestMemory) -> Result<(u64, u64), Error> {
        let w = mem.load_acquire_u32(self.control(WRITE_INDEX));
        let r = mem.load_acquire_u32(self.control(READ_INDEX));
        let (Some(w), Some(r)) = (w, r) else {
            return Err(Error::Corrupt);
        };
        let (w, r) = (u64::from(w), u64::from(r));
        if w >= self.size() || r >= self.size() || w % 8 != 0 || r % 8 != 0 {
            return Err(Error::Corrupt);
        }
        Ok((w, r))
    }

    /// Copy between the data at offset `off` (wrapping at its end) and `len`
    /// bytes of a host buffer, a page at a time: `copy(gpa, at, n)` moves `n`
    /// bytes at buffer offset `at`.
    fn walk(
        &self,
        mut off: u64,
        len: usize,
        mut copy: impl FnMut(u64, usize, usize) -> bool,
    ) -> bool {
        let mut done = 0;
        while done < len {
            let in_page = off % PAGE;
            let n = ((PAGE - in_page) as usize).min(len - done);
            if !copy(self.pages[1 + (off / PAGE) as usize] + in_page, done, n) {
                return false;
            }
            done += n;
            off = (off + n as u64) % self.size();
        }
        true
    }

    /// Read the next packet from a ring the guest writes: its type, with its
    /// payload (at most `max` bytes) in `buf`. None if the ring is empty.
    pub fn read(
        &self,
        mem: &GuestMemory,
        buf: &mut Vec<u8>,
        max: usize,
    ) -> Result<Option<u16>, Error> {
        let (w, r) = self.indices(mem)?;
        if w == r {
            return Ok(None);
        }
        let available = (w + self.size() - r) % self.size();
        let mut d = [0u8; DESCRIPTOR_LEN as usize];
        if !self.walk(r, d.len(), |gpa, at, n| {
            mem.read_into(gpa, &mut d[at..at + n])
        }) {
            return Err(Error::Corrupt);
        }
        let kind = u16::from_le_bytes([d[0], d[1]]);
        let offset = u64::from(u16::from_le_bytes([d[2], d[3]])) * 8;
        let len = u64::from(u16::from_le_bytes([d[4], d[5]])) * 8;
        if offset < DESCRIPTOR_LEN || len < offset || len + TRAILER_LEN > available {
            return Err(Error::Corrupt);
        }
        let payload = (len - offset) as usize;
        if payload > max {
            return Err(Error::Corrupt);
        }
        buf.resize(payload, 0);
        let start = (r + offset) % self.size();
        if !self.walk(start, payload, |gpa, at, n| {
            mem.read_into(gpa, &mut buf[at..at + n])
        }) {
            return Err(Error::Corrupt);
        }
        let next = (r + len + TRAILER_LEN) % self.size();
        if !mem.store_release_u32(self.control(READ_INDEX), next as u32) {
            return Err(Error::Corrupt);
        }
        Ok(Some(kind))
    }

    /// Write `payload` as an in-band packet to a ring the guest reads. Returns
    /// whether the guest needs a signal to notice it.
    pub fn write(&self, mem: &GuestMemory, payload: &[u8]) -> Result<bool, Error> {
        let (w, r) = self.indices(mem)?;
        let len = DESCRIPTOR_LEN + (payload.len() as u64).next_multiple_of(8);
        let total = len + TRAILER_LEN;
        // Strictly less than the free space: a full ring would look empty.
        let free = self.size() - (w + self.size() - r) % self.size();
        if len / 8 > u64::from(u16::MAX) || total >= free {
            return Err(Error::Full);
        }
        let mut packet = Vec::with_capacity(total as usize);
        packet.extend(PACKET_INBAND.to_le_bytes());
        packet.extend(((DESCRIPTOR_LEN / 8) as u16).to_le_bytes());
        packet.extend(((len / 8) as u16).to_le_bytes());
        packet.extend([0u8; 10]); // flags, transaction ID
        packet.extend(payload);
        packet.resize(len as usize, 0);
        packet.extend((w << 32).to_le_bytes());
        if !self.walk(w, packet.len(), |gpa, at, n| {
            mem.write_bytes(gpa, &packet[at..at + n])
        }) {
            return Err(Error::Corrupt);
        }
        let next = (w + total) % self.size();
        if !mem.store_release_u32(self.control(WRITE_INDEX), next as u32) {
            return Err(Error::Corrupt);
        }
        // Publish the index before looking at the reader's state, as Linux's
        // writer does (hv_signal_on_write), so a reader going idle either sees
        // the packet or is signaled.
        fence(Ordering::SeqCst);
        let mask = mem
            .load_acquire_u32(self.control(INTERRUPT_MASK))
            .ok_or(Error::Corrupt)?;
        let read = mem
            .load_acquire_u32(self.control(READ_INDEX))
            .ok_or(Error::Corrupt)?;
        Ok(mask == 0 && u64::from(read) == w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guest memory with a ring at PFN 1 whose data pages are PFNs 4 and 2:
    /// the data is in pages that aren't adjacent, nor in order.
    fn ring() -> (GuestMemory, Ring) {
        (
            GuestMemory::new_host_only(8 * 4096).unwrap(),
            Ring::new(&[1, 4, 2]).unwrap(),
        )
    }

    fn set(mem: &GuestMemory, field: u64, v: u32) {
        assert!(mem.store_release_u32(4096 + field, v));
    }

    #[test]
    fn packets_round_trip_across_page_breaks_and_the_wrap() {
        let (mem, ring) = ring();
        // Start 24 bytes before the end of the data, so a 64-byte packet
        // wraps to its start.
        set(&mem, WRITE_INDEX, 8192 - 24);
        set(&mem, READ_INDEX, 8192 - 24);
        let mut buf = Vec::new();
        for payload in [&b"0123456789abcdef0123456789abcdef!"[..], b"x", b""] {
            ring.write(&mem, payload).unwrap();
            assert_eq!(ring.read(&mem, &mut buf, 64), Ok(Some(PACKET_INBAND)));
            // The reader gets the payload padded to 8 bytes.
            assert_eq!(&buf[..payload.len()], payload);
            assert_eq!(buf.len(), payload.len().next_multiple_of(8));
        }
        assert_eq!(ring.read(&mem, &mut buf, 64), Ok(None));
        // The first packet's start landed on the last data page (PFN 2): its
        // descriptor and the payload's first 8 bytes; the rest wrapped to the
        // first (PFN 4).
        assert_eq!(mem.read_u16(2 * 4096 + 4096 - 24), Some(PACKET_INBAND));
        assert_eq!(&mem.read_array::<4>(4 * 4096).unwrap(), b"89ab");
    }

    #[test]
    fn the_guest_is_signaled_only_when_it_may_be_idle() {
        let (mem, ring) = ring();
        assert_eq!(
            ring.write(&mem, b"first"),
            Ok(true),
            "the reader was caught up"
        );
        assert_eq!(
            ring.write(&mem, b"second"),
            Ok(false),
            "it has yet to read the first"
        );
        let mut buf = Vec::new();
        while ring.read(&mem, &mut buf, 64).unwrap().is_some() {}
        set(&mem, INTERRUPT_MASK, 1);
        assert_eq!(ring.write(&mem, b"third"), Ok(false), "it is polling");
    }

    #[test]
    fn a_full_ring_refuses_a_packet() {
        let (mem, ring) = ring();
        let payload = [7u8; 1000]; // 1024-byte packets
        let written = std::iter::from_fn(|| ring.write(&mem, &payload).ok()).count();
        // 8 KiB of data holds 7: an 8th would fill it, which reads as empty.
        assert_eq!(written, 7);
        assert_eq!(ring.write(&mem, &payload), Err(Error::Full));
    }

    #[test]
    fn nonsense_from_the_guest_is_corrupt() {
        let (mem, ring) = ring();
        let mut buf = Vec::new();
        set(&mem, WRITE_INDEX, 8192);
        assert_eq!(
            ring.read(&mem, &mut buf, 64),
            Err(Error::Corrupt),
            "index past the data"
        );
        set(&mem, WRITE_INDEX, 12);
        assert_eq!(
            ring.read(&mem, &mut buf, 64),
            Err(Error::Corrupt),
            "unaligned index"
        );
        // A 16-byte packet whose descriptor claims 64 bytes.
        set(&mem, WRITE_INDEX, 24);
        assert!(mem.write_bytes(4 * 4096, &[6, 0, 2, 0, 8, 0]));
        assert_eq!(ring.read(&mem, &mut buf, 64), Err(Error::Corrupt));
        // A payload offset inside the descriptor.
        assert!(mem.write_bytes(4 * 4096, &[6, 0, 1, 0, 2, 0]));
        assert_eq!(ring.read(&mem, &mut buf, 64), Err(Error::Corrupt));
        // A 32-byte packet (16 of payload) is more than a caller taking 8 can.
        assert!(mem.write_bytes(4 * 4096, &[6, 0, 2, 0, 4, 0]));
        set(&mem, WRITE_INDEX, 40);
        assert_eq!(ring.read(&mem, &mut buf, 8), Err(Error::Corrupt));
        assert_eq!(ring.read(&mem, &mut buf, 16), Ok(Some(6)));
        assert_eq!(mem.read_u32(4096 + READ_INDEX), Some(40));
        assert!(Ring::new(&[1]).is_none(), "no data page");
        assert!(
            Ring::new(&[1, u64::MAX]).is_none(),
            "PFN beyond any address"
        );
    }
}
