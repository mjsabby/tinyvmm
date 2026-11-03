//! Partition tables: GPT (behind its protective MBR), or MBR including the
//! logical partitions of an extended partition. A disk with neither is taken
//! to hold one filesystem on the whole disk. Reads are whole sectors.

use crate::convenience::ReadAt;
use crate::error::{Error, Result};

const SECTOR: u64 = 512;
const MBR_TABLE: usize = 446;
const MBR_SIGNATURE: [u8; 2] = [0x55, 0xAA];
const GPT_PROTECTIVE: u8 = 0xEE;
const MBR_EXTENDED: [u8; 3] = [0x05, 0x0F, 0x85];
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
/// Linux numbers logical partitions from 5.
const FIRST_LOGICAL: u32 = 5;
/// Caps on what a crafted table can make us read.
const MAX_GPT_ENTRIES: u64 = 4096;
const MAX_GPT_ENTRY_SIZE: u64 = 4096;
const MAX_LOGICAL: u32 = 128;

/// A partition's number, as Linux numbers it (0 for a whole-disk filesystem),
/// and its byte range on the disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partition {
    pub number: u32,
    pub start: u64,
    pub len: u64,
}

/// The partitions of a `disk_size`-byte disk, in table order. A partition
/// that runs past the end of the disk is cut short there, as Linux does.
pub fn partitions<R: ReadAt>(disk: &R, disk_size: u64) -> Result<Vec<Partition>> {
    let whole = vec![Partition {
        number: 0,
        start: 0,
        len: disk_size,
    }];
    let mut mbr = [0u8; SECTOR as usize];
    read(disk, 0, &mut mbr)?;
    if mbr[510..] != MBR_SIGNATURE {
        return Ok(whole);
    }
    let entries: Vec<_> = (0..4).map(|i| mbr_entry(&mbr, i)).collect();
    if entries.iter().any(|e| e.kind == GPT_PROTECTIVE) {
        return gpt(disk, disk_size);
    }
    let mut parts = Vec::new();
    for (slot, e) in (1..).zip(&entries) {
        if e.kind == 0 || e.sectors == 0 {
            continue;
        }
        if MBR_EXTENDED.contains(&e.kind) {
            logical(disk, disk_size, e.start, &mut parts)?;
        } else {
            push(&mut parts, disk_size, slot, e.start, e.sectors);
        }
    }
    // A boot sector's signature with no partitions behind it.
    Ok(if parts.is_empty() { whole } else { parts })
}

struct MbrEntry {
    kind: u8,
    start: u64,
    sectors: u64,
}

fn mbr_entry(sector: &[u8; SECTOR as usize], index: usize) -> MbrEntry {
    let e = &sector[MBR_TABLE + 16 * index..][..16];
    MbrEntry {
        kind: e[4],
        start: u64::from(u32::from_le_bytes([e[8], e[9], e[10], e[11]])),
        sectors: u64::from(u32::from_le_bytes([e[12], e[13], e[14], e[15]])),
    }
}

/// The chain of extended boot records from `first`: each holds one logical
/// partition (relative to itself) and a link to the next (relative to `first`).
fn logical<R: ReadAt>(
    disk: &R,
    disk_size: u64,
    first: u64,
    parts: &mut Vec<Partition>,
) -> Result<()> {
    let mut ebr = first;
    for number in FIRST_LOGICAL..FIRST_LOGICAL + MAX_LOGICAL {
        let mut sector = [0u8; SECTOR as usize];
        if ebr.checked_mul(SECTOR).is_none_or(|at| at >= disk_size) {
            break;
        }
        read(disk, ebr * SECTOR, &mut sector)?;
        if sector[510..] != MBR_SIGNATURE {
            break;
        }
        let part = mbr_entry(&sector, 0);
        if part.kind != 0 && part.sectors != 0 {
            push(parts, disk_size, number, ebr + part.start, part.sectors);
        }
        let next = mbr_entry(&sector, 1);
        if next.kind == 0 || next.start == 0 {
            break;
        }
        ebr = first + next.start;
    }
    Ok(())
}

fn gpt<R: ReadAt>(disk: &R, disk_size: u64) -> Result<Vec<Partition>> {
    let mut header = [0u8; SECTOR as usize];
    read(disk, SECTOR, &mut header)?;
    if &header[..8] != GPT_SIGNATURE {
        return Err(Error::msg("GPT: no header behind the protective MBR"));
    }
    let le64 = |at: usize| u64::from_le_bytes(header[at..at + 8].try_into().unwrap_or_default());
    let le32 = |at: usize| {
        u64::from(u32::from_le_bytes(
            header[at..at + 4].try_into().unwrap_or_default(),
        ))
    };
    let (table, count, size) = (le64(72), le32(80), le32(84));
    if count > MAX_GPT_ENTRIES || !(128..=MAX_GPT_ENTRY_SIZE).contains(&size) || size % 8 != 0 {
        return Err(Error::msg("GPT: bad partition entry array"));
    }
    let mut entries = vec![0u8; (count * size).next_multiple_of(SECTOR) as usize];
    let at = table
        .checked_mul(SECTOR)
        .filter(|at| {
            at.checked_add(entries.len() as u64)
                .is_some_and(|end| end <= disk_size)
        })
        .ok_or_else(|| Error::msg("GPT: partition entries lie past the end of the disk"))?;
    read(disk, at, &mut entries)?;
    let mut parts = Vec::new();
    for (number, e) in (1..).zip(entries.chunks_exact(size as usize).take(count as usize)) {
        // An all-zero type GUID marks an unused entry.
        if e[..16].iter().all(|&b| b == 0) {
            continue;
        }
        let first = u64::from_le_bytes(e[32..40].try_into().unwrap_or_default());
        let last = u64::from_le_bytes(e[40..48].try_into().unwrap_or_default());
        if last >= first {
            push(&mut parts, disk_size, number, first, last - first + 1);
        }
    }
    Ok(parts)
}

fn push(parts: &mut Vec<Partition>, disk_size: u64, number: u32, first: u64, sectors: u64) {
    let Some(start) = first.checked_mul(SECTOR).filter(|&start| start < disk_size) else {
        return;
    };
    let len = sectors.saturating_mul(SECTOR).min(disk_size - start);
    parts.push(Partition { number, start, len });
}

fn read<R: ReadAt>(disk: &R, offset: u64, buf: &mut [u8]) -> Result<()> {
    disk.read_exact_at(offset, buf)
        .map_err(|e| Error::msg(format!("partition table: read at 0x{offset:x}: {e}")))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A disk image of `size` bytes with a GPT holding `parts` (first sector,
    /// contents) as partitions 1, 2, ... in its 128-entry array at sector 2.
    pub(crate) fn gpt_disk(size: usize, parts: &[(u64, &[u8])]) -> Vec<u8> {
        let mut disk = vec![0u8; size];
        disk[MBR_TABLE + 4] = GPT_PROTECTIVE;
        disk[MBR_TABLE + 8] = 1;
        disk[MBR_TABLE + 12..MBR_TABLE + 16].copy_from_slice(&u32::MAX.to_le_bytes());
        disk[510..512].copy_from_slice(&MBR_SIGNATURE);
        let header = &mut disk[512..1024];
        header[..8].copy_from_slice(GPT_SIGNATURE);
        header[72..80].copy_from_slice(&2u64.to_le_bytes());
        header[80..84].copy_from_slice(&128u32.to_le_bytes());
        header[84..88].copy_from_slice(&128u32.to_le_bytes());
        for (i, &(first, data)) in parts.iter().enumerate() {
            let e = &mut disk[1024 + 128 * i..][..128];
            e[..16].copy_from_slice(&[0x0f; 16]);
            let last = first + (data.len() as u64).div_ceil(SECTOR) - 1;
            e[32..40].copy_from_slice(&first.to_le_bytes());
            e[40..48].copy_from_slice(&last.to_le_bytes());
            let at = (first * SECTOR) as usize;
            disk[at..at + data.len()].copy_from_slice(data);
        }
        disk
    }

    fn mbr_slot(sector: &mut [u8], index: usize, kind: u8, start: u32, sectors: u32) {
        let e = &mut sector[MBR_TABLE + 16 * index..][..16];
        e[4] = kind;
        e[8..12].copy_from_slice(&start.to_le_bytes());
        e[12..16].copy_from_slice(&sectors.to_le_bytes());
        sector[510..512].copy_from_slice(&MBR_SIGNATURE);
    }

    fn part(number: u32, first: u64, sectors: u64) -> Partition {
        Partition {
            number,
            start: first * SECTOR,
            len: sectors * SECTOR,
        }
    }

    #[test]
    fn reads_gpt_entries_in_order() {
        let disk = gpt_disk(1 << 20, &[(34, &[1; 7 * 512]), (64, &[2; 1984 * 512])]);
        let parts = partitions(&disk, disk.len() as u64).unwrap();
        assert_eq!(parts, [part(1, 34, 7), part(2, 64, 1984)]);
    }

    #[test]
    fn reads_mbr_primary_and_logical_partitions() {
        let mut disk = vec![0u8; 8 << 20];
        mbr_slot(&mut disk[..512], 0, 0x83, 2048, 100);
        mbr_slot(&mut disk[..512], 1, 0x05, 4096, 4000);
        // Two logical partitions: each EBR's partition is relative to the
        // EBR, its link relative to the extended partition.
        let ebr1 = 4096 * 512;
        mbr_slot(&mut disk[ebr1..ebr1 + 512], 0, 0x83, 63, 100);
        mbr_slot(&mut disk[ebr1..ebr1 + 512], 1, 0x05, 200, 300);
        let ebr2 = (4096 + 200) * 512;
        mbr_slot(&mut disk[ebr2..ebr2 + 512], 0, 0x82, 63, 50);
        let parts = partitions(&disk, disk.len() as u64).unwrap();
        assert_eq!(
            parts,
            [
                part(1, 2048, 100),
                part(5, 4096 + 63, 100),
                part(6, 4296 + 63, 50)
            ]
        );
    }

    #[test]
    fn takes_a_disk_without_a_table_whole_and_cuts_partitions_at_its_end() {
        let disk = vec![0u8; 1 << 20];
        assert_eq!(partitions(&disk, 1 << 20).unwrap(), [part(0, 0, 2048)]);
        let mut disk = vec![0u8; 1 << 20];
        mbr_slot(&mut disk[..512], 0, 0x83, 2000, 1000);
        mbr_slot(&mut disk[..512], 1, 0x83, 4000, 10);
        assert_eq!(partitions(&disk, 1 << 20).unwrap(), [part(1, 2000, 48)]);
        // A GPT whose entry array is malformed is an error, not a panic.
        let mut disk = gpt_disk(1 << 20, &[]);
        disk[512 + 84..512 + 88].copy_from_slice(&7u32.to_le_bytes());
        assert!(partitions(&disk, 1 << 20).is_err());
    }
}
