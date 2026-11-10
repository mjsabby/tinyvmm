//! Read-only ext2/3/4 reader with just enough to read a file by path: group
//! descriptors (32- and 64-bit, `meta_bg`), inodes, extent trees and classic
//! block maps, directories (an htree directory scans the same way: its index
//! blocks look empty to a linear scan) and symlinks.
//!
//! A filesystem that wasn't cleanly unmounted can hold its newest metadata
//! only in its journal (as after a VM is killed rather than shut down), so the
//! journal's committed transactions are replayed in memory: a map from each
//! block they log to the journal block holding its newest copy, which reads
//! consult first. Reads then see what Linux sees after recovery. Every field
//! read from the image is bounds-checked; a malformed image yields an error,
//! not a panic. A guest may have written the image, so what it can make us
//! allocate or read is bounded too: files, paths and the journal have caps,
//! and a file's block map is held to the order Linux requires of it, in
//! which no part of the file is mapped twice.

use std::collections::{HashMap, HashSet};

use crate::convenience::ReadAt;
use crate::error::{Error, Result};

const SUPERBLOCK: u64 = 1024;
const MAGIC: u16 = 0xEF53;
const ROOT_INODE: u32 = 2;

const COMPAT_HAS_JOURNAL: u32 = 0x4;
const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_RECOVER: u32 = 0x4;
const INCOMPAT_META_BG: u32 = 0x10;
const INCOMPAT_EXTENTS: u32 = 0x40;
const INCOMPAT_64BIT: u32 = 0x80;
const INCOMPAT_MMP: u32 = 0x100;
const INCOMPAT_FLEX_BG: u32 = 0x200;
const INCOMPAT_EA_INODE: u32 = 0x400;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_LARGEDIR: u32 = 0x4000;
const INCOMPAT_INLINE_DATA: u32 = 0x8000;
const INCOMPAT_ENCRYPT: u32 = 0x1_0000;
const INCOMPAT_CASEFOLD: u32 = 0x2_0000;
/// Incompatible features this reader handles, or that don't change where a
/// file's bytes are. Inline data and encryption are refused file by file.
const INCOMPAT_SUPPORTED: u32 = INCOMPAT_FILETYPE
    | INCOMPAT_RECOVER
    | INCOMPAT_META_BG
    | INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_MMP
    | INCOMPAT_FLEX_BG
    | INCOMPAT_EA_INODE
    | INCOMPAT_CSUM_SEED
    | INCOMPAT_LARGEDIR
    | INCOMPAT_INLINE_DATA
    | INCOMPAT_ENCRYPT
    | INCOMPAT_CASEFOLD;
const RO_COMPAT_SPARSE_SUPER: u32 = 0x1;

const INODE_ENCRYPT: u32 = 0x800;
const INODE_EXTENTS: u32 = 0x8_0000;
const INODE_INLINE_DATA: u32 = 0x1000_0000;
const S_IFMT: u16 = 0xF000;
const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const S_IFLNK: u16 = 0xA000;
/// `i_block`: the block map, extent tree root, or fast symlink target.
const I_BLOCK: usize = 0x28;
const I_BLOCK_LEN: usize = 60;

const EXTENT_MAGIC: u16 = 0xF30A;
/// The longest initialized extent; a longer length marks an unwritten one.
const EXTENT_INIT_MAX: u16 = 32768;
const MAX_EXTENT_DEPTH: u16 = 5;
const MAX_SYMLINKS: usize = 40;
/// Caps on what a crafted image can make us allocate or walk.
const MAX_FILE_BYTES: u64 = 1 << 30;
const MAX_DIR_BYTES: u64 = 64 << 20;
const MAX_SYMLINK_BYTES: u64 = 4096;
const MAX_MAP_BLOCKS: usize = 1 << 16;
/// A path (Linux's `PATH_MAX`), and the names looked up along one, those of
/// its symlinks' targets included: each lookup reads a directory.
const MAX_PATH_BYTES: usize = 4096;
const MAX_LOOKUPS: usize = 256;
/// A journal: four times the largest mke2fs makes by default (2^18 blocks,
/// 1 GiB of 4 KiB ones). Its log is walked a block at a time.
const MAX_JOURNAL_BYTES: u64 = 4 << 30;
const MAX_JOURNAL_BLOCKS: u64 = 1 << 20;
/// The revoke records in a journal's log.
const MAX_REVOKES: usize = 4 << 20;
/// Contiguous blocks are read in pieces of at most this many bytes.
const READ_PIECE: usize = 4 << 20;

const JBD2_MAGIC: u32 = 0xC03B_3998;
const JBD2_DESCRIPTOR: u32 = 1;
const JBD2_COMMIT: u32 = 2;
const JBD2_SUPERBLOCK_V1: u32 = 3;
const JBD2_SUPERBLOCK_V2: u32 = 4;
const JBD2_REVOKE: u32 = 5;
const JBD2_64BIT: u32 = 0x2;
const JBD2_CSUM_V2: u32 = 0x8;
const JBD2_CSUM_V3: u32 = 0x10;
const JBD2_FAST_COMMIT: u32 = 0x20;
const JBD2_DEFAULT_FAST_COMMIT_BLOCKS: u64 = 256;
const JBD2_TAG_ESCAPE: u16 = 1;
const JBD2_TAG_SAME_UUID: u16 = 2;
const JBD2_TAG_LAST: u16 = 8;

/// What a path names, after following symlinks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Other,
}

pub struct Ext4<R: ReadAt> {
    src: R,
    block_size: u64,
    blocks_count: u64,
    first_data_block: u64,
    blocks_per_group: u64,
    inodes_count: u64,
    inodes_per_group: u64,
    inode_size: u64,
    desc_size: u64,
    first_meta_bg: u64,
    incompat: u32,
    ro_compat: u32,
    /// Blocks recovered from the journal: where each one's newest copy is.
    journal: HashMap<u64, JournalCopy>,
}

#[derive(Clone, Copy)]
struct JournalCopy {
    /// The filesystem block holding the copy.
    at: u64,
    /// The block began with the journal's magic number, logged as zeros.
    escaped: bool,
}

struct Inode {
    mode: u16,
    flags: u32,
    size: u64,
    block: [u8; I_BLOCK_LEN],
}

/// `len` blocks of a file from block `logical`, stored from block `physical`;
/// an unwritten run reads as zeros.
#[derive(Clone, Copy)]
struct Run {
    logical: u64,
    physical: u64,
    len: u64,
    unwritten: bool,
}

/// An extent tree as it is walked.
struct ExtentWalk {
    runs: Vec<Run>,
    /// The file's size in blocks: nothing is mapped from there on.
    blocks: u64,
    /// The first block the next entry may map: those before it are taken.
    next: u64,
    /// Index blocks that may still be read.
    budget: usize,
}

impl<R: ReadAt> Ext4<R> {
    /// Open the filesystem on `src`, replaying its journal if it needs
    /// recovery; `None` if `src` holds no ext2/3/4 filesystem.
    pub fn probe(src: R) -> Result<Option<Self>> {
        let mut sb = [0u8; 1024];
        read(&src, SUPERBLOCK, &mut sb)?;
        if le16(&sb, 0x38) != MAGIC {
            return Ok(None);
        }
        let incompat = le32(&sb, 0x60);
        let unsupported = incompat & !INCOMPAT_SUPPORTED;
        if unsupported != 0 {
            return Err(Error::msg(format!(
                "ext4: unsupported incompatible features 0x{unsupported:x}"
            )));
        }
        let log_block_size = le32(&sb, 0x18);
        if log_block_size > 6 {
            return Err(Error::msg("ext4: bad block size"));
        }
        let block_size = 1024u64 << log_block_size;
        let bit64 = incompat & INCOMPAT_64BIT != 0;
        let high = |at| {
            if bit64 {
                u64::from(le32(&sb, at)) << 32
            } else {
                0
            }
        };
        let inode_size = match le32(&sb, 0x4C) {
            0 => 128,
            _ => u64::from(le16(&sb, 0x58)),
        };
        let desc_size = if bit64 {
            u64::from(le16(&sb, 0xFE))
        } else {
            32
        };
        let mut fs = Ext4 {
            src,
            block_size,
            blocks_count: u64::from(le32(&sb, 0x4)) | high(0x150),
            first_data_block: u64::from(le32(&sb, 0x14)),
            blocks_per_group: u64::from(le32(&sb, 0x20)),
            inodes_count: u64::from(le32(&sb, 0x0)),
            inodes_per_group: u64::from(le32(&sb, 0x28)),
            inode_size,
            desc_size,
            first_meta_bg: u64::from(le32(&sb, 0x104)),
            incompat,
            ro_compat: le32(&sb, 0x64),
            journal: HashMap::new(),
        };
        // Inodes and descriptors must tile blocks: none straddles two.
        let tiles = |size: u64, min| size >= min && size.is_power_of_two() && size <= block_size;
        if fs.blocks_per_group == 0
            || fs.inodes_per_group == 0
            || fs.first_data_block >= fs.blocks_count
            || !tiles(inode_size, 128)
            || !tiles(desc_size, 32)
        {
            return Err(Error::msg("ext4: bad superblock"));
        }
        let journal_inode = le32(&sb, 0xE0);
        if incompat & INCOMPAT_RECOVER != 0
            && le32(&sb, 0x5C) & COMPAT_HAS_JOURNAL != 0
            && journal_inode != 0
        {
            fs.journal = fs.replay(journal_inode)?;
        }
        Ok(Some(fs))
    }

    /// How many blocks reads take from the journal instead of their home.
    pub fn journal_blocks(&self) -> usize {
        self.journal.len()
    }

    /// What `path` names, following symlinks; `None` if nothing.
    pub fn lookup(&self, path: &str) -> Result<Option<Kind>> {
        Ok(self.resolve(path)?.map(|inode| match inode.mode & S_IFMT {
            S_IFREG => Kind::File,
            S_IFDIR => Kind::Dir,
            _ => Kind::Other,
        }))
    }

    /// Read a whole regular file, following symlinks.
    #[cfg(test)]
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        self.read_file_capped(path, MAX_FILE_BYTES)
    }

    /// Read a whole regular file of at most `max` bytes, following symlinks.
    /// A larger one is an error before any of it is read (or allocated).
    pub fn read_file_capped(&self, path: &str, max: u64) -> Result<Vec<u8>> {
        let inode = self
            .resolve(path)?
            .filter(|inode| inode.mode & S_IFMT == S_IFREG)
            .ok_or_else(|| Error::msg(format!("ext4: no file {path}")))?;
        let max = max.min(MAX_FILE_BYTES);
        if inode.size > max {
            return Err(Error::msg(format!(
                "ext4: {path} is too large ({} bytes; at most {max} here)",
                inode.size
            )));
        }
        self.read_data(&inode, max)
    }

    /// The inode `path` names: each component is looked up in the directory
    /// before it, `..` steps back, and a symlink's target is spliced in.
    fn resolve(&self, path: &str) -> Result<Option<Inode>> {
        if path.len() > MAX_PATH_BYTES {
            return Err(Error::msg(format!(
                "ext4: a {}-byte path is too long",
                path.len()
            )));
        }
        let mut chain = vec![ROOT_INODE];
        let mut todo: Vec<Vec<u8>> = components(path.as_bytes());
        let (mut links, mut lookups) = (0, 0);
        while let Some(name) = todo.pop() {
            match name.as_slice() {
                b"" | b"." => continue,
                b".." => {
                    if chain.len() > 1 {
                        chain.pop();
                    }
                    continue;
                }
                _ => {}
            }
            lookups += 1;
            if lookups > MAX_LOOKUPS {
                return Err(Error::msg(format!(
                    "ext4: {path}: too many path components"
                )));
            }
            let dir = self.read_inode(chain[chain.len() - 1])?;
            if dir.mode & S_IFMT != S_IFDIR {
                return Ok(None);
            }
            let Some(number) = self.find(&dir, &name)? else {
                return Ok(None);
            };
            let inode = self.read_inode(number)?;
            if inode.mode & S_IFMT != S_IFLNK {
                chain.push(number);
                continue;
            }
            links += 1;
            if links > MAX_SYMLINKS {
                return Err(Error::msg(format!(
                    "ext4: {path}: too many levels of symbolic links"
                )));
            }
            let target = self.symlink_target(&inode)?;
            if target.first() == Some(&b'/') {
                chain.truncate(1);
            }
            todo.extend(components(&target));
        }
        self.read_inode(chain[chain.len() - 1]).map(Some)
    }

    /// The inode number `name` has in `dir`.
    fn find(&self, dir: &Inode, name: &[u8]) -> Result<Option<u32>> {
        let data = self.read_data(dir, MAX_DIR_BYTES)?;
        let wide_names = self.incompat & INCOMPAT_FILETYPE == 0;
        for block in data.chunks(self.block_size as usize) {
            let mut at = 0usize;
            while let Some(head) = block.get(at..at + 8) {
                let rec_len = match le16(head, 4) {
                    0 | 65535 if block.len() == 65536 => 65536,
                    n => usize::from(n),
                };
                let name_len = if wide_names {
                    usize::from(le16(head, 6))
                } else {
                    usize::from(head[6])
                };
                if rec_len < 8 || name_len + 8 > rec_len || at + rec_len > block.len() {
                    break;
                }
                let inode = le32(head, 0);
                if inode != 0 && block[at + 8..at + 8 + name_len] == *name {
                    return Ok(Some(inode));
                }
                at += rec_len;
            }
        }
        Ok(None)
    }

    fn symlink_target(&self, inode: &Inode) -> Result<Vec<u8>> {
        // A target shorter than `i_block` is stored there ("fast" symlink).
        if inode.size < I_BLOCK_LEN as u64 && inode.flags & (INODE_EXTENTS | INODE_INLINE_DATA) == 0
        {
            return Ok(inode.block[..inode.size as usize].to_vec());
        }
        self.read_data(inode, MAX_SYMLINK_BYTES)
    }

    fn read_inode(&self, number: u32) -> Result<Inode> {
        let index = u64::from(number)
            .checked_sub(1)
            .filter(|&index| index < self.inodes_count)
            .ok_or_else(|| Error::msg(format!("ext4: bad inode number {number}")))?;
        let table = self.inode_table(index / self.inodes_per_group)?;
        let byte = index % self.inodes_per_group * self.inode_size;
        let mut buf = vec![0u8; self.block_size as usize];
        self.read_block(table.saturating_add(byte / self.block_size), &mut buf)?;
        let raw = &buf[(byte % self.block_size) as usize..][..self.inode_size as usize];
        let mut block = [0u8; I_BLOCK_LEN];
        block.copy_from_slice(&raw[I_BLOCK..I_BLOCK + I_BLOCK_LEN]);
        Ok(Inode {
            mode: le16(raw, 0x0),
            flags: le32(raw, 0x20),
            size: u64::from(le32(raw, 0x4)) | u64::from(le32(raw, 0x6C)) << 32,
            block,
        })
    }

    /// The first block of `group`'s inode table, from its descriptor.
    fn inode_table(&self, group: u64) -> Result<u64> {
        let per_block = self.block_size / self.desc_size;
        let index = group / per_block;
        // With meta_bg, each run of `per_block` groups keeps its descriptors in
        // its first group, after that group's superblock backup if it has one.
        let block = if self.incompat & INCOMPAT_META_BG != 0 && index >= self.first_meta_bg {
            let first = index * per_block;
            first
                .saturating_mul(self.blocks_per_group)
                .saturating_add(self.first_data_block + u64::from(self.has_super(first)))
        } else {
            self.first_data_block + 1 + index
        };
        let mut buf = vec![0u8; self.block_size as usize];
        self.read_block(block, &mut buf)?;
        let desc = &buf[(group % per_block * self.desc_size) as usize..];
        let high = if self.incompat & INCOMPAT_64BIT != 0 && self.desc_size >= 64 {
            u64::from(le32(desc, 0x28)) << 32
        } else {
            0
        };
        Ok(high | u64::from(le32(desc, 0x8)))
    }

    /// Whether `group` starts with a superblock backup.
    fn has_super(&self, group: u64) -> bool {
        let power_of = |base: u64| {
            let mut n = group;
            while n.is_multiple_of(base) {
                n /= base;
            }
            n == 1
        };
        group <= 1
            || self.ro_compat & RO_COMPAT_SPARSE_SUPER == 0
            || [3, 5, 7].into_iter().any(power_of)
    }

    /// Where a file's blocks are, in file order: no two runs share a block
    /// of the file, and none starts past its end, so a file has no more runs
    /// than blocks and reading them reads no more than its size.
    fn runs(&self, inode: &Inode) -> Result<Vec<Run>> {
        if inode.flags & INODE_INLINE_DATA != 0 {
            return Err(Error::msg("ext4: inline data is not supported"));
        }
        let blocks = inode.size.div_ceil(self.block_size);
        if inode.flags & INODE_EXTENTS != 0 {
            let mut walk = ExtentWalk {
                runs: Vec::new(),
                blocks,
                next: 0,
                budget: MAX_MAP_BLOCKS,
            };
            self.extent_runs(&inode.block, None, &mut walk)?;
            return Ok(walk.runs);
        }
        let mut runs = Vec::new();
        let mut budget = MAX_MAP_BLOCKS;
        // Twelve direct blocks, then single, double and triple indirect ones.
        let pointer = |i: usize| le32(&inode.block, 4 * i);
        let mut logical = 0;
        for i in 0..12 {
            if logical < blocks {
                push_block(&mut runs, logical, pointer(i));
            }
            logical += 1;
        }
        for level in 1..=3 {
            let at = 11 + level as usize;
            self.indirect_runs(
                pointer(at),
                level,
                &mut logical,
                blocks,
                &mut runs,
                &mut budget,
            )?;
        }
        Ok(runs)
    }

    /// The runs below a node of an extent tree. A node's entries must be as
    /// Linux requires them (`ext4_valid_extent_entries`): in file order, no
    /// extent empty or overlapping the one before it, and a child's entries
    /// at or after the index entry that leads to them. However a crafted
    /// tree's blocks are linked, each run then maps blocks no other does.
    fn extent_runs(&self, node: &[u8], depth: Option<u16>, walk: &mut ExtentWalk) -> Result<()> {
        let bad = || Error::msg("ext4: bad extent tree");
        if node.len() < 12 || le16(node, 0) != EXTENT_MAGIC {
            return Err(bad());
        }
        let (entries, max) = (usize::from(le16(node, 2)), usize::from(le16(node, 4)));
        let here = le16(node, 6);
        if here > MAX_EXTENT_DEPTH || depth.is_some_and(|d| d != here) || entries > max {
            return Err(bad());
        }
        let body = node.get(12..12 + 12 * max).ok_or_else(bad)?;
        for e in &body.as_chunks::<12>().0[..entries] {
            let logical = u64::from(le32(e, 0));
            if logical < walk.next {
                return Err(bad());
            }
            // An entry past the end of the file (blocks preallocated there)
            // is held to the same order, but maps nothing and is not read.
            let mapped = logical < walk.blocks;
            if here == 0 {
                let (len, unwritten) = match le16(e, 4) {
                    len if len > EXTENT_INIT_MAX => (len - EXTENT_INIT_MAX, true),
                    len => (len, false),
                };
                if len == 0 {
                    return Err(bad());
                }
                if mapped {
                    walk.runs.push(Run {
                        logical,
                        physical: u64::from(le16(e, 6)) << 32 | u64::from(le32(e, 8)),
                        len: u64::from(len),
                        unwritten,
                    });
                }
                walk.next = logical + u64::from(len);
            } else {
                walk.next = logical;
                if mapped {
                    walk.budget = walk.budget.checked_sub(1).ok_or_else(bad)?;
                    let child = u64::from(le16(e, 8)) << 32 | u64::from(le32(e, 4));
                    let mut buf = vec![0u8; self.block_size as usize];
                    self.read_block(child, &mut buf)?;
                    self.extent_runs(&buf, Some(here - 1), walk)?;
                }
                // The next index entry leads to later blocks than this one.
                walk.next = walk.next.max(logical + 1);
            }
        }
        Ok(())
    }

    /// The blocks below an indirect block `level` steps above the data.
    fn indirect_runs(
        &self,
        block: u32,
        level: u32,
        logical: &mut u64,
        blocks: u64,
        runs: &mut Vec<Run>,
        budget: &mut usize,
    ) -> Result<()> {
        let per_block = self.block_size / 4;
        if *logical >= blocks {
            return Ok(());
        }
        if block == 0 {
            *logical += per_block.pow(level);
            return Ok(());
        }
        *budget = budget
            .checked_sub(1)
            .ok_or_else(|| Error::msg("ext4: block map too large"))?;
        let mut buf = vec![0u8; self.block_size as usize];
        self.read_block(u64::from(block), &mut buf)?;
        for pointer in buf.as_chunks::<4>().0 {
            if *logical >= blocks {
                break;
            }
            let pointer = u32::from_le_bytes(*pointer);
            if level == 1 {
                push_block(runs, *logical, pointer);
                *logical += 1;
            } else {
                self.indirect_runs(pointer, level - 1, logical, blocks, runs, budget)?;
            }
        }
        Ok(())
    }

    /// A file's bytes; holes and unwritten runs read as zeros.
    fn read_data(&self, inode: &Inode, cap: u64) -> Result<Vec<u8>> {
        if inode.flags & INODE_ENCRYPT != 0 {
            return Err(Error::msg("ext4: encrypted files are not supported"));
        }
        if inode.size > cap {
            return Err(Error::msg(format!(
                "ext4: a {}-byte file is too large",
                inode.size
            )));
        }
        let mut out = vec![0u8; inode.size as usize];
        for run in self.runs(inode)? {
            let bounds = run.logical.checked_mul(self.block_size).zip(
                run.logical
                    .checked_add(run.len)
                    .and_then(|end| end.checked_mul(self.block_size)),
            );
            let Some((start, end)) = bounds else {
                return Err(Error::msg("ext4: bad block run"));
            };
            if run.unwritten || start >= inode.size {
                continue;
            }
            let end = end.min(inode.size);
            self.read_run(run.physical, &mut out[start as usize..end as usize])?;
        }
        Ok(out)
    }

    /// Fill `dst` from consecutive blocks from `first`, its last one perhaps
    /// partly, then put in the journal's newer copies.
    fn read_run(&self, first: u64, dst: &mut [u8]) -> Result<()> {
        let block_size = self.block_size as usize;
        let whole = dst.len() / block_size * block_size;
        let mut block = first;
        for piece in dst[..whole].chunks_mut(READ_PIECE) {
            self.read_raw(block, piece)?;
            block += (piece.len() / block_size) as u64;
        }
        let mut buf = vec![0u8; block_size];
        if whole < dst.len() {
            self.read_raw(block, &mut buf)?;
            let tail = dst.len() - whole;
            dst[whole..].copy_from_slice(&buf[..tail]);
        }
        if !self.journal.is_empty() {
            for (block, piece) in (first..).zip(dst.chunks_mut(block_size)) {
                if self.journal.contains_key(&block) {
                    self.read_block(block, &mut buf)?;
                    let len = piece.len();
                    piece.copy_from_slice(&buf[..len]);
                }
            }
        }
        Ok(())
    }

    /// Read one block, from the journal if it holds a newer copy.
    fn read_block(&self, block: u64, buf: &mut [u8]) -> Result<()> {
        match self.journal.get(&block) {
            Some(copy) => {
                self.read_raw(copy.at, buf)?;
                if copy.escaped {
                    buf[..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
                }
                Ok(())
            }
            None => self.read_raw(block, buf),
        }
    }

    /// Read whole blocks from `block` as they are on the disk.
    fn read_raw(&self, block: u64, buf: &mut [u8]) -> Result<()> {
        let count = buf.len() as u64 / self.block_size;
        if block
            .checked_add(count)
            .is_none_or(|end| end > self.blocks_count)
        {
            return Err(Error::msg(format!("ext4: block {block} is past the end")));
        }
        read(&self.src, block * self.block_size, buf)
    }

    /// Recover the journal's committed transactions: for each block they log,
    /// where its newest copy is, unless a revoke record in the same or a later
    /// transaction cancels it (as jbd2's recovery does).
    fn replay(&self, journal_inode: u32) -> Result<HashMap<u64, JournalCopy>> {
        let bad = |what: &str| Error::msg(format!("ext4: bad journal ({what})"));
        let inode = self.read_inode(journal_inode)?;
        // A regular file, as Linux requires, and of a size that bounds its
        // block map and the walk of its log below. A larger journal isn't a
        // bad one, only more than is replayed here.
        if inode.mode & S_IFMT != S_IFREG {
            return Err(bad("not a regular file"));
        }
        let blocks = inode.size / self.block_size;
        if inode.size > MAX_JOURNAL_BYTES || blocks > MAX_JOURNAL_BLOCKS {
            return Err(Error::msg(format!(
                "ext4: a {}-byte journal is too large to replay",
                inode.size
            )));
        }
        let runs = self.runs(&inode)?;
        // The filesystem block holding journal block `n`: runs are in file
        // order, so the first that ends after `n` is the one that may hold it.
        let locate = |n: u64| {
            runs.get(runs.partition_point(|r| r.logical + r.len <= n))
                .filter(|r| !r.unwritten && n < blocks && r.logical <= n)
                .map(|r| r.physical + (n - r.logical))
                .ok_or_else(|| bad("unmapped block"))
        };
        let block_size = self.block_size as usize;
        let mut buf = vec![0u8; block_size];
        self.read_raw(locate(0)?, &mut buf)?;
        let kind = be32(&buf, 4);
        if be32(&buf, 0) != JBD2_MAGIC || !matches!(kind, JBD2_SUPERBLOCK_V1 | JBD2_SUPERBLOCK_V2) {
            return Err(bad("superblock"));
        }
        if u64::from(be32(&buf, 12)) != self.block_size {
            return Err(bad("block size"));
        }
        let (max_len, first) = (u64::from(be32(&buf, 16)), u64::from(be32(&buf, 20)));
        let mut sequence = be32(&buf, 24);
        let start = u64::from(be32(&buf, 28));
        if start == 0 {
            // Every transaction was checkpointed.
            return Ok(HashMap::new());
        }
        let features = if kind == JBD2_SUPERBLOCK_V2 {
            be32(&buf, 40)
        } else {
            0
        };
        // Fast commits keep their own area at the end of the log.
        let last = if features & JBD2_FAST_COMMIT != 0 {
            let area = match u64::from(be32(&buf, 0x54)) {
                0 => JBD2_DEFAULT_FAST_COMMIT_BLOCKS,
                n => n,
            };
            max_len.saturating_sub(area)
        } else {
            max_len
        };
        if first == 0 || last > blocks || !(first..last).contains(&start) {
            return Err(bad("log bounds"));
        }
        let tag_bytes = if features & JBD2_CSUM_V3 != 0 {
            16
        } else {
            let base = if features & JBD2_CSUM_V2 != 0 { 14 } else { 12 };
            if features & JBD2_64BIT != 0 {
                base
            } else {
                base - 4
            }
        };
        let tail = if features & (JBD2_CSUM_V2 | JBD2_CSUM_V3) != 0 {
            4
        } else {
            0
        };
        let next = |n: u64| if n + 1 == last { first } else { n + 1 };

        let mut logged: Vec<(u64, JournalCopy)> = Vec::new();
        let mut committed: Vec<(u32, u64, JournalCopy)> = Vec::new();
        // The blocks the open transaction revokes, and jbd2's revoke table:
        // the newest committed transaction to revoke each block. Both hold a
        // block once however many records name it.
        let mut revokes: HashSet<u64> = HashSet::new();
        let mut revoked: HashMap<u64, u32> = HashMap::new();
        let mut revoke_records = 0usize;
        let mut at = start;
        // The log is circular: visit each of its blocks at most once. A
        // logged block takes one of them, which bounds `logged` and
        // `committed` by the log's length.
        let mut budget = last - first;
        'log: while budget > 0 {
            budget -= 1;
            self.read_raw(locate(at)?, &mut buf)?;
            at = next(at);
            // The log ends at the first block that doesn't continue it.
            if be32(&buf, 0) != JBD2_MAGIC || be32(&buf, 8) != sequence {
                break;
            }
            match be32(&buf, 4) {
                JBD2_DESCRIPTOR => {
                    let mut tag_at = 12;
                    while tag_at + tag_bytes <= block_size - tail {
                        let tag = &buf[tag_at..tag_at + tag_bytes];
                        // Both tag layouts keep the flags' low half here.
                        let flags = be16(tag, 6);
                        let high = if features & JBD2_64BIT != 0 {
                            u64::from(be32(tag, 8)) << 32
                        } else {
                            0
                        };
                        tag_at += tag_bytes;
                        if flags & JBD2_TAG_SAME_UUID == 0 {
                            tag_at += 16;
                        }
                        if budget == 0 {
                            break 'log;
                        }
                        budget -= 1;
                        let copy = JournalCopy {
                            at: locate(at)?,
                            escaped: flags & JBD2_TAG_ESCAPE != 0,
                        };
                        logged.push((high | u64::from(be32(tag, 0)), copy));
                        at = next(at);
                        if flags & JBD2_TAG_LAST != 0 {
                            break;
                        }
                    }
                }
                JBD2_COMMIT => {
                    committed.extend(
                        logged
                            .drain(..)
                            .map(|(block, copy)| (sequence, block, copy)),
                    );
                    for block in revokes.drain() {
                        let newest = revoked.entry(block).or_insert(sequence);
                        if newer(sequence, *newest) {
                            *newest = sequence;
                        }
                    }
                    sequence = sequence.wrapping_add(1);
                }
                JBD2_REVOKE => {
                    let used = (be32(&buf, 12) as usize).min(block_size - tail);
                    let size = if features & JBD2_64BIT != 0 { 8 } else { 4 };
                    let mut record = 16;
                    while record + size <= used {
                        revoke_records += 1;
                        if revoke_records > MAX_REVOKES {
                            return Err(Error::msg(
                                "ext4: the journal has too many revoke records to replay",
                            ));
                        }
                        revokes.insert(if size == 8 {
                            be64(&buf, record)
                        } else {
                            u64::from(be32(&buf, record))
                        });
                        record += size;
                    }
                }
                _ => break,
            }
        }
        let mut copies = HashMap::new();
        for (sequence, block, copy) in committed {
            let cancelled = revoked.get(&block).is_some_and(|&r| !newer(sequence, r));
            if block < self.blocks_count && !cancelled {
                copies.insert(block, copy);
            }
        }
        Ok(copies)
    }
}

/// A path's components, last first (to pop them in order).
fn components(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|&c| c == b'/')
        .rev()
        .map(<[u8]>::to_vec)
        .collect()
}

/// Add a block-mapped file's block (0 is a hole) to its runs.
fn push_block(runs: &mut Vec<Run>, logical: u64, physical: u32) {
    if physical == 0 {
        return;
    }
    let physical = u64::from(physical);
    if let Some(last) = runs.last_mut()
        && last.logical + last.len == logical
        && last.physical + last.len == physical
    {
        last.len += 1;
        return;
    }
    runs.push(Run {
        logical,
        physical,
        len: 1,
        unwritten: false,
    });
}

/// Whether transaction `a` is newer than `b`; IDs wrap around.
fn newer(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

fn read<R: ReadAt>(src: &R, offset: u64, buf: &mut [u8]) -> Result<()> {
    src.read_exact_at(offset, buf)
        .map_err(|e| Error::msg(format!("ext4: read at 0x{offset:x}: {e}")))
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn be64(b: &[u8], at: usize) -> u64 {
    u64::from(be32(b, at)) << 32 | u64::from(be32(b, at + 4))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const INODE_SIZE: usize = 256;
    const FIRST_FREE_INODE: u32 = 11;
    const JOURNAL_INODE: u32 = 8;
    const DIR_TAIL: usize = 12;

    /// A directory tree for [`Image::new`].
    pub(crate) enum Node<'a> {
        Dir(&'a str, Vec<Node<'a>>),
        File(&'a str, &'a [u8]),
        /// A file whose blocks lie apart: a run (extent) per block.
        Scattered(&'a str, &'a [u8]),
        /// A file of this many hole blocks, then a block starting with the bytes.
        Sparse(&'a str, u64, &'a [u8]),
        /// A file whose one extent is unwritten over these (stale) bytes.
        Unwritten(&'a str, &'a [u8]),
        Link(&'a str, &'a str),
    }

    #[derive(Clone, Copy)]
    pub(crate) struct Layout {
        pub block_size: usize,
        pub blocks: u64,
        pub blocks_per_group: u64,
        pub inodes_per_group: u32,
        /// 64 turns on the 64bit feature.
        pub desc_size: usize,
        pub meta_bg: bool,
        /// Files are mapped by extent trees, else by classic block maps.
        pub extents: bool,
    }

    pub(crate) const SMALL: Layout = Layout {
        block_size: 1024,
        blocks: 4096,
        blocks_per_group: 8192,
        inodes_per_group: 512,
        desc_size: 32,
        meta_bg: false,
        extents: true,
    };

    /// A filesystem image laid out the way mke2fs lays one out, with
    /// checksum tails on directory blocks (but no checksums).
    pub(crate) struct Image {
        pub bytes: Vec<u8>,
        layout: Layout,
        used: Vec<bool>,
        next_block: u64,
        next_inode: u32,
        /// Each path's inode number, and each file's data blocks.
        pub inodes: HashMap<String, u32>,
        pub blocks: HashMap<String, Vec<u64>>,
    }

    /// A run of a file: (logical block, physical block, blocks, unwritten).
    type Extent = (u64, u64, u64, bool);

    /// A journal transaction: new contents for blocks, revoke records, and
    /// whether its commit block made it to the log.
    pub(crate) struct Tx {
        pub writes: Vec<(u64, Vec<u8>)>,
        pub revokes: Vec<u64>,
        pub commit: bool,
    }

    fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
        buf[at..at + bytes.len()].copy_from_slice(bytes);
    }

    pub(crate) fn pattern(len: usize, seed: u32) -> Vec<u8> {
        (0..len as u32)
            .map(|i| (i.wrapping_mul(2_654_435_761).wrapping_add(seed) >> 24) as u8)
            .collect()
    }

    impl Image {
        pub(crate) fn new(layout: Layout, tree: Vec<Node>) -> Image {
            let bs = layout.block_size;
            let first_data = u64::from(bs == 1024);
            let groups = (layout.blocks - first_data).div_ceil(layout.blocks_per_group);
            let mut img = Image {
                bytes: vec![0; layout.blocks as usize * bs],
                layout,
                used: vec![false; layout.blocks as usize],
                next_block: first_data + 1,
                next_inode: FIRST_FREE_INODE,
                inodes: HashMap::new(),
                blocks: HashMap::new(),
            };
            img.used[..=first_data as usize].fill(true);
            let per_block = (bs / layout.desc_size) as u64;
            for i in 0..groups.div_ceil(per_block) {
                let block = img.desc_block(i);
                img.used[block as usize] = true;
            }
            let table_blocks = (layout.inodes_per_group as usize * INODE_SIZE).div_ceil(bs);
            for group in 0..groups {
                let table = img.alloc(table_blocks);
                let at = img.desc_at(group);
                put(&mut img.bytes, at + 0x8, &(table as u32).to_le_bytes());
                if layout.desc_size >= 64 {
                    put(
                        &mut img.bytes,
                        at + 0x28,
                        &((table >> 32) as u32).to_le_bytes(),
                    );
                }
            }
            let mut incompat = INCOMPAT_FILETYPE;
            if layout.extents {
                incompat |= INCOMPAT_EXTENTS;
            }
            if layout.desc_size >= 64 {
                incompat |= INCOMPAT_64BIT;
            }
            if layout.meta_bg {
                incompat |= INCOMPAT_META_BG;
            }
            let sb = &mut img.bytes[1024..2048];
            let inodes = groups as u32 * layout.inodes_per_group;
            put(sb, 0x0, &inodes.to_le_bytes());
            put(sb, 0x4, &(layout.blocks as u32).to_le_bytes());
            put(sb, 0x14, &(first_data as u32).to_le_bytes());
            put(sb, 0x18, &(bs / 1024).trailing_zeros().to_le_bytes());
            put(sb, 0x20, &(layout.blocks_per_group as u32).to_le_bytes());
            put(sb, 0x28, &layout.inodes_per_group.to_le_bytes());
            put(sb, 0x38, &MAGIC.to_le_bytes());
            put(sb, 0x4C, &1u32.to_le_bytes());
            put(sb, 0x54, &FIRST_FREE_INODE.to_le_bytes());
            put(sb, 0x58, &(INODE_SIZE as u16).to_le_bytes());
            put(sb, 0x60, &incompat.to_le_bytes());
            put(sb, 0x64, &RO_COMPAT_SPARSE_SUPER.to_le_bytes());
            put(sb, 0xFE, &(layout.desc_size as u16).to_le_bytes());
            img.dir(ROOT_INODE, ROOT_INODE, "", &tree);
            img
        }

        /// Set or clear incompatible feature bits in the superblock.
        pub(crate) fn set_incompat(bytes: &mut [u8], bits: u32, on: bool) {
            let old = le32(&bytes[1024..], 0x60);
            let new = if on { old | bits } else { old & !bits };
            put(bytes, 1024 + 0x60, &new.to_le_bytes());
        }

        fn has_super(group: u64) -> bool {
            group <= 1
                || [3u64, 5, 7].iter().any(|&base| {
                    let mut power = base;
                    while power < group {
                        power *= base;
                    }
                    power == group
                })
        }

        /// Where descriptor block `i` lives.
        fn desc_block(&self, i: u64) -> u64 {
            let first_data = u64::from(self.layout.block_size == 1024);
            if self.layout.meta_bg {
                let group = i * (self.layout.block_size / self.layout.desc_size) as u64;
                first_data
                    + group * self.layout.blocks_per_group
                    + u64::from(Self::has_super(group))
            } else {
                first_data + 1 + i
            }
        }

        fn desc_at(&self, group: u64) -> usize {
            let per_block = (self.layout.block_size / self.layout.desc_size) as u64;
            self.desc_block(group / per_block) as usize * self.layout.block_size
                + (group % per_block) as usize * self.layout.desc_size
        }

        /// The block holding inode `number`, and its offset there.
        pub(crate) fn inode_location(&self, number: u32) -> (u64, usize) {
            let index = u64::from(number - 1);
            let ipg = u64::from(self.layout.inodes_per_group);
            let desc = self.desc_at(index / ipg);
            let mut table = u64::from(le32(&self.bytes, desc + 0x8));
            if self.layout.desc_size >= 64 {
                table |= u64::from(le32(&self.bytes, desc + 0x28)) << 32;
            }
            let byte = (index % ipg) as usize * INODE_SIZE;
            let bs = self.layout.block_size;
            (table + (byte / bs) as u64, byte % bs)
        }

        pub(crate) fn block(&self, block: u64) -> Vec<u8> {
            let bs = self.layout.block_size;
            self.bytes[block as usize * bs..][..bs].to_vec()
        }

        fn alloc(&mut self, count: usize) -> u64 {
            let count = count as u64;
            let mut start = self.next_block;
            while (start..start + count).any(|b| self.used[b as usize]) {
                start += 1;
            }
            for b in start..start + count {
                self.used[b as usize] = true;
            }
            self.next_block = start + count;
            start
        }

        fn write_blocks(&mut self, blocks: &[u64], data: &[u8]) {
            let bs = self.layout.block_size;
            for (&block, chunk) in blocks.iter().zip(data.chunks(bs)) {
                put(&mut self.bytes, block as usize * bs, chunk);
            }
        }

        fn put_inode(&mut self, number: u32, mode: u16, size: u64, flags: u32, i_block: &[u8; 60]) {
            let (block, offset) = self.inode_location(number);
            let at = block as usize * self.layout.block_size + offset;
            let raw = &mut self.bytes[at..at + INODE_SIZE];
            put(raw, 0x0, &mode.to_le_bytes());
            put(raw, 0x4, &(size as u32).to_le_bytes());
            put(raw, 0x20, &flags.to_le_bytes());
            put(raw, I_BLOCK, i_block);
            put(raw, 0x6C, &((size >> 32) as u32).to_le_bytes());
        }

        /// `i_block` and inode flags mapping `extents` of a `blocks`-block file.
        fn map(&mut self, extents: &[Extent], blocks: u64) -> ([u8; 60], u32) {
            if self.layout.extents {
                return (self.extent_root(extents), INODE_EXTENTS);
            }
            let mut physical = vec![0u64; blocks as usize];
            for &(logical, start, len, _) in extents {
                for i in 0..len {
                    physical[(logical + i) as usize] = start + i;
                }
            }
            (self.block_map(&physical), 0)
        }

        fn extent_header(node: &mut [u8], entries: usize, max: usize, depth: u16) {
            put(node, 0, &EXTENT_MAGIC.to_le_bytes());
            put(node, 2, &(entries as u16).to_le_bytes());
            put(node, 4, &(max as u16).to_le_bytes());
            put(node, 6, &depth.to_le_bytes());
        }

        fn extent_leaf(node: &mut [u8], extents: &[Extent], max: usize) {
            Self::extent_header(node, extents.len(), max, 0);
            for (i, &(logical, physical, len, unwritten)) in extents.iter().enumerate() {
                let e = &mut node[12 + 12 * i..24 + 12 * i];
                let len = len as u16 + if unwritten { EXTENT_INIT_MAX } else { 0 };
                put(e, 0, &(logical as u32).to_le_bytes());
                put(e, 4, &len.to_le_bytes());
                put(e, 6, &((physical >> 32) as u16).to_le_bytes());
                put(e, 8, &(physical as u32).to_le_bytes());
            }
        }

        /// The root of an extent tree: the extents themselves if four fit,
        /// else an index entry for a leaf block holding them.
        fn extent_root(&mut self, extents: &[Extent]) -> [u8; 60] {
            let mut root = [0u8; 60];
            if extents.len() <= 4 {
                Self::extent_leaf(&mut root, extents, 4);
                return root;
            }
            let bs = self.layout.block_size;
            let child = self.alloc(1);
            Self::extent_leaf(
                &mut self.bytes[child as usize * bs..][..bs],
                extents,
                (bs - 12) / 12,
            );
            Self::extent_header(&mut root, 1, 4, 1);
            put(&mut root, 12, &(extents[0].0 as u32).to_le_bytes());
            put(&mut root, 16, &(child as u32).to_le_bytes());
            put(&mut root, 20, &((child >> 32) as u16).to_le_bytes());
            root
        }

        /// Twelve direct pointers, then single and double indirect blocks.
        fn block_map(&mut self, physical: &[u64]) -> [u8; 60] {
            let per_block = self.layout.block_size / 4;
            let mut root = [0u8; 60];
            for (i, &p) in physical.iter().take(12).enumerate() {
                put(&mut root, 4 * i, &(p as u32).to_le_bytes());
            }
            let rest = physical.get(12..).unwrap_or_default();
            let single = self.indirect(&rest[..rest.len().min(per_block)]);
            put(&mut root, 48, &single.to_le_bytes());
            let rest = rest.get(per_block..).unwrap_or_default();
            assert!(rest.len() <= per_block * per_block, "test file too large");
            let pointers: Vec<u64> = rest
                .chunks(per_block)
                .map(|c| u64::from(self.indirect(c)))
                .collect();
            let double = self.indirect(&pointers);
            put(&mut root, 52, &double.to_le_bytes());
            root
        }

        /// A block of pointers, or 0 (a hole) if they're all holes.
        fn indirect(&mut self, pointers: &[u64]) -> u32 {
            if pointers.iter().all(|&p| p == 0) {
                return 0;
            }
            let block = self.alloc(1);
            let at = block as usize * self.layout.block_size;
            for (i, &p) in pointers.iter().enumerate() {
                put(&mut self.bytes, at + 4 * i, &(p as u32).to_le_bytes());
            }
            block as u32
        }

        fn dir(&mut self, number: u32, parent: u32, path: &str, nodes: &[Node]) {
            let bs = self.layout.block_size;
            let mut entries = vec![
                (number, ".".to_string(), 2u8),
                (parent, "..".to_string(), 2),
            ];
            for node in nodes {
                let child = self.next_inode;
                self.next_inode += 1;
                let (name, kind) = match node {
                    Node::Dir(name, _) => (name, 2),
                    Node::Link(name, _) => (name, 7),
                    Node::File(name, _)
                    | Node::Scattered(name, _)
                    | Node::Sparse(name, _, _)
                    | Node::Unwritten(name, _) => (name, 1),
                };
                let child_path = format!("{path}/{name}");
                self.inodes.insert(child_path.clone(), child);
                entries.push((child, name.to_string(), kind));
                match node {
                    Node::Dir(_, children) => self.dir(child, number, &child_path, children),
                    Node::File(_, data) | Node::Unwritten(_, data) => {
                        let count = data.len().div_ceil(bs);
                        let first = self.alloc(count);
                        let blocks = (first..first + count as u64).collect();
                        let unwritten = matches!(node, Node::Unwritten(..));
                        self.file(child, &child_path, data, blocks, unwritten);
                    }
                    Node::Scattered(_, data) => {
                        let blocks = (0..data.len().div_ceil(bs))
                            .map(|_| self.alloc(2))
                            .collect();
                        self.file(child, &child_path, data, blocks, false);
                    }
                    Node::Sparse(_, holes, tail) => {
                        let block = self.alloc(1);
                        self.write_blocks(&[block], tail);
                        let (i_block, flags) = self.map(&[(*holes, block, 1, false)], holes + 1);
                        let size = holes * bs as u64 + tail.len() as u64;
                        self.put_inode(child, S_IFREG | 0o644, size, flags, &i_block);
                    }
                    Node::Link(_, target) if target.len() < I_BLOCK_LEN => {
                        let mut i_block = [0u8; 60];
                        put(&mut i_block, 0, target.as_bytes());
                        let size = target.len() as u64;
                        self.put_inode(child, S_IFLNK | 0o777, size, 0, &i_block);
                    }
                    Node::Link(_, target) => {
                        let block = self.alloc(1);
                        self.write_blocks(&[block], target.as_bytes());
                        let (i_block, flags) = self.map(&[(0, block, 1, false)], 1);
                        let size = target.len() as u64;
                        self.put_inode(child, S_IFLNK | 0o777, size, flags, &i_block);
                    }
                }
            }
            let data = self.dir_blocks(&entries);
            let count = data.len() / bs;
            let first = self.alloc(count);
            let blocks: Vec<u64> = (first..first + count as u64).collect();
            self.write_blocks(&blocks, &data);
            let (i_block, flags) = self.map(&[(0, first, count as u64, false)], count as u64);
            self.put_inode(number, S_IFDIR | 0o755, data.len() as u64, flags, &i_block);
        }

        fn file(
            &mut self,
            number: u32,
            path: &str,
            data: &[u8],
            blocks: Vec<u64>,
            unwritten: bool,
        ) {
            self.write_blocks(&blocks, data);
            let mut extents: Vec<Extent> = Vec::new();
            for (logical, &physical) in (0u64..).zip(&blocks) {
                match extents.last_mut() {
                    Some(e) if e.1 + e.2 == physical => e.2 += 1,
                    _ => extents.push((logical, physical, 1, unwritten)),
                }
            }
            let (i_block, flags) = self.map(&extents, blocks.len() as u64);
            self.put_inode(number, S_IFREG | 0o644, data.len() as u64, flags, &i_block);
            self.blocks.insert(path.to_string(), blocks);
        }

        /// Directory entries packed into blocks, each ending in a checksum
        /// tail entry.
        fn pack(&self, entries: &[(u32, String, u8)]) -> Vec<Vec<u8>> {
            let bs = self.layout.block_size;
            let close = |block: &mut [u8], last: usize| {
                put(
                    block,
                    last + 4,
                    &((bs - DIR_TAIL - last) as u16).to_le_bytes(),
                );
                put(block, bs - DIR_TAIL + 4, &(DIR_TAIL as u16).to_le_bytes());
                block[bs - DIR_TAIL + 7] = 0xDE;
            };
            let mut blocks = Vec::new();
            let mut block = vec![0u8; bs];
            let (mut at, mut last) = (0usize, 0usize);
            for (number, name, kind) in entries {
                let len = (8 + name.len()).next_multiple_of(4);
                if at + len > bs - DIR_TAIL {
                    close(&mut block, last);
                    blocks.push(std::mem::replace(&mut block, vec![0u8; bs]));
                    at = 0;
                }
                put(&mut block, at, &number.to_le_bytes());
                put(&mut block, at + 4, &(len as u16).to_le_bytes());
                block[at + 6] = name.len() as u8;
                block[at + 7] = *kind;
                put(&mut block, at + 8, name.as_bytes());
                last = at;
                at += len;
            }
            close(&mut block, last);
            blocks.push(block);
            blocks
        }

        /// A directory's blocks. Entries that don't fit one block go behind an
        /// htree root and an index node, which a linear scan finds empty.
        fn dir_blocks(&self, entries: &[(u32, String, u8)]) -> Vec<u8> {
            let bs = self.layout.block_size;
            let linear = self.pack(entries);
            if linear.len() == 1 {
                return linear.concat();
            }
            let mut root = vec![0xA5u8; bs];
            for (at, len, number, name) in [
                (0, 12, entries[0].0, "."),
                (12, bs - 12, entries[1].0, ".."),
            ] {
                put(&mut root, at, &number.to_le_bytes());
                put(&mut root, at + 4, &(len as u16).to_le_bytes());
                root[at + 6] = name.len() as u8;
                root[at + 7] = 2;
                put(&mut root, at + 8, &[0; 4]);
                put(&mut root, at + 8, name.as_bytes());
            }
            let mut node = vec![0x5Au8; bs];
            put(&mut node, 0, &0u32.to_le_bytes());
            put(&mut node, 4, &(bs as u16).to_le_bytes());
            let mut blocks = vec![root, node];
            blocks.extend(self.pack(&entries[2..]));
            blocks.concat()
        }

        /// Give the filesystem a `len`-block journal whose log holds `txs`
        /// from log block `start` and transaction `sequence` on, laid out with
        /// `features`, and mark the filesystem as needing recovery.
        pub(crate) fn journal(
            &mut self,
            len: u64,
            start: u64,
            sequence: u32,
            features: u32,
            txs: &[Tx],
        ) {
            let bs = self.layout.block_size;
            let first = self.alloc(len as usize);
            let (i_block, flags) = self.map(&[(0, first, len, false)], len);
            self.put_inode(
                JOURNAL_INODE,
                S_IFREG | 0o600,
                len * bs as u64,
                flags,
                &i_block,
            );
            let at = |n: u64| (first + n) as usize * bs;
            let header = |bytes: &mut [u8], at: usize, kind: u32, sequence: u32| {
                put(bytes, at, &JBD2_MAGIC.to_be_bytes());
                put(bytes, at + 4, &kind.to_be_bytes());
                put(bytes, at + 8, &sequence.to_be_bytes());
            };
            header(&mut self.bytes, at(0), JBD2_SUPERBLOCK_V2, 0);
            let fields = [
                (12, bs as u32),
                (16, len as u32),
                (20, 1),
                (24, sequence),
                (28, start as u32),
                (40, features),
            ];
            for (offset, value) in fields {
                put(&mut self.bytes, at(0) + offset, &value.to_be_bytes());
            }
            let tag_bytes = if features & JBD2_CSUM_V3 != 0 {
                16
            } else if features & JBD2_64BIT != 0 {
                12
            } else {
                8
            };
            let mut log = start;
            let mut next = || {
                let here = log;
                log = if log + 1 == len { 1 } else { log + 1 };
                here
            };
            for (sequence, tx) in (sequence..).zip(txs) {
                if !tx.revokes.is_empty() {
                    let block = at(next());
                    header(&mut self.bytes, block, JBD2_REVOKE, sequence);
                    let size = if features & JBD2_64BIT != 0 { 8 } else { 4 };
                    let used = (16 + size * tx.revokes.len()) as u32;
                    put(&mut self.bytes, block + 12, &used.to_be_bytes());
                    for (i, &revoked) in tx.revokes.iter().enumerate() {
                        let bytes = revoked.to_be_bytes();
                        put(&mut self.bytes, block + 16 + size * i, &bytes[8 - size..]);
                    }
                }
                if !tx.writes.is_empty() {
                    let descriptor = at(next());
                    header(&mut self.bytes, descriptor, JBD2_DESCRIPTOR, sequence);
                    let mut tag = descriptor + 12;
                    for (i, (block, data)) in tx.writes.iter().enumerate() {
                        let mut data = data.clone();
                        data.resize(bs, 0);
                        let mut flags = 0u16;
                        if i > 0 {
                            flags |= JBD2_TAG_SAME_UUID;
                        }
                        if i + 1 == tx.writes.len() {
                            flags |= JBD2_TAG_LAST;
                        }
                        if be32(&data, 0) == JBD2_MAGIC {
                            flags |= JBD2_TAG_ESCAPE;
                            data[..4].fill(0);
                        }
                        put(&mut self.bytes, tag, &(*block as u32).to_be_bytes());
                        if tag_bytes == 16 {
                            put(&mut self.bytes, tag + 4, &u32::from(flags).to_be_bytes());
                        } else {
                            put(&mut self.bytes, tag + 6, &flags.to_be_bytes());
                        }
                        if tag_bytes >= 12 {
                            put(
                                &mut self.bytes,
                                tag + 8,
                                &((block >> 32) as u32).to_be_bytes(),
                            );
                        }
                        tag += tag_bytes + if i == 0 { 16 } else { 0 };
                        let copy = at(next());
                        put(&mut self.bytes, copy, &data);
                    }
                }
                if tx.commit {
                    let block = at(next());
                    header(&mut self.bytes, block, JBD2_COMMIT, sequence);
                }
            }
            let compat = le32(&self.bytes[1024..], 0x5C) | COMPAT_HAS_JOURNAL;
            put(&mut self.bytes, 1024 + 0x5C, &compat.to_le_bytes());
            put(&mut self.bytes, 1024 + 0xE0, &JOURNAL_INODE.to_le_bytes());
            Self::set_incompat(&mut self.bytes, INCOMPAT_RECOVER, true);
        }
    }

    #[test]
    fn reads_files_directories_and_symlinks() {
        let layouts = [
            SMALL,
            Layout {
                block_size: 4096,
                blocks: 1024,
                ..SMALL
            },
            Layout {
                extents: false,
                ..SMALL
            },
        ];
        for layout in layouts {
            let bs = layout.block_size;
            let cfg = b"menuentry 'Ubuntu' {\n linux /boot/vmlinuz root=UUID=x ro\n}\n".to_vec();
            // Ten blocks apart: more extents than the inode holds.
            let kernel = pattern(9 * bs + 100, 1);
            let initrd = pattern(30_000, 2);
            let names: Vec<String> = (0..200).map(|i| format!("entry-{i:03}")).collect();
            let long = format!("{}/boot/grub/grub.cfg", "/.".repeat(40));
            let mut tree = vec![
                Node::Dir(
                    "boot",
                    vec![
                        Node::Dir("grub", vec![Node::File("grub.cfg", &cfg)]),
                        Node::Scattered("vmlinuz-1", &kernel),
                        Node::File("initrd.img-1", &initrd),
                        Node::Link("vmlinuz", "vmlinuz-1"),
                        Node::Link("initrd.img", "/boot/initrd.img-1"),
                    ],
                ),
                Node::Dir(
                    "many",
                    names.iter().map(|n| Node::File(n, n.as_bytes())).collect(),
                ),
                Node::Sparse("sparse", 20, b"tail"),
                Node::Link("long", &long),
                Node::Link("loop-a", "loop-b"),
                Node::Link("loop-b", "loop-a"),
            ];
            if layout.extents {
                tree.push(Node::Unwritten("unwritten", b"stale bytes"));
            }
            let fs = Ext4::probe(Image::new(layout, tree).bytes)
                .unwrap()
                .unwrap();
            assert_eq!(fs.read_file("/boot/grub/grub.cfg").unwrap(), cfg);
            assert_eq!(fs.read_file("boot/vmlinuz").unwrap(), kernel);
            assert_eq!(fs.read_file("/boot/initrd.img").unwrap(), initrd);
            assert_eq!(fs.read_file("/boot/grub/../vmlinuz-1").unwrap(), kernel);
            assert_eq!(fs.read_file("/many/entry-000").unwrap(), b"entry-000");
            assert_eq!(fs.read_file("/many/entry-199").unwrap(), b"entry-199");
            assert_eq!(fs.read_file("/long").unwrap(), cfg);
            let mut sparse = vec![0u8; 20 * bs];
            sparse.extend_from_slice(b"tail");
            assert_eq!(fs.read_file("/sparse").unwrap(), sparse);
            if layout.extents {
                assert_eq!(fs.read_file("/unwritten").unwrap(), [0; 11]);
            }
            assert_eq!(fs.lookup("/boot/grub").unwrap(), Some(Kind::Dir));
            assert_eq!(fs.lookup("/boot/vmlinuz").unwrap(), Some(Kind::File));
            assert_eq!(fs.lookup("/boot/none").unwrap(), None);
            assert_eq!(fs.lookup("/boot/grub/grub.cfg/x").unwrap(), None);
            assert!(fs.read_file("/boot").is_err());
            assert!(fs.lookup("/loop-a").is_err());
            assert_eq!(fs.journal_blocks(), 0);
        }
    }

    #[test]
    fn reads_block_maps_and_64bit_descriptors_with_meta_bg() {
        // 1 KiB blocks: a 300-block file reaches its double-indirect block. A
        // block holds 16 descriptors, so groups 16 and up keep theirs in meta
        // group 1 (group 16's first block); 2 inodes a group puts inode 33 on.
        let layout = Layout {
            block_size: 1024,
            blocks: 8192,
            blocks_per_group: 256,
            inodes_per_group: 2,
            desc_size: 64,
            meta_bg: true,
            extents: false,
        };
        let big = pattern(300 * 1024 + 7, 3);
        let names: Vec<String> = (0..40).map(|i| format!("f{i}")).collect();
        let mut tree = vec![Node::File("big", &big), Node::Sparse("holes", 280, b"end")];
        tree.extend(names.iter().map(|n| Node::File(n, n.as_bytes())));
        let image = Image::new(layout, tree);
        assert!(image.inodes["/f39"] > 32);
        let fs = Ext4::probe(image.bytes).unwrap().unwrap();
        assert_eq!(fs.read_file("/big").unwrap(), big);
        for name in &names {
            assert_eq!(fs.read_file(name).unwrap(), name.as_bytes());
        }
        let mut holes = vec![0u8; 280 * 1024];
        holes.extend_from_slice(b"end");
        assert_eq!(fs.read_file("/holes").unwrap(), holes);
    }

    #[test]
    fn replays_committed_journal_transactions() {
        for features in [0, JBD2_64BIT | JBD2_CSUM_V3] {
            let old_cfg = b"old grub.cfg".to_vec();
            let tree = vec![
                Node::Dir(
                    "boot",
                    vec![Node::Dir("grub", vec![Node::File("grub.cfg", &old_cfg)])],
                ),
                Node::File("a", b"a-home"),
                Node::File("b", b"b-home"),
                Node::File("escaped", b"e-home!!"),
            ];
            let mut image = Image::new(SMALL, tree);
            // A longer grub.cfg, as Linux logs it: its data block, and the
            // inode table block with its new size.
            let new_cfg = b"new grub.cfg, longer than the old one".to_vec();
            let (inode_block, offset) = image.inode_location(image.inodes["/boot/grub/grub.cfg"]);
            let mut inode_copy = image.block(inode_block);
            put(
                &mut inode_copy,
                offset + 4,
                &(new_cfg.len() as u32).to_le_bytes(),
            );
            let block_of = |path: &str| image.blocks[path][0];
            let escaped = [&JBD2_MAGIC.to_be_bytes()[..], b"tail"].concat();
            let txs = [
                Tx {
                    writes: vec![
                        (inode_block, inode_copy),
                        (block_of("/boot/grub/grub.cfg"), new_cfg.clone()),
                    ],
                    revokes: vec![],
                    commit: true,
                },
                Tx {
                    writes: vec![
                        (block_of("/a"), b"a-tx2!".to_vec()),
                        (block_of("/b"), b"b-tx2!".to_vec()),
                    ],
                    revokes: vec![],
                    commit: true,
                },
                // Revoking /b's block cancels the copy logged before.
                Tx {
                    writes: vec![(block_of("/escaped"), escaped.clone())],
                    revokes: vec![block_of("/b")],
                    commit: true,
                },
                // Never committed: ignored.
                Tx {
                    writes: vec![(block_of("/a"), b"a-lost".to_vec())],
                    revokes: vec![],
                    commit: false,
                },
            ];
            // The log starts near its end, so it wraps.
            image.journal(16, 13, 7, features, &txs);
            let fs = Ext4::probe(image.bytes.clone()).unwrap().unwrap();
            assert_eq!(fs.read_file("/boot/grub/grub.cfg").unwrap(), new_cfg);
            assert_eq!(fs.read_file("/a").unwrap(), b"a-tx2!");
            assert_eq!(fs.read_file("/b").unwrap(), b"b-home");
            assert_eq!(fs.read_file("/escaped").unwrap(), escaped);
            assert_eq!(fs.journal_blocks(), 4);
            // Cleanly unmounted: the journal is not replayed.
            let mut clean = image.bytes;
            Image::set_incompat(&mut clean, INCOMPAT_RECOVER, false);
            let fs = Ext4::probe(clean).unwrap().unwrap();
            assert_eq!(fs.read_file("/boot/grub/grub.cfg").unwrap(), old_cfg);
            assert_eq!(fs.read_file("/a").unwrap(), b"a-home");
        }
    }

    #[test]
    fn rejects_other_and_malformed_filesystems() {
        assert!(Ext4::probe(vec![0u8; 64 << 10]).unwrap().is_none());
        let image = Image::new(SMALL, vec![Node::File("f", b"data")]);
        // An incompatible feature this reader doesn't know (compression).
        let mut unknown = image.bytes.clone();
        Image::set_incompat(&mut unknown, 0x1, true);
        assert!(Ext4::probe(unknown).is_err());
        // A corrupt extent tree, and blocks past a truncated image's end, are
        // errors, not panics.
        let (block, offset) = image.inode_location(image.inodes["/f"]);
        let mut corrupt = image.bytes.clone();
        corrupt[block as usize * 1024 + offset + I_BLOCK] ^= 0xFF;
        let fs = Ext4::probe(corrupt).unwrap().unwrap();
        assert!(fs.read_file("/f").is_err());
        let fs = Ext4::probe(image.bytes[..8 << 10].to_vec())
            .unwrap()
            .unwrap();
        assert!(fs.read_file("/f").is_err());
    }

    /// Where `path`'s `i_block` is in the image.
    fn i_block_at(image: &Image, path: &str) -> usize {
        let (block, offset) = image.inode_location(image.inodes[path]);
        block as usize * image.layout.block_size + offset + I_BLOCK
    }

    #[test]
    fn extents_map_each_block_of_a_file_once_and_in_order() {
        let data = pattern(3 * SMALL.block_size, 4);
        let file = || Image::new(SMALL, vec![Node::File("f", &data)]);
        let first = file().blocks["/f"][0];
        // The file as `extents` map it.
        let read = |extents: &[Extent]| {
            let mut image = file();
            let (i_block, flags) = image.map(extents, 0);
            let number = image.inodes["/f"];
            image.put_inode(number, S_IFREG | 0o644, data.len() as u64, flags, &i_block);
            Ext4::probe(image.bytes).unwrap().unwrap().read_file("/f")
        };
        let bad = |extents: &[Extent]| {
            let error = read(extents).map(|_| ()).unwrap_err().to_string();
            assert_eq!(error, "ext4: bad extent tree", "{extents:?}");
        };
        // Extents in file order read as before, one after the other.
        assert_eq!(read(&[(0, first, 3, false)]).unwrap(), data);
        let split = [(0, first, 1, false), (1, first + 1, 2, false)];
        assert_eq!(read(&split).unwrap(), data);
        // One that maps blocks again made us read them again: eighty times
        // here, and a tree of such leaves as often as it had extents.
        bad(&[(0, first, 3, false); 2]);
        bad(&[(0, first, 3, false); 80]);
        bad(&[(0, first, 2, false), (1, first + 1, 2, false)]);
        bad(&[(0, first, 2, false), (1, first + 1, 1, true)]);
        // Out of order, and empty (which could repeat without end).
        bad(&[(1, first + 1, 2, false), (0, first, 1, false)]);
        bad(&[(0, first, 0, false), (0, first, 3, false)]);
        // Blocks preallocated past the end of the file aren't read, as
        // before, but their extents are held to the same order.
        let past = [
            (0, first, 3, false),
            (5, first, 1, true),
            (9, first, 1, false),
        ];
        assert_eq!(read(&past).unwrap(), data);
        bad(&[
            (0, first, 3, false),
            (9, first, 1, false),
            (5, first, 1, true),
        ]);
    }

    #[test]
    fn extent_index_entries_lead_to_blocks_after_those_before_them() {
        let bs = SMALL.block_size;
        let data = pattern(6 * bs, 5);
        // Six extents: in a leaf, behind the one index entry in the inode.
        let mut image = Image::new(SMALL, vec![Node::Scattered("f", &data)]);
        let root = i_block_at(&image, "/f");
        assert_eq!(image.bytes[root..root + 8], [0x0A, 0xF3, 1, 0, 4, 0, 1, 0]);
        let leaf = le32(&image.bytes, root + 16) as usize * bs;
        let number = image.inodes["/f"];
        // The file, and how many runs it is mapped by.
        let read = |bytes: &[u8]| {
            let fs = Ext4::probe(bytes.to_vec()).unwrap().unwrap();
            let runs = fs.runs(&fs.read_inode(number)?)?;
            Ok::<_, Error>((fs.read_file("/f")?, runs.len()))
        };
        let bad = |bytes: &[u8]| {
            let error = read(bytes).map(|_| ()).unwrap_err().to_string();
            assert_eq!(error, "ext4: bad extent tree");
        };
        assert_eq!(read(&image.bytes).unwrap(), (data.clone(), 6));

        // As a crafted image has it: all four index entries of the inode
        // lead to the one leaf, to have its blocks read four times.
        let mut aliased = image.bytes.clone();
        aliased[root + 2] = 4;
        for entry in 1..4 {
            aliased.copy_within(root + 12..root + 24, root + 12 + 12 * entry);
        }
        bad(&aliased);
        // Nor when the entries claim to lead to later and later blocks (2, 4
        // and 6): the leaf's extents run on past the second entry's block.
        // With only two extents in the leaf, they come before it.
        for entry in 1..4 {
            let at = root + 12 + 12 * entry;
            put(&mut aliased, at, &(2 * entry as u32).to_le_bytes());
        }
        bad(&aliased);
        aliased[leaf + 2] = 2;
        bad(&aliased);

        // Two leaves in file order read as the one did: the first three
        // extents stay, and the others move to a block of their own, which
        // the inode's second index entry leads to.
        let second = image.alloc(1) as usize;
        let mut split = image.bytes.clone();
        split.copy_within(leaf..leaf + 12, second * bs);
        split.copy_within(leaf + 12 + 3 * 12..leaf + 12 + 6 * 12, second * bs + 12);
        split[leaf + 2] = 3;
        split[second * bs + 2] = 3;
        split[root + 2] = 2;
        put(&mut split, root + 24, &3u32.to_le_bytes());
        put(&mut split, root + 28, &(second as u32).to_le_bytes());
        assert_eq!(read(&split).unwrap(), (data.clone(), 6));
        // Unless the second leaf's extents come before its index entry.
        put(&mut split, root + 24, &4u32.to_le_bytes());
        bad(&split);

        // A node has no more entries than it says it holds, and holds no
        // more than fit it: four in an inode, 84 in a 1 KiB block.
        for (at, max) in [(root, 0), (root, 5), (leaf, 5), (leaf, 85)] {
            let mut bytes = image.bytes.clone();
            bytes[at + 4] = max;
            bad(&bytes);
        }
    }

    #[test]
    fn a_journal_is_a_regular_file_of_bounded_size() {
        for extents in [true, false] {
            let layout = Layout { extents, ..SMALL };
            let mut image = Image::new(layout, vec![Node::File("a", b"a-home")]);
            let tx = Tx {
                writes: vec![(image.blocks["/a"][0], b"a-tx7!".to_vec())],
                revokes: vec![],
                commit: true,
            };
            image.journal(16, 1, 7, 0, &[tx]);
            let replayed = |bytes: &[u8]| {
                let fs = Ext4::probe(bytes.to_vec())?.unwrap();
                Ok::<_, Error>((fs.journal_blocks(), fs.read_file("/a")?))
            };
            assert_eq!(replayed(&image.bytes).unwrap(), (1, b"a-tx7!".to_vec()));

            // As Linux, which takes no directory (or device) for a journal.
            let (block, offset) = image.inode_location(JOURNAL_INODE);
            let inode = block as usize * layout.block_size + offset;
            let mut bytes = image.bytes.clone();
            put(&mut bytes, inode, &(S_IFDIR | 0o600).to_le_bytes());
            assert!(replayed(&bytes).is_err());
            // Its size bounds its block map and the walk of its log: 2^20
            // blocks (1 GiB of these) are the most.
            let sized = |size: u64| {
                let mut bytes = image.bytes.clone();
                put(&mut bytes, inode + 0x4, &(size as u32).to_le_bytes());
                put(
                    &mut bytes,
                    inode + 0x6C,
                    &((size >> 32) as u32).to_le_bytes(),
                );
                replayed(&bytes).map(|(blocks, _)| blocks)
            };
            let most = MAX_JOURNAL_BLOCKS * layout.block_size as u64;
            assert_eq!(sized(most).unwrap(), 1);
            let error = sized(most + layout.block_size as u64).unwrap_err();
            assert_eq!(
                error.to_string(),
                "ext4: a 1073742848-byte journal is too large to replay"
            );
            assert!(sized(MAX_JOURNAL_BYTES + 1).is_err());
            assert!(sized(u64::MAX).is_err());
        }
    }

    /// A filesystem whose journal's log is `runs` runs of 256 blocks, all of
    /// them the same 256 blocks on the disk: revoke blocks, 252 records
    /// each, of a transaction that never commits.
    fn revoking(runs: u64) -> Vec<u8> {
        let bs = SMALL.block_size;
        let mut image = Image::new(SMALL, vec![Node::File("f", b"data")]);
        let (superblock, revokes) = (image.alloc(1), image.alloc(256));
        let mut log: Vec<Extent> = vec![(0, superblock, 1, false)];
        log.extend((0..runs).map(|i| (1 + 256 * i, revokes, 256, false)));
        let blocks = 1 + 256 * runs;
        let (i_block, flags) = image.map(&log, blocks);
        image.put_inode(
            JOURNAL_INODE,
            S_IFREG | 0o600,
            blocks * bs as u64,
            flags,
            &i_block,
        );
        // A block of transaction 7's, with these fields after its header.
        let mut write = |block: u64, kind: u32, fields: &[(usize, u32)]| {
            let header = [(0, JBD2_MAGIC), (4, kind), (8, 7)];
            for &(offset, value) in header.iter().chain(fields) {
                put(
                    &mut image.bytes,
                    block as usize * bs + offset,
                    &value.to_be_bytes(),
                );
            }
        };
        // Block size, log length, first block, sequence, start.
        let fields = [
            (12, bs as u32),
            (16, blocks as u32),
            (20, 1),
            (24, 7),
            (28, 1),
        ];
        write(superblock, JBD2_SUPERBLOCK_V2, &fields);
        for block in revokes..revokes + 256 {
            // Full of records (of block 0, over and over).
            write(block, JBD2_REVOKE, &[(12, bs as u32)]);
        }
        let compat = le32(&image.bytes[1024..], 0x5C) | COMPAT_HAS_JOURNAL;
        put(&mut image.bytes, 1024 + 0x5C, &compat.to_le_bytes());
        put(&mut image.bytes, 1024 + 0xE0, &JOURNAL_INODE.to_le_bytes());
        Image::set_incompat(&mut image.bytes, INCOMPAT_RECOVER, true);
        image.bytes
    }

    #[test]
    fn a_log_of_revoke_records_is_read_up_to_their_cap() {
        // A block is revoked once however many records name it, so a log
        // under the cap costs nothing to remember: 65 * 256 * 252 records.
        let fs = Ext4::probe(revoking(65)).unwrap().unwrap();
        assert_eq!(fs.journal_blocks(), 0);
        assert_eq!(fs.read_file("/f").unwrap(), b"data");
        // One run more is over 2^22 records: an error, where every record
        // read took eight bytes for as long as the log went on.
        let error = Ext4::probe(revoking(66)).err().unwrap();
        assert_eq!(
            error.to_string(),
            "ext4: the journal has too many revoke records to replay"
        );
    }

    #[test]
    fn paths_are_bounded_in_length_and_in_names_looked_up() {
        let tree = vec![Node::Dir("boot", vec![Node::File("k", b"kernel")])];
        let fs = Ext4::probe(Image::new(SMALL, tree).bytes).unwrap().unwrap();
        // Each name looked up reads a directory: 256 are the most, however
        // a path comes by them.
        let looking_up = |names: usize| format!("{}boot/k", "boot/../".repeat(names - 2));
        assert_eq!(fs.read_file(&looking_up(256)).unwrap(), b"kernel");
        let error = fs.read_file(&looking_up(257)).unwrap_err().to_string();
        assert!(error.ends_with("too many path components"), "{error}");
        // And a path is 4096 bytes at most.
        let long = |len: usize| format!("{}boot/k", "/".repeat(len - 6));
        assert_eq!(fs.read_file(&long(4096)).unwrap(), b"kernel");
        assert!(fs.read_file(&long(4097)).is_err());
        assert!(fs.lookup(&long(4097)).is_err());
    }

    #[test]
    fn a_file_over_the_callers_cap_is_refused_unread() {
        let image = Image::new(SMALL, vec![Node::Sparse("big", 2000, b"tail")]);
        let fs = Ext4::probe(image.bytes).unwrap().unwrap();
        let size = 2000 * 1024 + 4;
        assert_eq!(
            fs.read_file_capped("/big", size).unwrap().len() as u64,
            size
        );
        let error = fs.read_file_capped("/big", size - 1).unwrap_err();
        assert_eq!(
            error.to_string(),
            "ext4: /big is too large (2048004 bytes; at most 2048003 here)"
        );
    }
}
