use anyhow::{Context, Result, anyhow, ensure};
use std::{
    cmp::Reverse,
    io::{BufRead, BufReader, Read},
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];
const ZSTD_MAGIC: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];
/// fetch-rootfs.py starts a pack with this zstd skippable frame. The first
/// zstd frame then holds directories and symlinks; every later frame holds
/// whole regular-file tar entries and can be extracted independently.
const PACK_MAGIC: u32 = 0x184D_2A5E;
const PACK_ID: &[u8] = b"tinyinit-rootfs-v1";

pub struct Unpacked {
    pub format: &'static str,
    pub frames: usize,
    pub threads: usize,
}

/// Unpack a trusted in-memory archive. tinyinit packs extract their file
/// frames on every available CPU; gzip, zstd and plain tar archives stream
/// sequentially.
pub fn unpack_bytes(data: &[u8], target: &Path) -> Result<Unpacked> {
    let Some(frames) = pack_frames(data)? else {
        let format = format_name(data);
        unpack(data, target)?;
        return Ok(Unpacked {
            format,
            frames: 1,
            threads: 1,
        });
    };
    let (skeleton, files) = frames.split_first().context("rootfs pack has no frames")?;
    extract_frame(skeleton, target).context("unpack rootfs directories and links")?;
    let mut files = files.to_vec();
    // Largest first keeps the busiest worker close to the average share.
    files.sort_by_key(|frame| Reverse(frame_size(frame)));
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .clamp(1, files.len().max(1));
    for_each_parallel(&files, threads, |frame| extract_frame(frame, target))
        .context("unpack rootfs files")?;
    Ok(Unpacked {
        format: "tinyinit-zstd",
        frames: frames.len(),
        threads,
    })
}

pub fn unpack(reader: impl Read, target: &Path) -> Result<()> {
    let mut reader = BufReader::new(reader);
    let head = reader.fill_buf()?;
    let gzip = head.starts_with(GZIP_MAGIC);
    let zstd = head.starts_with(ZSTD_MAGIC) || skippable(head);
    if gzip {
        unpack_tar(flate2::read::GzDecoder::new(reader), target)
    } else if zstd {
        unpack_tar(zstd::stream::read::Decoder::with_buffer(reader)?, target)
    } else {
        unpack_tar(reader, target)
    }
}

fn format_name(data: &[u8]) -> &'static str {
    if data.starts_with(GZIP_MAGIC) {
        "gzip"
    } else if data.starts_with(ZSTD_MAGIC) || skippable(data) {
        "zstd"
    } else {
        "tar"
    }
}

fn skippable(data: &[u8]) -> bool {
    data.get(..4)
        .and_then(|magic| magic.try_into().ok())
        .is_some_and(|magic| u32::from_le_bytes(magic) & 0xffff_fff0 == 0x184d_2a50)
}

fn pack_frames(data: &[u8]) -> Result<Option<Vec<&[u8]>>> {
    let header = 8 + PACK_ID.len();
    let Some(prefix) = data.get(..header) else {
        return Ok(None);
    };
    if prefix[..4] != PACK_MAGIC.to_le_bytes()
        || prefix[4..8] != (PACK_ID.len() as u32).to_le_bytes()
        || &prefix[8..] != PACK_ID
    {
        return Ok(None);
    }
    let mut rest = &data[header..];
    let mut frames = Vec::new();
    while !rest.is_empty() {
        let size = zstd::zstd_safe::find_frame_compressed_size(rest).map_err(|code| {
            anyhow!(
                "invalid zstd frame in rootfs pack: {}",
                zstd::zstd_safe::get_error_name(code)
            )
        })?;
        ensure!(size > 0 && size <= rest.len(), "invalid zstd frame size");
        let (frame, next) = rest.split_at(size);
        if frame.starts_with(ZSTD_MAGIC) {
            frames.push(frame);
        }
        rest = next;
    }
    Ok(Some(frames))
}

fn frame_size(frame: &[u8]) -> u64 {
    match zstd::zstd_safe::get_frame_content_size(frame) {
        Ok(Some(size)) => size,
        _ => frame.len() as u64,
    }
}

fn extract_frame(frame: &[u8], target: &Path) -> Result<()> {
    unpack_tar(zstd::stream::read::Decoder::with_buffer(frame)?, target)
}

fn for_each_parallel<T: Sync>(
    items: &[T],
    threads: usize,
    work: impl Fn(&T) -> Result<()> + Sync,
) -> Result<()> {
    if threads <= 1 {
        return items.iter().try_for_each(&work);
    }
    let next = AtomicUsize::new(0);
    let failure = Mutex::new(None);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                while let Some(item) = items.get(next.fetch_add(1, Ordering::Relaxed)) {
                    if let Err(error) = work(item) {
                        next.store(items.len(), Ordering::Relaxed);
                        if let Ok(mut slot) = failure.lock() {
                            slot.get_or_insert(error);
                        }
                    }
                }
            });
        }
    });
    match failure.into_inner() {
        Ok(None) => Ok(()),
        Ok(Some(error)) => Err(error),
        Err(_) => Err(anyhow!("rootfs worker failed")),
    }
}

fn unpack_tar(reader: impl Read, target: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    // Rootfs images are trusted executable inputs, not untrusted user uploads.
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    archive.set_unpack_xattrs(true);
    archive.unpack(target).context("unpack trusted rootfs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
    };

    fn scratch(name: &str) -> Result<PathBuf> {
        let target = std::env::temp_dir().join(format!("tinyinit-{name}-{}", std::process::id()));
        fs::create_dir(&target)?;
        Ok(target)
    }

    #[test]
    fn preserves_trusted_modes_ownership_links_and_xattrs() -> Result<()> {
        let target = scratch("rootfs")?;
        let result = (|| {
            let uid = unsafe { libc::getuid() };
            let gid = unsafe { libc::getgid() };
            let (owner, group) = if uid == 0 { (1234, 2345) } else { (uid, gid) };
            let mut builder = tar::Builder::new(Vec::new());
            builder
                .append_pax_extensions([("SCHILY.xattr.user.tinyinit", b"preserved".as_slice())])?;
            let mut header = tar::Header::new_gnu();
            header.set_size(4);
            header.set_mode(0o1755);
            header.set_uid(u64::from(owner));
            header.set_gid(u64::from(group));
            header.set_cksum();
            builder.append_data(&mut header, "data", b"test".as_slice())?;
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_mode(0o777);
            header.set_uid(u64::from(owner));
            header.set_gid(u64::from(group));
            header.set_size(0);
            builder.append_link(&mut header, "link", "data")?;
            let data = builder.into_inner()?;
            unpack(data.as_slice(), &target)?;
            let metadata = fs::metadata(target.join("data"))?;
            assert_eq!(metadata.mode() & 0o7777, 0o1755);
            assert_eq!((metadata.uid(), metadata.gid()), (owner, group));
            assert_eq!(fs::read_link(target.join("link"))?, Path::new("data"));
            let path = std::ffi::CString::new(target.join("data").as_os_str().as_encoded_bytes())?;
            let mut value = [0u8; 16];
            let length = unsafe {
                libc::getxattr(
                    path.as_ptr(),
                    c"user.tinyinit".as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                )
            };
            assert_eq!(length, 9);
            assert_eq!(&value[..9], b"preserved");
            Ok(())
        })();
        fs::remove_dir_all(&target)?;
        result
    }

    /// Whole tar entries without the end-of-archive marker, as packed by
    /// fetch-rootfs.py.
    fn fragment(add: impl FnOnce(&mut tar::Builder<Vec<u8>>) -> Result<()>) -> Result<Vec<u8>> {
        let mut builder = tar::Builder::new(Vec::new());
        add(&mut builder)?;
        Ok(builder.get_ref().clone())
    }

    fn header(kind: tar::EntryType, mode: u32, size: u64) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_mode(mode);
        header.set_size(size);
        header.set_uid(u64::from(unsafe { libc::getuid() }));
        header.set_gid(u64::from(unsafe { libc::getgid() }));
        header
    }

    fn file(builder: &mut tar::Builder<Vec<u8>>, path: &str, mode: u32, data: &[u8]) -> Result<()> {
        let mut header = header(tar::EntryType::Regular, mode, data.len() as u64);
        header.set_cksum();
        Ok(builder.append_data(&mut header, path, data)?)
    }

    #[test]
    fn parallel_pack_extracts_like_its_tar_stream() -> Result<()> {
        let skeleton = fragment(|builder| {
            let mut directory = header(tar::EntryType::Directory, 0o751, 0);
            directory.set_cksum();
            builder.append_data(&mut directory, "etc", std::io::empty())?;
            let mut link = header(tar::EntryType::Symlink, 0o777, 0);
            builder.append_link(&mut link, "lib", "usr/lib")?;
            Ok(())
        })?;
        let first = fragment(|builder| file(builder, "etc/a", 0o640, b"first"))?;
        let mut second = fragment(|builder| file(builder, "usr/lib/b", 0o755, b"second"))?;
        second.extend([0u8; 1024]);
        let mut pack = PACK_MAGIC.to_le_bytes().to_vec();
        pack.extend((PACK_ID.len() as u32).to_le_bytes());
        pack.extend(PACK_ID);
        for frame in [skeleton, first, second] {
            pack.extend(zstd::stream::encode_all(frame.as_slice(), 3)?);
        }

        let parallel = scratch("pack-parallel")?;
        let sequential = scratch("pack-sequential")?;
        let result = (|| {
            let report = unpack_bytes(&pack, &parallel)?;
            assert_eq!((report.format, report.frames), ("tinyinit-zstd", 3));
            // Standard zstd readers skip the marker and see one ordinary tar stream.
            unpack(pack.as_slice(), &sequential)?;
            for target in [&parallel, &sequential] {
                assert_eq!(fs::read(target.join("etc/a"))?, b"first");
                assert_eq!(fs::read(target.join("usr/lib/b"))?, b"second");
                assert_eq!(fs::read_link(target.join("lib"))?, Path::new("usr/lib"));
                assert_eq!(
                    fs::metadata(target.join("etc"))?.permissions().mode() & 0o7777,
                    0o751
                );
                assert_eq!(
                    fs::metadata(target.join("etc/a"))?.permissions().mode() & 0o7777,
                    0o640
                );
            }
            Ok(())
        })();
        fs::remove_dir_all(&parallel)?;
        fs::remove_dir_all(&sequential)?;
        result
    }
}
