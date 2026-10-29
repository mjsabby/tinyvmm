use anyhow::{Context, Result};
use std::{
    io::{BufRead, BufReader, Read},
    path::Path,
};

pub fn unpack(reader: impl Read, target: &Path) -> Result<()> {
    let mut reader = BufReader::new(reader);
    if reader.fill_buf()?.starts_with(&[0x1f, 0x8b]) {
        unpack_tar(flate2::read::GzDecoder::new(reader), target)
    } else {
        unpack_tar(reader, target)
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
    use std::{fs, os::unix::fs::MetadataExt};

    #[test]
    fn preserves_trusted_modes_ownership_links_and_xattrs() -> Result<()> {
        let target = std::env::temp_dir().join(format!("tinyinit-rootfs-{}", std::process::id()));
        fs::create_dir(&target)?;
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
        fs::remove_file(target.join("link")).ok();
        fs::remove_file(target.join("data")).ok();
        fs::remove_dir(&target)?;
        result
    }
}
