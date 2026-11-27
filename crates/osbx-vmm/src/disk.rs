//! Sparse raw disk images on every host: create, grow and copy without allocating the zeros.
//!
//! Unix file systems leave holes when a file is extended; NTFS only does for files flagged
//! sparse (`FSCTL_SET_SPARSE`), so on Windows every image is flagged before it is extended.
//! Copies skip all-zero blocks, which become holes in the destination.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

#[cfg(windows)]
#[allow(unsafe_code)]
fn set_sparse(f: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;
    let mut returned = 0u32;
    // SAFETY: a valid file handle owned by `f`; no input or output buffers.
    let ok = unsafe {
        DeviceIoControl(
            f.as_raw_handle(),
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn set_sparse(_f: &File) -> io::Result<()> {
    Ok(())
}

/// Create (or truncate) `path` as an all-zero sparse image of `len` bytes.
pub fn create_sparse(path: &Path, len: u64) -> io::Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    set_sparse(&f)?;
    f.set_len(len)
}

/// Grow `path` to `len` bytes, keeping the new part sparse. Never shrinks; returns whether
/// the file grew.
pub fn grow_sparse(path: &Path, len: u64) -> io::Result<bool> {
    let f = OpenOptions::new().read(true).write(true).open(path)?;
    if f.metadata()?.len() >= len {
        return Ok(false);
    }
    set_sparse(&f)?;
    f.set_len(len)?;
    Ok(true)
}

/// Copy `src` to `dst` (replaced), leaving all-zero 64 KiB blocks as holes.
pub fn copy_sparse(src: &Path, dst: &Path) -> io::Result<()> {
    const BLOCK: usize = 64 << 10;
    let mut input = File::open(src)?;
    let len = input.metadata()?.len();
    let tmp = dst.with_extension("copying");
    let mut out = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    set_sparse(&out)?;
    let mut buf = vec![0u8; BLOCK];
    let mut pos = 0u64;
    while pos < len {
        let want = BLOCK.min((len - pos) as usize);
        input.read_exact(&mut buf[..want])?;
        if buf[..want].iter().any(|&b| b != 0) {
            out.seek(SeekFrom::Start(pos))?;
            out.write_all(&buf[..want])?;
        }
        pos += want as u64;
    }
    out.set_len(len)?;
    out.sync_all()?;
    drop(out);
    std::fs::rename(&tmp, dst)
}

/// Bytes actually allocated on disk for `path`, where the platform can tell (for reporting).
pub fn allocated(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|m| m.blocks() * 512)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_create_grow_copy() {
        let dir = std::env::temp_dir().join(format!("osbx-disk-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.img");
        create_sparse(&a, 1 << 20).unwrap();
        {
            let mut f = OpenOptions::new().write(true).open(&a).unwrap();
            f.seek(SeekFrom::Start(300_000)).unwrap();
            f.write_all(b"osbx").unwrap();
        }
        assert!(grow_sparse(&a, 4 << 20).unwrap());
        assert!(!grow_sparse(&a, 2 << 20).unwrap(), "never shrinks");
        let b = dir.join("b.img");
        copy_sparse(&a, &b).unwrap();
        let data = std::fs::read(&b).unwrap();
        assert_eq!(data.len(), 4 << 20);
        assert_eq!(&data[300_000..300_004], b"osbx");
        assert_eq!(data.iter().filter(|&&x| x != 0).count(), 4);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
