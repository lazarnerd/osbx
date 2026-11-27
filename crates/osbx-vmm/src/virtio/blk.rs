//! virtio-block: a raw or QCOW2 image exposed as a disk.

use super::{
    Activation, GuestMem, INT_USED_RING, Interrupt, SharedQueue, VIRTIO_F_VERSION_1, VirtioDevice,
};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use virtio_queue::{QueueOwnedT, QueueT};

const SECTOR: u64 = 512;
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
const T_GET_ID: u32 = 8;
const S_OK: u8 = 0;
const S_IOERR: u8 = 1;
const S_UNSUPP: u8 = 2;
const F_SEG_MAX: u64 = 1 << 2;
const F_BLK_SIZE: u64 = 1 << 6;
const F_RO: u64 = 1 << 5;
const F_FLUSH: u64 = 1 << 9;
/// Device id string reported to the guest (visible as /sys/block/vdX/serial).
const ID: &[u8; 20] = b"osbx-disk\0\0\0\0\0\0\0\0\0\0\0";

/// A random-access block storage backend (raw file, QCOW2 overlay, etc.).
pub trait BlockBackend: Send + Sync {
    /// Virtual disk size in bytes.
    fn len(&self) -> u64;
    /// Returns true if the disk has zero length.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Read `buf.len()` bytes starting at `offset`.
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;
    /// Write all of `buf` starting at `offset`.
    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()>;
    /// Flush dirty writes to durable storage.
    fn flush(&self) -> io::Result<()>;
}

/// Flat raw file block backend.
pub struct RawDisk {
    file: File,
    len: u64,
}

impl RawDisk {
    /// Open `path` as a flat raw disk image.
    pub fn open(path: &Path, read_only: bool) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(path)?;
        let len = file.metadata()?.len();
        Ok(Self { file, len })
    }
}

impl BlockBackend for RawDisk {
    fn len(&self) -> u64 {
        self.len
    }
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        read_exact_at(&self.file, buf, offset)
    }
    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        write_all_at(&self.file, buf, offset)
    }
    fn flush(&self) -> io::Result<()> {
        self.file.sync_data()
    }
}

/// A virtio-blk device backed by a [`BlockBackend`].
pub struct Block {
    backend: Box<dyn BlockBackend>,
    sectors: u64,
    read_only: bool,
    active: Option<(GuestMem, SharedQueue, Interrupt)>,
}

impl Block {
    /// Open `path` (auto-detecting QCOW2 v3 vs. flat raw image); the guest sees `floor(size / 512)`
    /// sectors.
    pub fn open(path: &Path, read_only: bool) -> io::Result<Self> {
        let backend: Box<dyn BlockBackend> = if crate::qcow2::is_qcow2(path)? {
            Box::new(crate::qcow2::Qcow2Disk::open(path, read_only)?)
        } else {
            Box::new(RawDisk::open(path, read_only)?)
        };
        Ok(Self::from_backend(backend, read_only))
    }

    /// Construct from an already-opened [`BlockBackend`].
    pub fn from_backend(backend: Box<dyn BlockBackend>, read_only: bool) -> Self {
        let sectors = backend.len() / SECTOR;
        Self {
            backend,
            sectors,
            read_only,
            active: None,
        }
    }
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        2
    }
    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1
            | F_SEG_MAX
            | F_BLK_SIZE
            | F_FLUSH
            | if self.read_only { F_RO } else { 0 }
    }
    fn queue_max_sizes(&self) -> Vec<u16> {
        vec![256]
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // virtio_blk_config: capacity (0..8), size_max (8..12), seg_max (12..16),
        // geometry (16..20), blk_size (20..24).
        let mut cfg = [0u8; 24];
        cfg[0..8].copy_from_slice(&self.sectors.to_le_bytes());
        cfg[12..16].copy_from_slice(&126u32.to_le_bytes());
        cfg[20..24].copy_from_slice(&(SECTOR as u32).to_le_bytes());
        for (i, b) in data.iter_mut().enumerate() {
            *b = cfg.get(offset as usize + i).copied().unwrap_or(0);
        }
    }
    fn activate(&mut self, a: Activation) {
        self.active = Some((a.mem, a.queues[0].clone(), a.irq));
    }
    fn queue_notify(&mut self, _queue: u32) {
        let Some((mem, queue, irq)) = self.active.clone() else {
            return;
        };
        let mut q = queue.lock().unwrap();
        let mut signal = false;
        while let Ok(iter) = q.iter(&mem) {
            let chains: Vec<_> = iter.collect();
            if chains.is_empty() {
                // re-enable notifications; stop unless more arrived in the meantime
                if q.enable_notification(&mem).unwrap_or(false) {
                    continue;
                }
                break;
            }
            for chain in chains {
                let head = chain.head_index();
                let used = self.handle(&mem, chain);
                if q.add_used(&mem, head, used).is_ok() {
                    signal = true;
                }
            }
        }
        if signal && q.needs_notification(&mem).unwrap_or(true) {
            drop(q);
            irq.signal(INT_USED_RING);
        }
    }
}

impl Block {
    /// Process one request; returns the number of bytes written into the guest's buffers.
    fn handle(&self, mem: &GuestMem, chain: virtio_queue::DescriptorChain<&GuestMem>) -> u32 {
        let (Ok(mut rd), Ok(mut wr)) = (chain.clone().reader(mem), chain.writer(mem)) else {
            return 0;
        };
        let mut hdr = [0u8; 16];
        if rd.read_exact(&mut hdr).is_err() {
            return 0;
        }
        let kind = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let sector = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
        let writable = wr.available_bytes();
        let mut status = S_OK;
        let mut written = 0u32;
        match kind {
            T_IN if writable >= 1 => {
                let len = writable - 1;
                let end = sector
                    .checked_mul(SECTOR)
                    .and_then(|o| o.checked_add(len as u64));
                if end.is_none_or(|e| e > self.sectors * SECTOR) {
                    status = S_IOERR;
                } else {
                    let mut buf = vec![0u8; len];
                    if self
                        .backend
                        .read_exact_at(&mut buf, sector * SECTOR)
                        .is_ok()
                        && wr.write_all(&buf).is_ok()
                    {
                        written = len as u32;
                    } else {
                        status = S_IOERR;
                    }
                }
            }
            T_OUT if !self.read_only => {
                let len = rd.available_bytes();
                let end = sector
                    .checked_mul(SECTOR)
                    .and_then(|o| o.checked_add(len as u64));
                if end.is_none_or(|e| e > self.sectors * SECTOR) {
                    status = S_IOERR;
                } else {
                    let mut buf = vec![0u8; len];
                    if rd.read_exact(&mut buf).is_err()
                        || self.backend.write_all_at(&buf, sector * SECTOR).is_err()
                    {
                        status = S_IOERR;
                    }
                }
            }
            T_OUT => status = S_IOERR,
            T_FLUSH => {
                if self.backend.flush().is_err() {
                    status = S_IOERR;
                }
            }
            T_GET_ID if writable >= 21 => {
                if wr.write_all(ID).is_ok() {
                    written = ID.len() as u32;
                }
            }
            _ => status = S_UNSUPP,
        }
        // The status byte is the last byte of the writable area. Writes fill buffers in order, so
        // skip any unwritten data bytes before it.
        let pad = writable.saturating_sub(written as usize + 1);
        if pad > 0 && wr.write_all(&vec![0u8; pad]).is_err() {
            return written;
        }
        if wr.write_all(&[status]).is_ok() {
            writable as u32
        } else {
            written
        }
    }
}

/// Positional read of exactly `buf.len()` bytes at `off`.
pub(crate) fn read_exact_at(f: &File, mut buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::FileExt;
    #[cfg(windows)]
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        #[cfg(unix)]
        let n = f.read_at(buf, off)?;
        #[cfg(windows)]
        let n = f.seek_read(buf, off)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n..];
        off += n as u64;
    }
    Ok(())
}

/// Positional write of all of `buf` at `off`.
pub(crate) fn write_all_at(f: &File, mut buf: &[u8], mut off: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::FileExt;
    #[cfg(windows)]
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        #[cfg(unix)]
        let n = f.write_at(buf, off)?;
        #[cfg(windows)]
        let n = f.seek_write(buf, off)?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        buf = &buf[n..];
        off += n as u64;
    }
    Ok(())
}
