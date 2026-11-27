//! Pure-Rust QCOW2 v3 block backend with copy-on-write backing file support.
//!
//! Designed for instant Windows sandbox creation (`osbx create --os windows`) on any host
//! filesystem (Linux ext4/xfs/btrfs and Windows NTFS) without copying 20–40 GiB base disks.
//! Images created and written here conform to the QCOW2 v3 specification (`qemu-img check` clean).

use crate::virtio::blk::{BlockBackend, RawDisk, read_exact_at, write_all_at};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// QCOW2 file magic (`"QFI\xfb"`).
pub const QCOW2_MAGIC: [u8; 4] = [b'Q', b'F', b'I', 0xfb];
const QCOW2_VERSION: u32 = 3;
const DEFAULT_CLUSTER_BITS: u32 = 16; // 64 KiB clusters
const HEADER_LEN_V3: u32 = 104;
const REFCOUNT_ORDER_16BIT: u32 = 4; // 2^4 = 16-bit refcount entries
const EXT_END: u32 = 0;
const EXT_BACKING_FORMAT: u32 = 0xe279_2aca;
const OFLAG_COPIED: u64 = 1 << 63;
const OFLAG_COMPRESSED: u64 = 1 << 62;
const OFLAG_ZERO: u64 = 1;
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const MAX_CACHED_L2: usize = 512;

/// Backing image format recorded in the QCOW2 header extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackingFormat {
    /// Raw flat image.
    Raw,
    /// Another QCOW2 image.
    Qcow2,
}

impl BackingFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Qcow2 => "qcow2",
        }
    }
}

/// Returns `true` if `path` starts with the QCOW2 magic bytes.
pub fn is_qcow2(path: &Path) -> io::Result<bool> {
    let f = File::open(path)?;
    if f.metadata()?.len() < 4 {
        return Ok(false);
    }
    let mut magic = [0u8; 4];
    read_exact_at(&f, &mut magic, 0)?;
    Ok(magic == QCOW2_MAGIC)
}

/// Create an empty sparse QCOW2 v3 base image of `virtual_size` bytes.
pub fn create_base(path: &Path, virtual_size: u64) -> io::Result<()> {
    create_image(path, virtual_size, None)
}

/// Create a QCOW2 v3 copy-on-write overlay backed by `backing_path`.
///
/// The overlay inherits the virtual size of `backing_path` and starts at ~256 KiB on disk.
pub fn create_overlay(overlay_path: &Path, backing_path: &Path) -> io::Result<()> {
    let (virtual_size, fmt) = if is_qcow2(backing_path)? {
        let b = Qcow2Disk::open(backing_path, true)?;
        (b.len(), BackingFormat::Qcow2)
    } else {
        (std::fs::metadata(backing_path)?.len(), BackingFormat::Raw)
    };
    let backing_str = backing_path.to_string_lossy();
    create_image(overlay_path, virtual_size, Some((&backing_str, fmt)))
}

fn create_image(
    path: &Path,
    virtual_size: u64,
    backing: Option<(&str, BackingFormat)>,
) -> io::Result<()> {
    if virtual_size == 0 || !virtual_size.is_multiple_of(512) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "qcow2 virtual size must be a positive multiple of 512 bytes",
        ));
    }
    let cluster_size = 1u64 << DEFAULT_CLUSTER_BITS;
    let l2_entries = cluster_size / 8;
    let l1_coverage = l2_entries * cluster_size;
    let l1_size = virtual_size.div_ceil(l1_coverage) as u32;
    let l1_bytes = u64::from(l1_size) * 8;
    let l1_clusters = l1_bytes.div_ceil(cluster_size).max(1);

    let refcount_table_offset = cluster_size; // cluster 1
    let refcount_block_offset = 2 * cluster_size; // cluster 2
    let l1_table_offset = 3 * cluster_size; // cluster 3..
    let total_initial_clusters = 3 + l1_clusters;

    let mut hdr = vec![0u8; cluster_size as usize];
    hdr[0..4].copy_from_slice(&QCOW2_MAGIC);
    hdr[4..8].copy_from_slice(&QCOW2_VERSION.to_be_bytes());
    // backing_file_offset/size filled below if backing is present
    hdr[20..24].copy_from_slice(&DEFAULT_CLUSTER_BITS.to_be_bytes());
    hdr[24..32].copy_from_slice(&virtual_size.to_be_bytes());
    hdr[32..36].copy_from_slice(&0u32.to_be_bytes()); // crypt_method = none
    hdr[36..40].copy_from_slice(&l1_size.to_be_bytes());
    hdr[40..48].copy_from_slice(&l1_table_offset.to_be_bytes());
    hdr[48..56].copy_from_slice(&refcount_table_offset.to_be_bytes());
    hdr[56..60].copy_from_slice(&1u32.to_be_bytes()); // refcount_table_clusters = 1
    hdr[96..100].copy_from_slice(&REFCOUNT_ORDER_16BIT.to_be_bytes());
    hdr[100..104].copy_from_slice(&HEADER_LEN_V3.to_be_bytes());

    let mut cursor = HEADER_LEN_V3 as usize;
    if let Some((backing_name, fmt)) = backing {
        let fmt_bytes = fmt.as_str().as_bytes();
        hdr[cursor..cursor + 4].copy_from_slice(&EXT_BACKING_FORMAT.to_be_bytes());
        hdr[cursor + 4..cursor + 8].copy_from_slice(&(fmt_bytes.len() as u32).to_be_bytes());
        cursor += 8;
        hdr[cursor..cursor + fmt_bytes.len()].copy_from_slice(fmt_bytes);
        cursor += fmt_bytes.len().next_multiple_of(8);
        // End-of-extensions marker
        hdr[cursor..cursor + 4].copy_from_slice(&EXT_END.to_be_bytes());
        hdr[cursor + 4..cursor + 8].copy_from_slice(&0u32.to_be_bytes());
        cursor += 8;

        let name_bytes = backing_name.as_bytes();
        if cursor + name_bytes.len() > cluster_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backing file path exceeds header cluster size",
            ));
        }
        hdr[8..16].copy_from_slice(&(cursor as u64).to_be_bytes());
        hdr[16..20].copy_from_slice(&(name_bytes.len() as u32).to_be_bytes());
        hdr[cursor..cursor + name_bytes.len()].copy_from_slice(name_bytes);
    }

    let mut rc_table = vec![0u8; cluster_size as usize];
    rc_table[0..8].copy_from_slice(&refcount_block_offset.to_be_bytes());

    let mut rc_block = vec![0u8; cluster_size as usize];
    for c in 0..total_initial_clusters as usize {
        rc_block[c * 2..c * 2 + 2].copy_from_slice(&1u16.to_be_bytes());
    }

    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.set_len(total_initial_clusters * cluster_size)?;
    write_all_at(&f, &hdr, 0)?;
    write_all_at(&f, &rc_table, refcount_table_offset)?;
    write_all_at(&f, &rc_block, refcount_block_offset)?;
    f.sync_data()?;
    Ok(())
}

struct Qcow2Inner {
    file: File,
    read_only: bool,
    cluster_size: u64,
    virtual_size: u64,
    l1_table_offset: u64,
    l1_table: Vec<u64>,
    rc_table_offset: u64,
    rc_table: Vec<u64>,
    rc_entries_per_block: u64,
    next_free_cluster: u64,
    l2_cache: HashMap<u64, Vec<u64>>,
    backing: Option<Box<dyn BlockBackend>>,
}

/// A QCOW2 v3 block device backend (supports optional read-only backing chain).
pub struct Qcow2Disk {
    virtual_size: u64,
    inner: Mutex<Qcow2Inner>,
}

impl Qcow2Disk {
    /// Open an existing QCOW2 v3 file (and its backing chain, if any).
    pub fn open(path: &Path, read_only: bool) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(!read_only).open(path)?;
        let file_len = file.metadata()?.len();
        if file_len < u64::from(HEADER_LEN_V3) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file too small to be a qcow2 v3 image",
            ));
        }
        let mut hdr = [0u8; HEADER_LEN_V3 as usize];
        read_exact_at(&file, &mut hdr, 0)?;
        if hdr[0..4] != QCOW2_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid qcow2 magic",
            ));
        }
        let version = u32::from_be_bytes(hdr[4..8].try_into().unwrap());
        if version != QCOW2_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported qcow2 version {version} (expected 3)"),
            ));
        }
        let backing_off = u64::from_be_bytes(hdr[8..16].try_into().unwrap());
        let backing_len = u32::from_be_bytes(hdr[16..20].try_into().unwrap()) as usize;
        let cluster_bits = u32::from_be_bytes(hdr[20..24].try_into().unwrap());
        if !(12..=21).contains(&cluster_bits) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported qcow2 cluster_bits {cluster_bits}"),
            ));
        }
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = u64::from_be_bytes(hdr[24..32].try_into().unwrap());
        let crypt_method = u32::from_be_bytes(hdr[32..36].try_into().unwrap());
        if crypt_method != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "encrypted qcow2 images are not supported",
            ));
        }
        let l1_size = u32::from_be_bytes(hdr[36..40].try_into().unwrap()) as usize;
        let l1_table_offset = u64::from_be_bytes(hdr[40..48].try_into().unwrap());
        let rc_table_offset = u64::from_be_bytes(hdr[48..56].try_into().unwrap());
        let rc_table_clusters = u32::from_be_bytes(hdr[56..60].try_into().unwrap()) as u64;
        let incompat = u64::from_be_bytes(hdr[72..80].try_into().unwrap());
        if incompat != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported qcow2 incompatible_features 0x{incompat:x}"),
            ));
        }
        let rc_order = u32::from_be_bytes(hdr[96..100].try_into().unwrap());
        if rc_order != REFCOUNT_ORDER_16BIT {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported qcow2 refcount_order {rc_order} (expected 4)"),
            ));
        }

        let l1_table = read_u64_table(&file, l1_table_offset, l1_size)?;
        let rc_table_entries = (rc_table_clusters * cluster_size / 8) as usize;
        let rc_table = read_u64_table(&file, rc_table_offset, rc_table_entries)?;
        let rc_entries_per_block = cluster_size / 2;

        let backing: Option<Box<dyn BlockBackend>> = if backing_off != 0 && backing_len > 0 {
            let mut raw = vec![0u8; backing_len];
            read_exact_at(&file, &mut raw, backing_off)?;
            let name = String::from_utf8(raw).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 backing file path")
            })?;
            let resolved = resolve_backing_path(path, &name);
            if is_qcow2(&resolved)? {
                Some(Box::new(Qcow2Disk::open(&resolved, true)?))
            } else {
                Some(Box::new(RawDisk::open(&resolved, true)?))
            }
        } else {
            None
        };

        let next_free_cluster = file_len.div_ceil(cluster_size).max(4);
        Ok(Self {
            virtual_size,
            inner: Mutex::new(Qcow2Inner {
                file,
                read_only,
                cluster_size,
                virtual_size,
                l1_table_offset,
                l1_table,
                rc_table_offset,
                rc_table,
                rc_entries_per_block,
                next_free_cluster,
                l2_cache: HashMap::new(),
                backing,
            }),
        })
    }
}

impl Qcow2Inner {
    fn l2_entries(&self) -> u64 {
        self.cluster_size / 8
    }

    fn alloc_cluster(&mut self) -> io::Result<u64> {
        let cluster_idx = self.next_free_cluster;
        self.next_free_cluster += 1;
        let host_off = cluster_idx * self.cluster_size;
        self.file.set_len(host_off + self.cluster_size)?;
        self.set_refcount_one(cluster_idx)?;
        Ok(host_off)
    }

    fn set_refcount_one(&mut self, cluster_idx: u64) -> io::Result<()> {
        let rt_idx = (cluster_idx / self.rc_entries_per_block) as usize;
        let rb_idx = (cluster_idx % self.rc_entries_per_block) as usize;
        if rt_idx >= self.rc_table.len() {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "qcow2 refcount table capacity exceeded",
            ));
        }
        let mut rb_off = self.rc_table[rt_idx] & OFFSET_MASK;
        if rb_off == 0 {
            // Allocate a fresh refcount block cluster and record it in the refcount table.
            let rb_cluster = self.next_free_cluster;
            self.next_free_cluster += 1;
            rb_off = rb_cluster * self.cluster_size;
            self.file.set_len(rb_off + self.cluster_size)?;
            let zeros = vec![0u8; self.cluster_size as usize];
            write_all_at(&self.file, &zeros, rb_off)?;
            self.rc_table[rt_idx] = rb_off;
            write_all_at(
                &self.file,
                &rb_off.to_be_bytes(),
                self.rc_table_offset + (rt_idx as u64) * 8,
            )?;
            // Mark the new refcount block's own cluster refcount = 1.
            let self_rt = (rb_cluster / self.rc_entries_per_block) as usize;
            let self_rb = (rb_cluster % self.rc_entries_per_block) as usize;
            let self_off = self.rc_table[self_rt] & OFFSET_MASK;
            write_all_at(
                &self.file,
                &1u16.to_be_bytes(),
                self_off + (self_rb as u64) * 2,
            )?;
        }
        write_all_at(
            &self.file,
            &1u16.to_be_bytes(),
            rb_off + (rb_idx as u64) * 2,
        )
    }

    fn load_l2(&mut self, l2_off: u64) -> io::Result<&Vec<u64>> {
        if !self.l2_cache.contains_key(&l2_off) {
            if self.l2_cache.len() >= MAX_CACHED_L2 {
                self.l2_cache.clear();
            }
            let table = read_u64_table(&self.file, l2_off, self.l2_entries() as usize)?;
            self.l2_cache.insert(l2_off, table);
        }
        Ok(self.l2_cache.get(&l2_off).unwrap())
    }

    fn read_backing_or_zero(&self, buf: &mut [u8], guest_off: u64) -> io::Result<()> {
        if let Some(b) = &self.backing {
            let b_len = b.len();
            if guest_off >= b_len {
                buf.fill(0);
                return Ok(());
            }
            let avail = (b_len - guest_off).min(buf.len() as u64) as usize;
            b.read_exact_at(&mut buf[..avail], guest_off)?;
            if avail < buf.len() {
                buf[avail..].fill(0);
            }
        } else {
            buf.fill(0);
        }
        Ok(())
    }

    fn read_exact_at(&mut self, mut buf: &mut [u8], mut guest_off: u64) -> io::Result<()> {
        if guest_off
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.virtual_size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "qcow2 read past end of virtual disk",
            ));
        }
        let cs = self.cluster_size;
        let l2_count = self.l2_entries();
        while !buf.is_empty() {
            let cluster = guest_off / cs;
            let in_cluster = (guest_off % cs) as usize;
            let take = ((cs as usize) - in_cluster).min(buf.len());
            let l1_idx = (cluster / l2_count) as usize;
            let l2_idx = (cluster % l2_count) as usize;

            let l1_entry = self.l1_table.get(l1_idx).copied().unwrap_or(0);
            let l2_off = l1_entry & OFFSET_MASK;
            if l2_off == 0 {
                self.read_backing_or_zero(&mut buf[..take], guest_off)?;
            } else {
                let l2_entry = self.load_l2(l2_off)?[l2_idx];
                if l2_entry & OFLAG_COMPRESSED != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "compressed qcow2 clusters are not supported",
                    ));
                }
                if l2_entry & OFLAG_ZERO != 0 {
                    buf[..take].fill(0);
                } else {
                    let data_off = l2_entry & OFFSET_MASK;
                    if data_off == 0 {
                        self.read_backing_or_zero(&mut buf[..take], guest_off)?;
                    } else {
                        read_exact_at(&self.file, &mut buf[..take], data_off + in_cluster as u64)?;
                    }
                }
            }

            buf = &mut buf[take..];
            guest_off += take as u64;
        }
        Ok(())
    }

    fn write_all_at(&mut self, mut buf: &[u8], mut guest_off: u64) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "qcow2 image opened read-only",
            ));
        }
        if guest_off
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.virtual_size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "qcow2 write past end of virtual disk",
            ));
        }
        let cs = self.cluster_size;
        let l2_count = self.l2_entries();
        while !buf.is_empty() {
            let cluster = guest_off / cs;
            let in_cluster = (guest_off % cs) as usize;
            let take = ((cs as usize) - in_cluster).min(buf.len());
            let l1_idx = (cluster / l2_count) as usize;
            let l2_idx = (cluster % l2_count) as usize;

            let mut l2_off = self.l1_table[l1_idx] & OFFSET_MASK;
            if l2_off == 0 {
                l2_off = self.alloc_cluster()?;
                let zeros = vec![0u8; cs as usize];
                write_all_at(&self.file, &zeros, l2_off)?;
                let l1_entry = l2_off | OFLAG_COPIED;
                self.l1_table[l1_idx] = l1_entry;
                write_all_at(
                    &self.file,
                    &l1_entry.to_be_bytes(),
                    self.l1_table_offset + (l1_idx as u64) * 8,
                )?;
                self.l2_cache.insert(l2_off, vec![0u64; l2_count as usize]);
            }

            let l2_entry = self.load_l2(l2_off)?[l2_idx];
            if l2_entry & OFLAG_COMPRESSED != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "overwriting compressed qcow2 clusters is not supported",
                ));
            }
            let existing_off = l2_entry & OFFSET_MASK;
            let is_zero = l2_entry & OFLAG_ZERO != 0;
            let data_off = if existing_off == 0 || is_zero {
                let new_off = self.alloc_cluster()?;
                if in_cluster != 0 || take != cs as usize {
                    // Copy-on-write: materialize untouched bytes of this cluster from backing/zeros.
                    let mut full = vec![0u8; cs as usize];
                    if !is_zero {
                        self.read_backing_or_zero(&mut full, cluster * cs)?;
                    }
                    full[in_cluster..in_cluster + take].copy_from_slice(&buf[..take]);
                    write_all_at(&self.file, &full, new_off)?;
                } else {
                    write_all_at(&self.file, &buf[..take], new_off)?;
                }
                let new_l2_entry = new_off | OFLAG_COPIED;
                if let Some(cached) = self.l2_cache.get_mut(&l2_off) {
                    cached[l2_idx] = new_l2_entry;
                }
                write_all_at(
                    &self.file,
                    &new_l2_entry.to_be_bytes(),
                    l2_off + (l2_idx as u64) * 8,
                )?;
                new_off
            } else {
                write_all_at(&self.file, &buf[..take], existing_off + in_cluster as u64)?;
                existing_off
            };
            let _ = data_off;

            buf = &buf[take..];
            guest_off += take as u64;
        }
        Ok(())
    }
}

impl BlockBackend for Qcow2Disk {
    fn len(&self) -> u64 {
        self.virtual_size
    }

    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.inner.lock().unwrap().read_exact_at(buf, offset)
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        self.inner.lock().unwrap().write_all_at(buf, offset)
    }

    fn flush(&self) -> io::Result<()> {
        self.inner.lock().unwrap().file.sync_data()
    }
}

fn read_u64_table(file: &File, offset: u64, count: usize) -> io::Result<Vec<u64>> {
    let mut raw = vec![0u8; count * 8];
    read_exact_at(file, &mut raw, offset)?;
    Ok(raw
        .as_chunks::<8>()
        .0
        .iter()
        .map(|&c| u64::from_be_bytes(c))
        .collect())
}

fn resolve_backing_path(overlay: &Path, backing: &str) -> PathBuf {
    let p = Path::new(backing);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        overlay.parent().unwrap_or_else(|| Path::new(".")).join(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(tag: &str) -> (PathBuf, Cleanup) {
        let dir = std::env::temp_dir().join(format!("osbx-qcow2-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (dir.clone(), Cleanup(dir))
    }

    #[test]
    fn base_and_overlay_cow_preserves_backing_and_reopens() {
        let (dir, _guard) = temp_dir("cow");
        let base_path = dir.join("base.qcow2");
        let overlay_path = dir.join("overlay.qcow2");
        let size = 4 << 20; // 4 MiB

        create_base(&base_path, size).unwrap();
        assert!(is_qcow2(&base_path).unwrap());

        {
            let base = Qcow2Disk::open(&base_path, false).unwrap();
            assert_eq!(base.len(), size);
            // Write across a 64 KiB cluster boundary in the base image.
            let pattern: Vec<u8> = (0..81920u32).map(|i| (i % 251) as u8).collect();
            base.write_all_at(&pattern, 60000).unwrap();
            base.flush().unwrap();
        }
        let base_bytes_before = std::fs::read(&base_path).unwrap();

        create_overlay(&overlay_path, &base_path).unwrap();
        assert!(std::fs::metadata(&overlay_path).unwrap().len() < 512 * 1024);

        {
            let ov = Qcow2Disk::open(&overlay_path, false).unwrap();
            assert_eq!(ov.len(), size);

            // Reads fall through to base image.
            let mut got = vec![0u8; 81920];
            ov.read_exact_at(&mut got, 60000).unwrap();
            let expected: Vec<u8> = (0..81920u32).map(|i| (i % 251) as u8).collect();
            assert_eq!(got, expected);

            // Partial-cluster CoW write modifies only the written range; surrounding bytes stay intact.
            ov.write_all_at(b"OVERLAY-PATCH", 65530).unwrap();
            ov.flush().unwrap();
        }

        // Reopen overlay and verify persistence + CoW integrity.
        {
            let ov = Qcow2Disk::open(&overlay_path, true).unwrap();
            let mut got = vec![0u8; 81920];
            ov.read_exact_at(&mut got, 60000).unwrap();
            let mut expected: Vec<u8> = (0..81920u32).map(|i| (i % 251) as u8).collect();
            expected[5530..5530 + 13].copy_from_slice(b"OVERLAY-PATCH");
            assert_eq!(got, expected);

            // Unwritten region reads as zeros.
            let mut zeros = vec![0xaa; 4096];
            ov.read_exact_at(&mut zeros, 2 << 20).unwrap();
            assert!(zeros.iter().all(|&b| b == 0));
        }

        // Base image must be byte-for-byte untouched.
        assert_eq!(std::fs::read(&base_path).unwrap(), base_bytes_before);

        // If qemu-img is installed, verify both images pass `qemu-img check` with 0 errors.
        if Command::new("qemu-img").arg("--version").output().is_ok() {
            for p in [&base_path, &overlay_path] {
                let out = Command::new("qemu-img")
                    .args(["check", "-f", "qcow2"])
                    .arg(p)
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "qemu-img check failed for {}:\nstdout: {}\nstderr: {}",
                    p.display(),
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }

    #[test]
    fn overlay_over_raw_backing_works() {
        let (dir, _guard) = temp_dir("raw-backing");
        let raw_path = dir.join("base.raw");
        let overlay_path = dir.join("ov.qcow2");
        let mut raw = vec![0u8; 256 * 1024];
        raw[1024..1035].copy_from_slice(b"hello-world");
        std::fs::write(&raw_path, &raw).unwrap();

        create_overlay(&overlay_path, &raw_path).unwrap();
        let ov = Qcow2Disk::open(&overlay_path, false).unwrap();
        let mut buf = [0u8; 11];
        ov.read_exact_at(&mut buf, 1024).unwrap();
        assert_eq!(&buf, b"hello-world");

        ov.write_all_at(b"HELLO", 1024).unwrap();
        ov.read_exact_at(&mut buf, 1024).unwrap();
        assert_eq!(&buf, b"HELLO-world");
        // Raw backing untouched.
        assert_eq!(
            &std::fs::read(&raw_path).unwrap()[1024..1035],
            b"hello-world"
        );
    }
}
