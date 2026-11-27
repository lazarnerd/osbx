//! Minimal Intel/CFI parallel flash (`pflash`) emulation for persistent UEFI NVRAM
//! (`OVMF_VARS_4M.fd`).
//!
//! OVMF's `QemuFlashFvbServicesRuntimeDxe` probes the NVRAM window with CFI commands (`0x50`
//! clear status, `0x70` read status, `0x98` CFI query, `0x40`/`0x10` program, `0x20`/`0xD0` block
//! erase, `0xE8`/`0xD0` buffered write, `0xFF` read array). Writes are persisted to the backing
//! `OVMF_VARS` file so UEFI boot entries (`\EFI\Microsoft\Boot\bootmgfw.efi`) survive reboots.

use crate::virtio::blk::write_all_at;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;
use std::sync::Mutex;

const BLOCK_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    ReadArray,
    ReadStatus,
    ReadId,
    CfiQuery,
    Program,
    EraseSetup,
    BufferCount,
    BufferData {
        remaining: usize,
        dirty_start: usize,
        dirty_end: usize,
    },
    BufferConfirm {
        dirty_start: usize,
        dirty_end: usize,
    },
}

struct Inner {
    file: Option<File>,
    data: Vec<u8>,
    mode: Mode,
    status: u8,
}

/// Persistent CFI parallel flash device backing `OVMF_VARS`.
pub struct Pflash {
    base: u64,
    len: u64,
    inner: Mutex<Inner>,
}

impl Pflash {
    /// Open `path` as writable persistent NVRAM mapped at `base`.
    pub fn open(path: &Path, base: u64) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let data = std::fs::read(path)?;
        if data.is_empty() || !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("pflash file size {} is not 4 KiB-aligned", data.len()),
            ));
        }
        let len = data.len() as u64;
        Ok(Self {
            base,
            len,
            inner: Mutex::new(Inner {
                file: Some(file),
                data,
                mode: Mode::ReadArray,
                status: 0x80, // Ready
            }),
        })
    }

    /// Create an in-memory (non-persisted) pflash from initial bytes (used for unified `OVMF.fd`).
    pub fn from_bytes(data: Vec<u8>, base: u64) -> Self {
        let len = data.len() as u64;
        Self {
            base,
            len,
            inner: Mutex::new(Inner {
                file: None,
                data,
                mode: Mode::ReadArray,
                status: 0x80,
            }),
        }
    }

    /// Guest physical base address of this flash window.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Byte length of this flash window.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Returns true if the flash window is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns true if `addr` falls inside this flash window.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.len
    }

    /// Handle a guest MMIO read at absolute GPA `addr`.
    pub fn read(&self, addr: u64, out: &mut [u8]) {
        let off = (addr - self.base) as usize;
        let inner = self.inner.lock().unwrap();
        match inner.mode {
            Mode::ReadArray => {
                for (i, b) in out.iter_mut().enumerate() {
                    *b = inner.data.get(off + i).copied().unwrap_or(0xff);
                }
            }
            Mode::ReadStatus
            | Mode::Program
            | Mode::EraseSetup
            | Mode::BufferCount
            | Mode::BufferData { .. }
            | Mode::BufferConfirm { .. } => {
                out.fill(0);
                if let Some(first) = out.first_mut() {
                    *first = inner.status;
                }
            }
            Mode::ReadId => {
                out.fill(0);
                let val = match off & 0xff {
                    0x00 => 0x89, // Intel
                    0x01 => 0x18, // 128 Mbit / generic
                    _ => 0x00,
                };
                if let Some(first) = out.first_mut() {
                    *first = val;
                }
            }
            Mode::CfiQuery => {
                out.fill(0);
                let cfi = cfi_query_byte(off, inner.data.len());
                if let Some(first) = out.first_mut() {
                    *first = cfi;
                }
            }
        }
    }

    /// Handle a guest MMIO write at absolute GPA `addr`.
    pub fn write(&self, addr: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let off = (addr - self.base) as usize;
        let cmd = data[0];
        let mut inner = self.inner.lock().unwrap();

        match inner.mode {
            Mode::Program => {
                let end = (off + data.len()).min(inner.data.len());
                for (i, &b) in data.iter().enumerate() {
                    if off + i < end {
                        inner.data[off + i] = b;
                    }
                }
                persist(&inner, off, end);
                inner.status = 0x80;
                inner.mode = Mode::ReadStatus;
                return;
            }
            Mode::EraseSetup => {
                if cmd == 0xd0 {
                    let blk_start = (off / BLOCK_SIZE) * BLOCK_SIZE;
                    let blk_end = (blk_start + BLOCK_SIZE).min(inner.data.len());
                    inner.data[blk_start..blk_end].fill(0xff);
                    persist(&inner, blk_start, blk_end);
                }
                inner.status = 0x80;
                inner.mode = Mode::ReadStatus;
                return;
            }
            Mode::BufferCount => {
                let count = usize::from(cmd) + 1;
                inner.mode = Mode::BufferData {
                    remaining: count,
                    dirty_start: inner.data.len(),
                    dirty_end: 0,
                };
                return;
            }
            Mode::BufferData {
                remaining,
                mut dirty_start,
                mut dirty_end,
            } => {
                let end = (off + data.len()).min(inner.data.len());
                for (i, &b) in data.iter().enumerate() {
                    if off + i < end {
                        inner.data[off + i] = b;
                    }
                }
                dirty_start = dirty_start.min(off);
                dirty_end = dirty_end.max(end);
                if remaining <= 1 {
                    inner.mode = Mode::BufferConfirm {
                        dirty_start,
                        dirty_end,
                    };
                } else {
                    inner.mode = Mode::BufferData {
                        remaining: remaining - 1,
                        dirty_start,
                        dirty_end,
                    };
                }
                return;
            }
            Mode::BufferConfirm {
                dirty_start,
                dirty_end,
            } => {
                if cmd == 0xd0 && dirty_start < dirty_end {
                    persist(&inner, dirty_start, dirty_end);
                }
                inner.status = 0x80;
                inner.mode = Mode::ReadStatus;
                return;
            }
            _ => {}
        }

        match cmd {
            0xff => inner.mode = Mode::ReadArray,
            0x70 => inner.mode = Mode::ReadStatus,
            0x50 => {
                // Match QEMU pflash_cfi01: CLEAR_STATUS clears the status byte to 0x00
                // (OVMF's QemuFlashDetected checks for 0x00 after 0x50 -> 0x70).
                inner.status = 0x00;
                inner.mode = Mode::ReadArray;
            }
            0x90 => inner.mode = Mode::ReadId,
            0x98 => inner.mode = Mode::CfiQuery,
            0x40 | 0x10 => inner.mode = Mode::Program,
            0x20 => inner.mode = Mode::EraseSetup,
            0xe8 => {
                inner.status = 0x80;
                inner.mode = Mode::BufferCount;
            }
            _ => inner.mode = Mode::ReadArray,
        }
    }
}

fn persist(inner: &Inner, start: usize, end: usize) {
    if let Some(f) = &inner.file
        && start < end
    {
        let _ = write_all_at(f, &inner.data[start..end], start as u64);
    }
}

/// Minimal Intel CFI query table (8-bit device width) for OVMF `QemuFlashDetected`.
fn cfi_query_byte(off: usize, total_len: usize) -> u8 {
    let blocks = (total_len / BLOCK_SIZE).saturating_sub(1);
    let blk_256 = BLOCK_SIZE / 256;
    let size_pow2 = total_len.next_power_of_two().trailing_zeros() as u8;
    match off & 0xff {
        0x10 => b'Q',
        0x11 => b'R',
        0x12 => b'Y',
        0x13 => 0x01, // Primary vendor command set: Intel/Sharp Extended
        0x14 => 0x00,
        0x15 => 0x31, // Primary extended table addr
        0x16 => 0x00,
        0x1b => 0x45, // Vcc min
        0x1c => 0x55, // Vcc max
        0x1f..=0x26 => 0x00,
        0x27 => size_pow2,
        0x28 => 0x00, // x8 interface
        0x29 => 0x00,
        0x2a => 0x08, // max buffer write = 2^8 = 256 bytes
        0x2b => 0x00,
        0x2c => 0x01, // 1 erase block region
        0x2d => (blocks & 0xff) as u8,
        0x2e => ((blocks >> 8) & 0xff) as u8,
        0x2f => (blk_256 & 0xff) as u8,
        0x30 => ((blk_256 >> 8) & 0xff) as u8,
        _ => 0x00,
    }
}
