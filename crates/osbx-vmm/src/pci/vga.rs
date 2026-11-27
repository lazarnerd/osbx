//! Minimal Bochs VBE PCI display adapter (`1234:1111`) for UEFI GOP framebuffer support.
//!
//! OVMF's `QemuVideoDxe` binds to PCI `1234:1111` and exposes a UEFI Graphics Output Protocol
//! (GOP) linear framebuffer over BAR0 (`16 MiB`). Windows `bootmgfw.efi` and Windows Setup
//! require a UEFI GOP framebuffer even on headless Server Core editions.

use crate::pci::{BarSet, BarSpec, PciDevice};
use std::sync::{Arc, Mutex};

/// Size of the linear framebuffer BAR0 (16 MiB).
pub const VGA_FB_SIZE: u64 = 16 << 20;
/// Size of the Bochs VGA MMIO register BAR2 (4 KiB).
pub const VGA_MMIO_SIZE: u64 = 0x1000;
/// Bochs VBE dispi index I/O port.
pub const VBE_DISPI_INDEX_PORT: u16 = 0x01ce;
/// Bochs VBE dispi data I/O port.
pub const VBE_DISPI_DATA_PORT: u16 = 0x01cf;

/// Callback notified whenever BAR0's guest physical address changes (or Memory Space Enable
/// toggles) so the hypervisor can map the linear framebuffer backing memory directly into guest
/// RAM (zero VM exits for pixel writes).
pub type BarMapper = Arc<dyn Fn(Option<u64>) + Send + Sync>;

/// Shared VBE mode registers + host-accessible framebuffer metadata.
#[derive(Default)]
pub struct VbeState {
    index: u16,
    regs: [u16; 11],
}

impl VbeState {
    fn new() -> Self {
        let mut regs = [0u16; 11];
        regs[0] = 0xb0c5; // VBE_DISPI_ID5
        regs[1] = 1024; // XRES
        regs[2] = 768; // YRES
        regs[3] = 32; // BPP
        regs[10] = (VGA_FB_SIZE >> 16) as u16; // video memory in 64 KiB units (256 = 16 MiB)
        Self { index: 0, regs }
    }

    /// Write VBE index port (`0x01CE`).
    pub fn write_index(&mut self, val: u16) {
        self.index = val;
    }

    /// Read VBE index port (`0x01CE`).
    pub fn read_index(&self) -> u16 {
        self.index
    }

    /// Read a Bochs dispi register by index directly (used by BAR2 MMIO at `0x500 + idx*2`).
    pub fn read_reg(&self, idx: usize) -> u16 {
        match idx {
            0 => self.regs[0],
            1..=9 => self.regs[idx],
            10 => (VGA_FB_SIZE >> 16) as u16,
            _ => 0,
        }
    }

    /// Write a Bochs dispi register by index directly (used by BAR2 MMIO at `0x500 + idx*2`).
    pub fn write_reg(&mut self, idx: usize, val: u16) {
        if idx == 0 {
            if (0xb0c0..=0xb0c5).contains(&val) {
                self.regs[0] = val;
            }
        } else if idx < 10 {
            self.regs[idx] = val;
        }
    }

    /// Write VBE data port (`0x01CF`).
    pub fn write_data(&mut self, val: u16) {
        self.write_reg(usize::from(self.index), val);
    }

    /// Read VBE data port (`0x01CF`).
    pub fn read_data(&self) -> u16 {
        self.read_reg(usize::from(self.index))
    }

    /// Current `(width, height, bpp, enabled)`.
    pub fn mode(&self) -> (u16, u16, u16, bool) {
        (
            self.regs[1],
            self.regs[2],
            self.regs[3],
            self.regs[4] & 1 != 0,
        )
    }
}

/// Bochs VBE PCI device (`1234:1111`, class `030000` VGA compatible).
pub struct BochsVga {
    cfg: [u8; 256],
    bars: BarSet,
    mapped_base: Option<u64>,
    mapper: BarMapper,
    vbe: Arc<Mutex<VbeState>>,
    ext_endian: Mutex<u32>,
    retrace: Mutex<u8>,
}

impl BochsVga {
    /// Create a Bochs VBE PCI device with initial BAR0 `bar0`, BAR2 MMIO `bar2`, and hypervisor
    /// slot `mapper`.
    pub fn new(bar0: u64, bar2: u64, mapper: BarMapper) -> (Self, Arc<Mutex<VbeState>>) {
        let mut cfg = [0u8; 256];
        cfg[0x00..0x02].copy_from_slice(&0x1234u16.to_le_bytes()); // Vendor: Bochs/QEMU
        cfg[0x02..0x04].copy_from_slice(&0x1111u16.to_le_bytes()); // Device: Bochs Display
        cfg[0x08..0x0c].copy_from_slice(&0x0300_0002u32.to_le_bytes()); // Class: VGA, rev 2
        cfg[0x2c..0x2e].copy_from_slice(&0x1af4u16.to_le_bytes());
        cfg[0x2e..0x30].copy_from_slice(&0x1100u16.to_le_bytes());

        let bars = BarSet::new(
            vec![
                BarSpec {
                    index: 0,
                    size: VGA_FB_SIZE,
                    is_64bit: false,
                    prefetchable: true,
                    direct_mapped: true,
                },
                BarSpec {
                    index: 2,
                    size: VGA_MMIO_SIZE,
                    is_64bit: false,
                    prefetchable: false,
                    direct_mapped: false,
                },
            ],
            &[(0, bar0), (2, bar2)],
        );
        let vbe = Arc::new(Mutex::new(VbeState::new()));
        let dev = Self {
            cfg,
            bars,
            mapped_base: None,
            mapper,
            vbe: vbe.clone(),
            ext_endian: Mutex::new(0x1e1e_1e1e),
            retrace: Mutex::new(0),
        };
        (dev, vbe)
    }

    /// Access the shared VBE register state.
    pub fn vbe(&self) -> &Arc<Mutex<VbeState>> {
        &self.vbe
    }

    fn sync_mapping(&mut self) {
        let cmd = u16::from_le_bytes([self.cfg[0x04], self.cfg[0x05]]);
        let mem_enabled = cmd & 0x02 != 0;
        let base = self.bars.base(0);
        let want = (mem_enabled && base != 0).then_some(base);
        if want != self.mapped_base {
            self.mapped_base = want;
            (self.mapper)(want);
        }
    }
}

impl PciDevice for BochsVga {
    fn config_read(&self, offset: usize, data: &mut [u8]) {
        if (0x10..0x28).contains(&offset) {
            let reg_idx = (offset - 0x10) / 4;
            let byte_off = (offset - 0x10) % 4;
            let v = self.bars.read_u32(reg_idx).to_le_bytes();
            for (i, b) in data.iter_mut().enumerate() {
                *b = v.get(byte_off + i).copied().unwrap_or(0);
            }
            return;
        }
        for (i, b) in data.iter_mut().enumerate() {
            *b = self.cfg.get(offset + i).copied().unwrap_or(0);
        }
    }

    fn config_write(&mut self, offset: usize, data: &[u8]) {
        if (0x10..0x28).contains(&offset) && data.len() == 4 && offset.is_multiple_of(4) {
            let reg_idx = (offset - 0x10) / 4;
            let val = u32::from_le_bytes(data.try_into().unwrap());
            self.bars.write_u32(reg_idx, val);
            self.sync_mapping();
            return;
        }
        let mut cmd_changed = false;
        for (i, &b) in data.iter().enumerate() {
            let idx = offset + i;
            if matches!(idx, 0x04..=0x05 | 0x0c..=0x0d | 0x3c) {
                self.cfg[idx] = b;
                if matches!(idx, 0x04..=0x05) {
                    cmd_changed = true;
                }
            }
        }
        if cmd_changed {
            self.sync_mapping();
        }
    }

    fn active_bars(&self) -> Vec<(usize, u64, u64)> {
        // BAR0 is direct-mapped as a KVM memory slot; BAR2 exposes MMIO VBE/VGA registers.
        let cmd = u16::from_le_bytes([self.cfg[0x04], self.cfg[0x05]]);
        if cmd & 0x02 == 0 {
            return Vec::new();
        }
        let base2 = self.bars.base(2);
        if base2 != 0 {
            vec![(2, base2, VGA_MMIO_SIZE)]
        } else {
            Vec::new()
        }
    }

    fn bar_read(&self, bar: usize, offset: u64, data: &mut [u8]) {
        if bar != 2 {
            data.fill(0xff);
            return;
        }
        match offset {
            0x41a => {
                let mut r = self.retrace.lock().unwrap();
                *r ^= 0x09;
                data.fill(0);
                if let Some(b) = data.first_mut() {
                    *b = *r;
                }
            }
            0x400..=0x41f => data.fill(0),
            0x500..=0x515 if data.len() >= 2 => {
                let reg = ((offset - 0x500) / 2) as usize;
                let v = self.vbe.lock().unwrap().read_reg(reg).to_le_bytes();
                data[0] = v[0];
                data[1] = v[1];
                for b in &mut data[2..] {
                    *b = 0;
                }
            }
            0x600..=0x603 => {
                let v = self.ext_endian.lock().unwrap().to_le_bytes();
                let start = (offset - 0x600) as usize;
                for (i, b) in data.iter_mut().enumerate() {
                    *b = v.get(start + i).copied().unwrap_or(0);
                }
            }
            _ => data.fill(0),
        }
    }

    fn bar_write(&mut self, bar: usize, offset: u64, data: &[u8]) {
        if bar != 2 {
            return;
        }
        match offset {
            0x500..=0x515 if data.len() >= 2 => {
                let reg = ((offset - 0x500) / 2) as usize;
                let val = u16::from_le_bytes([data[0], data[1]]);
                self.vbe.lock().unwrap().write_reg(reg, val);
            }
            0x600 if data.len() >= 4 => {
                let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                *self.ext_endian.lock().unwrap() = val;
            }
            _ => {}
        }
    }
}
