//! Q35 PCIe root complex, ECAM MMIO + legacy `0xCF8`/`0xCFC` config space, and dynamic BAR
//! routing.
//!
//! Designed to be hypervisor-neutral: KVM and WHP backends plug in an [`MsiRouter`] to deliver
//! MSI-X interrupts from [`virtio_pci::VirtioPciTransport`].

pub mod ahci;
pub mod vga;
pub mod virtio_pci;

use std::io;
use std::sync::{Arc, Mutex};

/// Default base of the PCIe Enhanced Configuration Access Mechanism (ECAM) MMIO window
/// (`0xE000_0000`, matching EDK2 OVMF's Q35 `PcdPciExpressBaseAddress`; `PciBus` also honors
/// whatever `PCIEXBAR` firmware programs into `00:00.0` reg `0x60`).
pub const PCIE_ECAM_BASE: u64 = 0xe000_0000;
/// Size of the 256-bus ECAM window (`256 MiB`, `[0xE000_0000..0xF000_0000)`).
pub const PCIE_ECAM_SIZE: u64 = 0x1000_0000;
/// Start of the 32-bit PCI MMIO BAR allocation window (above 2 GiB low RAM).
pub const PCI_MMIO32_BASE: u64 = 0x8000_0000;
/// End of the 32-bit PCI MMIO BAR allocation window (below `0xE000_0000` ECAM).
pub const PCI_MMIO32_END: u64 = 0xe000_0000;

/// Hypervisor-specific MSI/MSI-X routing and trigger sink.
pub trait MsiRouter: Send + Sync {
    /// Allocate an opaque vector handle (e.g. a KVM GSI + irqfd).
    fn allocate(&self) -> io::Result<u32>;
    /// Program the guest-selected MSI address and data for `handle`.
    fn configure(&self, handle: u32, addr: u64, data: u32) -> io::Result<()>;
    /// Trigger the interrupt associated with `handle`.
    fn trigger(&self, handle: u32);
}

/// Description of one PCI BAR exposed by a [`PciDevice`].
#[derive(Debug, Clone, Copy)]
pub struct BarSpec {
    /// BAR index (`0..6`; a 64-bit BAR consumes `index` and `index + 1`).
    pub index: usize,
    /// Size in bytes (power of two, >= 4096).
    pub size: u64,
    /// Whether this BAR is 64-bit (`true`) or 32-bit (`false`).
    pub is_64bit: bool,
    /// Whether this BAR is prefetchable.
    pub prefetchable: bool,
    /// Optional fixed/pre-mapped guest address (e.g. framebuffer RAM slot handled by hypervisor
    /// rather than MMIO exits).
    pub direct_mapped: bool,
}

/// A device residing at a `(bus, device, function)` address on the [`PciBus`].
pub trait PciDevice: Send {
    /// Read from the device's 256-byte (or 4096-byte PCIe) configuration space.
    fn config_read(&self, offset: usize, data: &mut [u8]);
    /// Write to configuration space.
    fn config_write(&mut self, offset: usize, data: &[u8]);
    /// Currently active MMIO BAR windows `(bar_index, base_addr, size)` when Memory Space Enable
    /// is set in the PCI Command register.
    fn active_bars(&self) -> Vec<(usize, u64, u64)>;
    /// Handle an MMIO read inside `bar_index` at `offset`.
    fn bar_read(&self, bar_index: usize, offset: u64, data: &mut [u8]);
    /// Handle an MMIO write inside `bar_index` at `offset`.
    fn bar_write(&mut self, bar_index: usize, offset: u64, data: &[u8]);
}

/// Helper managing standard PCI Type-0 BAR registers (`0x10..0x28`) with proper size probing.
#[derive(Debug, Clone)]
pub struct BarSet {
    specs: Vec<BarSpec>,
    /// Current base address of each BAR (aligned to size).
    bases: [u64; 6],
    /// Whether the guest just wrote all-ones to probe the size mask for a BAR DWORD.
    probing: [bool; 6],
}

impl BarSet {
    /// Create a BAR set with initial non-overlapping addresses from `specs`.
    pub fn new(specs: Vec<BarSpec>, initial_bases: &[(usize, u64)]) -> Self {
        let mut bases = [0u64; 6];
        for &(idx, base) in initial_bases {
            if idx < 6 {
                bases[idx] = base;
            }
        }
        Self {
            specs,
            bases,
            probing: [false; 6],
        }
    }

    fn spec_for_reg(&self, reg_idx: usize) -> Option<(BarSpec, bool)> {
        for &s in &self.specs {
            if s.index == reg_idx {
                return Some((s, false));
            }
            if s.is_64bit && s.index + 1 == reg_idx {
                return Some((s, true));
            }
        }
        None
    }

    /// Read a 32-bit BAR register (`reg_idx` in `0..6`).
    pub fn read_u32(&self, reg_idx: usize) -> u32 {
        let Some((spec, is_high)) = self.spec_for_reg(reg_idx) else {
            return 0;
        };
        let mask = !(spec.size - 1);
        let flags: u32 = (if spec.is_64bit { 0x04 } else { 0x00 })
            | (if spec.prefetchable { 0x08 } else { 0x00 });
        if self.probing[reg_idx] {
            if is_high {
                (mask >> 32) as u32
            } else {
                (mask as u32) | flags
            }
        } else if is_high {
            (self.bases[spec.index] >> 32) as u32
        } else {
            ((self.bases[spec.index] as u32) & !0xf) | flags
        }
    }

    /// Write a 32-bit BAR register (`reg_idx` in `0..6`).
    pub fn write_u32(&mut self, reg_idx: usize, val: u32) {
        let Some((spec, is_high)) = self.spec_for_reg(reg_idx) else {
            return;
        };
        let mask = !(spec.size - 1);
        if val == 0xffff_ffff || (!is_high && (val & !0xf) == 0xffff_fff0) {
            self.probing[reg_idx] = true;
            return;
        }
        self.probing[reg_idx] = false;
        if is_high {
            let hi = u64::from(val) << 32;
            self.bases[spec.index] = (self.bases[spec.index] & 0xffff_ffff) | (hi & mask);
        } else {
            let lo = u64::from(val & !0xf) & mask;
            self.bases[spec.index] = (self.bases[spec.index] & !0xffff_ffff) | lo;
        }
    }

    /// Return all active MMIO BAR windows (excluding `direct_mapped` ones).
    pub fn active_mmio(&self) -> Vec<(usize, u64, u64)> {
        self.specs
            .iter()
            .filter(|s| !s.direct_mapped)
            .filter_map(|s| {
                let base = self.bases[s.index];
                (base != 0).then_some((s.index, base, s.size))
            })
            .collect()
    }

    /// Current base address of BAR `index`.
    pub fn base(&self, index: usize) -> u64 {
        self.bases[index]
    }
}

/// Q35 MCH Host Bridge (`00:00.0`, `8086:29c0`).
struct Q35HostBridge {
    cfg: [u8; 256],
}

impl Q35HostBridge {
    fn new() -> Self {
        let mut cfg = [0u8; 256];
        cfg[0x00..0x04].copy_from_slice(&0x29c0_8086u32.to_le_bytes());
        cfg[0x08..0x0c].copy_from_slice(&0x0600_0000u32.to_le_bytes());
        // PCIEXBAR at 0x60: 256 MiB ECAM at PCIE_ECAM_BASE, enabled (bit 0 = 1, bits 2:1 = 00).
        cfg[0x60..0x68].copy_from_slice(&(PCIE_ECAM_BASE | 1).to_le_bytes());
        Self { cfg }
    }

    fn ecam_window(&self) -> Option<(u64, u64)> {
        let raw = u64::from_le_bytes(self.cfg[0x60..0x68].try_into().unwrap());
        if raw & 1 == 0 {
            return None;
        }
        let size = match (raw >> 1) & 0x3 {
            0 => 256 << 20,
            1 => 128 << 20,
            2 => 64 << 20,
            _ => return None,
        };
        let base = raw & !(size - 1);
        (base != 0).then_some((base, size))
    }
}

impl PciDevice for Q35HostBridge {
    fn config_read(&self, offset: usize, data: &mut [u8]) {
        for (i, b) in data.iter_mut().enumerate() {
            *b = self.cfg.get(offset + i).copied().unwrap_or(0);
        }
    }
    fn config_write(&mut self, offset: usize, data: &[u8]) {
        for (i, &b) in data.iter().enumerate() {
            let idx = offset + i;
            let writable = matches!(idx, 0x04..=0x05 | 0x0c..=0x0d | 0x50..=0xff);
            if writable && idx < self.cfg.len() {
                self.cfg[idx] = b;
            }
        }
    }
    fn active_bars(&self) -> Vec<(usize, u64, u64)> {
        Vec::new()
    }
    fn bar_read(&self, _: usize, _: u64, data: &mut [u8]) {
        data.fill(0xff);
    }
    fn bar_write(&mut self, _: usize, _: u64, _: &[u8]) {}
}

/// ICH9 LPC / ISA / ACPI PM Bridge (`00:1f.0`, `8086:2918`).
struct Ich9Lpc {
    cfg: [u8; 256],
}

impl Ich9Lpc {
    fn new() -> Self {
        let mut cfg = [0u8; 256];
        cfg[0x00..0x04].copy_from_slice(&0x2918_8086u32.to_le_bytes());
        cfg[0x08..0x0c].copy_from_slice(&0x0601_0002u32.to_le_bytes());
        cfg[0x0e] = 0x80; // multifunction
        cfg[0x40..0x44].copy_from_slice(&0x0000_0601u32.to_le_bytes()); // PMBASE = 0x0600 | I/O bit
        cfg[0x44] = 0x80; // ACPI_CNTL: ACPI I/O enabled
        Self { cfg }
    }

    fn pm_base(&self) -> Option<u16> {
        if self.cfg[0x44] & 0x80 == 0 {
            return None;
        }
        let raw = u32::from_le_bytes(self.cfg[0x40..0x44].try_into().unwrap());
        let base = (raw & 0xff80) as u16;
        (base != 0).then_some(base)
    }
}

impl PciDevice for Ich9Lpc {
    fn config_read(&self, offset: usize, data: &mut [u8]) {
        for (i, b) in data.iter_mut().enumerate() {
            *b = self.cfg.get(offset + i).copied().unwrap_or(0);
        }
    }
    fn config_write(&mut self, offset: usize, data: &[u8]) {
        for (i, &b) in data.iter().enumerate() {
            let idx = offset + i;
            let writable = matches!(idx, 0x04..=0x05 | 0x0c..=0x0d | 0x40..=0xff);
            if writable && idx < self.cfg.len() {
                self.cfg[idx] = b;
            }
        }
        self.cfg[0x40] |= 0x01; // PMBASE I/O space bit stays set
    }
    fn active_bars(&self) -> Vec<(usize, u64, u64)> {
        Vec::new()
    }
    fn bar_read(&self, _: usize, _: u64, data: &mut [u8]) {
        data.fill(0xff);
    }
    fn bar_write(&mut self, _: usize, _: u64, _: &[u8]) {}
}

type PciSlot = (u8, u8, Arc<Mutex<dyn PciDevice>>);

/// Q35 PCIe bus owning the host bridge, LPC/PM bridge, and attached PCIe devices.
pub struct PciBus {
    cf8: u32,
    host: Q35HostBridge,
    lpc: Ich9Lpc,
    devices: Vec<PciSlot>,
    next_mmio32: u64,
}

impl Default for PciBus {
    fn default() -> Self {
        Self::new()
    }
}

impl PciBus {
    /// Create a Q35 PCIe bus with MCH (`00:00.0`) and ICH9 LPC (`00:1f.0`).
    pub fn new() -> Self {
        Self {
            cf8: 0,
            host: Q35HostBridge::new(),
            lpc: Ich9Lpc::new(),
            devices: Vec::new(),
            next_mmio32: PCI_MMIO32_BASE,
        }
    }

    /// Reserve a power-of-two aligned 32-bit PCI MMIO BAR window.
    pub fn alloc_mmio32(&mut self, size: u64) -> Option<u64> {
        let align = size.max(4096);
        let addr = (self.next_mmio32 + align - 1) & !(align - 1);
        if addr
            .checked_add(size)
            .is_none_or(|end| end > PCI_MMIO32_END)
        {
            return None;
        }
        self.next_mmio32 = addr + size;
        Some(addr)
    }

    /// Attach a PCIe device on Bus 0 at `(dev, func)`.
    pub fn add_device(&mut self, dev: u8, func: u8, device: Arc<Mutex<dyn PciDevice>>) {
        self.devices.push((dev, func, device));
    }

    /// Currently programmed ICH9 ACPI PM I/O base address (typically `0x0600`).
    pub fn pm_base(&self) -> Option<u16> {
        self.lpc.pm_base()
    }

    /// Write legacy `0xCF8` config-address register.
    pub fn write_cf8(&mut self, val: u32) {
        self.cf8 = val;
    }

    /// Read legacy `0xCF8` config-address register.
    pub fn read_cf8(&self) -> u32 {
        self.cf8
    }

    /// Read legacy `0xCFC..=0xCFF`.
    pub fn read_cfc(&self, port_off: usize, data: &mut [u8]) {
        if self.cf8 & 0x8000_0000 == 0 {
            data.fill(0xff);
            return;
        }
        let bus = ((self.cf8 >> 16) & 0xff) as u8;
        let dev = ((self.cf8 >> 11) & 0x1f) as u8;
        let func = ((self.cf8 >> 8) & 0x07) as u8;
        let reg = ((self.cf8 & 0xfc) as usize) + port_off;
        self.config_read(bus, dev, func, reg, data);
    }

    /// Write legacy `0xCFC..=0xCFF`.
    pub fn write_cfc(&mut self, port_off: usize, data: &[u8]) {
        if self.cf8 & 0x8000_0000 == 0 {
            return;
        }
        let bus = ((self.cf8 >> 16) & 0xff) as u8;
        let dev = ((self.cf8 >> 11) & 0x1f) as u8;
        let func = ((self.cf8 >> 8) & 0x07) as u8;
        let reg = ((self.cf8 & 0xfc) as usize) + port_off;
        self.config_write(bus, dev, func, reg, data);
    }

    /// Handle an MMIO read (ECAM config space or any active device BAR). Returns `true` if claimed.
    pub fn mmio_read(&self, addr: u64, data: &mut [u8]) -> bool {
        if let Some((ecam_base, ecam_size)) = self.host.ecam_window()
            && addr >= ecam_base
            && addr < ecam_base + ecam_size
        {
            let off = addr - ecam_base;
            let bus = ((off >> 20) & 0xff) as u8;
            let dev = ((off >> 15) & 0x1f) as u8;
            let func = ((off >> 12) & 0x07) as u8;
            let reg = (off & 0xfff) as usize;
            self.config_read(bus, dev, func, reg, data);
            return true;
        }
        for (_, _, d) in &self.devices {
            let dev = d.lock().unwrap();
            for (bar, base, size) in dev.active_bars() {
                if addr >= base && addr < base + size {
                    dev.bar_read(bar, addr - base, data);
                    return true;
                }
            }
        }
        false
    }

    /// Handle an MMIO write (ECAM config space or any active device BAR). Returns `true` if claimed.
    pub fn mmio_write(&mut self, addr: u64, data: &[u8]) -> bool {
        if let Some((ecam_base, ecam_size)) = self.host.ecam_window()
            && addr >= ecam_base
            && addr < ecam_base + ecam_size
        {
            let off = addr - ecam_base;
            let bus = ((off >> 20) & 0xff) as u8;
            let dev = ((off >> 15) & 0x1f) as u8;
            let func = ((off >> 12) & 0x07) as u8;
            let reg = (off & 0xfff) as usize;
            self.config_write(bus, dev, func, reg, data);
            return true;
        }
        for (_, _, d) in &self.devices {
            let mut dev = d.lock().unwrap();
            for (bar, base, size) in dev.active_bars() {
                if addr >= base && addr < base + size {
                    dev.bar_write(bar, addr - base, data);
                    return true;
                }
            }
        }
        false
    }

    fn config_read(&self, bus: u8, dev: u8, func: u8, reg: usize, data: &mut [u8]) {
        if bus != 0 {
            data.fill(0xff);
            return;
        }
        match (dev, func) {
            (0, 0) => self.host.config_read(reg, data),
            (0x1f, 0) => self.lpc.config_read(reg, data),
            _ => {
                if let Some((_, _, d)) = self
                    .devices
                    .iter()
                    .find(|(dd, ff, _)| *dd == dev && *ff == func)
                {
                    d.lock().unwrap().config_read(reg, data);
                } else {
                    data.fill(0xff);
                }
            }
        }
    }

    fn config_write(&mut self, bus: u8, dev: u8, func: u8, reg: usize, data: &[u8]) {
        if bus != 0 {
            return;
        }
        match (dev, func) {
            (0, 0) => self.host.config_write(reg, data),
            (0x1f, 0) => self.lpc.config_write(reg, data),
            _ => {
                if let Some((_, _, d)) = self
                    .devices
                    .iter()
                    .find(|(dd, ff, _)| *dd == dev && *ff == func)
                {
                    d.lock().unwrap().config_write(reg, data);
                }
            }
        }
    }
}
