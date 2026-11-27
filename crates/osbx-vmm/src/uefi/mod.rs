//! Q35 PCIe UEFI (EDK2 OVMF) virtual machine monitor on KVM (Linux) and WHP (Windows).
//!
//! Boots UEFI guests (Windows Server 2022/2025, Windows 11, UEFI Linux) from the x86 16-bit
//! reset vector (`0xFFFF_FFF0`) with:
//! - Q35 MCH (`8086:29c0`) + ICH9 LPC/PM (`8086:2918`) + PCIe ECAM (`0xE000_0000`)
//! - ACPI 2.0 tables (`RSDP`, `XSDT`, `FADT`, `MADT`, `MCFG`, `HPET`, `DSDT`) via `fw_cfg`
//! - Persistent CFI `pflash` for `OVMF_VARS_4M.fd` + read-only `OVMF_CODE_4M.fd`
//! - Bochs VBE PCI display (`1234:1111`, 16 MiB linear framebuffer + BAR2 MMIO regs) for UEFI GOP
//! - ICH9 AHCI 1.3 ATAPI controller (`8086:2922` at `00:1f.2`) for ISO CD-ROMs
//! - Modern Virtio 1.0 `virtio-pci` devices (`Block` raw/QCOW2, `Fs`, `Vsock`) with MSI-X routing
//! - Hyper-V enlightenments (`hv_relaxed`, `hv_vapic`, `hv_vpindex`, `hv_time`, `hv_synic`,
//!   `hv_stimer`, `hv_runtime`, `hv_reset`, `hv_tlbflush`)

#[cfg(target_os = "linux")]
mod kvm;
#[cfg(target_os = "linux")]
use kvm as backend;

#[cfg(windows)]
mod whp;
#[cfg(windows)]
use whp as backend;

use crate::acpi;
use crate::boot::{BootConfig, BootError, DiskConfig, ExitReason, ShareConfig, err};
use crate::devices::{COM1, COM1_IRQ, Sink, Uart, UartIrq};
use crate::hpet::{HPET_BASE, HPET_SIZE, Hpet};
use crate::ioapic::{IOAPIC_SIZE, IoApic};
use crate::mptable::IOAPIC_ADDR;
use crate::pci::PciBus;
use crate::pci::ahci::{AHCI_BAR5_SIZE, AhciController};
use crate::pci::vga::{
    BochsVga, VBE_DISPI_DATA_PORT, VBE_DISPI_INDEX_PORT, VGA_FB_SIZE, VGA_MMIO_SIZE, VbeState,
};
use crate::pci::virtio_pci::{VIRTIO_BAR0_SIZE, VIRTIO_BAR2_SIZE, VirtioPciTransport};
use crate::pflash::Pflash;
use crate::tpm::{TPM_CRB_BASE, TPM_CRB_SIZE, Tpm2Crb};
use crate::virtio::blk::Block;
use crate::virtio::fs::Fs;
use crate::virtio::vsock::{VsockHost, vsock};
use crate::virtio::{GuestMem, VirtioDevice};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vm_superio::Serial;

/// 4 GiB boundary; firmware ROM is mapped ending right below this address.
const FOUR_GIB: u64 = 1u64 << 32;
/// Top of low RAM on Q35 (2 GiB), leaving `0x8000_0000..0xE000_0000` for PCI MMIO and `0xE000_0000` for ECAM.
const UEFI_LOW_MEM_END: u64 = 0x8000_0000;
/// ACPI PM timer frequency (3.579545 MHz).
const ACPI_PM_TIMER_HZ: u128 = 3_579_545;

/// Configuration for booting a Q35 PCIe UEFI (OVMF) VM.
#[derive(Debug, Clone)]
pub struct UefiConfig {
    /// Path to `OVMF.fd` (unified 4 MiB) or `OVMF_CODE_4M.fd` (when `vars` is set).
    pub firmware: PathBuf,
    /// Optional writable `OVMF_VARS_4M.fd` backed by CFI `pflash`.
    pub vars: Option<PathBuf>,
    /// Guest RAM in MiB (128 ..= 65536).
    pub mem_mib: usize,
    /// Number of vCPUs (1 ..= 32).
    pub cpus: u8,
    /// Stop the VM after this duration if it has not exited on its own (used by [`boot_uefi`]).
    pub timeout: Option<Duration>,
    /// Echo COM1 serial console output to host stdout.
    pub echo: bool,
    /// Echo OVMF port `0x402` debugcon output to host stderr.
    pub echo_debugcon: bool,
    /// Forward host stdin to COM1.
    pub stdin: bool,
    /// Disks attached via `virtio-blk` (PCIe, raw or QCOW2).
    pub disks: Vec<DiskConfig>,
    /// Read-only ISO CD-ROMs attached via ICH9 AHCI ATAPI (`00:1f.2`, ports `0..cdroms.len()`).
    pub cdroms: Vec<PathBuf>,
    /// Host directories shared over `virtio-fs` (PCIe).
    pub shares: Vec<ShareConfig>,
    /// Attach a `virtio-vsock` (PCIe) device with this guest CID (3 is conventional).
    pub vsock_cid: Option<u64>,
    /// Expose Hyper-V enlightenments (`hv_relaxed`, `hv_time`, `hv_synic`, `hv_stimer`, etc.).
    pub hyperv: bool,
    /// Optional persistent state file for an emulated CRB vTPM 2.0 device at `0xFED4_0000`.
    pub vtpm: Option<PathBuf>,
    /// Optional trigger + bytes to inject into COM1 once `trigger` appears in serial output.
    pub send_on_match: Option<(String, Vec<u8>)>,
}

impl UefiConfig {
    /// Convenience constructor with sensible defaults (512 MiB, 1 vCPU, Hyper-V enlightenments on).
    pub fn new(firmware: PathBuf) -> Self {
        Self {
            firmware,
            vars: None,
            mem_mib: 512,
            cpus: 1,
            timeout: None,
            echo: false,
            echo_debugcon: false,
            stdin: false,
            disks: Vec::new(),
            cdroms: Vec::new(),
            shares: Vec::new(),
            vsock_cid: None,
            hyperv: true,
            vtpm: None,
            send_on_match: None,
        }
    }
}

/// Result of a synchronous [`boot_uefi`] run.
#[derive(Debug)]
pub struct UefiOutcome {
    /// Output written by UEFI / guest to COM1 (`0x3F8`).
    pub console: String,
    /// OVMF diagnostic log written to ISA debugcon (`0x402`).
    pub debugcon: String,
    /// Why execution ended.
    pub exit: ExitReason,
    /// True when the guest exited via ACPI S5 poweroff (`PM1a_CNT` `SLP_EN`) rather than a reboot.
    pub powered_off: bool,
}

/// Page-aligned backing store for the Bochs VGA 16 MiB linear framebuffer memory slot.
pub(super) struct FbBuffer {
    buf: Vec<u8>,
    offset: usize,
    len: usize,
}

impl FbBuffer {
    fn new(len: usize) -> Self {
        let buf = vec![0u8; len + 4096];
        let addr = buf.as_ptr() as usize;
        let offset = (4096 - (addr % 4096)) % 4096;
        Self { buf, offset, len }
    }

    pub(super) fn as_ptr(&self) -> *const u8 {
        self.buf[self.offset..].as_ptr()
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[self.offset..self.offset + self.len]
    }
}

/// CMOS RAM + UTC RTC with QEMU-style memory size registers for OVMF `MemDetect`.
struct UefiCmos {
    index: u8,
    low_mem: u64,
    high_mem: u64,
    cpus: u8,
}

impl UefiCmos {
    fn new(low_mem: u64, high_mem: u64, cpus: u8) -> Self {
        Self {
            index: 0,
            low_mem,
            high_mem,
            cpus,
        }
    }

    fn write(&mut self, port: u16, val: u8) {
        if port == 0x70 {
            self.index = val & 0x7f;
        }
    }

    fn read(&self, port: u16) -> u8 {
        if port == 0x70 {
            return 0xff;
        }
        let above_16m = (self.low_mem.saturating_sub(16 << 20) >> 16) as u16;
        let above_4g = self.high_mem >> 16;
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()) as i64;
        let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
        let (y, mo, d) = civil_from_days(days);
        let bcd = |x: u32| (((x / 10) << 4) | (x % 10)) as u8;
        match self.index {
            0x00 => bcd((rem % 60) as u32),
            0x02 => bcd((rem / 60 % 60) as u32),
            0x04 => bcd((rem / 3600) as u32),
            0x06 => bcd(((days + 4).rem_euclid(7) + 1) as u32),
            0x07 => bcd(d),
            0x08 => bcd(mo),
            0x09 => bcd((y % 100) as u32),
            0x0a => 0x26,
            0x0b => 0x02,
            0x0c => 0x00,
            0x0d => 0x80,
            0x0f => 0x00,
            0x32 => bcd((y / 100) as u32),
            0x34 => (above_16m & 0xff) as u8,
            0x35 => (above_16m >> 8) as u8,
            0x5b => (above_4g & 0xff) as u8,
            0x5c => ((above_4g >> 8) & 0xff) as u8,
            0x5d => ((above_4g >> 16) & 0xff) as u8,
            0x5f => self.cpus.saturating_sub(1),
            _ => 0,
        }
    }
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// QEMU `fw_cfg` device (`0x510` selector, `0x511` data, `0x514`/`0x518` DMA) serving `etc/e820`,
/// `etc/acpi/*`, `etc/table-loader`, and `etc/boot-fail-wait`.
struct FwCfg {
    selector: u16,
    offset: usize,
    dma_hi: u32,
    cpus: u16,
    files: Vec<(String, Vec<u8>)>,
    file_dir: Vec<u8>,
}

impl FwCfg {
    fn new(low_mem: u64, high_mem: u64, cpus: u8, acpi_blobs: acpi::AcpiBlobs) -> Self {
        let mut e820 = Vec::new();
        let mut push_e820 = |addr: u64, len: u64, ty: u32| {
            e820.extend_from_slice(&addr.to_le_bytes());
            e820.extend_from_slice(&len.to_le_bytes());
            e820.extend_from_slice(&ty.to_le_bytes());
        };
        push_e820(0, low_mem, 1);
        push_e820(crate::pci::PCIE_ECAM_BASE, crate::pci::PCIE_ECAM_SIZE, 2);
        if high_mem > 0 {
            push_e820(FOUR_GIB, high_mem, 1);
        }

        let files = vec![
            ("etc/acpi/rsdp".to_owned(), acpi_blobs.rsdp),
            ("etc/acpi/tables".to_owned(), acpi_blobs.tables),
            ("etc/boot-fail-wait".to_owned(), 0u32.to_le_bytes().to_vec()),
            ("etc/e820".to_owned(), e820),
            ("etc/table-loader".to_owned(), acpi_blobs.loader),
        ];

        let mut file_dir = Vec::new();
        file_dir.extend_from_slice(&(files.len() as u32).to_be_bytes());
        for (i, (name, blob)) in files.iter().enumerate() {
            file_dir.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            file_dir.extend_from_slice(&(0x0020u16 + i as u16).to_be_bytes());
            file_dir.extend_from_slice(&0u16.to_be_bytes());
            let mut n = [0u8; 56];
            let bytes = name.as_bytes();
            let take = bytes.len().min(55);
            n[..take].copy_from_slice(&bytes[..take]);
            file_dir.extend_from_slice(&n);
        }

        Self {
            selector: 0,
            offset: 0,
            dma_hi: 0,
            cpus: u16::from(cpus),
            files,
            file_dir,
        }
    }

    fn current_blob(&self) -> Vec<u8> {
        match self.selector {
            0x0000 => b"QEMU".to_vec(),
            0x0001 => 0x0000_0003u32.to_le_bytes().to_vec(),
            0x0005 | 0x000e => self.cpus.to_le_bytes().to_vec(),
            0x0019 => self.file_dir.clone(),
            s if s >= 0x0020 => self
                .files
                .get((s - 0x0020) as usize)
                .map(|(_, b)| b.clone())
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    fn select(&mut self, sel: u16) {
        self.selector = sel;
        self.offset = 0;
    }

    fn read_byte(&mut self) -> u8 {
        let blob = self.current_blob();
        let b = blob.get(self.offset).copied().unwrap_or(0);
        self.offset = self.offset.saturating_add(1);
        b
    }

    fn dma_write_hi(&mut self, data: &[u8]) {
        if data.len() == 4 {
            self.dma_hi = u32::from_be_bytes(data.try_into().unwrap());
        }
    }

    fn dma_write_lo(&mut self, data: &[u8], mem: &GuestMem) {
        if data.len() != 4 {
            return;
        }
        let lo = u32::from_be_bytes(data.try_into().unwrap());
        let desc_gpa = (u64::from(self.dma_hi) << 32) | u64::from(lo);
        self.dma_hi = 0;

        let mut hdr = [0u8; 16];
        if mem.read_slice(&mut hdr, GuestAddress(desc_gpa)).is_err() {
            return;
        }
        let control = u32::from_be_bytes(hdr[0..4].try_into().unwrap());
        let length = u32::from_be_bytes(hdr[4..8].try_into().unwrap()) as usize;
        let address = u64::from_be_bytes(hdr[8..16].try_into().unwrap());

        if control & 0x08 != 0 {
            self.select((control >> 16) as u16);
        }
        let mut out_ctl = 0u32;
        if control & 0x02 != 0 {
            let blob = self.current_blob();
            let mut buf = vec![0u8; length];
            if self.offset < blob.len() {
                let avail = (blob.len() - self.offset).min(length);
                buf[..avail].copy_from_slice(&blob[self.offset..self.offset + avail]);
            }
            self.offset = self.offset.saturating_add(length);
            if mem.write_slice(&buf, GuestAddress(address)).is_err() {
                out_ctl = 0x01;
            }
        } else if control & 0x04 != 0 || control & 0x10 != 0 {
            self.offset = self.offset.saturating_add(length);
        }
        let _ = mem.write_slice(&out_ctl.to_be_bytes(), GuestAddress(desc_gpa));
    }
}

pub(super) struct UefiDevices {
    uart: Arc<Mutex<Uart>>,
    debugcon: Arc<Mutex<Vec<u8>>>,
    echo_debugcon: bool,
    pci: Mutex<PciBus>,
    vbe: Arc<Mutex<VbeState>>,
    hpet: Hpet,
    pflash: Option<Pflash>,
    ioapic: Option<Arc<IoApic>>,
    tpm: Option<Mutex<Tpm2Crb>>,
    cmos: Mutex<UefiCmos>,
    fw_cfg: Mutex<FwCfg>,
    mem: GuestMem,
    boot_instant: Instant,
    port_61: Mutex<u8>,
    port_92: Mutex<u8>,
    pm1_cnt: Mutex<u16>,
    vga_retrace: Mutex<u8>,
    powered_off: Arc<AtomicBool>,
}

impl UefiDevices {
    #[cfg(target_os = "linux")]
    pub(super) fn mark_powered_off(&self) {
        self.powered_off.store(true, Ordering::SeqCst);
    }

    fn pm_timer_ticks(&self) -> u32 {
        let ns = self.boot_instant.elapsed().as_nanos();
        ((ns * ACPI_PM_TIMER_HZ) / 1_000_000_000) as u32 & 0x00ff_ffff
    }

    pub(super) fn io_out(&self, port: u16, data: &[u8]) -> Option<ExitReason> {
        if let Some(pm_base) = self.pci.lock().unwrap().pm_base()
            && port >= pm_base
            && port < pm_base.saturating_add(0x80)
        {
            let off = port - pm_base;
            if off == 0x04 && data.len() >= 2 {
                let val = u16::from_le_bytes([data[0], data[1]]);
                *self.pm1_cnt.lock().unwrap() = val;
                if val & 0x2000 != 0 {
                    self.powered_off.store(true, Ordering::SeqCst);
                    return Some(ExitReason::GuestReset);
                }
            }
            return None;
        }

        match port {
            p if (COM1..COM1 + 8).contains(&p) => {
                let _ = self.uart.lock().unwrap().write((p - COM1) as u8, data[0]);
            }
            VBE_DISPI_INDEX_PORT if data.len() >= 2 => {
                self.vbe
                    .lock()
                    .unwrap()
                    .write_index(u16::from_le_bytes([data[0], data[1]]));
            }
            VBE_DISPI_DATA_PORT if data.len() >= 2 => {
                self.vbe
                    .lock()
                    .unwrap()
                    .write_data(u16::from_le_bytes([data[0], data[1]]));
            }
            0x402 => {
                self.debugcon.lock().unwrap().extend_from_slice(data);
                if self.echo_debugcon {
                    let mut err = io::stderr().lock();
                    let _ = err.write_all(data);
                    let _ = err.flush();
                }
            }
            0x61 => {
                if let Some(&b) = data.first() {
                    *self.port_61.lock().unwrap() = b & 0x0f;
                }
            }
            0x64 if data.first() == Some(&0xfe) => return Some(ExitReason::GuestReset),
            0x70 | 0x71 => {
                if let Some(&b) = data.first() {
                    self.cmos.lock().unwrap().write(port, b);
                }
            }
            0x92 => {
                if let Some(&b) = data.first() {
                    *self.port_92.lock().unwrap() = b;
                    if b & 0x01 != 0 {
                        return Some(ExitReason::GuestReset);
                    }
                }
            }
            0x510 if data.len() >= 2 => {
                self.fw_cfg
                    .lock()
                    .unwrap()
                    .select(u16::from_le_bytes([data[0], data[1]]));
            }
            0x514 => self.fw_cfg.lock().unwrap().dma_write_hi(data),
            0x518 => self.fw_cfg.lock().unwrap().dma_write_lo(data, &self.mem),
            0xcf8 if data.len() == 4 => {
                self.pci
                    .lock()
                    .unwrap()
                    .write_cf8(u32::from_le_bytes(data.try_into().unwrap()));
            }
            0xcf9 if data.first().is_some_and(|b| b & 0x04 != 0) => {
                return Some(ExitReason::GuestReset);
            }
            0xcfc..=0xcff => {
                self.pci
                    .lock()
                    .unwrap()
                    .write_cfc((port - 0xcfc) as usize, data);
            }
            _ => {}
        }
        None
    }

    pub(super) fn io_in(&self, port: u16, data: &mut [u8]) {
        if let Some(pm_base) = self.pci.lock().unwrap().pm_base()
            && port >= pm_base
            && port < pm_base.saturating_add(0x80)
        {
            let off = port - pm_base;
            match off {
                0x04 => {
                    let v = self.pm1_cnt.lock().unwrap().to_le_bytes();
                    for (i, b) in data.iter_mut().enumerate() {
                        *b = v.get(i).copied().unwrap_or(0);
                    }
                }
                0x08 => {
                    let v = self.pm_timer_ticks().to_le_bytes();
                    for (i, b) in data.iter_mut().enumerate() {
                        *b = v.get(i).copied().unwrap_or(0);
                    }
                }
                _ => data.fill(0),
            }
            return;
        }

        match port {
            p if (COM1..COM1 + 8).contains(&p) => {
                data[0] = self.uart.lock().unwrap().read((p - COM1) as u8);
            }
            VBE_DISPI_INDEX_PORT if data.len() >= 2 => {
                let v = self.vbe.lock().unwrap().read_index().to_le_bytes();
                data[0..2].copy_from_slice(&v);
            }
            VBE_DISPI_DATA_PORT if data.len() >= 2 => {
                let v = self.vbe.lock().unwrap().read_data().to_le_bytes();
                data[0..2].copy_from_slice(&v);
            }
            0x3da => {
                let mut r = self.vga_retrace.lock().unwrap();
                *r ^= 0x09;
                data[0] = *r;
            }
            0x3c0..=0x3df => data.fill(0),
            0x402 => data.fill(0xe9),
            0x60 | 0x64 => data.fill(0xff),
            0x61 => {
                let mut v = self.port_61.lock().unwrap();
                *v ^= 0x10;
                data[0] = *v;
            }
            0x70 | 0x71 => data[0] = self.cmos.lock().unwrap().read(port),
            0x92 => data[0] = *self.port_92.lock().unwrap(),
            0x511 => {
                let mut cfg = self.fw_cfg.lock().unwrap();
                for b in data.iter_mut() {
                    *b = cfg.read_byte();
                }
            }
            0x514 if data.len() == 4 => data.copy_from_slice(b"QEMU"),
            0x518 if data.len() == 4 => data.copy_from_slice(b" CFG"),
            0xcf8 if data.len() == 4 => {
                data.copy_from_slice(&self.pci.lock().unwrap().read_cf8().to_le_bytes());
            }
            0xcfc..=0xcff => {
                self.pci
                    .lock()
                    .unwrap()
                    .read_cfc((port - 0xcfc) as usize, data);
            }
            _ => data.fill(0xff),
        }
    }

    pub(super) fn mmio_read(&self, addr: u64, data: &mut [u8]) {
        if let Some(pf) = &self.pflash
            && pf.contains(addr)
        {
            pf.read(addr, data);
            return;
        }
        if (HPET_BASE..HPET_BASE + HPET_SIZE).contains(&addr) {
            self.hpet.read(addr - HPET_BASE, data);
            return;
        }
        let ioapic_base = u64::from(IOAPIC_ADDR);
        if let Some(ioapic) = &self.ioapic
            && (ioapic_base..ioapic_base + IOAPIC_SIZE).contains(&addr)
        {
            ioapic.read(addr - ioapic_base, data);
            return;
        }
        if let Some(tpm) = &self.tpm
            && (TPM_CRB_BASE..TPM_CRB_BASE + TPM_CRB_SIZE).contains(&addr)
        {
            tpm.lock().unwrap().read(addr - TPM_CRB_BASE, data);
            return;
        }
        if !self.pci.lock().unwrap().mmio_read(addr, data) {
            data.fill(0xff);
        }
    }

    pub(super) fn mmio_write(&self, addr: u64, data: &[u8]) {
        if let Some(pf) = &self.pflash
            && pf.contains(addr)
        {
            pf.write(addr, data);
            return;
        }
        if (HPET_BASE..HPET_BASE + HPET_SIZE).contains(&addr) {
            self.hpet.write(addr - HPET_BASE, data);
            return;
        }
        let ioapic_base = u64::from(IOAPIC_ADDR);
        if let Some(ioapic) = &self.ioapic
            && (ioapic_base..ioapic_base + IOAPIC_SIZE).contains(&addr)
        {
            ioapic.write(addr - ioapic_base, data);
            return;
        }
        if let Some(tpm) = &self.tpm
            && (TPM_CRB_BASE..TPM_CRB_BASE + TPM_CRB_SIZE).contains(&addr)
        {
            tpm.lock().unwrap().write(addr - TPM_CRB_BASE, data);
            return;
        }
        self.pci.lock().unwrap().mmio_write(addr, data);
    }
}

/// A running Q35 PCIe UEFI virtual machine (Linux/KVM or Windows/WHP).
pub struct UefiVm {
    machine: Arc<backend::UefiMachine>,
    vsock: Option<VsockHost>,
    uart: Arc<Mutex<Uart>>,
    captured: Arc<Mutex<Vec<u8>>>,
    debugcon: Arc<Mutex<Vec<u8>>>,
    fb_mem: Arc<Mutex<FbBuffer>>,
    vbe: Arc<Mutex<VbeState>>,
    stop: Arc<AtomicBool>,
    powered_off: Arc<AtomicBool>,
    rx: Mutex<mpsc::Receiver<Result<ExitReason, String>>>,
    done: Mutex<Option<Result<ExitReason, String>>>,
    threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl UefiVm {
    /// Build the Q35 PCIe UEFI machine, load firmware/devices, and start all vCPU threads.
    pub fn start(cfg: &UefiConfig) -> Result<Self, BootError> {
        if !(128..=65536).contains(&cfg.mem_mib) {
            return Err(BootError("mem_mib must be between 128 and 65536".into()));
        }
        if !(1..=crate::mptable::MAX_CPUS).contains(&cfg.cpus) {
            return Err(BootError(format!(
                "cpus must be between 1 and {}",
                crate::mptable::MAX_CPUS
            )));
        }

        let code_bytes = std::fs::read(&cfg.firmware).map_err(err("read OVMF firmware"))?;
        if code_bytes.is_empty() || !code_bytes.len().is_multiple_of(4096) {
            return Err(BootError(format!(
                "unexpected OVMF firmware size: {} bytes",
                code_bytes.len()
            )));
        }

        let (pflash, code_base, code_readonly) = if let Some(vars_path) = &cfg.vars {
            let vars_len = std::fs::metadata(vars_path)
                .map_err(err("stat OVMF vars"))?
                .len();
            let total = vars_len + code_bytes.len() as u64;
            if total > (16 << 20) || !vars_len.is_multiple_of(4096) {
                return Err(BootError(format!("unexpected OVMF vars+code size {total}")));
            }
            let vars_base = FOUR_GIB - total;
            let pf = Pflash::open(vars_path, vars_base).map_err(err("open OVMF vars pflash"))?;
            (Some(pf), vars_base + vars_len, true)
        } else {
            let total = code_bytes.len() as u64;
            if total > (16 << 20) {
                return Err(BootError(format!("unexpected OVMF size {total}")));
            }
            (None, FOUR_GIB - total, false)
        };

        let mem_size = (cfg.mem_mib as u64) << 20;
        let low_mem = mem_size.min(UEFI_LOW_MEM_END);
        let high_mem = mem_size.saturating_sub(UEFI_LOW_MEM_END);

        let mut ranges = vec![
            (GuestAddress(0), low_mem as usize),
            (GuestAddress(code_base), code_bytes.len()),
        ];
        if high_mem > 0 {
            ranges.push((GuestAddress(FOUR_GIB), high_mem as usize));
        }
        let mem = GuestMemoryMmap::<()>::from_ranges(&ranges).map_err(err("guest memory"))?;
        mem.write_slice(&code_bytes, GuestAddress(code_base))
            .map_err(err("load firmware"))?;

        let machine = Arc::new(backend::UefiMachine::new(
            &mem,
            cfg.cpus,
            code_base,
            code_readonly,
            cfg.hyperv,
        )?);
        let msi_router = machine.msi_router();
        let mut pci = PciBus::new();

        // Slot 00:01.0: Bochs VBE GOP framebuffer (BAR0 16 MiB linear FB, BAR2 4 KiB MMIO regs)
        let fb_mem = Arc::new(Mutex::new(FbBuffer::new(VGA_FB_SIZE as usize)));
        let fb_bar0 = pci
            .alloc_mmio32(VGA_FB_SIZE)
            .ok_or_else(|| BootError("out of PCI MMIO32 for VGA BAR0".into()))?;
        let fb_bar2 = pci
            .alloc_mmio32(VGA_MMIO_SIZE)
            .ok_or_else(|| BootError("out of PCI MMIO32 for VGA BAR2".into()))?;
        let fb_mapper = machine.fb_mapper(fb_mem.clone());
        let (vga_dev, vbe) = BochsVga::new(fb_bar0, fb_bar2, fb_mapper);
        pci.add_device(1, 0, Arc::new(Mutex::new(vga_dev)));

        // Attach virtio-pci devices starting at PCI device 2 (matching ACPI _PRT GSIs 16..19).
        let mut next_dev: u8 = 2;
        let mut attach_virtio = |dev: Box<dyn VirtioDevice>| -> Result<(), BootError> {
            let slot = next_dev;
            next_dev += 1;
            let gsi = 16 + u32::from((slot - 1) % 4);
            let bar0 = pci
                .alloc_mmio32(VIRTIO_BAR0_SIZE)
                .ok_or_else(|| BootError("out of PCI MMIO32 for virtio BAR0".into()))?;
            let bar2 = pci
                .alloc_mmio32(VIRTIO_BAR2_SIZE)
                .ok_or_else(|| BootError("out of PCI MMIO32 for virtio BAR2".into()))?;
            let intx = machine.make_irq(gsi)?;
            let transport = VirtioPciTransport::new(
                dev,
                mem.clone(),
                bar0,
                bar2,
                gsi as u8,
                intx,
                msi_router.clone(),
            );
            pci.add_device(slot, 0, Arc::new(Mutex::new(transport)));
            Ok(())
        };

        for disk in &cfg.disks {
            let blk = Block::open(&disk.path, disk.read_only)
                .map_err(|e| BootError(format!("open disk {}: {e}", disk.path.display())))?;
            attach_virtio(Box::new(blk))?;
        }
        for share in &cfg.shares {
            let fs = Fs::new(&share.tag, &share.host_dir, share.read_only)
                .map_err(|e| BootError(format!("open share {:?}: {e}", share.tag)))?;
            attach_virtio(Box::new(fs))?;
        }
        let mut vsock_host = None;
        if let Some(cid) = cfg.vsock_cid {
            let (dev, host) = vsock(cid);
            attach_virtio(Box::new(dev))?;
            vsock_host = Some(host);
        }
        if !cfg.cdroms.is_empty() {
            // Attach CD-ROMs on ICH9 AHCI (`00:1f.2`, `8086:2922`) so both OVMF and Windows WinPE
            // (`storahci.sys`) discover them using inbox drivers.
            let ahci_bar5 = pci
                .alloc_mmio32(AHCI_BAR5_SIZE)
                .ok_or_else(|| BootError("out of PCI MMIO32 for AHCI BAR5".into()))?;
            let ahci_gsi = 16 + ((31 - 1) % 4);
            let ahci = AhciController::open(
                &cfg.cdroms,
                mem.clone(),
                ahci_bar5,
                ahci_gsi as u8,
                machine.make_irq(ahci_gsi)?,
                msi_router.clone(),
            )
            .map_err(|e| BootError(format!("open AHCI cdroms: {e}")))?;
            pci.add_device(0x1f, 2, Arc::new(Mutex::new(ahci)));
        }

        let pci_mmio64_base = (FOUR_GIB + high_mem).next_multiple_of(1 << 30);
        let acpi_blobs = acpi::build(
            cfg.cpus,
            Some((pci_mmio64_base, pci_mmio64_base + (2 << 30))),
            cfg.vtpm.is_some(),
        );
        let tpm = cfg
            .vtpm
            .as_deref()
            .map(|p| Mutex::new(Tpm2Crb::open(Some(p))));

        let captured = Arc::new(Mutex::new(Vec::new()));
        let uart: Arc<Mutex<Uart>> = Arc::new(Mutex::new(Serial::new(
            UartIrq(machine.make_irq(COM1_IRQ)?),
            Sink {
                captured: captured.clone(),
                echo: cfg.echo,
            },
        )));
        let debugcon = Arc::new(Mutex::new(Vec::new()));

        let powered_off = Arc::new(AtomicBool::new(false));
        let devices = Arc::new(UefiDevices {
            uart: uart.clone(),
            debugcon: debugcon.clone(),
            echo_debugcon: cfg.echo_debugcon,
            pci: Mutex::new(pci),
            vbe: vbe.clone(),
            hpet: Hpet::new(),
            pflash,
            ioapic: machine.ioapic(),
            tpm,
            cmos: Mutex::new(UefiCmos::new(low_mem, high_mem, cfg.cpus)),
            fw_cfg: Mutex::new(FwCfg::new(low_mem, high_mem, cfg.cpus, acpi_blobs)),
            mem: mem.clone(),
            boot_instant: Instant::now(),
            port_61: Mutex::new(0),
            port_92: Mutex::new(0x02),
            pm1_cnt: Mutex::new(0),
            vga_retrace: Mutex::new(0),
            powered_off: powered_off.clone(),
        });

        let mut vcpus = Vec::with_capacity(cfg.cpus as usize);
        for id in 0..cfg.cpus {
            let vcpu = machine.create_vcpu(id, cfg.cpus, cfg.hyperv)?;
            vcpus.push(vcpu);
        }

        let stop = Arc::new(AtomicBool::new(false));
        if cfg.stdin {
            let uart = uart.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 256];
                while let Ok(n) = io::Read::read(&mut io::stdin(), &mut buf) {
                    if n == 0 {
                        break;
                    }
                    enqueue_uart(&uart, &buf[..n]);
                }
            });
        }
        if let Some((trigger, payload)) = cfg.send_on_match.clone() {
            let (captured, uart, stop) = (captured.clone(), uart.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let matched = {
                        let guard = captured.lock().unwrap();
                        String::from_utf8_lossy(&guard).contains(&trigger)
                    };
                    if matched {
                        std::thread::sleep(Duration::from_millis(250));
                        enqueue_uart(&uart, &payload);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            });
        }

        let (tx, rx) = mpsc::channel();
        let keep = Arc::new((machine.clone(), mem, fb_mem.clone()));
        let threads = vcpus
            .into_iter()
            .map(|mut vcpu| {
                let (stop, tx, devices, keep) =
                    (stop.clone(), tx.clone(), devices.clone(), keep.clone());
                std::thread::spawn(move || {
                    let r = vcpu.run(&devices, &stop).map_err(|e| e.0);
                    let _ = tx.send(r);
                    drop(vcpu);
                    drop(keep);
                })
            })
            .collect();
        drop(tx);
        drop(keep);

        Ok(Self {
            machine,
            vsock: vsock_host,
            uart,
            captured,
            debugcon,
            fb_mem,
            vbe,
            stop,
            powered_off,
            rx: Mutex::new(rx),
            done: Mutex::new(None),
            threads: Mutex::new(threads),
        })
    }

    /// Inject raw bytes into the guest's COM1 serial input FIFO.
    pub fn send_serial(&self, data: &[u8]) {
        enqueue_uart(&self.uart, data);
    }

    /// The host side of the guest's `virtio-vsock` PCIe device, if configured.
    pub fn vsock(&self) -> Option<&VsockHost> {
        self.vsock.as_ref()
    }

    /// Everything the guest has written to COM1 so far.
    pub fn console(&self) -> String {
        String::from_utf8_lossy(&self.captured.lock().unwrap()).into_owned()
    }

    /// Everything OVMF has written to ISA debugcon (`0x402`) so far.
    pub fn debugcon(&self) -> String {
        String::from_utf8_lossy(&self.debugcon.lock().unwrap()).into_owned()
    }

    /// Snapshot the Bochs VBE framebuffer `(width, height, bpp, bytes)` if VBE is enabled.
    pub fn framebuffer(&self) -> Option<(u16, u16, u16, Vec<u8>)> {
        let (w, h, bpp, enabled) = self.vbe.lock().unwrap().mode();
        if !enabled || w == 0 || h == 0 || bpp == 0 {
            return None;
        }
        let bytes = usize::from(w) * usize::from(h) * usize::from(bpp / 8);
        let guard = self.fb_mem.lock().unwrap();
        let slice = guard.as_slice();
        let take = bytes.min(slice.len());
        Some((w, h, bpp, slice[..take].to_vec()))
    }

    /// True if the guest exited via ACPI S5 poweroff (`PM1a_CNT` `SLP_EN`) rather than a reboot.
    pub fn powered_off(&self) -> bool {
        self.powered_off.load(Ordering::SeqCst)
    }

    /// Has the VM stopped?
    pub fn finished(&self) -> bool {
        self.done.lock().unwrap().is_some() || self.poll(Duration::ZERO).is_some()
    }

    fn kick_all(&self) {
        for (i, t) in self.threads.lock().unwrap().iter().enumerate() {
            self.machine.kick(i, t);
        }
    }

    fn poll(&self, timeout: Duration) -> Option<Result<ExitReason, String>> {
        let mut done = self.done.lock().unwrap();
        if done.is_none() {
            let rx = self.rx.lock().unwrap();
            match rx.recv_timeout(timeout) {
                Ok(r) => {
                    *done = Some(r);
                    self.stop.store(true, Ordering::SeqCst);
                    self.kick_all();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    *done = Some(Err("vCPU thread died".into()))
                }
            }
        }
        done.clone()
    }

    /// Wait for the guest to exit. `None` means `timeout` elapsed first.
    pub fn wait(&self, timeout: Option<Duration>) -> Option<Result<ExitReason, BootError>> {
        let r = match timeout {
            Some(t) => self.poll(t),
            None => loop {
                if let Some(r) = self.poll(Duration::from_secs(3600)) {
                    break Some(r);
                }
            },
        };
        r.map(|r| r.map_err(BootError))
    }

    /// Stop the VM immediately. Idempotent.
    pub fn stop(&self) -> ExitReason {
        if let Some(Ok(r)) = self.poll(Duration::ZERO) {
            return r;
        }
        self.stop.store(true, Ordering::SeqCst);
        self.kick_all();
        match self.poll(Duration::from_secs(5)) {
            Some(Ok(r)) => r,
            _ => ExitReason::Timeout,
        }
    }
}

impl Drop for UefiVm {
    fn drop(&mut self) {
        let _ = self.stop();
        for t in self.threads.lock().unwrap().drain(..) {
            let _ = t.join();
        }
    }
}

/// Boot a Q35 PCIe UEFI (OVMF) VM synchronously until it exits or times out.
pub fn boot_uefi(cfg: &UefiConfig) -> Result<UefiOutcome, BootError> {
    let vm = UefiVm::start(cfg)?;
    let exit = match vm.wait(cfg.timeout) {
        Some(r) => r?,
        None => vm.stop(),
    };
    Ok(UefiOutcome {
        console: vm.console(),
        debugcon: vm.debugcon(),
        exit,
        powered_off: vm.powered_off(),
    })
}

/// Unused helper re-export marker to keep `BootConfig` import clean.
#[allow(dead_code)]
fn _assert_types(_: &BootConfig) {}

fn enqueue_uart(uart: &Arc<Mutex<Uart>>, mut pending: &[u8]) {
    while !pending.is_empty() {
        let mut u = uart.lock().unwrap();
        let take = u.fifo_capacity().min(pending.len());
        if take > 0 && u.enqueue_raw_bytes(&pending[..take]).is_ok() {
            pending = &pending[take..];
            continue;
        }
        drop(u);
        std::thread::sleep(Duration::from_millis(5));
    }
}
