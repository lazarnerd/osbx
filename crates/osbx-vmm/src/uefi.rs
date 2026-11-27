//! Q35 PCIe UEFI (EDK2 OVMF) virtual machine monitor on KVM.
//!
//! Boots UEFI guests (Windows Server 2022/2025, Windows 11, UEFI Linux) from the x86 16-bit
//! reset vector (`0xFFFF_FFF0`) with:
//! - Q35 MCH (`8086:29c0`) + ICH9 LPC/PM (`8086:2918`) + PCIe ECAM (`0xB000_0000`)
//! - ACPI 2.0 tables (`RSDP`, `XSDT`, `FADT`, `MADT`, `MCFG`, `HPET`, `DSDT`) via `fw_cfg`
//! - Persistent CFI `pflash` for `OVMF_VARS_4M.fd` + `KVM_MEM_READONLY` `OVMF_CODE_4M.fd`
//! - Bochs VBE PCI display (`1234:1111`, 16 MiB linear framebuffer) for UEFI GOP
//! - Modern Virtio 1.0 `virtio-pci` devices (`Block` raw/QCOW2, `VirtioScsi` CD-ROM, `Vsock`)
//!   with KVM MSI-X routing (`KVM_SET_GSI_ROUTING` + `irqfd`)
//! - KVM Hyper-V enlightenments (`hv_relaxed`, `hv_vapic`, `hv_vpindex`, `hv_time`, `hv_synic`,
//!   `hv_stimer`, `hv_runtime`, `hv_reset`, `hv_tlbflush`)

use crate::acpi;
use crate::boot::{BootConfig, BootError, DiskConfig, ExitReason, cpuid_topology, err};
use crate::devices::{COM1, COM1_IRQ, Sink, Uart, UartIrq};
use crate::hpet::{HPET_BASE, HPET_SIZE, Hpet};
use crate::irq::{Irq, IrqLine};
use crate::pci::ahci::{AHCI_BAR5_SIZE, AhciController};
use crate::pci::vga::{
    BochsVga, VBE_DISPI_DATA_PORT, VBE_DISPI_INDEX_PORT, VGA_FB_SIZE, VGA_MMIO_SIZE, VbeState,
};
use crate::pci::virtio_pci::{VIRTIO_BAR0_SIZE, VIRTIO_BAR2_SIZE, VirtioPciTransport};
use crate::pci::{MsiRouter, PciBus};
use crate::pflash::Pflash;
use crate::virtio::blk::Block;
use crate::virtio::vsock::{VsockHost, vsock};
use crate::virtio::{GuestMem, VirtioDevice};
use kvm_bindings::{
    KVM_CAP_HYPERV_SYNIC2, KVM_EXIT_HYPERV_HCALL, KVM_EXIT_HYPERV_SYNDBG, KVM_EXIT_HYPERV_SYNIC,
    KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI, KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER,
    KVM_IRQCHIP_PIC_SLAVE, KVM_MAX_CPUID_ENTRIES, KVM_MEM_READONLY, KVM_PIT_SPEAKER_DUMMY,
    KVM_SYSTEM_EVENT_SHUTDOWN, KvmIrqRouting, Msrs, kvm_enable_cap, kvm_fpu, kvm_irq_routing_entry,
    kvm_msr_entry, kvm_pit_config, kvm_userspace_memory_region,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use std::io::{self, Write};
use std::os::unix::thread::JoinHandleExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vm_superio::Serial;
use vmm_sys_util::eventfd::EventFd;

/// 4 GiB boundary; firmware ROM is mapped ending right below this address.
const FOUR_GIB: u64 = 1u64 << 32;
/// Top of low RAM on Q35 (2 GiB), leaving `0xB000_0000` for PCIe ECAM and `0xC000_0000` for PCI MMIO.
const UEFI_LOW_MEM_END: u64 = 0x8000_0000;
/// KVM TSS and identity-map addresses kept below IOAPIC (`0xFEC0_0000`) and flash (`0xFFC0_0000`).
const UEFI_KVM_TSS_ADDR: u64 = 0xfeb0_0000;
const UEFI_KVM_IDENTITY_MAP_ADDR: u64 = 0xfeb0_4000;
/// Dedicated KVM memory slot for Bochs VGA 16 MiB linear framebuffer.
const VGA_FB_KVM_SLOT: u32 = 10;
/// ACPI PM timer frequency (3.579545 MHz).
const ACPI_PM_TIMER_HZ: u128 = 3_579_545;

/// Configuration for booting a Q35 PCIe UEFI (OVMF) VM on KVM.
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
    /// Read-only ISO CD-ROMs attached via `virtio-scsi` (PCIe, targets `0..cdroms.len()`).
    pub cdroms: Vec<PathBuf>,
    /// Attach a `virtio-vsock` (PCIe) device with this guest CID (3 is conventional).
    pub vsock_cid: Option<u64>,
    /// Expose KVM Hyper-V enlightenments (`hv_relaxed`, `hv_time`, `hv_synic`, `hv_stimer`, etc.).
    pub hyperv: bool,
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
            vsock_cid: None,
            hyperv: true,
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

struct EventFdLine(EventFd);
impl IrqLine for EventFdLine {
    fn pulse(&self) {
        let _ = self.0.write(1);
    }
}

/// KVM MSI-X router backed by `KVM_SET_GSI_ROUTING` + per-vector `EventFd` (`KVM_IRQFD`).
struct KvmMsiRouter {
    vm: Arc<VmFd>,
    state: Mutex<MsiRouterState>,
}

struct MsiEntry {
    gsi: u32,
    evt: EventFd,
    addr: u64,
    data: u32,
    configured: bool,
}

struct MsiRouterState {
    next_gsi: u32,
    entries: Vec<MsiEntry>,
}

impl KvmMsiRouter {
    fn new(vm: Arc<VmFd>) -> Self {
        Self {
            vm,
            state: Mutex::new(MsiRouterState {
                next_gsi: 24, // 0..24 are reserved for PIC/IOAPIC
                entries: Vec::new(),
            }),
        }
    }

    fn rebuild_routing(&self, entries: &[MsiEntry]) -> io::Result<()> {
        // Base legacy PIC (0..16) + IOAPIC (0..24) routes + active MSI routes.
        let mut raw_entries: Vec<kvm_irq_routing_entry> = Vec::new();
        for pin in 0u32..16 {
            let (chip, chip_pin) = if pin < 8 {
                (KVM_IRQCHIP_PIC_MASTER, pin)
            } else {
                (KVM_IRQCHIP_PIC_SLAVE, pin - 8)
            };
            let mut e = kvm_irq_routing_entry {
                gsi: pin,
                type_: KVM_IRQ_ROUTING_IRQCHIP,
                flags: 0,
                ..Default::default()
            };
            e.u.irqchip.irqchip = chip;
            e.u.irqchip.pin = chip_pin;
            raw_entries.push(e);
        }
        for pin in 0u32..24 {
            let mut e = kvm_irq_routing_entry {
                gsi: pin,
                type_: KVM_IRQ_ROUTING_IRQCHIP,
                flags: 0,
                ..Default::default()
            };
            e.u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC;
            e.u.irqchip.pin = pin;
            raw_entries.push(e);
        }
        for m in entries {
            if !m.configured {
                continue;
            }
            let mut e = kvm_irq_routing_entry {
                gsi: m.gsi,
                type_: KVM_IRQ_ROUTING_MSI,
                flags: 0,
                ..Default::default()
            };
            e.u.msi.address_lo = m.addr as u32;
            e.u.msi.address_hi = (m.addr >> 32) as u32;
            e.u.msi.data = m.data;
            raw_entries.push(e);
        }

        let mut routing = KvmIrqRouting::new(raw_entries.len()).map_err(io::Error::other)?;
        routing.as_mut_slice().copy_from_slice(&raw_entries);
        self.vm
            .set_gsi_routing(&routing)
            .map_err(|e| io::Error::other(format!("KVM_SET_GSI_ROUTING: {e}")))
    }
}

impl MsiRouter for KvmMsiRouter {
    fn allocate(&self) -> io::Result<u32> {
        let mut st = self.state.lock().unwrap();
        let gsi = st.next_gsi;
        st.next_gsi += 1;
        let evt = EventFd::new(0)?;
        self.vm
            .register_irqfd(&evt, gsi)
            .map_err(|e| io::Error::other(format!("KVM_IRQFD(msi {gsi}): {e}")))?;
        let handle = st.entries.len() as u32;
        st.entries.push(MsiEntry {
            gsi,
            evt,
            addr: 0,
            data: 0,
            configured: false,
        });
        Ok(handle)
    }

    fn configure(&self, handle: u32, addr: u64, data: u32) -> io::Result<()> {
        let mut st = self.state.lock().unwrap();
        let Some(entry) = st.entries.get_mut(handle as usize) else {
            return Ok(());
        };
        if entry.configured && entry.addr == addr && entry.data == data {
            return Ok(());
        }
        entry.addr = addr;
        entry.data = data;
        entry.configured = true;
        let res = self.rebuild_routing(&st.entries);
        if let Err(ref e) = res {
            eprintln!(
                "[osbx-vmm] KVM_SET_GSI_ROUTING failed (h={handle}, addr={addr:#x}, data={data:#x}): {e}"
            );
        }
        res
    }

    fn trigger(&self, handle: u32) {
        let st = self.state.lock().unwrap();
        if let Some(entry) = st.entries.get(handle as usize) {
            let _ = entry.evt.write(1);
        }
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
        // Reserve PCIe ECAM window (`0xB000_0000..0xC000_0000`)
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

struct UefiDevices {
    uart: Arc<Mutex<Uart>>,
    debugcon: Arc<Mutex<Vec<u8>>>,
    echo_debugcon: bool,
    pci: Mutex<PciBus>,
    vbe: Arc<Mutex<VbeState>>,
    hpet: Hpet,
    pflash: Option<Pflash>,
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
    fn pm_timer_ticks(&self) -> u32 {
        let ns = self.boot_instant.elapsed().as_nanos();
        ((ns * ACPI_PM_TIMER_HZ) / 1_000_000_000) as u32 & 0x00ff_ffff
    }

    fn io_out(&self, port: u16, data: &[u8]) -> Option<ExitReason> {
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

    fn io_in(&self, port: u16, data: &mut [u8]) {
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

    fn mmio_read(&self, addr: u64, data: &mut [u8]) {
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
        if !self.pci.lock().unwrap().mmio_read(addr, data) {
            data.fill(0xff);
        }
    }

    fn mmio_write(&self, addr: u64, data: &[u8]) {
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
        self.pci.lock().unwrap().mmio_write(addr, data);
    }
}

/// Page-aligned backing store for the Bochs VGA 16 MiB linear framebuffer KVM slot.
struct FbBuffer {
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

    fn as_ptr(&self) -> *const u8 {
        self.buf[self.offset..].as_ptr()
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[self.offset..self.offset + self.len]
    }
}

/// A running Q35 PCIe UEFI virtual machine on KVM.
pub struct UefiVm {
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

        let kvm = Kvm::new().map_err(err("open /dev/kvm"))?;
        let vm = Arc::new(kvm.create_vm().map_err(err("KVM_CREATE_VM"))?);
        map_uefi_memory(&vm, &mem, code_base, code_readonly)?;
        vm.set_tss_address(UEFI_KVM_TSS_ADDR as usize)
            .map_err(err("KVM_SET_TSS_ADDR"))?;
        vm.set_identity_map_address(UEFI_KVM_IDENTITY_MAP_ADDR)
            .map_err(err("KVM_SET_IDENTITY_MAP_ADDR"))?;
        vm.create_irq_chip().map_err(err("KVM_CREATE_IRQCHIP"))?;
        vm.create_pit2(kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..Default::default()
        })
        .map_err(err("KVM_CREATE_PIT2"))?;
        install_kick_handler();

        let make_irq = |gsi: u32| -> Result<Irq, BootError> {
            let evt = EventFd::new(0).map_err(err("eventfd"))?;
            vm.register_irqfd(&evt, gsi).map_err(err("KVM_IRQFD"))?;
            Ok(Arc::new(EventFdLine(evt)))
        };

        let msi_router: Arc<dyn MsiRouter> = Arc::new(KvmMsiRouter::new(vm.clone()));
        let mut pci = PciBus::new();

        // Slot 00:01.0: Bochs VBE GOP framebuffer (BAR0 16 MiB linear FB, BAR2 4 KiB MMIO regs)
        let fb_mem = Arc::new(Mutex::new(FbBuffer::new(VGA_FB_SIZE as usize)));
        let fb_bar0 = pci
            .alloc_mmio32(VGA_FB_SIZE)
            .ok_or_else(|| BootError("out of PCI MMIO32 for VGA BAR0".into()))?;
        let fb_bar2 = pci
            .alloc_mmio32(VGA_MMIO_SIZE)
            .ok_or_else(|| BootError("out of PCI MMIO32 for VGA BAR2".into()))?;
        let fb_mapper = make_fb_mapper(vm.clone(), fb_mem.clone());
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
            let intx = make_irq(gsi)?;
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
                make_irq(ahci_gsi)?,
                msi_router.clone(),
            )
            .map_err(|e| BootError(format!("open AHCI cdroms: {e}")))?;
            pci.add_device(0x1f, 2, Arc::new(Mutex::new(ahci)));
        }

        let pci_mmio64_base = (FOUR_GIB + high_mem).next_multiple_of(1 << 30);
        let acpi_blobs = acpi::build(
            cfg.cpus,
            Some((pci_mmio64_base, pci_mmio64_base + (2 << 30))),
        );

        let captured = Arc::new(Mutex::new(Vec::new()));
        let uart: Arc<Mutex<Uart>> = Arc::new(Mutex::new(Serial::new(
            UartIrq(make_irq(COM1_IRQ)?),
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
            let mut vcpu = vm
                .create_vcpu(u64::from(id))
                .map_err(err("KVM_CREATE_VCPU"))?;
            setup_uefi_vcpu(&kvm, &mut vcpu, id, cfg.cpus, cfg.hyperv)?;
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
        let keep = Arc::new((vm, mem, fb_mem.clone()));
        let threads = vcpus
            .into_iter()
            .map(|mut vcpu| {
                let (stop, tx, devices, keep) =
                    (stop.clone(), tx.clone(), devices.clone(), keep.clone());
                std::thread::spawn(move || {
                    let r = run_uefi_vcpu(&mut vcpu, &devices, &stop).map_err(|e| e.0);
                    let _ = tx.send(r);
                    drop(vcpu);
                    drop(keep);
                })
            })
            .collect();
        drop(tx);
        drop(keep);

        Ok(Self {
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
        for t in self.threads.lock().unwrap().iter() {
            kick_thread(t);
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

#[allow(unsafe_code)]
fn make_fb_mapper(vm: Arc<VmFd>, fb_mem: Arc<Mutex<FbBuffer>>) -> crate::pci::vga::BarMapper {
    let current = Mutex::new(None::<u64>);
    Arc::new(move |new_gpa: Option<u64>| {
        let mut cur = current.lock().unwrap();
        if *cur == new_gpa {
            return;
        }
        let guard = fb_mem.lock().unwrap();
        let host_ptr = guard.as_ptr() as u64;
        if let Some(old) = *cur {
            let unmap = kvm_userspace_memory_region {
                slot: VGA_FB_KVM_SLOT,
                flags: 0,
                guest_phys_addr: old,
                memory_size: 0,
                userspace_addr: host_ptr,
            };
            // SAFETY: unmapping slot VGA_FB_KVM_SLOT with memory_size = 0.
            let _ = unsafe { vm.set_user_memory_region(unmap) };
        }
        if let Some(gpa) = new_gpa {
            let map = kvm_userspace_memory_region {
                slot: VGA_FB_KVM_SLOT,
                flags: 0,
                guest_phys_addr: gpa,
                memory_size: guard.len as u64,
                userspace_addr: host_ptr,
            };
            // SAFETY: `fb_mem` is page-aligned, kept alive in `keep` for the entire lifetime of
            // the VM, and never reallocated after creation.
            if let Err(e) = unsafe { vm.set_user_memory_region(map) } {
                eprintln!("[osbx-vmm] warning: failed to map VGA framebuffer at {gpa:#x}: {e}");
            } else {
                *cur = Some(gpa);
                return;
            }
        }
        *cur = None;
    })
}

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

#[allow(unsafe_code)]
fn map_uefi_memory(
    vm: &VmFd,
    mem: &GuestMem,
    code_base: u64,
    code_readonly: bool,
) -> Result<(), BootError> {
    for (slot, region) in mem.iter().enumerate() {
        let host = mem
            .get_host_address(region.start_addr())
            .map_err(err("host address"))?;
        let gpa = region.start_addr().raw_value();
        let flags = if code_readonly && gpa == code_base {
            KVM_MEM_READONLY
        } else {
            0
        };
        let r = kvm_userspace_memory_region {
            slot: slot as u32,
            flags,
            guest_phys_addr: gpa,
            memory_size: region.len(),
            userspace_addr: host as u64,
        };
        // SAFETY: `host` points at `region.len()` bytes owned by `mem`, kept alive by `keep`
        // until every vCPU thread exits and drops its handle.
        unsafe { vm.set_user_memory_region(r) }.map_err(err("KVM_SET_USER_MEMORY_REGION"))?;
    }
    Ok(())
}

fn setup_uefi_vcpu(
    kvm: &Kvm,
    vcpu: &mut VcpuFd,
    id: u8,
    cpus: u8,
    hyperv: bool,
) -> Result<(), BootError> {
    let mut cpuid = kvm
        .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
        .map_err(err("KVM_GET_SUPPORTED_CPUID"))?;
    for e in cpuid.as_mut_slice() {
        let mut r = [e.eax, e.ebx, e.ecx, e.edx];
        cpuid_topology(e.function, e.index, &mut r, id, cpus);
        [e.eax, e.ebx, e.ecx, e.edx] = r;
    }

    if hyperv {
        // Enable KVM Hyper-V SynIC2 if supported by the host kernel.
        let cap = kvm_enable_cap {
            cap: KVM_CAP_HYPERV_SYNIC2,
            ..Default::default()
        };
        let synic_ok = vcpu.enable_cap(&cap).is_ok();

        // Relocate KVM's own hypervisor leaves from 0x4000_0000 to 0x4000_0100 so both
        // Windows (Hyper-V TLFS at 0x4000_0000) and Linux (KVM at 0x4000_0100) detect their
        // paravirtualization interfaces cleanly.
        let mut merged: Vec<kvm_bindings::kvm_cpuid_entry2> = cpuid
            .as_slice()
            .iter()
            .copied()
            .map(|mut e| {
                if (0x4000_0000..0x4000_0100).contains(&e.function) {
                    e.function += 0x100;
                    if e.function == 0x4000_0100 && e.eax >= 0x4000_0000 {
                        e.eax += 0x100;
                    }
                }
                e
            })
            .collect();

        // Hyper-V TLFS CPUID leaves (0x4000_0000..=0x4000_0005), supported natively by KVM.
        let mut hv_features: u32 = (1 << 0)  // HV_MSR_VP_RUNTIME_AVAILABLE
            | (1 << 1)  // HV_MSR_TIME_REF_COUNT_AVAILABLE
            | (1 << 4)  // HV_MSR_APIC_ACCESS_AVAILABLE
            | (1 << 5)  // HV_MSR_HYPERCALL_AVAILABLE
            | (1 << 6)  // HV_MSR_VP_INDEX_AVAILABLE
            | (1 << 7)  // HV_MSR_RESET_AVAILABLE
            | (1 << 9)  // HV_MSR_REFERENCE_TSC_AVAILABLE
            | (1 << 11); // HV_ACCESS_FREQUENCY_MSRS
        if synic_ok {
            hv_features |= (1 << 2) | (1 << 3); // HV_MSR_SYNIC_AVAILABLE | HV_MSR_SYNTIMER_AVAILABLE
        }
        let hv_entry = |function: u32, eax: u32, ebx: u32, ecx: u32, edx: u32| {
            kvm_bindings::kvm_cpuid_entry2 {
                function,
                index: 0,
                flags: 0,
                eax,
                ebx,
                ecx,
                edx,
                padding: [0; 3],
            }
        };
        merged.extend_from_slice(&[
            // 0x4000_0000: Hyper-V vendor ID ("Microsoft Hv")
            hv_entry(
                0x4000_0000,
                0x4000_0005,
                u32::from_le_bytes(*b"Micr"),
                u32::from_le_bytes(*b"osof"),
                u32::from_le_bytes(*b"t Hv"),
            ),
            // 0x4000_0001: Hyper-V interface ("Hv#1")
            hv_entry(0x4000_0001, u32::from_le_bytes(*b"Hv#1"), 0, 0, 0),
            // 0x4000_0002: Hyper-V version (Windows Server 2016/2025 compatible build)
            hv_entry(0x4000_0002, 0x0000_1db1, 0x0006_0001, 0, 0),
            // 0x4000_0003: Hyper-V feature identification (enable direct-mode stimer when SynIC ok)
            hv_entry(
                0x4000_0003,
                hv_features,
                0,
                0,
                if synic_ok { 1 << 19 } else { 0 },
            ),
            // 0x4000_0004: Implementation recommendations (relaxed timing, APIC access, TLB flush)
            hv_entry(0x4000_0004, (1 << 2) | (1 << 3) | (1 << 5), 0x0fff, 0, 0),
            // 0x4000_0005: Implementation limits (max VPs / logical processors)
            hv_entry(0x4000_0005, 64, 64, 0, 0),
        ]);
        if let Ok(new_cpuid) = kvm_bindings::CpuId::from_entries(&merged) {
            cpuid = new_cpuid;
        }
    }

    vcpu.set_cpuid2(&cpuid).map_err(err("KVM_SET_CPUID2"))?;

    let msrs = Msrs::from_entries(&[
        kvm_msr_entry {
            index: 0x1a0,
            data: 1,
            ..Default::default()
        },
        kvm_msr_entry {
            index: 0x2ff,
            data: (1 << 11) | 6,
            ..Default::default()
        },
    ])
    .map_err(err("msr list"))?;
    vcpu.set_msrs(&msrs).map_err(err("KVM_SET_MSRS"))?;
    vcpu.set_fpu(&kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    })
    .map_err(err("KVM_SET_FPU"))?;
    Ok(())
}

fn run_uefi_vcpu(
    vcpu: &mut VcpuFd,
    dev: &UefiDevices,
    stop: &AtomicBool,
) -> Result<ExitReason, BootError> {
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(ExitReason::Timeout);
        }
        match vcpu.run() {
            Ok(VcpuExit::IoOut(port, data)) => {
                if let Some(r) = dev.io_out(port, data) {
                    return Ok(r);
                }
            }
            Ok(VcpuExit::IoIn(port, data)) => dev.io_in(port, data),
            Ok(VcpuExit::MmioRead(addr, data)) => dev.mmio_read(addr, data),
            Ok(VcpuExit::MmioWrite(addr, data)) => dev.mmio_write(addr, data),
            Ok(VcpuExit::Shutdown) => return Ok(ExitReason::TripleFault),
            Ok(VcpuExit::SystemEvent(ty, _)) => {
                if ty == KVM_SYSTEM_EVENT_SHUTDOWN {
                    dev.powered_off.store(true, Ordering::SeqCst);
                }
                return Ok(ExitReason::GuestReset);
            }
            Ok(VcpuExit::Hyperv) => handle_hyperv_exit(vcpu),
            Ok(other) => return Err(BootError(format!("unhandled VM exit: {other:?}"))),
            Err(e) if e.errno() == libc::EINTR || e.errno() == libc::EAGAIN => {}
            Err(e) => return Err(BootError(format!("KVM_RUN: {e}"))),
        }
    }
}

#[allow(unsafe_code)]
fn handle_hyperv_exit(vcpu: &mut VcpuFd) {
    // SAFETY: KVM just exited with `KVM_EXIT_HYPERV`, so `kvm_run.__bindgen_anon_1.hyperv` is
    // the active union variant populated by the kernel.
    let hv = unsafe { &mut vcpu.get_kvm_run().__bindgen_anon_1.hyperv };
    match hv.type_ {
        // Guest wrote SynIC MSRs (SCONTROL/SIMP/SIEFP); KVM already updated internal state.
        KVM_EXIT_HYPERV_SYNIC | KVM_EXIT_HYPERV_SYNDBG => {}
        // Unhandled Hyper-V hypercall forwarded to userspace: return HV_STATUS_INVALID_HYPERCALL_CODE.
        KVM_EXIT_HYPERV_HCALL => {
            hv.u.hcall.result = 2;
        }
        _ => {}
    }
}

extern "C" fn on_kick(_: libc::c_int) {}

#[allow(unsafe_code)]
fn install_kick_handler() {
    // SAFETY: installs an empty, async-signal-safe SIGUSR1 handler so `kick_thread` interrupts
    // `KVM_RUN` with EINTR without terminating the process.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_kick as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
    }
}

#[allow(unsafe_code)]
fn kick_thread(t: &std::thread::JoinHandle<()>) {
    // SAFETY: `t` is a live, unjoined thread handle and SIGUSR1 has an empty handler installed.
    unsafe {
        libc::pthread_kill(t.as_pthread_t() as libc::pthread_t, libc::SIGUSR1);
    }
}
