//! Boot a Linux bzImage (x86_64) with a serial console, virtio-MMIO devices and an MP table.
//!
//! Layout (guest physical): `0x500` GDT, `0x7000` boot_params ("zero page"), `0x9000..0xc000`
//! identity page tables for the first GiB, `0x20000` kernel command line, `0x100000` kernel,
//! initrd at the top of low RAM. The boot CPU starts in 64-bit mode per the Linux boot protocol;
//! the others wait for INIT/SIPI.
//!
//! Everything here is hypervisor-neutral; [`crate::hv`] is the backend (KVM on Linux, the
//! Windows Hypervisor Platform on Windows). A guest `reboot -f` (keyboard-controller reset,
//! port 0x64 <- 0xfe) ends the run cleanly.

use crate::bus::{DEVICE_IRQS, MmioBus};
use crate::devices::{COM1_IRQ, Devices, Sink, Uart, UartIrq};
use crate::hv::{Machine, Vcpu};
use crate::virtio::VirtioDevice;
use crate::virtio::blk::Block;
use crate::virtio::mmio::{MMIO_SIZE, MmioTransport};
use crate::virtio::vsock::{VsockHost, vsock};
use linux_loader::cmdline::Cmdline;
use linux_loader::configurator::{BootConfigurator, BootParams, linux::LinuxBootConfigurator};
use linux_loader::loader::bootparam::{boot_e820_entry, boot_params};
use linux_loader::loader::{KernelLoader, bzimage::BzImage, load_cmdline};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vm_superio::Serial;

const GDT_ADDR: u64 = 0x500;
const ZERO_PAGE_ADDR: u64 = 0x7000;
const PML4_ADDR: u64 = 0x9000;
const PDPT_ADDR: u64 = 0xa000;
const PD_ADDR: u64 = 0xb000;
const CMDLINE_ADDR: u64 = 0x2_0000;
const KERNEL_ADDR: u64 = 0x10_0000;
const BOOT_STACK: u64 = 0x8ff0;
const E820_RAM: u32 = 1;

/// Default kernel arguments: console on COM1; no ACPI/PCI probing (neither is provided);
/// `reboot=k` makes a guest `reboot -f` use the keyboard-controller reset the VMM watches for.
/// Backends may append their own arguments (see `Machine::cmdline_extra`).
pub const DEFAULT_CMDLINE: &str = "console=ttyS0 earlyprintk=serial,ttyS0 reboot=k panic=1 acpi=off pci=off nokaslr tsc=reliable i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd";

/// A disk image attached as a virtio-blk device (`/dev/vda`, `/dev/vdb`, ... in order).
#[derive(Debug, Clone)]
pub struct DiskConfig {
    /// Raw image file.
    pub path: PathBuf,
    /// Expose it read-only.
    pub read_only: bool,
}

/// A host directory shared with the guest over virtio-fs (mount with `-t virtiofs <tag>`).
#[derive(Debug, Clone)]
pub struct ShareConfig {
    /// Mount tag (1..=36 bytes).
    pub tag: String,
    /// Host directory.
    pub host_dir: PathBuf,
    /// Refuse every modification on the host FUSE server (`EROFS`), even if guest root remounts rw.
    pub read_only: bool,
}

/// What to boot.
#[derive(Debug, Clone)]
pub struct BootConfig {
    /// bzImage (`vmlinuz`).
    pub kernel: PathBuf,
    /// Optional initramfs (cpio, optionally compressed).
    pub initrd: Option<PathBuf>,
    /// Kernel command line (the VMM appends only virtio device and backend arguments).
    pub cmdline: String,
    /// Guest RAM in MiB (64 ..= 65536). RAM above 3 GiB is placed above the 32-bit MMIO hole.
    pub mem_mib: usize,
    /// Number of vCPUs (1 ..= 32).
    pub cpus: u8,
    /// Stop the guest after this long.
    pub timeout: Option<Duration>,
    /// Copy console output to this process's stdout as it arrives.
    pub echo: bool,
    /// Forward this process's stdin to the guest console.
    pub stdin: bool,
    /// Disks, in guest order.
    pub disks: Vec<DiskConfig>,
    /// Attach a virtio-vsock device with this guest CID (3 is conventional).
    pub vsock_cid: Option<u64>,
    /// Host directories shared over virtio-fs.
    pub shares: Vec<ShareConfig>,
}

/// Why the run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// The guest asked for a reset or shutdown (keyboard-controller reset, ACPI-style event).
    GuestReset,
    /// Triple fault: the guest crashed hard.
    TripleFault,
    /// The timeout expired and the guest was stopped.
    Timeout,
}

/// Result of a run.
#[derive(Debug)]
pub struct BootOutcome {
    /// Everything the guest wrote to its serial console.
    pub console: String,
    /// Why it ended.
    pub exit: ExitReason,
}

/// Boot failure (before or during the run).
#[derive(Debug)]
pub struct BootError(pub String);
impl std::fmt::Display for BootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for BootError {}
pub(crate) fn err<E: std::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> BootError {
    move |e| BootError(format!("{what}: {e}"))
}

/// Top of low RAM: everything from here to 4 GiB is the 32-bit MMIO hole (virtio, IOAPIC, LAPIC).
pub(crate) const LOW_MEM_END: u64 = 0xc000_0000;
/// Where RAM continues above the hole.
const HIGH_MEM_START: u64 = 1 << 32;

/// Guest RAM ranges for `size` bytes: one low range, plus a high range if it does not fit.
fn memory_ranges(size: u64) -> Vec<(GuestAddress, usize)> {
    if size <= LOW_MEM_END {
        vec![(GuestAddress(0), size as usize)]
    } else {
        vec![
            (GuestAddress(0), LOW_MEM_END as usize),
            (GuestAddress(HIGH_MEM_START), (size - LOW_MEM_END) as usize),
        ]
    }
}

/// Register state of the boot CPU at the 64-bit kernel entry point.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Entry {
    pub rip: u64,
    pub rsp: u64,
    pub rsi: u64,
    pub gdt_base: u64,
    pub gdt_limit: u16,
    pub cs: Segment,
    pub ds: Segment,
    pub tr: Segment,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
}

/// A decoded GDT entry, in the shape both backends need.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Segment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
}

impl Segment {
    /// The VMX/SVM-style 16-bit access-rights word (WHP segment registers).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn attributes(&self) -> u16 {
        u16::from(self.type_)
            | u16::from(self.s) << 4
            | u16::from(self.dpl) << 5
            | u16::from(self.present) << 7
            | u16::from(self.avl) << 12
            | u16::from(self.l) << 13
            | u16::from(self.db) << 14
            | u16::from(self.g) << 15
    }
}

fn segment(entry: u64, index: u16) -> Segment {
    let g = ((entry >> 55) & 1) as u8;
    let limit = (((entry >> 32) & 0xf_0000) | (entry & 0xffff)) as u32;
    Segment {
        base: ((entry >> 16) & 0xff_ffff) | ((entry >> 32) & 0xff00_0000),
        limit: if g == 1 { (limit << 12) | 0xfff } else { limit },
        selector: index * 8,
        type_: ((entry >> 40) & 0xf) as u8,
        present: ((entry >> 47) & 1) as u8,
        dpl: ((entry >> 45) & 3) as u8,
        db: ((entry >> 54) & 1) as u8,
        s: ((entry >> 44) & 1) as u8,
        l: ((entry >> 53) & 1) as u8,
        g,
        avl: ((entry >> 52) & 1) as u8,
    }
}

/// Adjust one CPUID result so the guest sees `n` single-threaded cores, this vCPU being APIC
/// id `id`. `r` is `[eax, ebx, ecx, edx]` for leaf `function`, subleaf `index`.
pub(crate) fn cpuid_topology(function: u32, index: u32, r: &mut [u32; 4], id: u8, n: u8) {
    let (id, n) = (u32::from(id), u32::from(n));
    let core_bits = n.next_power_of_two().trailing_zeros();
    match function {
        1 => {
            r[1] = (r[1] & 0x0000_ffff) | (n << 16) | (id << 24); // logical CPUs, initial APIC id
            if n > 1 {
                r[3] |= 1 << 28; // HTT: more than one logical processor
            }
            r[2] |= 1 << 31; // running under a hypervisor
        }
        4 if n > 1 => r[0] = (r[0] & 0x03ff_ffff) | ((n - 1) << 26), // cores per package - 1
        0xb | 0x1f => {
            r[3] = id; // x2APIC id
            match index {
                0 => (r[0], r[1], r[2]) = (0, 1, 1 << 8), // SMT level: 1 thread
                1 => (r[0], r[1], r[2]) = (core_bits, n, (2 << 8) | 1), // core level: n cores
                i => (r[0], r[1], r[2]) = (0, 0, i),
            }
        }
        _ => {}
    }
}

/// A running (or finished) virtual machine.
pub struct Vm {
    vsock: Option<VsockHost>,
    captured: Arc<Mutex<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    machine: Arc<Machine>,
    rx: Mutex<mpsc::Receiver<Result<ExitReason, String>>>,
    done: Mutex<Option<Result<ExitReason, String>>>,
    threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl Vm {
    /// Build the machine, load the kernel and start the vCPU threads.
    pub fn start(cfg: &BootConfig) -> Result<Vm, BootError> {
        if !(64..=65536).contains(&cfg.mem_mib) {
            return Err(BootError("mem_mib must be between 64 and 65536".into()));
        }
        if !(1..=crate::mptable::MAX_CPUS).contains(&cfg.cpus) {
            return Err(BootError(format!(
                "cpus must be between 1 and {}",
                crate::mptable::MAX_CPUS
            )));
        }
        let mem_size = (cfg.mem_mib as u64) << 20;
        let mem = GuestMemoryMmap::<()>::from_ranges(&memory_ranges(mem_size))
            .map_err(err("guest memory"))?;
        let machine = Arc::new(Machine::new(&mem, cfg.cpus)?);

        // virtio devices: one MMIO window and one interrupt line each, announced on the command line.
        let mut bus = MmioBus::default();
        let mut cfg = cfg.clone();
        cfg.cmdline.push_str(&machine.cmdline_extra());
        let wanted = cfg.disks.len() + cfg.shares.len() + usize::from(cfg.vsock_cid.is_some());
        if wanted > DEVICE_IRQS.len() {
            return Err(BootError(format!(
                "at most {} virtio devices are supported",
                DEVICE_IRQS.len()
            )));
        }
        let mut slot = 0;
        let mut add = |dev: Box<dyn VirtioDevice>, cmdline: &mut String| -> Result<(), BootError> {
            let irq = machine.irq_line(DEVICE_IRQS[slot])?;
            bus.add(
                slot,
                Arc::new(Mutex::new(MmioTransport::new(dev, mem.clone(), irq))),
            );
            cmdline.push_str(&format!(
                " virtio_mmio.device={}@0x{:x}:{}",
                MMIO_SIZE,
                MmioBus::slot_base(slot),
                DEVICE_IRQS[slot]
            ));
            slot += 1;
            Ok(())
        };
        for disk in &cfg.disks {
            let blk = Block::open(&disk.path, disk.read_only)
                .map_err(|e| BootError(format!("open disk {}: {e}", disk.path.display())))?;
            add(Box::new(blk), &mut cfg.cmdline)?;
        }
        for share in &cfg.shares {
            let fs = crate::virtio::fs::Fs::new(&share.tag, &share.host_dir, share.read_only)
                .map_err(|e| BootError(format!("share {}: {e}", share.host_dir.display())))?;
            add(Box::new(fs), &mut cfg.cmdline)?;
        }
        let mut vsock_host = None;
        if let Some(cid) = cfg.vsock_cid {
            let (dev, host) = vsock(cid);
            add(Box::new(dev), &mut cfg.cmdline)?;
            vsock_host = Some(host);
        }
        let cfg = &cfg;

        let entry = load_guest(&mem, cfg, mem_size)?;
        crate::mptable::write(&mem, cfg.cpus).map_err(|e| BootError(format!("MP table: {e}")))?;

        let captured = Arc::new(Mutex::new(Vec::new()));
        let uart: Arc<Mutex<Uart>> = Arc::new(Mutex::new(Serial::new(
            UartIrq(machine.irq_line(COM1_IRQ)?),
            Sink {
                captured: captured.clone(),
                echo: cfg.echo,
            },
        )));
        let devices = Arc::new(Devices {
            uart: uart.clone(),
            bus,
            ioapic: machine.ioapic(),
            rtc: Default::default(),
        });

        let mut vcpus = Vec::with_capacity(cfg.cpus as usize);
        for id in 0..cfg.cpus {
            // Application processors wait for the boot CPU's INIT/SIPI in their local APIC;
            // only the boot CPU gets an initial register state.
            vcpus.push(machine.create_vcpu(id, cfg.cpus, (id == 0).then_some(&entry))?);
        }

        if cfg.stdin {
            let uart = uart.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 256];
                while let Ok(n) = io::Read::read(&mut io::stdin(), &mut buf) {
                    if n == 0 {
                        break;
                    }
                    // The UART receive FIFO is small (64 bytes); feed it as the guest drains it
                    // instead of dropping whatever does not fit.
                    let mut pending = &buf[..n];
                    while !pending.is_empty() {
                        let mut u = uart.lock().unwrap();
                        let take = u.fifo_capacity().min(pending.len());
                        if take > 0 && u.enqueue_raw_bytes(&pending[..take]).is_ok() {
                            pending = &pending[take..];
                            continue;
                        }
                        drop(u);
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }
            });
        }

        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        // Guest memory and the machine stay alive until the last vCPU thread is gone (the
        // machine is dropped first, so memory is never unmapped under a live partition).
        let keep = Arc::new((machine.clone(), mem));
        let threads = vcpus
            .into_iter()
            .map(|mut vcpu: Vcpu| {
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
        Ok(Vm {
            vsock: vsock_host,
            captured,
            stop,
            machine,
            rx: Mutex::new(rx),
            done: Mutex::new(None),
            threads: Mutex::new(threads),
        })
    }

    /// The host side of the guest's vsock device, if one was configured.
    pub fn vsock(&self) -> Option<&VsockHost> {
        self.vsock.as_ref()
    }

    /// Everything the guest has written to its serial console so far.
    pub fn console(&self) -> String {
        String::from_utf8_lossy(&self.captured.lock().unwrap()).into_owned()
    }

    /// Has the vCPU stopped?
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
                    // the first vCPU to finish ends the machine: stop the others too
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

    /// Wait for the guest to end. `None` means the timeout elapsed first.
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

    /// Stop the guest now (it is killed, not shut down gracefully). Idempotent.
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

/// Boot the configured kernel and run until it exits, times out or crashes.
pub fn boot_linux(cfg: &BootConfig) -> Result<BootOutcome, BootError> {
    let vm = Vm::start(cfg)?;
    let exit = match vm.wait(cfg.timeout) {
        Some(r) => r?,
        None => vm.stop(),
    };
    Ok(BootOutcome {
        console: vm.console(),
        exit,
    })
}

/// Load kernel, initrd, command line, boot params, GDT and page tables. Returns the boot CPU's
/// entry state.
fn load_guest(
    mem: &GuestMemoryMmap<()>,
    cfg: &BootConfig,
    mem_size: u64,
) -> Result<Entry, BootError> {
    let low_end = mem_size.min(LOW_MEM_END);
    // In memory: `File` implements vm-memory's ReadVolatile only on Unix.
    let mut kernel = io::Cursor::new(std::fs::read(&cfg.kernel).map_err(err("read kernel"))?);
    let loaded = BzImage::load(mem, Some(GuestAddress(KERNEL_ADDR)), &mut kernel, None)
        .map_err(err("load bzImage"))?;
    let hdr = loaded
        .setup_header
        .ok_or_else(|| BootError("kernel image has no setup header".into()))?;
    let mut params = boot_params {
        hdr,
        ..Default::default()
    };
    params.hdr.type_of_loader = 0xff;
    params.hdr.loadflags |= 0x80 | 0x01; // CAN_USE_HEAP | LOADED_HIGH

    let mut cmdline = Cmdline::new(4096).map_err(err("cmdline"))?;
    cmdline.insert_str(&cfg.cmdline).map_err(err("cmdline"))?;
    load_cmdline(mem, GuestAddress(CMDLINE_ADDR), &cmdline).map_err(err("write cmdline"))?;
    params.hdr.cmd_line_ptr = CMDLINE_ADDR as u32;
    params.hdr.cmdline_size = cfg.cmdline.len() as u32;

    if let Some(path) = &cfg.initrd {
        let data = std::fs::read(path).map_err(err("read initrd"))?;
        let addr = (low_end - data.len() as u64) & !0xfff; // initrd must stay below 4 GiB
        if addr <= loaded.kernel_end + (32 << 20) {
            return Err(BootError(
                "initrd does not fit above the kernel: raise mem_mib".into(),
            ));
        }
        mem.write_slice(&data, GuestAddress(addr))
            .map_err(err("write initrd"))?;
        params.hdr.ramdisk_image = addr as u32;
        params.hdr.ramdisk_size = data.len() as u32;
    }

    // e820: low RAM below the EBDA/VGA hole, then everything above 1 MiB.
    params.e820_table[0] = boot_e820_entry {
        addr: 0,
        size: 0x9fc00,
        type_: E820_RAM,
    };
    params.e820_table[1] = boot_e820_entry {
        addr: 0x10_0000,
        size: low_end - 0x10_0000,
        type_: E820_RAM,
    };
    params.e820_entries = 2;
    if mem_size > LOW_MEM_END {
        params.e820_table[2] = boot_e820_entry {
            addr: HIGH_MEM_START,
            size: mem_size - LOW_MEM_END,
            type_: E820_RAM,
        };
        params.e820_entries = 3;
    }
    LinuxBootConfigurator::write_bootparams(
        &BootParams::new::<boot_params>(&params, GuestAddress(ZERO_PAGE_ADDR)),
        mem,
    )
    .map_err(err("write boot params"))?;

    // GDT: null, 64-bit code, data, TSS.
    for (i, e) in GDT.iter().enumerate() {
        mem.write_obj(*e, GuestAddress(GDT_ADDR + 8 * i as u64))
            .map_err(err("write GDT"))?;
    }
    // Identity map the first GiB with 2 MiB pages.
    mem.write_obj(PDPT_ADDR | 3, GuestAddress(PML4_ADDR))
        .map_err(err("page tables"))?;
    mem.write_obj(PD_ADDR | 3, GuestAddress(PDPT_ADDR))
        .map_err(err("page tables"))?;
    for i in 0..512u64 {
        mem.write_obj((i << 21) | 0x83, GuestAddress(PD_ADDR + 8 * i))
            .map_err(err("page tables"))?;
    }
    Ok(Entry {
        rip: loaded.kernel_load.0 + 0x200, // 64-bit entry point
        rsp: BOOT_STACK,
        rsi: ZERO_PAGE_ADDR,
        gdt_base: GDT_ADDR,
        gdt_limit: (GDT.len() * 8 - 1) as u16,
        cs: segment(GDT[1], 1),
        ds: segment(GDT[2], 2),
        tr: segment(GDT[3], 3),
        cr0: 0x8000_0011, // PG | ET | PE
        cr3: PML4_ADDR,
        cr4: 1 << 5, // PAE
        efer: 0x500, // LME | LMA
    })
}

const fn gdt_entry(flags: u64, base: u64, limit: u64) -> u64 {
    ((base & 0xff00_0000) << (56 - 24))
        | ((flags & 0x0000_f0ff) << 40)
        | ((limit & 0x000f_0000) << (48 - 16))
        | ((base & 0x00ff_ffff) << 16)
        | (limit & 0x0000_ffff)
}
const GDT: [u64; 4] = [
    0,
    gdt_entry(0xa09b, 0, 0xfffff),
    gdt_entry(0xc093, 0, 0xfffff),
    gdt_entry(0x808b, 0, 0xfffff),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_segment_attributes() {
        let cs = segment(GDT[1], 1);
        assert_eq!((cs.l, cs.present, cs.s, cs.type_), (1, 1, 1, 0xb));
        assert_eq!(cs.attributes(), 0xa09b);
        assert_eq!(segment(GDT[2], 2).attributes(), 0xc093);
    }

    #[test]
    fn topology_leaves() {
        let mut r = [0, 0xffff_ffff, 0, 0];
        cpuid_topology(1, 0, &mut r, 3, 4);
        assert_eq!(r[1] >> 24, 3);
        assert_eq!((r[1] >> 16) & 0xff, 4);
        assert_ne!(r[2] & (1 << 31), 0);
        let mut r = [0; 4];
        cpuid_topology(0xb, 1, &mut r, 2, 4);
        assert_eq!(r, [2, 4, 0x201, 2]);
    }
}
