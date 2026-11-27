//! Linux/KVM hypervisor backend for Q35 PCIe UEFI VMs.

#![allow(unsafe_code)]

use super::{FbBuffer, UefiDevices};
use crate::boot::{BootError, ExitReason, cpuid_topology, err};
use crate::ioapic::IoApic;
use crate::irq::{Irq, IrqLine};
use crate::pci::MsiRouter;
use crate::virtio::GuestMem;
use kvm_bindings::{
    KVM_CAP_HYPERV_SYNIC2, KVM_EXIT_HYPERV_HCALL, KVM_EXIT_HYPERV_SYNDBG, KVM_EXIT_HYPERV_SYNIC,
    KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI, KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER,
    KVM_IRQCHIP_PIC_SLAVE, KVM_MAX_CPUID_ENTRIES, KVM_MEM_READONLY, KVM_PIT_SPEAKER_DUMMY,
    KVM_SYSTEM_EVENT_SHUTDOWN, KvmIrqRouting, Msrs, kvm_enable_cap, kvm_fpu, kvm_irq_routing_entry,
    kvm_msr_entry, kvm_pit_config, kvm_userspace_memory_region,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use std::io;
use std::os::unix::thread::JoinHandleExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use vm_memory::{Address, GuestMemory, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

/// KVM TSS and identity-map addresses kept below IOAPIC (`0xFEC0_0000`) and flash (`0xFFC0_0000`).
const UEFI_KVM_TSS_ADDR: u64 = 0xfeb0_0000;
const UEFI_KVM_IDENTITY_MAP_ADDR: u64 = 0xfeb0_4000;
/// Dedicated KVM memory slot for Bochs VGA 16 MiB linear framebuffer.
const VGA_FB_KVM_SLOT: u32 = 10;

struct EventFdLine(EventFd);
impl IrqLine for EventFdLine {
    fn pulse(&self) {
        let _ = self.0.write(1);
    }
}

/// KVM MSI/MSI-X router backed by `KVM_SET_GSI_ROUTING` + per-vector `EventFd` (`KVM_IRQFD`).
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

pub(super) struct UefiMachine {
    kvm: Kvm,
    vm: Arc<VmFd>,
}

impl UefiMachine {
    pub(super) fn new(
        mem: &GuestMem,
        _cpus: u8,
        code_base: u64,
        code_readonly: bool,
        _hyperv: bool,
    ) -> Result<Self, BootError> {
        let kvm = Kvm::new().map_err(err("open /dev/kvm"))?;
        let vm = Arc::new(kvm.create_vm().map_err(err("KVM_CREATE_VM"))?);
        map_uefi_memory(&vm, mem, code_base, code_readonly)?;
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
        Ok(Self { kvm, vm })
    }

    pub(super) fn ioapic(&self) -> Option<Arc<IoApic>> {
        None
    }

    pub(super) fn make_irq(&self, gsi: u32) -> Result<Irq, BootError> {
        let evt = EventFd::new(0).map_err(err("eventfd"))?;
        self.vm
            .register_irqfd(&evt, gsi)
            .map_err(err("KVM_IRQFD"))?;
        Ok(Arc::new(EventFdLine(evt)))
    }

    pub(super) fn msi_router(&self) -> Arc<dyn MsiRouter> {
        Arc::new(KvmMsiRouter::new(self.vm.clone()))
    }

    pub(super) fn fb_mapper(&self, fb_mem: Arc<Mutex<FbBuffer>>) -> crate::pci::vga::BarMapper {
        let vm = self.vm.clone();
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
                    memory_size: guard.len() as u64,
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

    pub(super) fn create_vcpu(
        &self,
        id: u8,
        cpus: u8,
        hyperv: bool,
    ) -> Result<UefiVcpu, BootError> {
        let mut vcpu = self
            .vm
            .create_vcpu(u64::from(id))
            .map_err(err("KVM_CREATE_VCPU"))?;
        setup_uefi_vcpu(&self.kvm, &mut vcpu, id, cpus, hyperv)?;
        Ok(UefiVcpu { vcpu })
    }

    pub(super) fn kick(&self, _id: usize, t: &std::thread::JoinHandle<()>) {
        // SAFETY: `t` is a live, unjoined thread handle and SIGUSR1 has an empty handler installed.
        unsafe {
            libc::pthread_kill(t.as_pthread_t() as libc::pthread_t, libc::SIGUSR1);
        }
    }
}

pub(super) struct UefiVcpu {
    vcpu: VcpuFd,
}

impl UefiVcpu {
    pub(super) fn run(
        &mut self,
        dev: &UefiDevices,
        stop: &AtomicBool,
    ) -> Result<ExitReason, BootError> {
        loop {
            if stop.load(Ordering::SeqCst) {
                return Ok(ExitReason::Timeout);
            }
            match self.vcpu.run() {
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
                        dev.mark_powered_off();
                    }
                    return Ok(ExitReason::GuestReset);
                }
                Ok(VcpuExit::Hyperv) => handle_hyperv_exit(&mut self.vcpu),
                Ok(other) => return Err(BootError(format!("unhandled VM exit: {other:?}"))),
                Err(e) if e.errno() == libc::EINTR || e.errno() == libc::EAGAIN => {}
                Err(e) => return Err(BootError(format!("KVM_RUN: {e}"))),
            }
        }
    }
}

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
        let cap = kvm_enable_cap {
            cap: KVM_CAP_HYPERV_SYNIC2,
            ..Default::default()
        };
        let synic_ok = vcpu.enable_cap(&cap).is_ok();

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
            hv_entry(
                0x4000_0000,
                0x4000_0005,
                u32::from_le_bytes(*b"Micr"),
                u32::from_le_bytes(*b"osof"),
                u32::from_le_bytes(*b"t Hv"),
            ),
            hv_entry(0x4000_0001, u32::from_le_bytes(*b"Hv#1"), 0, 0, 0),
            hv_entry(0x4000_0002, 0x0000_1db1, 0x0006_0001, 0, 0),
            hv_entry(
                0x4000_0003,
                hv_features,
                0,
                0,
                if synic_ok { 1 << 19 } else { 0 },
            ),
            hv_entry(0x4000_0004, (1 << 2) | (1 << 3) | (1 << 5), 0x0fff, 0, 0),
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

fn handle_hyperv_exit(vcpu: &mut VcpuFd) {
    // SAFETY: KVM just exited with `KVM_EXIT_HYPERV`, so `kvm_run.__bindgen_anon_1.hyperv` is
    // the active union variant populated by the kernel.
    let hv = unsafe { &mut vcpu.get_kvm_run().__bindgen_anon_1.hyperv };
    match hv.type_ {
        KVM_EXIT_HYPERV_SYNIC | KVM_EXIT_HYPERV_SYNDBG => {}
        KVM_EXIT_HYPERV_HCALL => {
            hv.u.hcall.result = 2;
        }
        _ => {}
    }
}

extern "C" fn on_kick(_: libc::c_int) {}

fn install_kick_handler() {
    // SAFETY: installs an empty, async-signal-safe SIGUSR1 handler so `kick` interrupts
    // `KVM_RUN` with EINTR without terminating the process.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_kick as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
    }
}
