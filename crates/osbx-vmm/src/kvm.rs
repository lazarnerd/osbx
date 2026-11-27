//! KVM backend (Linux): in-kernel irqchip (PIC, IOAPIC, LAPIC) and PIT, irqfd interrupt lines,
//! SIGUSR1 to kick a vCPU out of `KVM_RUN`.

use crate::boot::{BootError, Entry, ExitReason, Segment, cpuid_topology, err};
use crate::devices::Devices;
use crate::ioapic::IoApic;
use crate::irq::{Irq, IrqLine};
use crate::virtio::GuestMem;
use kvm_bindings::{
    KVM_MAX_CPUID_ENTRIES, KVM_PIT_SPEAKER_DUMMY, Msrs, kvm_fpu, kvm_msr_entry, kvm_pit_config,
    kvm_segment, kvm_userspace_memory_region,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use std::os::unix::thread::JoinHandleExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use vm_memory::{Address, GuestMemory, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

/// An irqfd: writing it raises the line in KVM's in-kernel IOAPIC.
struct EventFdLine(EventFd);
impl IrqLine for EventFdLine {
    fn pulse(&self) {
        let _ = self.0.write(1);
    }
}

/// The VM.
pub(crate) struct Machine {
    kvm: Kvm,
    vm: VmFd,
}

impl Machine {
    /// Create the VM, map `mem`, and create the in-kernel irqchip and PIT.
    pub fn new(mem: &GuestMem, _cpus: u8) -> Result<Self, BootError> {
        let kvm = Kvm::new().map_err(err("open /dev/kvm"))?;
        let vm = kvm.create_vm().map_err(err("KVM_CREATE_VM"))?;
        map_memory(&vm, mem)?;
        // Interrupt controller and timer must exist before the vCPUs.
        vm.set_tss_address(0xfffb_d000)
            .map_err(err("KVM_SET_TSS_ADDR"))?;
        vm.set_identity_map_address(0xfffb_c000)
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

    /// Kernel arguments this backend needs (none).
    pub fn cmdline_extra(&self) -> String {
        String::new()
    }

    /// The in-kernel IOAPIC handles everything.
    pub fn ioapic(&self) -> Option<Arc<IoApic>> {
        None
    }

    /// An irqfd for IOAPIC pin `gsi`.
    pub fn irq_line(&self, gsi: u32) -> Result<Irq, BootError> {
        let evt = EventFd::new(0).map_err(err("eventfd"))?;
        self.vm
            .register_irqfd(&evt, gsi)
            .map_err(err("KVM_IRQFD"))?;
        Ok(Arc::new(EventFdLine(evt)))
    }

    /// Create vCPU `id` of `cpus`; the boot CPU gets `entry`.
    pub fn create_vcpu(&self, id: u8, cpus: u8, entry: Option<&Entry>) -> Result<Vcpu, BootError> {
        let mut vcpu = self
            .vm
            .create_vcpu(u64::from(id))
            .map_err(err("KVM_CREATE_VCPU"))?;
        setup_vcpu(&self.kvm, &mut vcpu, id, cpus, entry)?;
        Ok(Vcpu(vcpu))
    }

    /// Interrupt vCPU thread `t` if it is inside `KVM_RUN`.
    #[allow(unsafe_code)]
    pub fn kick(&self, _index: usize, t: &std::thread::JoinHandle<()>) {
        // SAFETY: the pthread_t comes from a live JoinHandle (the thread has not been joined),
        // and SIGUSR1 has a handler installed, so delivery cannot terminate the process.
        unsafe {
            libc::pthread_kill(t.as_pthread_t() as libc::pthread_t, libc::SIGUSR1);
        }
    }
}

#[allow(unsafe_code)]
fn map_memory(vm: &VmFd, mem: &GuestMem) -> Result<(), BootError> {
    for (slot, region) in mem.iter().enumerate() {
        let host = mem
            .get_host_address(region.start_addr())
            .map_err(err("host address"))?;
        let r = kvm_userspace_memory_region {
            slot: slot as u32,
            flags: 0,
            guest_phys_addr: region.start_addr().raw_value(),
            memory_size: region.len(),
            userspace_addr: host as u64,
        };
        // SAFETY: `host` points at `region.len()` bytes of mapped memory owned by `mem`, which the
        // vCPU threads keep alive (Arc) until every vCPU has stopped running.
        unsafe { vm.set_user_memory_region(r) }.map_err(err("KVM_SET_USER_MEMORY_REGION"))?;
    }
    Ok(())
}

fn kvm_seg(s: &Segment) -> kvm_segment {
    kvm_segment {
        base: s.base,
        limit: s.limit,
        selector: s.selector,
        type_: s.type_,
        present: s.present,
        dpl: s.dpl,
        db: s.db,
        s: s.s,
        l: s.l,
        g: s.g,
        avl: s.avl,
        padding: 0,
        unusable: u8::from(s.present == 0),
    }
}

fn setup_vcpu(
    kvm: &Kvm,
    vcpu: &mut VcpuFd,
    id: u8,
    cpus: u8,
    entry: Option<&Entry>,
) -> Result<(), BootError> {
    let mut cpuid = kvm
        .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
        .map_err(err("KVM_GET_SUPPORTED_CPUID"))?;
    for e in cpuid.as_mut_slice() {
        let mut r = [e.eax, e.ebx, e.ecx, e.edx];
        cpuid_topology(e.function, e.index, &mut r, id, cpus);
        [e.eax, e.ebx, e.ecx, e.edx] = r;
    }
    vcpu.set_cpuid2(&cpuid).map_err(err("KVM_SET_CPUID2"))?;

    let msrs = Msrs::from_entries(&[
        kvm_msr_entry {
            index: 0x1a0,
            data: 1,
            ..Default::default()
        }, // IA32_MISC_ENABLE: fast strings
        kvm_msr_entry {
            index: 0x2ff,
            data: (1 << 11) | 6,
            ..Default::default()
        }, // MTRRdefType: enabled, write-back
    ])
    .map_err(err("msr list"))?;
    vcpu.set_msrs(&msrs).map_err(err("KVM_SET_MSRS"))?;
    vcpu.set_fpu(&kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    })
    .map_err(err("KVM_SET_FPU"))?;
    let Some(entry) = entry else { return Ok(()) };

    let mut sregs = vcpu.get_sregs().map_err(err("KVM_GET_SREGS"))?;
    let data = kvm_seg(&entry.ds);
    sregs.cs = kvm_seg(&entry.cs);
    sregs.ds = data;
    sregs.es = data;
    sregs.fs = data;
    sregs.gs = data;
    sregs.ss = data;
    sregs.tr = kvm_seg(&entry.tr);
    sregs.gdt.base = entry.gdt_base;
    sregs.gdt.limit = entry.gdt_limit;
    sregs.idt.base = 0;
    sregs.idt.limit = 0;
    sregs.cr0 = entry.cr0;
    sregs.cr3 = entry.cr3;
    sregs.cr4 = entry.cr4;
    sregs.efer = entry.efer;
    vcpu.set_sregs(&sregs).map_err(err("KVM_SET_SREGS"))?;

    let mut regs = vcpu.get_regs().map_err(err("KVM_GET_REGS"))?;
    regs.rflags = 2;
    regs.rip = entry.rip;
    regs.rsp = entry.rsp;
    regs.rbp = entry.rsp;
    regs.rsi = entry.rsi;
    vcpu.set_regs(&regs).map_err(err("KVM_SET_REGS"))
}

/// One vCPU.
pub(crate) struct Vcpu(VcpuFd);

impl Vcpu {
    /// Run until the guest resets, crashes or `stop` is set.
    pub fn run(&mut self, dev: &Devices, stop: &AtomicBool) -> Result<ExitReason, BootError> {
        loop {
            if stop.load(Ordering::SeqCst) {
                return Ok(ExitReason::Timeout);
            }
            match self.0.run() {
                Ok(VcpuExit::IoOut(port, data)) => {
                    if let Some(r) = dev.io_out(port, data) {
                        return Ok(r);
                    }
                }
                Ok(VcpuExit::IoIn(port, data)) => dev.io_in(port, data),
                Ok(VcpuExit::MmioRead(addr, data)) => dev.mmio_read(addr, data),
                Ok(VcpuExit::MmioWrite(addr, data)) => dev.mmio_write(addr, data),
                Ok(VcpuExit::Shutdown) => return Ok(ExitReason::TripleFault),
                Ok(VcpuExit::SystemEvent(..)) => return Ok(ExitReason::GuestReset),
                Ok(other) => return Err(BootError(format!("unhandled VM exit: {other:?}"))),
                Err(e) if e.errno() == libc::EINTR || e.errno() == libc::EAGAIN => {}
                Err(e) => return Err(BootError(format!("KVM_RUN: {e}"))),
            }
        }
    }
}

extern "C" fn on_kick(_: libc::c_int) {}

/// SIGUSR1 does nothing except interrupt a blocked `KVM_RUN` (it returns EINTR).
#[allow(unsafe_code)]
fn install_kick_handler() {
    // SAFETY: installs an empty, async-signal-safe handler. `sigaction` is given a zeroed struct
    // with a valid handler pointer, an empty mask and no flags.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_kick as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
    }
}
