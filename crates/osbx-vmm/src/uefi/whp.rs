//! Windows Hypervisor Platform (WHP) hypervisor backend for Q35 PCIe UEFI VMs.
//!
//! Runs the exact same Q35 PCIe / ACPI 2.0 / OVMF device model as [`super::kvm`] on Windows hosts:
//! - Userspace IOAPIC ([`IoApic`]) for legacy ISA + PCI INTx GSIs
//! - Direct MSI/MSI-X delivery via `WHvRequestInterrupt`
//! - `WinHvEmulation` (`WHvEmulatorTryIoEmulation` / `WHvEmulatorTryMmioEmulation`) for port I/O,
//!   PCIe ECAM, CFI `pflash`, HPET, IOAPIC, and device BAR MMIO
//! - Real-mode reset vector (`0xFFFF_FFF0`) for vCPU 0 and `StartupSuspend` (wait-for-SIPI) for APs

#![allow(unsafe_code)]
#![allow(non_upper_case_globals)]

use super::{FbBuffer, UefiDevices};
use crate::boot::{BootError, ExitReason, cpuid_topology};
use crate::ioapic::{IoApic, Message};
use crate::irq::{Irq, IrqLine};
use crate::pci::MsiRouter;
use crate::virtio::GuestMem;
use crate::whp::{Partition, PartitionSlot, check, hypervisor_present};
use std::ffi::c_void;
use std::io;
use std::mem::{size_of, zeroed};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use vm_memory::{Address, GuestMemory, GuestMemoryRegion};
use windows_sys::Win32::System::Hypervisor::*;

struct Pin(Arc<IoApic>, usize);
impl IrqLine for Pin {
    fn pulse(&self) {
        self.0.pulse(self.1);
    }
}

#[derive(Clone, Copy, Default)]
struct WhpMsiEntry {
    addr: u64,
    data: u32,
    configured: bool,
}

/// WHP MSI/MSI-X router delivering PCI interrupts directly via `WHvRequestInterrupt`.
struct WhpMsiRouter {
    part: Partition,
    entries: Mutex<Vec<WhpMsiEntry>>,
}

impl WhpMsiRouter {
    fn new(part: Partition) -> Self {
        Self {
            part,
            entries: Mutex::new(Vec::new()),
        }
    }
}

impl MsiRouter for WhpMsiRouter {
    fn allocate(&self) -> io::Result<u32> {
        let mut entries = self.entries.lock().unwrap();
        let handle = entries.len() as u32;
        entries.push(WhpMsiEntry::default());
        Ok(handle)
    }

    fn configure(&self, handle: u32, addr: u64, data: u32) -> io::Result<()> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(e) = entries.get_mut(handle as usize) {
            e.addr = addr;
            e.data = data;
            e.configured = addr != 0;
        }
        Ok(())
    }

    fn trigger(&self, handle: u32) {
        let entry = {
            let entries = self.entries.lock().unwrap();
            entries.get(handle as usize).copied()
        };
        if let Some(e) = entry
            && e.configured
        {
            // x86 MSI address format: bits 19:12 = destination APIC ID / logical mask,
            // bit 2 = Destination Mode (0 = physical, 1 = logical).
            // x86 MSI data format: bits 7:0 = vector, bits 10:8 = delivery mode.
            let msg = Message {
                vector: (e.data & 0xff) as u8,
                delivery: ((e.data >> 8) & 0x7) as u8,
                logical: (e.addr & (1 << 2)) != 0,
                dest: ((e.addr >> 12) & 0xff) as u8,
            };
            self.part.deliver(msg);
        }
    }
}

pub(super) struct UefiMachine {
    part: Partition,
    ioapic: Arc<IoApic>,
    _slot: PartitionSlot,
}

impl UefiMachine {
    pub(super) fn new(
        mem: &GuestMem,
        cpus: u8,
        code_base: u64,
        code_readonly: bool,
        _hyperv: bool,
    ) -> Result<Self, BootError> {
        let slot =
            PartitionSlot::acquire(std::time::Duration::from_secs(600)).ok_or_else(|| {
                BootError(
                    "another VM in this process is still running (WHP allows one per process)"
                        .into(),
                )
            })?;
        if !hypervisor_present() {
            return Err(BootError(
                "the Windows Hypervisor Platform is not enabled (enable the \"Windows Hypervisor Platform\" optional feature and reboot)".into(),
            ));
        }
        let mut handle: WHV_PARTITION_HANDLE = 0;
        // SAFETY: out-pointer to a WHP partition handle.
        check("WHvCreatePartition", unsafe {
            WHvCreatePartition(&mut handle)
        })?;
        let part = Partition(handle);
        let machine = Self {
            part,
            ioapic: Arc::new(IoApic::new(cpus, move |m| part.deliver(m))),
            _slot: slot,
        };

        check(
            "set ProcessorCount",
            part.set_property(WHvPartitionPropertyCodeProcessorCount, &u32::from(cpus)),
        )?;
        check(
            "set LocalApicEmulationMode",
            part.set_property(
                WHvPartitionPropertyCodeLocalApicEmulationMode,
                &WHvX64LocalApicEmulationModeXApic,
            ),
        )?;
        // Intercept CPUID for topology leaves.
        // SAFETY: WHV_EXTENDED_VM_EXITS is a plain u64 union.
        let mut exits: WHV_EXTENDED_VM_EXITS = unsafe { zeroed() };
        exits.AsUINT64 = 1; // X64CpuidExit
        check(
            "set ExtendedVmExits",
            part.set_property(WHvPartitionPropertyCodeExtendedVmExits, &exits),
        )?;
        let leaves: [u32; 4] = [1, 4, 0xb, 0x1f];
        check(
            "set CpuidExitList",
            part.set_property(WHvPartitionPropertyCodeCpuidExitList, &leaves),
        )?;
        let _ = part.set_property(
            WHvPartitionPropertyCodeUnimplementedMsrAction,
            &WHvMsrActionIgnoreWriteReadZero,
        );
        // SAFETY: the partition handle is valid and configured.
        check("WHvSetupPartition", unsafe { WHvSetupPartition(handle) })?;

        for region in mem.iter() {
            let host = region
                .get_host_address(vm_memory::MemoryRegionAddress(0))
                .map_err(|e| BootError(format!("host address: {e}")))?;
            let gpa = region.start_addr().raw_value();
            let flags = if code_readonly && gpa == code_base {
                WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagExecute
            } else {
                WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute
            };
            // SAFETY: `host` points at `region.len()` bytes owned by `mem`, kept alive by `keep`
            // until every vCPU exits and drops its handle.
            let hr =
                unsafe { WHvMapGpaRange(handle, host as *const c_void, gpa, region.len(), flags) };
            check("WHvMapGpaRange", hr)?;
        }

        Ok(machine)
    }

    pub(super) fn ioapic(&self) -> Option<Arc<IoApic>> {
        Some(self.ioapic.clone())
    }

    pub(super) fn make_irq(&self, gsi: u32) -> Result<Irq, BootError> {
        Ok(Arc::new(Pin(self.ioapic.clone(), gsi as usize)))
    }

    pub(super) fn msi_router(&self) -> Arc<dyn MsiRouter> {
        Arc::new(WhpMsiRouter::new(self.part))
    }

    pub(super) fn fb_mapper(&self, fb_mem: Arc<Mutex<FbBuffer>>) -> crate::pci::vga::BarMapper {
        let part = self.part;
        let current = Mutex::new(None::<u64>);
        Arc::new(move |new_gpa: Option<u64>| {
            let mut cur = current.lock().unwrap();
            if *cur == new_gpa {
                return;
            }
            let guard = fb_mem.lock().unwrap();
            if let Some(old) = *cur {
                // SAFETY: unmapping the previously mapped Bochs VGA framebuffer GPA range.
                let _ = unsafe { WHvUnmapGpaRange(part.0, old, guard.len() as u64) };
            }
            if let Some(gpa) = new_gpa {
                // SAFETY: `fb_mem` is page-aligned, kept alive in `keep` for the entire lifetime of
                // the VM, and never reallocated after creation.
                let hr = unsafe {
                    WHvMapGpaRange(
                        part.0,
                        guard.as_ptr().cast::<c_void>(),
                        gpa,
                        guard.len() as u64,
                        WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite,
                    )
                };
                if hr >= 0 {
                    *cur = Some(gpa);
                    return;
                }
                eprintln!(
                    "[osbx-vmm] warning: WHvMapGpaRange VGA framebuffer at {gpa:#x} failed: 0x{:08x}",
                    hr as u32
                );
            }
            *cur = None;
        })
    }

    pub(super) fn create_vcpu(
        &self,
        id: u8,
        cpus: u8,
        _hyperv: bool,
    ) -> Result<UefiVcpu, BootError> {
        let vp = u32::from(id);
        // SAFETY: valid partition handle; WHP validates the VP index.
        check("WHvCreateVirtualProcessor", unsafe {
            WHvCreateVirtualProcessor(self.part.0, vp, 0)
        })?;
        let mut emulator: *mut c_void = std::ptr::null_mut();
        // SAFETY: UEFI_EMULATOR_CALLBACKS is static and outlives the emulator handle.
        check("WHvEmulatorCreateEmulator", unsafe {
            WHvEmulatorCreateEmulator(&UEFI_EMULATOR_CALLBACKS, &mut emulator)
        })?;
        let vcpu = UefiVcpu {
            part: self.part,
            vp,
            id,
            cpus,
            emulator,
        };

        // Enable MTRRs with default Write-Back memory type.
        // SAFETY: WHV_REGISTER_VALUE is a plain union.
        let mut mtrr: WHV_REGISTER_VALUE = unsafe { zeroed() };
        mtrr.Reg64 = (1 << 11) | 6;
        self.part
            .set_registers(vp, &[WHvX64RegisterMsrMtrrDefType], &[mtrr])?;

        if id > 0 {
            // Application processors wait for INIT/SIPI from the BSP (OVMF MpInitLib / OS kernel).
            // SAFETY: WHV_REGISTER_VALUE is a plain union.
            let mut act: WHV_REGISTER_VALUE = unsafe { zeroed() };
            act.Reg64 = 1; // StartupSuspend
            self.part
                .set_registers(vp, &[WHvRegisterInternalActivityState], &[act])?;
        }
        Ok(vcpu)
    }

    pub(super) fn kick(&self, id: usize, _t: &std::thread::JoinHandle<()>) {
        // SAFETY: valid partition handle; cancelling a non-running VP is harmless.
        unsafe {
            WHvCancelRunVirtualProcessor(self.part.0, id as u32, 0);
        }
    }
}

impl Drop for UefiMachine {
    fn drop(&mut self) {
        // SAFETY: handle came from WHvCreatePartition and every vCPU has exited before drop.
        unsafe {
            WHvDeletePartition(self.part.0);
        }
    }
}

pub(super) struct UefiVcpu {
    part: Partition,
    vp: u32,
    id: u8,
    cpus: u8,
    emulator: *mut c_void,
}

// SAFETY: the emulator handle is only used by the thread that owns `UefiVcpu`.
unsafe impl Send for UefiVcpu {}

impl Drop for UefiVcpu {
    fn drop(&mut self) {
        // SAFETY: handles created in `create_vcpu`, released once on drop.
        unsafe {
            WHvEmulatorDestroyEmulator(self.emulator);
            WHvDeleteVirtualProcessor(self.part.0, self.vp);
        }
    }
}

static UEFI_EMULATOR_CALLBACKS: WHV_EMULATOR_CALLBACKS = WHV_EMULATOR_CALLBACKS {
    Size: size_of::<WHV_EMULATOR_CALLBACKS>() as u32,
    Reserved: 0,
    WHvEmulatorIoPortCallback: Some(emu_io),
    WHvEmulatorMemoryCallback: Some(emu_mmio),
    WHvEmulatorGetVirtualProcessorRegisters: Some(emu_get_regs),
    WHvEmulatorSetVirtualProcessorRegisters: Some(emu_set_regs),
    WHvEmulatorTranslateGvaPage: Some(emu_translate),
};

struct UefiEmuCtx<'a> {
    part: Partition,
    vp: u32,
    dev: &'a UefiDevices,
    reset: Option<ExitReason>,
}

const S_OK: i32 = 0;

unsafe extern "system" fn emu_io(ctx: *const c_void, io: *mut WHV_EMULATOR_IO_ACCESS_INFO) -> i32 {
    // SAFETY: `ctx` is `&mut UefiEmuCtx` and `io` is valid for this callback invocation.
    let (ctx, io) = unsafe { (&mut *(ctx as *mut UefiEmuCtx<'_>), &mut *io) };
    let n = usize::from(io.AccessSize).min(4);
    if io.Direction == 0 {
        let mut b = [0u8; 4];
        ctx.dev.io_in(io.Port, &mut b[..n]);
        io.Data = u32::from_le_bytes(b);
    } else {
        let b = io.Data.to_le_bytes();
        if let Some(r) = ctx.dev.io_out(io.Port, &b[..n]) {
            ctx.reset = Some(r);
        }
    }
    S_OK
}

unsafe extern "system" fn emu_mmio(
    ctx: *const c_void,
    m: *mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
) -> i32 {
    // SAFETY: as in `emu_io`.
    let (ctx, m) = unsafe { (&mut *(ctx as *mut UefiEmuCtx<'_>), &mut *m) };
    let n = usize::from(m.AccessSize).min(8);
    if m.Direction == 0 {
        ctx.dev.mmio_read(m.GpaAddress, &mut m.Data[..n]);
    } else {
        ctx.dev.mmio_write(m.GpaAddress, &m.Data[..n]);
    }
    S_OK
}

unsafe extern "system" fn emu_get_regs(
    ctx: *const c_void,
    names: *const WHV_REGISTER_NAME,
    count: u32,
    values: *mut WHV_REGISTER_VALUE,
) -> i32 {
    // SAFETY: arrays hold `count` valid elements for this callback invocation.
    unsafe {
        let ctx = &*(ctx as *const UefiEmuCtx<'_>);
        WHvGetVirtualProcessorRegisters(ctx.part.0, ctx.vp, names, count, values)
    }
}

unsafe extern "system" fn emu_set_regs(
    ctx: *const c_void,
    names: *const WHV_REGISTER_NAME,
    count: u32,
    values: *const WHV_REGISTER_VALUE,
) -> i32 {
    // SAFETY: as in `emu_get_regs`.
    unsafe {
        let ctx = &*(ctx as *const UefiEmuCtx<'_>);
        WHvSetVirtualProcessorRegisters(ctx.part.0, ctx.vp, names, count, values)
    }
}

unsafe extern "system" fn emu_translate(
    ctx: *const c_void,
    gva: u64,
    flags: WHV_TRANSLATE_GVA_FLAGS,
    result: *mut WHV_TRANSLATE_GVA_RESULT_CODE,
    gpa: *mut u64,
) -> i32 {
    // SAFETY: `result` and `gpa` are valid out-pointers for this callback invocation.
    unsafe {
        let ctx = &*(ctx as *const UefiEmuCtx<'_>);
        let mut r: WHV_TRANSLATE_GVA_RESULT = zeroed();
        let hr = WHvTranslateGva(ctx.part.0, ctx.vp, gva, flags, &mut r, gpa);
        *result = r.ResultCode;
        hr
    }
}

impl UefiVcpu {
    fn emulated(&self, ok: i32, status: WHV_EMULATOR_STATUS, what: &str) -> Result<(), BootError> {
        check(what, ok)?;
        // SAFETY: reading the u32 view of the status filled by WinHvEmulation.
        let bits = unsafe { status.AsUINT32 };
        if bits & 1 == 0 {
            return Err(BootError(format!(
                "{what}: instruction emulation failed (status 0x{bits:x})"
            )));
        }
        Ok(())
    }

    pub(super) fn run(
        &mut self,
        dev: &UefiDevices,
        stop: &AtomicBool,
    ) -> Result<ExitReason, BootError> {
        loop {
            if stop.load(Ordering::SeqCst) {
                return Ok(ExitReason::Timeout);
            }
            // SAFETY: plain-data exit context, fully populated by WHvRunVirtualProcessor.
            let mut exit: WHV_RUN_VP_EXIT_CONTEXT = unsafe { zeroed() };
            // SAFETY: valid partition handle and exit buffer.
            let hr = unsafe {
                WHvRunVirtualProcessor(
                    self.part.0,
                    self.vp,
                    (&mut exit as *mut WHV_RUN_VP_EXIT_CONTEXT).cast(),
                    size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
                )
            };
            check("WHvRunVirtualProcessor", hr)?;
            let mut ctx = UefiEmuCtx {
                part: self.part,
                vp: self.vp,
                dev,
                reset: None,
            };
            let ctxp = (&mut ctx as *mut UefiEmuCtx<'_>).cast::<c_void>();
            match exit.ExitReason {
                WHvRunVpExitReasonMemoryAccess => {
                    // SAFETY: zeroed status and matching exit union member.
                    let mut status: WHV_EMULATOR_STATUS = unsafe { zeroed() };
                    // SAFETY: valid emulator, context, and memory access exit info.
                    let hr = unsafe {
                        WHvEmulatorTryMmioEmulation(
                            self.emulator,
                            ctxp,
                            &exit.VpContext,
                            &exit.Anonymous.MemoryAccess,
                            &mut status,
                        )
                    };
                    self.emulated(hr, status, "MMIO emulation")?;
                }
                WHvRunVpExitReasonX64IoPortAccess => {
                    // SAFETY: as above.
                    let mut status: WHV_EMULATOR_STATUS = unsafe { zeroed() };
                    // SAFETY: valid emulator, context, and port I/O exit info.
                    let hr = unsafe {
                        WHvEmulatorTryIoEmulation(
                            self.emulator,
                            ctxp,
                            &exit.VpContext,
                            &exit.Anonymous.IoPortAccess,
                            &mut status,
                        )
                    };
                    self.emulated(hr, status, "port I/O emulation")?;
                    if let Some(r) = ctx.reset {
                        return Ok(r);
                    }
                }
                WHvRunVpExitReasonX64Cpuid => {
                    // SAFETY: union member matches `WHvRunVpExitReasonX64Cpuid`.
                    let c = unsafe { exit.Anonymous.CpuidAccess };
                    let mut r = [
                        c.DefaultResultRax as u32,
                        c.DefaultResultRbx as u32,
                        c.DefaultResultRcx as u32,
                        c.DefaultResultRdx as u32,
                    ];
                    cpuid_topology(c.Rax as u32, c.Rcx as u32, &mut r, self.id, self.cpus);
                    let len = u64::from(exit.VpContext._bitfield & 0x0f);
                    let r64 = |x: u64| {
                        // SAFETY: plain union.
                        let mut v: WHV_REGISTER_VALUE = unsafe { zeroed() };
                        v.Reg64 = x;
                        v
                    };
                    self.part.set_registers(
                        self.vp,
                        &[
                            WHvX64RegisterRax,
                            WHvX64RegisterRbx,
                            WHvX64RegisterRcx,
                            WHvX64RegisterRdx,
                            WHvX64RegisterRip,
                        ],
                        &[
                            r64(u64::from(r[0])),
                            r64(u64::from(r[1])),
                            r64(u64::from(r[2])),
                            r64(u64::from(r[3])),
                            r64(exit.VpContext.Rip + len),
                        ],
                    )?;
                }
                WHvRunVpExitReasonCanceled => {}
                WHvRunVpExitReasonX64Halt => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                WHvRunVpExitReasonX64ApicEoi => {}
                WHvRunVpExitReasonUnrecoverableException => return Ok(ExitReason::TripleFault),
                other => {
                    return Err(BootError(format!(
                        "unhandled WHP UEFI VM exit {other} at rip 0x{:x}",
                        exit.VpContext.Rip
                    )));
                }
            }
        }
    }
}
