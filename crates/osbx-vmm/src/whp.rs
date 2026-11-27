//! Windows Hypervisor Platform backend.
//!
//! WHP emulates the local APIC (xAPIC mode, including its timer and INIT/SIPI) but nothing
//! else, so osbx provides the IOAPIC ([`crate::ioapic`]) and tells the guest there is no 8259
//! PIC. Instructions that exit for port or MMIO access are decoded by Windows' own instruction
//! emulator (`WinHvEmulation.dll`), which calls back into [`Devices`].
//!
//! Timekeeping: the guest gets the TSC frequency on its command line (`tsc_early_khz`) and
//! uses the TSC-deadline local APIC timer, so no PIT is needed (`no_timer_check`).
//!
//! Nested virtualization is requested for every partition; if Windows accepts it the guest
//! sees VMX/SVM and can run its own KVM (`kvm@1`).

#![allow(unsafe_code)]
// WHP binding constants keep their Windows SDK names.
#![allow(non_upper_case_globals)]

use crate::boot::{BootError, Entry, ExitReason, Segment, cpuid_topology};
use crate::devices::Devices;
use crate::ioapic::{IoApic, Message};
use crate::irq::{Irq, IrqLine};
use crate::virtio::GuestMem;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use vm_memory::{GuestMemory, GuestMemoryRegion};
use windows_sys::Win32::System::Hypervisor::*;

pub(crate) fn check(what: &str, hr: i32) -> Result<(), BootError> {
    if hr < 0 {
        Err(BootError(format!("{what}: HRESULT 0x{:08x}", hr as u32)))
    } else {
        Ok(())
    }
}

/// Query one WHP capability.
pub(crate) fn capability(code: WHV_CAPABILITY_CODE) -> Option<WHV_CAPABILITY> {
    // SAFETY: WHV_CAPABILITY is plain old data; the buffer and its size are valid for the call.
    unsafe {
        let mut cap: WHV_CAPABILITY = zeroed();
        let mut written = 0u32;
        let hr = WHvGetCapability(
            code,
            (&mut cap as *mut WHV_CAPABILITY).cast(),
            size_of::<WHV_CAPABILITY>() as u32,
            &mut written,
        );
        (hr >= 0).then_some(cap)
    }
}

/// Is the Windows Hypervisor Platform present and enabled?
pub(crate) fn hypervisor_present() -> bool {
    // SAFETY: reading the BOOL member of a capability the call filled in.
    capability(WHvCapabilityCodeHypervisorPresent)
        .is_some_and(|c| unsafe { c.HypervisorPresent } != 0)
}

/// One live partition per process. Windows names the driver-side (VID) partition it creates
/// when a partition first maps memory per process: a second partition that maps memory while
/// another is alive in the same process fails with STATUS_VID_PARTITION_ALREADY_EXISTS
/// (0xc0370008). osbx runs each sandbox in its own supervisor process, so this only orders
/// in-process users (tests, the probe, the image builder): a second partition waits here until
/// the first is deleted.
static SLOT: (std::sync::Mutex<bool>, std::sync::Condvar) =
    (std::sync::Mutex::new(false), std::sync::Condvar::new());

/// Holds this process's partition slot; released on drop.
pub(crate) struct PartitionSlot(());

impl PartitionSlot {
    /// Wait (up to `timeout`) until no other partition is alive in this process.
    pub(crate) fn acquire(timeout: std::time::Duration) -> Option<Self> {
        let (lock, cv) = &SLOT;
        let busy = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (mut busy, res) = cv
            .wait_timeout_while(busy, timeout, |b| *b)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if res.timed_out() && *busy {
            return None;
        }
        *busy = true;
        Some(Self(()))
    }
}

impl Drop for PartitionSlot {
    fn drop(&mut self) {
        let (lock, cv) = &SLOT;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
        cv.notify_one();
    }
}

/// A partition handle (Send/Sync: WHP calls on one partition are thread-safe).
#[derive(Clone, Copy)]
pub(crate) struct Partition(pub(crate) WHV_PARTITION_HANDLE);

impl Partition {
    pub(crate) fn set_property<T>(&self, code: WHV_PARTITION_PROPERTY_CODE, value: &T) -> i32 {
        // SAFETY: `value` points at a properly sized, initialized property value of type T.
        unsafe {
            WHvSetPartitionProperty(
                self.0,
                code,
                (value as *const T).cast(),
                size_of::<T>() as u32,
            )
        }
    }

    pub(crate) fn set_registers(
        &self,
        vp: u32,
        names: &[WHV_REGISTER_NAME],
        values: &[WHV_REGISTER_VALUE],
    ) -> Result<(), BootError> {
        assert_eq!(names.len(), values.len());
        // SAFETY: both arrays hold `names.len()` initialized elements.
        let hr = unsafe {
            WHvSetVirtualProcessorRegisters(
                self.0,
                vp,
                names.as_ptr(),
                names.len() as u32,
                values.as_ptr(),
            )
        };
        check("WHvSetVirtualProcessorRegisters", hr)
    }

    pub(crate) fn deliver(&self, m: Message) {
        let mut ctl: WHV_INTERRUPT_CONTROL = WHV_INTERRUPT_CONTROL {
            _bitfield: 0,
            Destination: u32::from(m.dest),
            Vector: u32::from(m.vector),
        };
        // Type (bits 0-7) = IOAPIC delivery mode (fixed 0, lowest priority 1, NMI 2 is WHP's 2,
        // INIT 3/5 differ); DestinationMode (bits 8-11); TriggerMode (bits 12-15) edge = 0.
        let kind: u64 = match m.delivery {
            0 => WHvX64InterruptTypeFixed as u64,
            1 => WHvX64InterruptTypeLowestPriority as u64,
            4 => WHvX64InterruptTypeNmi as u64,
            5 => WHvX64InterruptTypeInit as u64,
            _ => return, // SMI / ExtINT: not supported
        };
        ctl._bitfield = kind | (u64::from(m.logical) << 8);
        // SAFETY: `ctl` is a fully initialized WHV_INTERRUPT_CONTROL of the size passed.
        unsafe {
            WHvRequestInterrupt(self.0, &ctl, size_of::<WHV_INTERRUPT_CONTROL>() as u32);
        }
    }
}

// SAFETY: a partition handle may be used from any thread; WHP serializes internally.
unsafe impl Send for Partition {}
// SAFETY: as above.
unsafe impl Sync for Partition {}

/// IOAPIC pin as an interrupt line.
struct Pin(Arc<IoApic>, usize);
impl IrqLine for Pin {
    fn pulse(&self) {
        self.0.pulse(self.1);
    }
}

/// The VM.
pub(crate) struct Machine {
    part: Partition,
    ioapic: Arc<IoApic>,
    tsc_khz: u64,
    /// Did WHP accept nested virtualization for this partition?
    pub nested: bool,
    /// Released (after the partition is deleted in `Drop`) so the next partition may start.
    _slot: PartitionSlot,
}

impl Machine {
    /// Create and set up a partition for `cpus` vCPUs and map `mem` into it.
    pub fn new(mem: &GuestMem, cpus: u8) -> Result<Self, BootError> {
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
        // SAFETY: out-pointer to a handle.
        check("WHvCreatePartition", unsafe {
            WHvCreatePartition(&mut handle)
        })?;
        let part = Partition(handle);
        let mut machine = Self {
            part,
            ioapic: Arc::new(IoApic::new(cpus, move |m| part.deliver(m))),
            tsc_khz: 0,
            nested: false,
            _slot: slot,
        };
        // From here on, Drop deletes the partition on any error.

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
        // Nested virtualization is best effort here; whether kvm@1 can be granted is decided by
        // the probe, which reports a refusal.
        let one: i32 = 1;
        machine.nested = part.set_property(WHvPartitionPropertyCodeNestedVirtualization, &one) >= 0;
        // CPUID exits for the topology leaves (APIC ids, core counts), like the KVM backend.
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
        // MSRs WHP does not implement read as zero and ignore writes instead of raising #GP.
        let _ = part.set_property(
            WHvPartitionPropertyCodeUnimplementedMsrAction,
            &WHvMsrActionIgnoreWriteReadZero,
        );
        // SAFETY: the partition handle is valid and not yet set up.
        check("WHvSetupPartition", unsafe { WHvSetupPartition(handle) })?;

        for region in mem.iter() {
            let host = region
                .get_host_address(vm_memory::MemoryRegionAddress(0))
                .map_err(|e| BootError(format!("host address: {e}")))?;
            // SAFETY: `host` points at `region.len()` bytes owned by `mem`, which outlives the
            // partition (see `Vm::start`: memory is dropped after the machine).
            let hr = unsafe {
                WHvMapGpaRange(
                    handle,
                    host as *const c_void,
                    region.start_addr().0,
                    region.len(),
                    WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute,
                )
            };
            check("WHvMapGpaRange", hr)?;
        }
        machine.tsc_khz = capability(WHvCapabilityCodeProcessorClockFrequency)
            // SAFETY: reading the u64 member the call filled in.
            .map_or(0, |c| unsafe { c.ProcessorClockFrequency } / 1000);
        Ok(machine)
    }

    /// Kernel arguments this backend needs: the TSC frequency (there is no PIT to calibrate
    /// against) and no IRQ0 timer check.
    pub fn cmdline_extra(&self) -> String {
        let mut s = String::from(" no_timer_check");
        if self.tsc_khz > 0 {
            s.push_str(&format!(" tsc_early_khz={}", self.tsc_khz));
        }
        s
    }

    /// The userspace IOAPIC.
    pub fn ioapic(&self) -> Option<Arc<IoApic>> {
        Some(self.ioapic.clone())
    }

    /// Interrupt line for IOAPIC pin `gsi`.
    pub fn irq_line(&self, gsi: u32) -> Result<Irq, BootError> {
        Ok(Arc::new(Pin(self.ioapic.clone(), gsi as usize)))
    }

    /// Create vCPU `id` of `cpus`; the boot CPU gets `entry`, the others wait for INIT/SIPI.
    pub fn create_vcpu(&self, id: u8, cpus: u8, entry: Option<&Entry>) -> Result<Vcpu, BootError> {
        let vp = u32::from(id);
        // SAFETY: valid partition handle; WHP validates the index.
        check("WHvCreateVirtualProcessor", unsafe {
            WHvCreateVirtualProcessor(self.part.0, vp, 0)
        })?;
        let mut emulator: *mut c_void = std::ptr::null_mut();
        // SAFETY: EMULATOR_CALLBACKS is a fully initialized static, so the pointer the emulator
        // keeps to it stays valid for the emulator's whole life; out-pointer to the handle.
        check("WHvEmulatorCreateEmulator", unsafe {
            WHvEmulatorCreateEmulator(&EMULATOR_CALLBACKS, &mut emulator)
        })?;
        let vcpu = Vcpu {
            part: self.part,
            vp,
            id,
            cpus,
            emulator,
        };

        // SAFETY: WHV_REGISTER_VALUE is a plain union; zero is a valid starting value.
        let mut mtrr: WHV_REGISTER_VALUE = unsafe { zeroed() };
        mtrr.Reg64 = (1 << 11) | 6; // MTRRs enabled, default type write-back
        self.part
            .set_registers(vp, &[WHvX64RegisterMsrMtrrDefType], &[mtrr])?;

        let Some(e) = entry else {
            // Application processor: hold it in wait-for-SIPI until the boot CPU starts it.
            // SAFETY: as above.
            let mut act: WHV_REGISTER_VALUE = unsafe { zeroed() };
            act.Reg64 = 1; // StartupSuspend
            self.part
                .set_registers(vp, &[WHvRegisterInternalActivityState], &[act])?;
            return Ok(vcpu);
        };
        let seg = |s: &Segment| {
            // SAFETY: as above.
            let mut v: WHV_REGISTER_VALUE = unsafe { zeroed() };
            v.Segment = WHV_X64_SEGMENT_REGISTER {
                Base: s.base,
                Limit: s.limit,
                Selector: s.selector,
                Anonymous: WHV_X64_SEGMENT_REGISTER_0 {
                    Attributes: s.attributes(),
                },
            };
            v
        };
        let r64 = |x: u64| {
            // SAFETY: as above.
            let mut v: WHV_REGISTER_VALUE = unsafe { zeroed() };
            v.Reg64 = x;
            v
        };
        // SAFETY: as above.
        let mut gdt: WHV_REGISTER_VALUE = unsafe { zeroed() };
        gdt.Table = WHV_X64_TABLE_REGISTER {
            Pad: [0; 3],
            Limit: e.gdt_limit,
            Base: e.gdt_base,
        };
        // SAFETY: as above.
        let idt: WHV_REGISTER_VALUE = unsafe { zeroed() };
        let names = [
            WHvX64RegisterCs,
            WHvX64RegisterDs,
            WHvX64RegisterEs,
            WHvX64RegisterFs,
            WHvX64RegisterGs,
            WHvX64RegisterSs,
            WHvX64RegisterTr,
            WHvX64RegisterGdtr,
            WHvX64RegisterIdtr,
            WHvX64RegisterCr0,
            WHvX64RegisterCr3,
            WHvX64RegisterCr4,
            WHvX64RegisterEfer,
            WHvX64RegisterRip,
            WHvX64RegisterRsp,
            WHvX64RegisterRbp,
            WHvX64RegisterRsi,
            WHvX64RegisterRflags,
        ];
        let values = [
            seg(&e.cs),
            seg(&e.ds),
            seg(&e.ds),
            seg(&e.ds),
            seg(&e.ds),
            seg(&e.ds),
            seg(&e.tr),
            gdt,
            idt,
            r64(e.cr0),
            r64(e.cr3),
            r64(e.cr4),
            r64(e.efer),
            r64(e.rip),
            r64(e.rsp),
            r64(e.rsp),
            r64(e.rsi),
            r64(2),
        ];
        self.part.set_registers(vp, &names, &values)?;
        Ok(vcpu)
    }

    /// Make vCPU `index` return from `WHvRunVirtualProcessor`.
    pub fn kick(&self, index: usize, _t: &std::thread::JoinHandle<()>) {
        // SAFETY: valid partition handle; cancelling a vCPU that is not running is harmless.
        unsafe {
            WHvCancelRunVirtualProcessor(self.part.0, index as u32, 0);
        }
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        // SAFETY: the handle came from WHvCreatePartition and every vCPU has been deleted
        // (vCPUs are dropped by their threads before the last reference to the machine).
        unsafe {
            WHvDeletePartition(self.part.0);
        }
    }
}

/// One vCPU.
pub(crate) struct Vcpu {
    part: Partition,
    vp: u32,
    id: u8,
    cpus: u8,
    emulator: *mut c_void,
}

// SAFETY: the emulator handle is only used by the thread that owns the Vcpu.
unsafe impl Send for Vcpu {}

impl Drop for Vcpu {
    fn drop(&mut self) {
        // SAFETY: handles created in `create_vcpu`, released exactly once.
        unsafe {
            WHvEmulatorDestroyEmulator(self.emulator);
            WHvDeleteVirtualProcessor(self.part.0, self.vp);
        }
    }
}

/// The instruction emulator's callback table. It must outlive every emulator: the emulator
/// keeps a pointer to it instead of copying it (a stack copy crashed release builds once the
/// slot was reused), so it is a static.
static EMULATOR_CALLBACKS: WHV_EMULATOR_CALLBACKS = WHV_EMULATOR_CALLBACKS {
    Size: size_of::<WHV_EMULATOR_CALLBACKS>() as u32,
    Reserved: 0,
    WHvEmulatorIoPortCallback: Some(emu_io),
    WHvEmulatorMemoryCallback: Some(emu_mmio),
    WHvEmulatorGetVirtualProcessorRegisters: Some(emu_get_regs),
    WHvEmulatorSetVirtualProcessorRegisters: Some(emu_set_regs),
    WHvEmulatorTranslateGvaPage: Some(emu_translate),
};

/// What the emulator callbacks need, for one exit.
struct EmuCtx<'a> {
    part: Partition,
    vp: u32,
    dev: &'a Devices,
    reset: Option<ExitReason>,
}

const S_OK: i32 = 0;

unsafe extern "system" fn emu_io(ctx: *const c_void, io: *mut WHV_EMULATOR_IO_ACCESS_INFO) -> i32 {
    // SAFETY: `ctx` is the &mut EmuCtx passed to WHvEmulatorTry*Emulation for this exit and
    // `io` is valid for the duration of the callback.
    let (ctx, io) = unsafe { (&mut *(ctx as *mut EmuCtx<'_>), &mut *io) };
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
    let (ctx, m) = unsafe { (&mut *(ctx as *mut EmuCtx<'_>), &mut *m) };
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
    // SAFETY: as in `emu_io`; the arrays hold `count` elements.
    unsafe {
        let ctx = &*(ctx as *const EmuCtx<'_>);
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
        let ctx = &*(ctx as *const EmuCtx<'_>);
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
    // SAFETY: as in `emu_io`; `result` and `gpa` are valid out-pointers.
    unsafe {
        let ctx = &*(ctx as *const EmuCtx<'_>);
        let mut r: WHV_TRANSLATE_GVA_RESULT = zeroed();
        let hr = WHvTranslateGva(ctx.part.0, ctx.vp, gva, flags, &mut r, gpa);
        *result = r.ResultCode;
        hr
    }
}

impl Vcpu {
    fn emulated(&self, ok: i32, status: WHV_EMULATOR_STATUS, what: &str) -> Result<(), BootError> {
        check(what, ok)?;
        // SAFETY: reading the u32 view of the status the emulator filled in.
        let bits = unsafe { status.AsUINT32 };
        if bits & 1 == 0 {
            return Err(BootError(format!(
                "{what}: instruction emulation failed (status 0x{bits:x})"
            )));
        }
        Ok(())
    }

    /// Run until the guest resets, crashes or `stop` is set.
    pub fn run(&mut self, dev: &Devices, stop: &AtomicBool) -> Result<ExitReason, BootError> {
        loop {
            if stop.load(Ordering::SeqCst) {
                return Ok(ExitReason::Timeout);
            }
            // SAFETY: plain-data exit context, fully written by the call.
            let mut exit: WHV_RUN_VP_EXIT_CONTEXT = unsafe { zeroed() };
            // SAFETY: valid handles; the buffer is the size passed.
            let hr = unsafe {
                WHvRunVirtualProcessor(
                    self.part.0,
                    self.vp,
                    (&mut exit as *mut WHV_RUN_VP_EXIT_CONTEXT).cast(),
                    size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
                )
            };
            check("WHvRunVirtualProcessor", hr)?;
            let mut ctx = EmuCtx {
                part: self.part,
                vp: self.vp,
                dev,
                reset: None,
            };
            let ctxp = (&mut ctx as *mut EmuCtx<'_>).cast::<c_void>();
            match exit.ExitReason {
                WHvRunVpExitReasonMemoryAccess => {
                    // SAFETY: zeroed status is valid; the exit union member matches the reason.
                    let mut status: WHV_EMULATOR_STATUS = unsafe { zeroed() };
                    // SAFETY: valid emulator, context and exit data for this exit.
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
                    // SAFETY: as above.
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
                    // SAFETY: the union member matches the exit reason.
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
                WHvRunVpExitReasonCanceled => {} // kicked: the loop checks `stop`
                WHvRunVpExitReasonX64Halt => {
                    // Only with interrupts off (an idle HLT is handled by the emulated APIC):
                    // the guest has stopped for good unless an NMI arrives.
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                WHvRunVpExitReasonX64ApicEoi => {} // edge-only IOAPIC: nothing to clear
                WHvRunVpExitReasonUnrecoverableException => return Ok(ExitReason::TripleFault),
                other => {
                    return Err(BootError(format!(
                        "unhandled VM exit {other} at rip 0x{:x}",
                        exit.VpContext.Rip
                    )));
                }
            }
        }
    }
}
