//! Windows Hypervisor Platform probe and smallest-possible guest.
//!
//! The `kvm@1` contract is about the *sandbox's* `/dev/kvm`: on a Windows host the guest
//! kernel provides KVM (and vhost-vsock) itself, on top of nested virtualization from WHP. So
//! the probe maps the contract onto WHP: the hypervisor is present, a partition can be created,
//! nested virtualization is accepted, and a guest CPU really sees VMX/SVM.

#![allow(unsafe_code)]
// WHP binding constants keep their Windows SDK names.
#![allow(non_upper_case_globals)]

use crate::GuestError;
use crate::report::{Probe, VsockReport};
use crate::whp::hypervisor_present;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use windows_sys::Win32::System::Hypervisor::*;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};

const MEM_SIZE: usize = 0x4000;
const CODE_ADDR: u64 = 0x1000;
/// Port the guest writes to when it is done. (With WHP's local APIC emulation, which nested
/// virtualization requires, `hlt` is handled inside the hypervisor and never exits.)
const DONE_PORT: u16 = 0x99;
/// Real mode: report CPUID.1:ECX on port 0x80 and CPUID.80000001h:ECX on port 0x81, write
/// "OK\n" to COM1, signal [`DONE_PORT`], halt.
const CODE: [u8; 43] = [
    0x66, 0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0x0f, 0xa2, // cpuid
    0x66, 0x89, 0xc8, // mov eax, ecx
    0x66, 0xe7, 0x80, // out 0x80, eax
    0x66, 0xb8, 0x01, 0x00, 0x00, 0x80, // mov eax, 0x80000001
    0x0f, 0xa2, // cpuid
    0x66, 0x89, 0xc8, // mov eax, ecx
    0x66, 0xe7, 0x81, // out 0x81, eax
    0xba, 0xf8, 0x03, // mov dx, 0x3f8
    0xb0, b'O', 0xee, // mov al, 'O'; out dx, al
    0xb0, b'K', 0xee, // mov al, 'K'; out dx, al
    0xb0, 0x0a, 0xee, // mov al, 10; out dx, al
    0xe6, 0x99, // out 0x99, al
    0xf4, // hlt
];

/// What the tiny guest reported.
struct TinyRun {
    serial: String,
    vmx: bool,
    svm: bool,
}

fn hr(what: &str, r: i32) -> Result<(), GuestError> {
    if r < 0 {
        Err(GuestError(format!("{what}: HRESULT 0x{:08x}", r as u32)))
    } else {
        Ok(())
    }
}

/// Boot a one-vCPU partition (nested virtualization requested if `nested`) running [`CODE`].
fn tiny_guest(nested: bool) -> Result<TinyRun, GuestError> {
    // one live partition per process (see whp::PartitionSlot); the run takes milliseconds
    let _slot = crate::whp::PartitionSlot::acquire(std::time::Duration::from_secs(600))
        .ok_or_else(|| GuestError("another VM in this process is still running".into()))?;
    // SAFETY: straightforward WHP calls on a partition and a VirtualAlloc buffer owned by this
    // function; the partition is deleted before the buffer is freed, on every path.
    unsafe {
        let mut part: WHV_PARTITION_HANDLE = 0;
        hr("WHvCreatePartition", WHvCreatePartition(&mut part))?;
        let mem = VirtualAlloc(
            std::ptr::null(),
            MEM_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) as *mut u8;
        let result = (|| {
            if mem.is_null() {
                return Err(GuestError("VirtualAlloc failed".into()));
            }
            let count: u32 = 1;
            hr(
                "set ProcessorCount",
                WHvSetPartitionProperty(
                    part,
                    WHvPartitionPropertyCodeProcessorCount,
                    (&count as *const u32).cast(),
                    4,
                ),
            )?;
            if nested {
                // nested virtualization is only accepted together with local APIC emulation
                hr(
                    "set LocalApicEmulationMode",
                    WHvSetPartitionProperty(
                        part,
                        WHvPartitionPropertyCodeLocalApicEmulationMode,
                        (&WHvX64LocalApicEmulationModeXApic as *const i32).cast(),
                        4,
                    ),
                )?;
                let one: i32 = 1;
                hr(
                    "set NestedVirtualization",
                    WHvSetPartitionProperty(
                        part,
                        WHvPartitionPropertyCodeNestedVirtualization,
                        (&one as *const i32).cast(),
                        4,
                    ),
                )?;
            }
            hr("WHvSetupPartition", WHvSetupPartition(part))?;
            std::ptr::copy_nonoverlapping(CODE.as_ptr(), mem.add(CODE_ADDR as usize), CODE.len());
            hr(
                "WHvMapGpaRange",
                WHvMapGpaRange(
                    part,
                    mem as *const c_void,
                    0,
                    MEM_SIZE as u64,
                    WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute,
                ),
            )?;
            hr(
                "WHvCreateVirtualProcessor",
                WHvCreateVirtualProcessor(part, 0, 0),
            )?;
            let names = [WHvX64RegisterCs, WHvX64RegisterRip];
            let mut vals: [WHV_REGISTER_VALUE; 2] = zeroed();
            hr(
                "get CS",
                WHvGetVirtualProcessorRegisters(part, 0, names.as_ptr(), 1, vals.as_mut_ptr()),
            )?;
            vals[0].Segment.Base = 0;
            vals[0].Segment.Selector = 0;
            vals[1].Reg64 = CODE_ADDR;
            hr(
                "set CS/RIP",
                WHvSetVirtualProcessorRegisters(part, 0, names.as_ptr(), 2, vals.as_ptr()),
            )?;

            let mut run = TinyRun {
                serial: String::new(),
                vmx: false,
                svm: false,
            };
            for _ in 0..100 {
                let mut exit: WHV_RUN_VP_EXIT_CONTEXT = zeroed();
                hr(
                    "WHvRunVirtualProcessor",
                    WHvRunVirtualProcessor(
                        part,
                        0,
                        (&mut exit as *mut WHV_RUN_VP_EXIT_CONTEXT).cast(),
                        size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
                    ),
                )?;
                match exit.ExitReason {
                    WHvRunVpExitReasonX64IoPortAccess => {
                        let io = exit.Anonymous.IoPortAccess;
                        let v = io.Rax as u32;
                        match io.PortNumber {
                            0x80 => run.vmx = v & (1 << 5) != 0,
                            0x81 => run.svm = v & (1 << 2) != 0,
                            0x3f8 => run.serial.push(char::from(v as u8)),
                            DONE_PORT => {
                                WHvDeleteVirtualProcessor(part, 0);
                                return Ok(run);
                            }
                            _ => {}
                        }
                        let len = u64::from(exit.VpContext._bitfield & 0x0f);
                        let mut rip: WHV_REGISTER_VALUE = zeroed();
                        rip.Reg64 = exit.VpContext.Rip + len;
                        hr(
                            "set RIP",
                            WHvSetVirtualProcessorRegisters(
                                part,
                                0,
                                [WHvX64RegisterRip].as_ptr(),
                                1,
                                &rip,
                            ),
                        )?;
                    }
                    WHvRunVpExitReasonX64Halt => {
                        WHvDeleteVirtualProcessor(part, 0);
                        return Ok(run);
                    }
                    other => {
                        WHvDeleteVirtualProcessor(part, 0);
                        return Err(GuestError(format!("unexpected VM exit {other}")));
                    }
                }
            }
            WHvDeleteVirtualProcessor(part, 0);
            Err(GuestError("guest did not halt within 100 exits".into()))
        })();
        WHvDeletePartition(part);
        if !mem.is_null() {
            VirtualFree(mem.cast(), 0, MEM_RELEASE);
        }
        result
    }
}

/// Boot a one-vCPU VM that prints `OK\n` on the serial port and halts; returns what it wrote.
pub fn run_hello_guest() -> Result<String, GuestError> {
    tiny_guest(false).map(|r| r.serial)
}

/// Probe the Windows Hypervisor Platform against the `kvm@1` contract (see the module docs).
pub fn probe() -> Probe {
    let mut p = Probe {
        hypervisor: "whp".into(),
        ..Probe::default()
    };
    if !hypervisor_present() {
        p.problems.push(
            "the Windows Hypervisor Platform is not available: enable the optional feature \"Windows Hypervisor Platform\" (HypervisorPlatform) and reboot".into(),
        );
        return p;
    }
    p.kvm.opens = true;
    // WHP has no API version; the contract's version check applies to the guest's /dev/kvm,
    // which the osbx guest kernel provides (KVM API 12).
    p.kvm.api_version = Some(crate::REQUIRED_KVM_API_VERSION);
    match tiny_guest(false) {
        Ok(_) => p.kvm.create_vm = true,
        Err(e) => p.problems.push(format!("cannot run a WHP partition: {e}")),
    }
    // vsock is emulated in userspace by osbx; the guest kernel provides /dev/vhost-vsock.
    p.vsock = VsockReport {
        opens: p.kvm.create_vm,
        features: p.kvm.create_vm.then_some(0),
    };
    match tiny_guest(true) {
        Ok(r) => {
            p.kvm.nested_enabled = Some(true);
            p.kvm.guest_virt_exposed = Some(r.vmx || r.svm);
            if !(r.vmx || r.svm) {
                p.problems.push(
                    "WHP accepted nested virtualization but the guest CPU shows no VMX/SVM".into(),
                );
            }
        }
        Err(e) => {
            p.kvm.nested_enabled = Some(false);
            p.problems.push(format!(
                "WHP refused nested virtualization ({e}); it needs Windows 11 / Server 2022 or later on a CPU with VT-x or AMD-V"
            ));
        }
    }
    p
}
