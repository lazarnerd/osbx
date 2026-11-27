//! osbx virtual machine monitor.
//!
//! A small x86_64 VMM that boots a Linux guest with a serial console, virtio-MMIO devices
//! (blk, vsock, fs) and an MP table, on two hypervisor backends: KVM (Linux hosts) and the
//! Windows Hypervisor Platform (Windows hosts). Everything above [`hv`] is shared.
//!
//! It also implements the `kvm@1` usability probe (spec
//! `capabilities/com.docker.sandbox/kvm@1`). `kvm@1` is a hard requirement for osbx (see
//! `docs/PLAN.md`): the runtime must be able to hand a sandbox usable `/dev/kvm` and
//! `/dev/vhost-vsock` on every host OS, which needs nested virtualization from the host
//! hypervisor.

pub mod disk;
#[cfg(windows)]
#[allow(unsafe_code)] // one statfs call, with a SAFETY comment
mod fuse;
mod report;
pub use report::{KvmReport, Probe, VsockReport};

/// KVM API version the `kvm@1` contract requires.
pub const REQUIRED_KVM_API_VERSION: i32 = 12;

/// A failure while running the probe guest.
#[derive(Debug)]
pub struct GuestError(pub String);
impl std::fmt::Display for GuestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for GuestError {}

#[cfg(any(target_os = "linux", windows))]
pub mod acpi;
#[cfg(any(target_os = "linux", windows))]
mod boot;
#[cfg(any(target_os = "linux", windows))]
mod bus;
#[cfg(any(target_os = "linux", windows))]
mod devices;
#[cfg(any(target_os = "linux", windows))]
pub mod hpet;
#[cfg(any(target_os = "linux", windows))]
pub mod ioapic;
#[cfg(any(target_os = "linux", windows))]
pub mod irq;
#[cfg(any(target_os = "linux", windows))]
mod mptable;
#[cfg(any(target_os = "linux", windows))]
pub mod pci;
#[cfg(any(target_os = "linux", windows))]
pub mod pflash;
#[cfg(any(target_os = "linux", windows))]
pub mod qcow2;
#[cfg(any(target_os = "linux", windows))]
pub mod virtio;
#[cfg(any(target_os = "linux", windows))]
pub use boot::{
    BootConfig, BootError, BootOutcome, DEFAULT_CMDLINE, DiskConfig, ExitReason, ShareConfig, Vm,
    boot_linux,
};

#[cfg(target_os = "linux")]
mod guest;
#[cfg(target_os = "linux")]
mod kvm;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod uefi;
#[cfg(target_os = "linux")]
pub use guest::run_hello_guest;
#[cfg(target_os = "linux")]
use kvm as hv;
#[cfg(target_os = "linux")]
pub use linux::probe;
#[cfg(target_os = "linux")]
pub use uefi::{UefiConfig, UefiOutcome, UefiVm, boot_uefi};

#[cfg(windows)]
mod whp;
#[cfg(windows)]
mod whp_probe;
#[cfg(windows)]
use whp as hv;
#[cfg(windows)]
pub use whp_probe::{probe, run_hello_guest};

/// Probe the host's hypervisor support.
#[cfg(not(any(target_os = "linux", windows)))]
pub fn probe() -> Probe {
    Probe::unsupported(std::env::consts::OS)
}

/// Print the `kvm@1` probe report (as `osbx vmm probe` and the in-guest `osbx-probe` do).
/// Returns whether the host passes (and, with `require_nested`, can also nest).
pub fn report_probe(run_guest: bool, require_nested: bool) -> bool {
    let p = probe();
    let yn = |b: bool| if b { "yes" } else { "NO" };
    let opt = |o: Option<bool>| o.map_or("unknown", |b| if b { "yes" } else { "NO" });
    if p.hypervisor == "whp" {
        println!("hypervisor                : Windows Hypervisor Platform");
        println!("WHP present               : {}", yn(p.kvm.opens));
        println!("partition runs            : {}", yn(p.kvm.create_vm));
        println!("nested virtualization     : {}", opt(p.kvm.nested_enabled));
    } else {
        println!("/dev/kvm opens read-write : {}", yn(p.kvm.opens));
        println!(
            "KVM_GET_API_VERSION       : {}",
            p.kvm.api_version.map_or("n/a".into(), |v| format!(
                "{v} (need {REQUIRED_KVM_API_VERSION})"
            ))
        );
        println!("KVM_CREATE_VM             : {}", yn(p.kvm.create_vm));
        println!("/dev/vhost-vsock usable   : {}", yn(p.vsock_usable()));
        println!("host nested virtualization: {}", opt(p.kvm.nested_enabled));
    }
    println!(
        "guest CPU can carry VMX/SVM: {}",
        opt(p.kvm.guest_virt_exposed)
    );
    #[allow(unused_mut)]
    let mut ok = p.grantable();
    println!("=> kvm@1 grantable        : {}", yn(ok));
    println!("=> sandbox can run own KVM: {}", yn(p.nested_ready()));
    if run_guest {
        #[cfg(any(target_os = "linux", windows))]
        match run_hello_guest() {
            Ok(out) => println!(
                "guest boot test           : ok (guest printed {:?})",
                out.trim_end()
            ),
            Err(e) => {
                ok = false;
                println!("guest boot test           : FAILED: {e}");
            }
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            ok = false;
            println!("guest boot test           : not supported on this OS yet");
        }
    }
    for problem in &p.problems {
        eprintln!("problem: {problem}");
    }
    ok && (!require_nested || p.nested_ready())
}
