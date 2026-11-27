//! Linux/KVM probing.

use crate::report::{KvmReport, Probe, VsockReport};
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::Kvm;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd;

/// `_IOR(0xAF, 0x00, __u64)`: linux/vhost.h `VHOST_GET_FEATURES`.
const VHOST_GET_FEATURES: u64 = 0x8008_AF00;

/// Run the `kvm@1` contract checks against this host.
pub fn probe() -> Probe {
    let mut p = Probe {
        hypervisor: "kvm".into(),
        ..Probe::default()
    };
    p.kvm = probe_kvm(&mut p.problems);
    p.vsock = probe_vsock(&mut p.problems);
    p
}

fn probe_kvm(problems: &mut Vec<String>) -> KvmReport {
    let mut r = KvmReport {
        nested_enabled: nested_param(),
        ..KvmReport::default()
    };
    let kvm = match Kvm::new() {
        Ok(k) => k,
        Err(e) => {
            problems.push(format!("/dev/kvm: {e} (missing device, no virtualization exposed, or user not in the kvm group)"));
            return r;
        }
    };
    r.opens = true;
    let v = kvm.get_api_version();
    r.api_version = Some(v);
    if v != crate::REQUIRED_KVM_API_VERSION {
        problems.push(format!(
            "KVM_GET_API_VERSION returned {v}, the kvm@1 contract needs {}",
            crate::REQUIRED_KVM_API_VERSION
        ));
    }
    match kvm.create_vm() {
        Ok(_) => r.create_vm = true,
        Err(e) => problems.push(format!("KVM_CREATE_VM failed: {e}")),
    }
    r.guest_virt_exposed = guest_virt_exposed(&kvm);
    if r.nested_enabled == Some(false) {
        problems.push(
            "host KVM has nested virtualization disabled: a sandbox could not run its own KVM"
                .into(),
        );
    }
    r
}

/// `/sys/module/kvm_{intel,amd}/parameters/nested` reads `Y`/`1` when enabled.
fn nested_param() -> Option<bool> {
    ["kvm_intel", "kvm_amd"].iter().find_map(|m| {
        let v = std::fs::read_to_string(format!("/sys/module/{m}/parameters/nested")).ok()?;
        Some(matches!(v.trim(), "Y" | "y" | "1"))
    })
}

/// Can KVM report VMX (CPUID.1:ECX[5]) or SVM (CPUID.80000001h:ECX[2]) as a supported guest feature?
fn guest_virt_exposed(kvm: &Kvm) -> Option<bool> {
    #[cfg(target_arch = "x86_64")]
    {
        let cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).ok()?;
        let has = |function: u32, bit: u32| {
            cpuid
                .as_slice()
                .iter()
                .any(|e| e.function == function && e.ecx & (1 << bit) != 0)
        };
        Some(has(1, 5) || has(0x8000_0001, 2))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (kvm, KVM_MAX_CPUID_ENTRIES);
        None
    }
}

fn probe_vsock(problems: &mut Vec<String>) -> VsockReport {
    let mut r = VsockReport::default();
    match vhost_features() {
        Ok((opened, features)) => {
            r.opens = opened;
            r.features = features;
            if features.is_none() {
                problems.push("VHOST_GET_FEATURES on /dev/vhost-vsock failed".into());
            }
        }
        Err(e) => problems.push(format!(
            "/dev/vhost-vsock: {e} (modprobe vhost_vsock; user needs kvm group access)"
        )),
    }
    r
}

/// Returns `(opened, features)`.
#[allow(unsafe_code)]
fn vhost_features() -> io::Result<(bool, Option<u64>)> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/vhost-vsock")?;
    let mut features: u64 = 0;
    // SAFETY: `f` keeps the descriptor open for the whole call, and VHOST_GET_FEATURES writes
    // exactly one u64 through the pointer, which refers to a live, properly aligned local.
    let rc = unsafe {
        libc::ioctl(
            f.as_raw_fd(),
            VHOST_GET_FEATURES as _,
            &mut features as *mut u64,
        )
    };
    Ok((true, (rc == 0).then_some(features)))
}
