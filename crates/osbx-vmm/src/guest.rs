//! The smallest possible guest: proves the host can really run a VM, not just open a device.

use crate::GuestError;
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Kvm, VcpuExit};
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

fn e<E: std::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> GuestError {
    move |err| GuestError(format!("{what}: {err}"))
}

const MEM_SIZE: usize = 0x4000;
const CODE_ADDR: u64 = 0x1000;
/// Real-mode code: write "OK\n" to the serial port (0x3f8), then halt.
///   mov dx,0x3f8 ; mov al,'O' ; out dx,al ; mov al,'K' ; out dx,al ; mov al,10 ; out dx,al ; hlt
const CODE: [u8; 13] = [
    0xba, 0xf8, 0x03, 0xb0, b'O', 0xee, 0xb0, b'K', 0xee, 0xb0, 0x0a, 0xee, 0xf4,
];

/// Boot a one-vCPU VM that prints `OK\n` on the serial port and halts; returns what the guest
/// wrote. Fails if any step of VM creation or execution fails.
#[allow(unsafe_code)]
pub fn run_hello_guest() -> Result<String, GuestError> {
    let kvm = Kvm::new().map_err(e("open /dev/kvm"))?;
    let vm = kvm.create_vm().map_err(e("KVM_CREATE_VM"))?;

    let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), MEM_SIZE)])
        .map_err(e("allocate guest memory"))?;
    mem.write_slice(&CODE, GuestAddress(CODE_ADDR))
        .map_err(e("load guest code"))?;
    let host_addr = mem
        .get_host_address(GuestAddress(0))
        .map_err(e("host address"))?;
    let region = kvm_userspace_memory_region {
        slot: 0,
        flags: 0,
        guest_phys_addr: 0,
        memory_size: MEM_SIZE as u64,
        userspace_addr: host_addr as u64,
    };
    // SAFETY: `host_addr` points at MEM_SIZE bytes of mapped memory owned by `mem`, which is kept
    // alive (and not resized) until after the vCPU stops running at the end of this function.
    unsafe { vm.set_user_memory_region(region) }.map_err(e("KVM_SET_USER_MEMORY_REGION"))?;

    let mut vcpu = vm.create_vcpu(0).map_err(e("KVM_CREATE_VCPU"))?;
    let mut sregs = vcpu.get_sregs().map_err(e("KVM_GET_SREGS"))?;
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    vcpu.set_sregs(&sregs).map_err(e("KVM_SET_SREGS"))?;
    let mut regs = vcpu.get_regs().map_err(e("KVM_GET_REGS"))?;
    regs.rip = CODE_ADDR;
    regs.rflags = 2; // bit 1 is reserved-set
    vcpu.set_regs(&regs).map_err(e("KVM_SET_REGS"))?;

    let mut out = Vec::new();
    for _ in 0..1000 {
        match vcpu.run().map_err(e("KVM_RUN"))? {
            VcpuExit::IoOut(0x3f8, data) => out.extend_from_slice(data),
            VcpuExit::Hlt => {
                drop(mem);
                return Ok(String::from_utf8_lossy(&out).into_owned());
            }
            other => return Err(GuestError(format!("unexpected VM exit: {other:?}"))),
        }
    }
    Err(GuestError("guest did not halt within 1000 exits".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_runs_and_talks_over_serial() {
        if !std::path::Path::new("/dev/kvm").exists() || Kvm::new().is_err() {
            eprintln!("no usable /dev/kvm: skipping");
            return;
        }
        assert_eq!(run_hello_guest().unwrap(), "OK\n");
    }
}
