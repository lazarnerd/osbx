//! Probe results (platform independent).

/// What was learned about `/dev/kvm`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KvmReport {
    /// `/dev/kvm` opened read-write.
    pub opens: bool,
    /// Result of `KVM_GET_API_VERSION`.
    pub api_version: Option<i32>,
    /// `KVM_CREATE_VM` succeeded.
    pub create_vm: bool,
    /// Host KVM module has nested virtualization enabled (`None` = cannot tell).
    pub nested_enabled: Option<bool>,
    /// A guest CPU can be given VMX (Intel) / SVM (AMD), i.e. a guest could itself run KVM.
    pub guest_virt_exposed: Option<bool>,
}

/// What was learned about `/dev/vhost-vsock`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VsockReport {
    /// Opened read-write.
    pub opens: bool,
    /// Result of `VHOST_GET_FEATURES`.
    pub features: Option<u64>,
}

/// Full probe outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Probe {
    /// Host hypervisor backend: `kvm` (Linux) or `whp` (Windows Hypervisor Platform). On WHP the
    /// `kvm` fields describe the equivalent checks (the guest kernel provides the sandbox's
    /// `/dev/kvm` and `/dev/vhost-vsock` on top of nested virtualization).
    pub hypervisor: String,
    /// `/dev/kvm` findings.
    pub kvm: KvmReport,
    /// `/dev/vhost-vsock` findings.
    pub vsock: VsockReport,
    /// Why something is missing, in plain words.
    pub problems: Vec<String>,
}

impl Probe {
    /// A host with no hypervisor backend implemented yet.
    pub fn unsupported(os: &str) -> Self {
        Self {
            problems: vec![format!(
                "no hypervisor backend for {os} yet (osbx implements Linux/KVM and Windows/WHP)"
            )],
            ..Self::default()
        }
    }

    /// The contract's definition of usable KVM: open rw, API version 12, `KVM_CREATE_VM` works.
    /// A device node alone does not count.
    pub fn kvm_usable(&self) -> bool {
        self.kvm.opens
            && self.kvm.api_version == Some(crate::REQUIRED_KVM_API_VERSION)
            && self.kvm.create_vm
    }

    /// Usable vhost-vsock: open rw and `VHOST_GET_FEATURES` succeeds.
    pub fn vsock_usable(&self) -> bool {
        self.vsock.opens && self.vsock.features.is_some()
    }

    /// May the runtime grant a `kvm@1` request on this host? Both devices must be usable.
    pub fn grantable(&self) -> bool {
        self.kvm_usable() && self.vsock_usable()
    }

    /// Could a *sandbox* then run its own KVM (the point of `kvm@1`): nested virtualization
    /// must be enabled on the host and the guest CPU must be able to carry VMX/SVM.
    pub fn nested_ready(&self) -> bool {
        self.grantable()
            && self.kvm.nested_enabled == Some(true)
            && self.kvm.guest_virt_exposed == Some(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> Probe {
        Probe {
            kvm: KvmReport {
                opens: true,
                api_version: Some(12),
                create_vm: true,
                nested_enabled: Some(true),
                guest_virt_exposed: Some(true),
            },
            vsock: VsockReport {
                opens: true,
                features: Some(0x3_3d00_0002),
            },
            problems: vec![],
            hypervisor: "kvm".into(),
        }
    }

    #[test]
    fn contract_needs_every_step() {
        assert!(good().grantable() && good().nested_ready());
        // a device node alone is not enough: each step of the contract must succeed
        let mut p = good();
        p.kvm.api_version = Some(11);
        assert!(!p.kvm_usable() && !p.grantable());
        let mut p = good();
        p.kvm.create_vm = false;
        assert!(!p.grantable());
        let mut p = good();
        p.vsock.features = None;
        assert!(!p.vsock_usable() && !p.grantable());
        let mut p = good();
        p.kvm.opens = false;
        assert!(!p.grantable());
    }

    #[test]
    fn nested_is_separate_from_grantable() {
        let mut p = good();
        p.kvm.nested_enabled = Some(false);
        assert!(p.grantable() && !p.nested_ready());
        p.kvm.nested_enabled = None; // unknown is not "ready"
        assert!(!p.nested_ready());
    }

    #[test]
    fn unsupported_hosts_are_never_grantable() {
        let p = Probe::unsupported("windows");
        assert!(!p.grantable() && !p.nested_ready() && p.problems[0].contains("windows"));
    }
}
