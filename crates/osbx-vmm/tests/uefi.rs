//! Integration tests for Q35 PCIe UEFI (OVMF) boot on KVM:
//! - Unified `OVMF.fd` -> UEFI Interactive Shell -> ACPI S5 shutdown
//! - Split `OVMF_CODE_4M.fd` + persistent CFI `pflash` `OVMF_VARS_4M.fd` + 4 GiB RAM
//! - `virtio-blk` (PCIe QCOW2 CoW disk with FAT32) + `virtio-scsi` (PCIe ISO9660 CD-ROM)

#![cfg(target_os = "linux")]

use osbx_vmm::{DiskConfig, ExitReason, UefiConfig, boot_uefi, qcow2};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn ovmf_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("OSBX_OVMF") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    let default = PathBuf::from("/usr/share/ovmf/OVMF.fd");
    default.exists().then_some(default)
}

#[test]
fn ovmf_boots_to_uefi_shell_and_shuts_down_via_acpi() {
    let Some(firmware) = ovmf_path() else {
        eprintln!("OVMF firmware not found at /usr/share/ovmf/OVMF.fd; skipping");
        return;
    };
    if !osbx_vmm::probe().grantable() {
        eprintln!("no usable /dev/kvm; skipping");
        return;
    }

    let mut cfg = UefiConfig::new(firmware);
    cfg.mem_mib = 512;
    cfg.cpus = 2;
    cfg.timeout = Some(Duration::from_secs(30));
    cfg.send_on_match = Some(("Shell>".into(), b"ver\r\npci\r\nreset -s\r\n".to_vec()));

    let out = boot_uefi(&cfg).expect("UEFI boot failed");
    assert!(
        out.console.contains("UEFI Interactive Shell"),
        "expected UEFI Interactive Shell on COM1.\nconsole:\n{}",
        out.console
    );
    assert!(
        out.console.contains("UEFI v2."),
        "expected `ver` output on COM1:\n{}",
        out.console
    );
    // Q35 MCH (8086:29C0) and Bochs Display (1234:1111) enumerated by UEFI PCI driver.
    assert!(
        out.console.contains("8086") && out.console.contains("1234"),
        "expected Q35 and Bochs VGA in `pci` output:\n{}",
        out.console
    );
    assert_eq!(out.exit, ExitReason::GuestReset);
}

#[test]
fn ovmf_split_pflash_persists_nvram_and_boots_above_4gib() {
    let code = PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.fd");
    let vars_src = PathBuf::from("/usr/share/OVMF/OVMF_VARS_4M.fd");
    if !code.exists() || !vars_src.exists() {
        eprintln!("split OVMF_CODE_4M/OVMF_VARS_4M not found; skipping");
        return;
    }
    if !osbx_vmm::probe().grantable() {
        eprintln!("no usable /dev/kvm; skipping");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("osbx-pflash-{}", std::process::id()));
    let _cleanup = TempDir(tmp.clone());
    std::fs::create_dir_all(&tmp).unwrap();
    let vars_copy = tmp.join("vars.fd");
    std::fs::copy(&vars_src, &vars_copy).unwrap();

    // Boot 1: verify 3 GiB memory map (spanning 4 GiB) + write a persistent UEFI NVRAM variable.
    let mut cfg = UefiConfig::new(code.clone());
    cfg.vars = Some(vars_copy.clone());
    cfg.mem_mib = 3072; // 2 GiB low + 1 GiB high above 4 GiB
    cfg.cpus = 2;
    cfg.timeout = Some(Duration::from_secs(30));
    cfg.send_on_match = Some((
        "Shell>".into(),
        b"memmap\r\nsetvar OsbxTest -guid 11111111-2222-3333-4444-555555555555 -nv -bs -rt =01020304\r\nsetvar OsbxTest -guid 11111111-2222-3333-4444-555555555555\r\nreset -s\r\n".to_vec(),
    ));

    let out1 = boot_uefi(&cfg).expect("split OVMF boot 1 failed");
    assert!(
        out1.console.contains("Total Memory:"),
        "expected `memmap` output:\n{}",
        out1.console
    );
    assert!(
        out1.console.contains("01 02 03 04"),
        "expected `setvar` to succeed in boot 1:\n{}",
        out1.console
    );
    assert_eq!(out1.exit, ExitReason::GuestReset);

    // Boot 2: verify persistent NVRAM survived reboot via CFI pflash!
    cfg.mem_mib = 512;
    cfg.send_on_match = Some((
        "Shell>".into(),
        b"setvar OsbxTest -guid 11111111-2222-3333-4444-555555555555\r\nreset -s\r\n".to_vec(),
    ));
    let out2 = boot_uefi(&cfg).expect("split OVMF boot 2 failed");
    assert!(
        out2.console.contains("01 02 03 04"),
        "expected persisted UEFI NVRAM variable across reboot.\nboot1:\n{}\nboot2:\n{}",
        out1.console,
        out2.console
    );
    assert_eq!(out2.exit, ExitReason::GuestReset);
}

#[test]
fn ovmf_reads_virtio_pci_qcow2_disk_and_virtio_scsi_iso() {
    let Some(firmware) = ovmf_path() else {
        eprintln!("OVMF firmware not found; skipping");
        return;
    };
    if !osbx_vmm::probe().grantable() {
        eprintln!("no usable /dev/kvm; skipping");
        return;
    }
    if Command::new("mformat").arg("--version").output().is_err()
        || Command::new("genisoimage")
            .arg("--version")
            .output()
            .is_err()
    {
        eprintln!("mtools/genisoimage unavailable; skipping");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("osbx-pcie-io-{}", std::process::id()));
    let _cleanup = TempDir(tmp.clone());
    std::fs::create_dir_all(tmp.join("iso")).unwrap();

    // 1. Build a 36 MiB sparse FAT32 disk image, then wrap it in a QCOW2 CoW overlay!
    let raw_fat = tmp.join("fat.raw");
    let fat_marker = tmp.join("disk.txt");
    std::fs::write(&fat_marker, "HELLO-FROM-QCOW2-VIRTIO-BLK\r\n").unwrap();
    osbx_vmm::disk::create_sparse(&raw_fat, 36 << 20).unwrap();
    assert!(
        Command::new("mformat")
            .args(["-i", raw_fat.to_str().unwrap(), "-F", "::"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("mcopy")
            .args([
                "-i",
                raw_fat.to_str().unwrap(),
                fat_marker.to_str().unwrap(),
                "::DISK.TXT",
            ])
            .status()
            .unwrap()
            .success()
    );
    let overlay = tmp.join("overlay.qcow2");
    qcow2::create_overlay(&overlay, &raw_fat).unwrap();

    // 2. Build an El Torito UEFI ISO9660 image (embedded FAT ESP, matching Windows install ISOs)
    // for virtio-scsi!
    let efi_img = tmp.join("iso/efiboot.img");
    let cd_marker = tmp.join("cdrom.txt");
    std::fs::write(&cd_marker, "HELLO-FROM-VIRTIO-SCSI-ISO\r\n").unwrap();
    osbx_vmm::disk::create_sparse(&efi_img, 2 << 20).unwrap();
    assert!(
        Command::new("mformat")
            .args(["-i", efi_img.to_str().unwrap(), "::"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("mcopy")
            .args([
                "-i",
                efi_img.to_str().unwrap(),
                cd_marker.to_str().unwrap(),
                "::CDROM.TXT",
            ])
            .status()
            .unwrap()
            .success()
    );
    let iso_path = tmp.join("test.iso");
    assert!(
        Command::new("xorriso")
            .args([
                "-as",
                "mkisofs",
                "-quiet",
                "-R",
                "-J",
                "-e",
                "efiboot.img",
                "-no-emul-boot",
                "-o",
            ])
            .arg(&iso_path)
            .arg(tmp.join("iso"))
            .status()
            .unwrap()
            .success()
    );

    let mut cfg = UefiConfig::new(firmware);
    cfg.mem_mib = 512;
    cfg.cpus = 2;
    cfg.disks = vec![DiskConfig {
        path: overlay,
        read_only: false,
    }];
    cfg.cdroms = vec![iso_path];
    cfg.timeout = Some(Duration::from_secs(30));
    cfg.send_on_match = Some((
        "Shell>".into(),
        b"map -r\r\ntype fs0:\\DISK.TXT\r\ntype fs1:\\DISK.TXT\r\ntype fs0:\\CDROM.TXT\r\ntype fs1:\\CDROM.TXT\r\nreset -s\r\n"
            .to_vec(),
    ));

    let out = boot_uefi(&cfg).expect("UEFI virtio-pci boot failed");
    assert!(
        out.console.contains("HELLO-FROM-QCOW2-VIRTIO-BLK"),
        "expected OVMF to read DISK.TXT from virtio-blk PCI QCOW2 overlay:\n{}",
        out.console
    );
    assert!(
        out.console.contains("HELLO-FROM-VIRTIO-SCSI-ISO"),
        "expected OVMF to read CDROM.TXT from virtio-scsi PCI ISO9660:\n{}",
        out.console
    );
    assert_eq!(out.exit, ExitReason::GuestReset);
}

#[allow(dead_code)]
fn _unused(_: &Path) {}
