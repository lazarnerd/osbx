//! Boot an EDK2 OVMF UEFI image inside `osbx-vmm` on Linux/KVM.
//!
//! `cargo run -p osbx-vmm --example uefi_boot -- [OVMF.fd] [timeout-secs] [--cdrom ISO]... [--disk IMG]... [--mem MiB] [--cpus N] [--interactive]`

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("uefi_boot example currently requires a Linux/KVM host");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    use osbx_vmm::{DiskConfig, UefiConfig, UefiVm};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut firmware = PathBuf::from("/usr/share/ovmf/OVMF.fd");
    let mut timeout_secs: u64 = 15;
    let mut mem_mib: usize = 512;
    let mut cpus: u8 = 2;
    let mut interactive = false;
    let mut cdroms = Vec::new();
    let mut disks = Vec::new();
    let mut fb_out: Option<PathBuf> = None;
    let mut pos = 0usize;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--cdrom" if i + 1 < args.len() => {
                cdroms.push(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--disk" if i + 1 < args.len() => {
                disks.push(DiskConfig {
                    path: PathBuf::from(&args[i + 1]),
                    read_only: false,
                });
                i += 2;
            }
            "--mem" if i + 1 < args.len() => {
                mem_mib = args[i + 1].parse().unwrap_or(512);
                i += 2;
            }
            "--cpus" if i + 1 < args.len() => {
                cpus = args[i + 1].parse().unwrap_or(2);
                i += 2;
            }
            "--fb" if i + 1 < args.len() => {
                fb_out = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--interactive" => {
                interactive = true;
                i += 1;
            }
            other => {
                if pos == 0 {
                    firmware = PathBuf::from(other);
                } else if pos == 1 {
                    timeout_secs = other.parse().unwrap_or(15);
                }
                pos += 1;
                i += 1;
            }
        }
    }
    let debug = std::env::var_os("OSBX_UEFI_DEBUG").is_some();

    let mut cfg = UefiConfig::new(firmware);
    cfg.mem_mib = mem_mib;
    cfg.cpus = cpus;
    cfg.disks = disks;
    cfg.cdroms = cdroms;
    cfg.vsock_cid = Some(3);
    cfg.timeout = Some(Duration::from_secs(timeout_secs));
    cfg.echo = true;
    cfg.echo_debugcon = debug;
    cfg.stdin = interactive;
    if !interactive {
        if !cfg.cdroms.is_empty() {
            // Send Enter after `BdsDxe` launches the CD-ROM boot loader (`cdboot.efi`).
            cfg.send_on_match = None;
        } else if cfg.disks.is_empty() {
            cfg.send_on_match = Some(("Shell>".into(), b"ver\r\nreset -s\r\n".to_vec()));
        }
    }

    let started = Instant::now();
    let vm = match UefiVm::start(&cfg) {
        Ok(vm) => vm,
        Err(e) => {
            eprintln!("[uefi_boot] error: {e}");
            std::process::exit(1);
        }
    };
    if !interactive && !cfg.cdroms.is_empty() {
        // Wait for `BdsDxe: starting Boot` then tap Enter a few times for `cdboot.efi`'s
        // "Press any key to boot from CD or DVD..." prompt (drawn on GOP when VGA is active).
        let deadline = started + Duration::from_secs(15);
        while Instant::now() < deadline && !vm.finished() {
            if vm.console().contains("BdsDxe: starting Boot") {
                for _ in 0..5 {
                    std::thread::sleep(Duration::from_millis(700));
                    if vm.finished() {
                        break;
                    }
                    vm.send_serial(b"\r");
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let remaining = cfg.timeout.map(|t| t.saturating_sub(started.elapsed()));
    let exit = match vm.wait(remaining) {
        Some(Ok(r)) => r,
        Some(Err(e)) => {
            eprintln!("[uefi_boot] error: {e}");
            std::process::exit(1);
        }
        None => {
            if let Some(p) = &fb_out
                && let Some((w, h, bpp, data)) = vm.framebuffer()
            {
                let mut ppm = format!("P6\n{w} {h}\n255\n").into_bytes();
                let stride = usize::from(bpp / 8);
                if stride >= 3 {
                    for px in data.chunks_exact(stride) {
                        // Bochs VBE 32bpp is BGRX
                        ppm.extend_from_slice(&[px[2], px[1], px[0]]);
                    }
                    let _ = std::fs::write(p, &ppm);
                    eprintln!(
                        "\n[uefi_boot] saved framebuffer ({w}x{h}x{bpp}) to {}",
                        p.display()
                    );
                }
            }
            vm.stop()
        }
    };
    let console = vm.console();
    let debugcon = vm.debugcon();
    if debug {
        eprintln!("\n[uefi_boot] raw serial: {:?}", console);
    }
    eprintln!(
        "\n[uefi_boot] exit: {:?} after {:.2}s (serial={} bytes, debugcon={} bytes)",
        exit,
        started.elapsed().as_secs_f64(),
        console.len(),
        debugcon.len()
    );
}
