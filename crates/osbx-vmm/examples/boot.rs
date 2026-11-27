//! Boot the guest assets directly on the host hypervisor and stream the console.
//!
//! `cargo run -p osbx-vmm --example boot -- <assets-dir> [mode] [cpus] [mem-mib] [extra kernel args...]`
//! (`mode` is the guest init's `osbx.mode`: test, kvm, blk, shell, agent; default test).

#[cfg(not(any(target_os = "linux", windows)))]
fn main() {
    eprintln!("boot example needs a Linux (KVM) or Windows (WHP) host");
    std::process::exit(1);
}

#[cfg(any(target_os = "linux", windows))]
fn main() {
    use osbx_vmm::{BootConfig, DEFAULT_CMDLINE, boot_linux};
    use std::path::PathBuf;
    use std::time::Duration;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(assets) = args.first().map(PathBuf::from) else {
        eprintln!("usage: boot <assets-dir> [mode] [cpus] [mem-mib] [extra kernel args...]");
        std::process::exit(2);
    };
    let mode = args.get(1).map_or("test", String::as_str);
    let cpus = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    let mem_mib = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(512);
    let extra = args.get(4..).map(|a| a.join(" ")).unwrap_or_default();
    let cfg = BootConfig {
        kernel: assets.join("vmlinuz"),
        initrd: Some(assets.join("initramfs.cpio.gz")),
        cmdline: format!("{DEFAULT_CMDLINE} osbx.mode={mode} {extra}"),
        mem_mib,
        cpus,
        timeout: Some(Duration::from_secs(if mode == "shell" {
            3600
        } else {
            120
        })),
        echo: true,
        stdin: mode == "shell",
        disks: vec![],
        vsock_cid: None,
        shares: vec![],
    };
    let t = std::time::Instant::now();
    // OSBX_BOOT_PARALLEL=n: boot n more copies at once in this process (backend stress test)
    let extra: usize = std::env::var("OSBX_BOOT_PARALLEL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let others: Vec<_> = (0..extra)
        .map(|i| {
            let mut c = cfg.clone();
            c.echo = false;
            std::thread::spawn(move || match boot_linux(&c) {
                Ok(o) => eprintln!("[parallel {i}] exit: {:?}", o.exit),
                Err(e) => eprintln!("[parallel {i}] error: {e}"),
            })
        })
        .collect();
    let main = boot_linux(&cfg);
    for o in others {
        let _ = o.join();
    }
    match main {
        Ok(out) => eprintln!(
            "\n[boot example] exit: {:?} after {:.1}s",
            out.exit,
            t.elapsed().as_secs_f64()
        ),
        Err(e) => {
            eprintln!("\n[boot example] error: {e}");
            std::process::exit(1);
        }
    }
}
