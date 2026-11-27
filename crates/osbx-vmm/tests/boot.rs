//! Boots real guests. Needs `/dev/kvm` and the assets from `guest/build-assets.sh` (add
//! `--with-osbx` for the nested-KVM test); each test skips with a note when something is missing.

#![cfg(target_os = "linux")]

use osbx_vmm::{BootConfig, DEFAULT_CMDLINE, ExitReason, boot_linux};
use std::path::PathBuf;
use std::time::Duration;

fn assets() -> Option<(PathBuf, PathBuf)> {
    let dir = std::env::var_os("OSBX_GUEST_ASSETS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../guest/assets"));
    let (kernel, initrd) = (dir.join("vmlinuz"), dir.join("initramfs.cpio.gz"));
    if !kernel.exists() || !initrd.exists() {
        eprintln!(
            "guest assets missing in {}: run guest/build-assets.sh; skipping",
            dir.display()
        );
        return None;
    }
    if !osbx_vmm::probe().grantable() {
        eprintln!("no usable /dev/kvm: skipping");
        return None;
    }
    Some((kernel, initrd))
}

fn boot(mode: &str, timeout: u64) -> Option<osbx_vmm::BootOutcome> {
    let (kernel, initrd) = assets()?;
    let cfg = BootConfig {
        kernel,
        initrd: Some(initrd),
        cmdline: format!("{DEFAULT_CMDLINE} osbx.mode={mode}"),
        mem_mib: 256,
        cpus: 1,
        timeout: Some(Duration::from_secs(timeout)),
        echo: false,
        stdin: false,
        disks: vec![],
        vsock_cid: None,
        shares: vec![],
    };
    Some(boot_linux(&cfg).expect("boot failed"))
}

/// Removes a directory when dropped, including when a test assertion panics.
struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tail(s: &str) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(25)..].join("\n")
}

#[test]
fn linux_boots_runs_init_and_shuts_down() {
    let Some(out) = boot("test", 60) else { return };
    assert_eq!(
        out.exit,
        ExitReason::GuestReset,
        "console tail:\n{}",
        tail(&out.console)
    );
    assert!(
        out.console.contains("osbx-guest: up: kernel"),
        "{}",
        tail(&out.console)
    );
    assert!(
        out.console.contains("osbx-guest: done"),
        "{}",
        tail(&out.console)
    );
    // the guest is told it runs under KVM (paravirtual clock etc.)
    assert!(out.console.contains("Hypervisor detected: KVM"));
}

#[test]
fn guest_can_run_its_own_kvm() {
    let Some(out) = boot("kvm", 90) else { return };
    if out.console.contains("no /bin/osbx-probe in this initramfs") {
        eprintln!("initramfs built without --with-osbx; skipping");
        return;
    }
    assert!(
        out.console
            .contains("/dev/kvm present, /dev/vhost-vsock present"),
        "{}",
        tail(&out.console)
    );
    assert!(
        out.console.contains("kvm@1 grantable        : yes"),
        "{}",
        tail(&out.console)
    );
    assert!(
        out.console.contains("guest boot test           : ok"),
        "{}",
        tail(&out.console)
    );
    assert!(
        out.console.contains("KVM-IN-GUEST OK"),
        "{}",
        tail(&out.console)
    );
}

#[test]
fn a_guest_that_never_finishes_is_stopped_by_the_timeout() {
    // Without an initramfs the kernel has no root filesystem; whatever it then does, the run
    // must end within the timeout instead of hanging the host.
    let Some((kernel, _)) = assets() else { return };
    let cfg = BootConfig {
        kernel,
        initrd: None,
        cmdline: format!("{DEFAULT_CMDLINE} panic=0"),
        mem_mib: 128,
        cpus: 1,
        timeout: Some(Duration::from_secs(8)),
        echo: false,
        stdin: false,
        disks: vec![],
        vsock_cid: None,
        shares: vec![],
    };
    let started = std::time::Instant::now();
    let out = boot_linux(&cfg).expect("boot failed");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "run did not end promptly"
    );
    assert!(
        matches!(
            out.exit,
            ExitReason::Timeout | ExitReason::GuestReset | ExitReason::TripleFault
        ),
        "{:?}",
        out.exit
    );
}

/// Build an ext4 image from a directory with `mke2fs -d` (no root needed). None if unavailable.
fn make_ext4(dir: &std::path::Path, image: &std::path::Path, size: &str) -> Option<()> {
    let ok = std::process::Command::new("mke2fs")
        .args(["-q", "-t", "ext4", "-d"])
        .arg(dir)
        .arg(image)
        .arg(size)
        .status()
        .ok()?
        .success();
    ok.then_some(())
}

fn debugfs_cat(image: &std::path::Path, path: &str) -> Option<String> {
    let out = std::process::Command::new("debugfs")
        .arg("-R")
        .arg(format!("cat {path}"))
        .arg(image)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn virtio_blk_guest_reads_and_writes_a_disk() {
    let Some((kernel, initrd)) = assets() else {
        return;
    };
    let tmp = std::env::temp_dir().join(format!("osbx-blk-{}", std::process::id()));
    let _cleanup = TempDir(tmp.clone());
    std::fs::create_dir_all(tmp.join("root")).unwrap();
    std::fs::write(tmp.join("root/hello.txt"), "hello-from-the-host\n").unwrap();
    let image = tmp.join("disk.img");
    if make_ext4(&tmp.join("root"), &image, "16M").is_none()
        || debugfs_cat(&image, "/hello.txt").is_none()
    {
        eprintln!("mke2fs/debugfs unavailable: skipping");
        return;
    }
    let cfg = BootConfig {
        kernel,
        initrd: Some(initrd),
        cmdline: format!("{DEFAULT_CMDLINE} osbx.mode=blk"),
        mem_mib: 256,
        cpus: 1,
        timeout: Some(Duration::from_secs(60)),
        echo: false,
        stdin: false,
        disks: vec![osbx_vmm::DiskConfig {
            path: image.clone(),
            read_only: false,
        }],
        vsock_cid: None,
        shares: vec![],
    };
    let out = boot_linux(&cfg).expect("boot failed");
    assert_eq!(out.exit, ExitReason::GuestReset, "{}", tail(&out.console));
    assert!(
        out.console
            .contains("osbx-guest: blk read: hello-from-the-host"),
        "{}",
        tail(&out.console)
    );
    assert!(
        out.console.contains("osbx-guest: blk done"),
        "{}",
        tail(&out.console)
    );
    // the host sees what the guest wrote, straight out of the image
    assert_eq!(
        debugfs_cat(&image, "/from-guest.txt").as_deref(),
        Some("written-by-guest\n")
    );
    let zeros = debugfs_cat(&image, "/zeros").unwrap();
    assert_eq!(zeros.len(), 4 << 20, "4 MiB written by the guest");
}

mod agent {
    use super::*;
    use osbx_proto::{AGENT_PORT, ExecRequest, POWEROFF, run_exec, write_frame};
    use osbx_vmm::Vm;

    /// Boot a guest running the agent and wait until its control port answers.
    pub fn start_agent_vm() -> Option<Vm> {
        let (kernel, initrd) = assets()?;
        let cfg = BootConfig {
            kernel,
            initrd: Some(initrd),
            cmdline: format!("{DEFAULT_CMDLINE} osbx.mode=agent"),
            mem_mib: 256,
            cpus: 1,
            timeout: None,
            echo: false,
            stdin: false,
            disks: vec![],
            vsock_cid: Some(3),
            shares: vec![],
        };
        let vm = Vm::start(&cfg).expect("boot failed");
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            // a probe connection: the agent answers an empty EXEC with an error and closes
            match vm
                .vsock()
                .unwrap()
                .connect(AGENT_PORT, Duration::from_secs(2))
            {
                Ok(_) => return Some(vm),
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(300))
                }
                Err(e) => panic!("agent never came up: {e}\n{}", tail(&vm.console())),
            }
        }
    }

    pub fn exec(vm: &Vm, argv: &[&str], stdin: Option<&[u8]>) -> (i32, Vec<u8>, Vec<u8>) {
        let s = vm
            .vsock()
            .unwrap()
            .connect(AGENT_PORT, Duration::from_secs(10))
            .expect("connect to agent");
        let req = ExecRequest {
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
            ..Default::default()
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let stdin: Option<Box<dyn std::io::Read + Send>> =
            stdin.map(|d| Box::new(std::io::Cursor::new(d.to_vec())) as _);
        let r = run_exec(s.try_clone(), s, &req, stdin, &mut out, &mut err).expect("exec");
        (r.code, out, err)
    }

    pub fn poweroff(vm: &Vm) {
        let mut s = vm
            .vsock()
            .unwrap()
            .connect(AGENT_PORT, Duration::from_secs(10))
            .expect("connect");
        write_frame(&mut s, POWEROFF, &[]).unwrap();
    }
}

#[test]
fn guest_agent_runs_commands_over_vsock() {
    let Some(vm) = agent::start_agent_vm() else {
        return;
    };
    if vm.console().contains("no such file") {
        panic!("{}", tail(&vm.console()));
    }

    let (code, out, err) = agent::exec(
        &vm,
        &["/bin/sh", "-c", "echo hello; echo oops >&2; exit 7"],
        None,
    );
    assert_eq!(
        (code, out.as_slice(), err.as_slice()),
        (7, &b"hello\n"[..], &b"oops\n"[..])
    );

    // stdin is delivered and closed
    let (code, out, _) = agent::exec(&vm, &["/bin/cat"], Some(b"ping through vsock"));
    assert_eq!((code, out.as_slice()), (0, &b"ping through vsock"[..]));

    // 3 MB of output exercises credit-based flow control in both directions
    let (code, out, _) = agent::exec(
        &vm,
        &["/bin/sh", "-c", "head -c 3000000 /dev/zero | tr '\\0' x"],
        None,
    );
    assert_eq!(code, 0);
    assert_eq!(out.len(), 3_000_000);
    assert!(out.iter().all(|b| *b == b'x'));

    // and a large stdin round trip
    let big: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
    let (code, echoed, _) = agent::exec(&vm, &["/bin/cat"], Some(&big));
    assert_eq!(code, 0);
    assert!(
        echoed == big,
        "echoed data differs ({} vs {} bytes)",
        echoed.len(),
        big.len()
    );

    // a missing program is an error, not a hang
    let s = vm
        .vsock()
        .unwrap()
        .connect(osbx_proto::AGENT_PORT, Duration::from_secs(5))
        .unwrap();
    let req = osbx_proto::ExecRequest {
        argv: vec!["/no/such/program".into()],
        ..Default::default()
    };
    let r = osbx_proto::run_exec(
        s.try_clone(),
        s,
        &req,
        None,
        &mut Vec::new(),
        &mut Vec::new(),
    );
    assert!(r.is_err_and(|e| e.to_string().contains("cannot run")));

    agent::poweroff(&vm);
    let exit = vm
        .wait(Some(Duration::from_secs(20)))
        .expect("guest should power off")
        .expect("no error");
    assert_eq!(exit, ExitReason::GuestReset);
}

#[test]
fn smp_and_memory_above_the_mmio_hole() {
    let Some((kernel, initrd)) = assets() else {
        return;
    };
    let cfg = BootConfig {
        kernel,
        initrd: Some(initrd),
        cmdline: format!("{DEFAULT_CMDLINE} osbx.mode=test"),
        mem_mib: 4096, // 3 GiB low + 1 GiB above 4 GiB
        cpus: 4,
        timeout: Some(Duration::from_secs(60)),
        echo: false,
        stdin: false,
        disks: vec![],
        vsock_cid: None,
        shares: vec![],
    };
    let out = boot_linux(&cfg).expect("boot failed");
    assert_eq!(out.exit, ExitReason::GuestReset, "{}", tail(&out.console));
    assert!(
        out.console.contains(", 4 cpu, "),
        "all four vCPUs online: {}",
        tail(&out.console)
    );
    let mib: u64 = out
        .console
        .lines()
        .find_map(|l| {
            l.strip_prefix("osbx-guest: up: ")
                .and_then(|r| r.split(", ").nth(2))
                .and_then(|m| m.split_whitespace().next()?.parse().ok())
        })
        .expect("banner with RAM size");
    assert!(
        mib > 3700,
        "RAM above the hole is usable: guest sees {mib} MiB"
    );
    assert!(
        out.console.contains("BIOS-e820: [mem 0x0000000100000000-"),
        "{}",
        tail(&out.console)
    );
}
