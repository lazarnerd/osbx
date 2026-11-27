//! Pull an image, build its root disk in a builder VM, then boot a sandbox from it.
//!
//! `cargo run -p osbx-image --example native_build -- <image> <work-dir> [assets-dir]`

use osbx_image::native::{NativeSpec, build_rootfs_native};
use osbx_image::oci::Client;
use osbx_policy::{PolicySet, Preset};
use osbx_proxy::{Ca, NoCredentials};
use osbx_sandbox::{Sandbox, SandboxConfig};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(image), Some(work)) = (args.first(), args.get(1).map(PathBuf::from)) else {
        eprintln!("usage: native_build <image> <work-dir> [assets-dir]");
        std::process::exit(2);
    };
    let assets = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../guest/assets"));
    std::fs::create_dir_all(&work).unwrap();
    let client = Client::new(&work.join("oci"));
    let t = Instant::now();
    let img = client.resolve(image, false).expect("resolve");
    println!(
        "{image}: config {} ({} layers), argv {:?}, user {:?} [{:.1}s]",
        img.short_id(),
        img.layers.len(),
        img.config.argv,
        img.config.user,
        t.elapsed().as_secs_f64()
    );
    let out = work.join(format!("{}.img", img.short_id()));
    let (kernel, initrd) = (assets.join("vmlinuz"), assets.join("initramfs.cpio.gz"));
    let agent = assets.join("osbx-agent");
    let t = Instant::now();
    build_rootfs_native(
        &client,
        &NativeSpec {
            image: &img,
            overlays: &[],
            agent: &agent,
            extra_bins: &[],
            ca_pem: None,
            hostname: "osbx",
            kernel: &kernel,
            initrd: &initrd,
            min_size_mib: 2048,
        },
        &out,
        &mut |l| println!("  {l}"),
    )
    .expect("build");
    println!(
        "built {} in {:.1}s",
        out.display(),
        t.elapsed().as_secs_f64()
    );

    let t = Instant::now();
    let sb = Sandbox::start(SandboxConfig {
        name: "native-test".into(),
        kernel,
        initrd,
        disks: vec![osbx_vmm::DiskConfig {
            path: out,
            read_only: false,
        }],
        extra_cmdline: "root=/dev/vda".into(),
        shares: vec![],
        mem_mib: 1024,
        cpus: 2,
        policy: Arc::new(RwLock::new(PolicySet::new(Preset::DenyAll))),
        credentials: Arc::new(NoCredentials),
        ca: Arc::new(Ca::generate("t").unwrap()),
        env: BTreeMap::new(),
        upstream: None,
        client_tls: None,
        events: None,
        ssh_agent: None,
    })
    .expect("start");
    sb.wait_ready(Duration::from_secs(60)).expect("ready");
    println!("sandbox ready in {:.1}s", t.elapsed().as_secs_f64());
    for cmd in [
        "head -2 /etc/os-release",
        "id; hostname; ls -ln /usr/bin/passwd /etc/shadow; df -h / | tail -1",
        "su -s /bin/sh nobody -c 'id -un' 2>&1; ls /tmp >/dev/null && echo tmp-ok",
    ] {
        let o = sb.exec(&["/bin/sh", "-c", cmd], None).expect("exec");
        print!(
            "$ {cmd}\n{}{}",
            o.stdout_str(),
            String::from_utf8_lossy(&o.stderr)
        );
    }
    sb.shutdown(Duration::from_secs(5));
}
