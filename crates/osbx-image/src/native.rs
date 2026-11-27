//! Build a root filesystem without Docker or fakeroot: a short-lived builder VM (the osbx
//! initramfs, agent mode, no root) gets a blank sparse disk, makes an ext4 file system on it and
//! extracts the image layers streamed from the host, as real root. Works on every host osbx
//! runs on.
//!
//! Per layer: the host scans for whiteouts, the guest deletes what they hide, the decompressed
//! layer is streamed into `tar -x`, and the whiteout marker files are removed again.

use crate::ImageError;
use crate::layer::{deletion_list, whiteouts};
use crate::oci::{Client, Image};
use osbx_policy::{PolicySet, Preset};
use osbx_proto::ExecRequest;
use osbx_proxy::{Ca, NoCredentials};
use osbx_sandbox::{Sandbox, SandboxConfig};
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// What to build.
pub struct NativeSpec<'a> {
    /// The base image (resolved).
    pub image: &'a Image,
    /// Images whose layers are applied over the base, in order (kit content).
    pub overlays: &'a [Image],
    /// Static guest agent, installed as `/usr/local/bin/osbx-agent`.
    pub agent: &'a Path,
    /// More static binaries for `/usr/local/bin`.
    pub extra_bins: &'a [&'a Path],
    /// PEM certificate appended to the system trust bundles, if any.
    pub ca_pem: Option<&'a str>,
    /// Guest hostname.
    pub hostname: &'a str,
    /// Guest kernel and initramfs (with e2fsprogs) for the builder VM.
    pub kernel: &'a Path,
    /// See `kernel`.
    pub initrd: &'a Path,
    /// Minimum disk size in MiB.
    pub min_size_mib: u64,
}

const MNT: &str = "/mnt/osbx-root";

fn sh(sb: &Sandbox, script: &str, stdin: Option<Box<dyn Read + Send>>) -> Result<(), ImageError> {
    let req = ExecRequest {
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        env: BTreeMap::from([("PATH".to_owned(), "/bin:/sbin".to_owned())]),
        ..Default::default()
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = sb.exec_streaming(req, stdin, &mut out, &mut err)?;
    if code != 0 {
        let first = script.lines().next().unwrap_or("").trim();
        return Err(ImageError(format!(
            "builder step `{first}` failed ({code}): {}{}",
            String::from_utf8_lossy(&err).trim(),
            String::from_utf8_lossy(&out).trim()
        )));
    }
    Ok(())
}

/// A tar with the osbx files every root filesystem gets.
fn injection_tar(spec: &NativeSpec<'_>) -> io::Result<Vec<u8>> {
    let mut b = tar::Builder::new(Vec::new());
    let mut add = |path: &str, mode: u32, data: &[u8]| -> io::Result<()> {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(mode);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(0);
        h.set_cksum();
        b.append_data(&mut h, path, data)
    };
    add(
        "usr/local/bin/osbx-agent",
        0o755,
        &std::fs::read(spec.agent)?,
    )?;
    for bin in spec.extra_bins {
        let name = bin
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| io::Error::other("extra binary without a file name"))?;
        add(
            &format!("usr/local/bin/{name}"),
            0o755,
            &std::fs::read(bin)?,
        )?;
    }
    add(
        "etc/hostname",
        0o644,
        format!("{}\n", spec.hostname).as_bytes(),
    )?;
    if let Some(pem) = spec.ca_pem {
        add(
            "usr/local/share/ca-certificates/osbx-ca.crt",
            0o644,
            pem.as_bytes(),
        )?;
    }
    b.into_inner()
}

/// Build `out` (a raw ext4 image) from `spec`, fetching blobs through `client`. `log` receives
/// progress lines.
pub fn build_rootfs_native(
    client: &Client,
    spec: &NativeSpec<'_>,
    out: &Path,
    log: &mut dyn FnMut(&str),
) -> Result<(), ImageError> {
    let images: Vec<&Image> = std::iter::once(spec.image)
        .chain(spec.overlays.iter())
        .collect();
    let mut compressed = 0u64;
    let mut layers = Vec::new();
    for img in &images {
        for l in &img.layers {
            if !client.layer_path(img, l).is_ok_and(|p| p.exists()) {
                log(&format!("fetching {} ({} MiB)", l.digest, l.size >> 20));
            }
            let path = client.layer_path(img, l)?;
            compressed += l.size;
            layers.push((path, l.media_type.clone()));
        }
    }
    // Room for the unpacked layers (compression is typically 2-4x) plus headroom; the disk is
    // sparse, and sandboxes grow it further at boot when asked to.
    let size_mib = ((compressed * 4) >> 20)
        .saturating_add(1024)
        .max(spec.min_size_mib);
    osbx_vmm::disk::create_sparse(out, size_mib << 20)?;

    log(&format!(
        "starting builder VM ({size_mib} MiB disk, {} layers)",
        layers.len()
    ));
    let sb = Sandbox::start(SandboxConfig {
        name: "osbx-builder".into(),
        kernel: spec.kernel.to_path_buf(),
        initrd: spec.initrd.to_path_buf(),
        disks: vec![osbx_vmm::DiskConfig {
            path: out.to_path_buf(),
            read_only: false,
        }],
        extra_cmdline: String::new(),
        shares: vec![],
        mem_mib: 512,
        cpus: 2,
        policy: Arc::new(RwLock::new(PolicySet::new(Preset::DenyAll))),
        credentials: Arc::new(NoCredentials),
        ca: Arc::new(Ca::generate("osbx builder").map_err(|e| ImageError(e.to_string()))?),
        env: BTreeMap::new(),
        upstream: None,
        client_tls: None,
        events: None,
    })?;
    let result = (|| {
        sb.wait_ready(Duration::from_secs(60))?;
        sh(
            &sb,
            &format!(
                "[ -x /sbin/mke2fs ] || {{ echo 'this initramfs has no mke2fs: rebuild guest assets (guest/build-assets.sh)'; exit 3; }}\n\
                 /sbin/mke2fs -q -F -t ext4 -L osbx-root -E assume_storage_prezeroed=1 /dev/vda 2>/dev/null || /sbin/mke2fs -q -F -t ext4 -L osbx-root /dev/vda\n\
                 mkdir -p {MNT} && mount -t ext4 /dev/vda {MNT}"
            ),
            None,
        )?;
        for (i, (blob, media)) in layers.iter().enumerate() {
            let w = whiteouts(blob, media)?;
            if !w.is_empty() {
                sh(
                    &sb,
                    &format!(
                        "while IFS= read -r l; do p=\"{MNT}/${{l#? }}\"; case \"$l\" in\n\
                         R*) rm -rf -- \"$p\" ;;\n\
                         O*) [ -d \"$p\" ] && find \"$p\" -mindepth 1 -maxdepth 1 -exec rm -rf -- {{}} + ;;\n\
                         esac; done"
                    ),
                    Some(Box::new(io::Cursor::new(deletion_list(&w).into_bytes()))),
                )?;
            }
            sh(
                &sb,
                &format!("tar -x -p -f - -C {MNT}"),
                Some(crate::layer::open(blob, media)?),
            )?;
            if !w.markers.is_empty() {
                let list: String = w.markers.iter().map(|m| format!("{m}\n")).collect();
                sh(
                    &sb,
                    &format!("while IFS= read -r m; do rm -f -- \"{MNT}/$m\"; done"),
                    Some(Box::new(io::Cursor::new(list.into_bytes()))),
                )?;
            }
            log(&format!("layer {}/{} extracted", i + 1, layers.len()));
        }
        sh(
            &sb,
            &format!("tar -x -p -f - -C {MNT}"),
            Some(Box::new(io::Cursor::new(injection_tar(spec)?))),
        )?;
        let ca_append = if spec.ca_pem.is_some() {
            format!(
                "for b in etc/ssl/certs/ca-certificates.crt etc/pki/tls/certs/ca-bundle.crt etc/ssl/cert.pem; do\n\
                   [ -f {MNT}/$b ] && cat {MNT}/usr/local/share/ca-certificates/osbx-ca.crt >> {MNT}/$b\n\
                 done\n"
            )
        } else {
            String::new()
        };
        sh(
            &sb,
            &format!(
                "cd {MNT} && mkdir -p proc sys dev tmp run mnt etc usr/local/bin && chmod 1777 tmp\n\
                 {ca_append}cd / && sync && umount {MNT}"
            ),
            None,
        )?;
        Ok::<(), ImageError>(())
    })();
    sb.shutdown(Duration::from_secs(10));
    if result.is_err() {
        let _ = std::fs::remove_file(out);
    }
    result
}
