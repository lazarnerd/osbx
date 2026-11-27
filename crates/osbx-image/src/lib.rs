//! OCI image -> ext4 root filesystem.
//!
//! Two builders: [`native`] (registry pull + a builder VM; no Docker, works on every host) and
//! [`build_rootfs`] below (Docker + fakeroot + mke2fs on the host; Linux only).
//!
//! Uses the host's `docker` only to read the image (`docker create` + `docker export`), then
//! unpacks and builds the filesystem under `fakeroot` so files keep their root ownership without
//! needing root. The guest agent, hostname and (optionally) the sandbox's CA certificate are
//! injected before the image is sealed with `mke2fs -d`.

pub mod layer;
pub mod native;
pub mod oci;

use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

/// What to build.
#[derive(Debug, Clone)]
pub struct RootfsSpec<'a> {
    /// Image reference (must be linux/amd64).
    pub image: &'a str,
    /// Minimum filesystem size in MiB; grown automatically to fit the image plus headroom.
    pub min_size_mib: u64,
    /// The static guest agent binary to install as `/usr/local/bin/osbx-agent`.
    pub agent: &'a Path,
    /// PEM certificate to trust (appended to the system bundle), if any.
    pub ca_pem: Option<&'a str>,
    /// Guest hostname.
    pub hostname: &'a str,
    /// More static binaries to install into `/usr/local/bin` (e.g. `osbx-probe`).
    pub extra_bins: &'a [&'a Path],
    /// Images whose filesystems are unpacked over the base, in order (kit mixin content).
    pub overlays: &'a [&'a str],
}

/// Build failure.
#[derive(Debug)]
pub struct ImageError(pub String);
impl std::fmt::Display for ImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ImageError {}
impl From<io::Error> for ImageError {
    fn from(e: io::Error) -> Self {
        Self(e.to_string())
    }
}

/// Tools the build needs; returns the names of any that are missing.
pub fn missing_tools() -> Vec<&'static str> {
    ["docker", "fakeroot", "tar", "mke2fs"]
        .into_iter()
        .filter(|t| {
            Command::new(t)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_err()
        })
        .collect()
}

/// Does `docker` have `image` locally?
pub fn image_present(image: &str) -> bool {
    Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The unpack-inject-seal script. Runs entirely inside one `fakeroot` session so ownership
/// recorded while unpacking is still visible to `mke2fs -d`.
const SCRIPT: &str = r#"
set -eu
ROOT="$1"; OUT="$2"; CID="$3"; MIN="$4"; AGENT="$5"; HOSTNAME="$6"; CA="$7"; EXTRA="$8"; OVERLAYS="$9"
mkdir -p "$ROOT"
docker export "$CID" | tar -x -p --same-owner --numeric-owner -C "$ROOT"
for o in $OVERLAYS; do
  docker export "$o" | tar -x -p --same-owner --numeric-owner -C "$ROOT"
done
mkdir -p "$ROOT/proc" "$ROOT/sys" "$ROOT/dev" "$ROOT/tmp" "$ROOT/run" "$ROOT/mnt" "$ROOT/etc" "$ROOT/usr/local/bin"
chmod 1777 "$ROOT/tmp"
install -m 0755 "$AGENT" "$ROOT/usr/local/bin/osbx-agent"
for b in $EXTRA; do install -m 0755 "$b" "$ROOT/usr/local/bin/$(basename "$b")"; done
printf '%s\n' "$HOSTNAME" > "$ROOT/etc/hostname"
if [ -n "$CA" ]; then
  mkdir -p "$ROOT/usr/local/share/ca-certificates"
  cp "$CA" "$ROOT/usr/local/share/ca-certificates/osbx-ca.crt"
  for b in etc/ssl/certs/ca-certificates.crt etc/pki/tls/certs/ca-bundle.crt etc/ssl/cert.pem; do
    [ -f "$ROOT/$b" ] && cat "$CA" >> "$ROOT/$b"
  done
fi
USED=$(du -sm "$ROOT" | cut -f1)
SIZE=$(( USED * 3 / 2 + 256 ))
[ "$SIZE" -lt "$MIN" ] && SIZE="$MIN"
rm -f "$OUT"
mke2fs -q -F -t ext4 -L osbx-root -d "$ROOT" "$OUT" "${SIZE}M"
"#;

/// Build `out` (a raw ext4 image) from `spec`.
pub fn build_rootfs(spec: &RootfsSpec<'_>, out: &Path) -> Result<(), ImageError> {
    let missing = missing_tools();
    if !missing.is_empty() {
        return Err(ImageError(format!("missing tools: {}", missing.join(", "))));
    }
    let work = std::env::temp_dir().join(format!(
        "osbx-rootfs-{}-{}",
        std::process::id(),
        spec.hostname
    ));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work)?;
    let result = (|| {
        let create = Command::new("docker")
            .args(["create", "--platform", "linux/amd64", spec.image, "x"])
            .output()?;
        if !create.status.success() {
            return Err(ImageError(format!(
                "docker create {}: {}",
                spec.image,
                String::from_utf8_lossy(&create.stderr).trim()
            )));
        }
        let cid = String::from_utf8_lossy(&create.stdout).trim().to_owned();
        let ca_file = match spec.ca_pem {
            Some(pem) => {
                let p = work.join("ca.pem");
                std::fs::write(&p, pem)?;
                p.to_string_lossy().into_owned()
            }
            None => String::new(),
        };
        let abs_out = if out.is_absolute() {
            out.to_path_buf()
        } else {
            std::env::current_dir()?.join(out)
        };
        // kit mixin images: one stopped container each, exported over the base in the script
        let mut overlay_ids = Vec::new();
        for img in spec.overlays {
            let o = Command::new("docker")
                .args(["create", "--platform", "linux/amd64", img, "x"])
                .output()?;
            if !o.status.success() {
                for id in overlay_ids.iter().chain(std::iter::once(&cid)) {
                    let _ = Command::new("docker").args(["rm", "-f", id]).output();
                }
                return Err(ImageError(format!(
                    "docker create {img}: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                )));
            }
            overlay_ids.push(String::from_utf8_lossy(&o.stdout).trim().to_owned());
        }
        let extra: Vec<String> = spec
            .extra_bins
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let run = Command::new("fakeroot")
            .arg("--")
            .arg("sh")
            .arg("-c")
            .arg(SCRIPT)
            .arg("osbx-rootfs")
            .arg(work.join("root"))
            .arg(&abs_out)
            .arg(&cid)
            .arg(spec.min_size_mib.to_string())
            .arg(spec.agent)
            .arg(spec.hostname)
            .arg(&ca_file)
            .arg(extra.join(" "))
            .arg(overlay_ids.join(" "))
            .output();
        for id in overlay_ids.iter().chain(std::iter::once(&cid)) {
            let _ = Command::new("docker")
                .args(["rm", "-f", id])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let run = run?;
        if !run.status.success() {
            return Err(ImageError(format!(
                "building the filesystem failed: {}",
                String::from_utf8_lossy(&run.stderr).trim()
            )));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&work);
    result
}
