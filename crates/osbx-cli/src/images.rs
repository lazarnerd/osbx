//! Image access for the CLI, through one of two backends:
//!
//! - **native** (default; the only one on Windows): osbx's own registry client
//!   ([`osbx_image::oci`], cache in `$OSBX_HOME/oci`) and the builder VM
//!   ([`osbx_image::native`]). Needs no Docker.
//! - **docker** (Linux hosts with a running Docker daemon): `docker pull/inspect/export`,
//!   `fakeroot` and `mke2fs`, as before.
//!
//! `OSBX_BUILDER=native|docker` forces one.

use crate::state::{Launch, assets_dir, home};
use osbx_image::oci::{Client, Image};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

/// Use Docker for images?
pub fn use_docker() -> bool {
    static USE: OnceLock<bool> = OnceLock::new();
    *USE.get_or_init(|| {
        if !cfg!(target_os = "linux") {
            return false;
        }
        match std::env::var("OSBX_BUILDER").as_deref() {
            Ok("native") => false,
            Ok("docker") => true,
            _ => Command::new("docker")
                .args(["version", "--format", "{{.Server.Version}}"])
                .output()
                .is_ok_and(|o| o.status.success()),
        }
    })
}

fn client() -> &'static Client {
    static C: OnceLock<Client> = OnceLock::new();
    C.get_or_init(|| Client::new(&home().join("oci")))
}

/// Resolve (and remember for this process) an image with the native client.
fn resolved(image: &str) -> io::Result<Image> {
    static CACHE: OnceLock<Mutex<HashMap<String, Image>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(i) = cache.lock().unwrap().get(image) {
        return Ok(i.clone());
    }
    if !client().has_ref(image) {
        eprintln!("pulling {image} ...");
    }
    let i = client()
        .resolve(image, false)
        .map_err(|e| io::Error::new(e.kind(), format!("{image}: {e}")))?;
    cache.lock().unwrap().insert(image.to_owned(), i.clone());
    Ok(i)
}

fn docker_json(args: &[&str]) -> io::Result<serde_json::Value> {
    let out = Command::new("docker").args(args).output()?;
    if !out.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(io::Error::other)
}

fn docker_pull_if_missing(image: &str) -> io::Result<()> {
    if !osbx_image::image_present(image) {
        eprintln!("pulling {image} ...");
        let st = Command::new("docker")
            .args(["pull", "--platform", "linux/amd64", image])
            .status()?;
        if !st.success() {
            return Err(io::Error::other(format!("docker pull {image} failed")));
        }
    }
    Ok(())
}

/// A short stable id of `image` (pulled if needed), for cache keys.
pub fn image_id(image: &str) -> io::Result<String> {
    if !use_docker() {
        return Ok(resolved(image)?.short_id());
    }
    docker_pull_if_missing(image)?;
    let id = docker_json(&["image", "inspect", "--format", "{{json .Id}}", image])?;
    Ok(id
        .as_str()
        .unwrap_or("")
        .trim_start_matches("sha256:")
        .chars()
        .take(16)
        .collect())
}

/// Entrypoint+Cmd, Env, User and WorkingDir from the image config.
pub fn launch_of(image: &str) -> io::Result<Launch> {
    let (mut argv, env, user, workdir) = if use_docker() {
        let cfg = docker_json(&["image", "inspect", "--format", "{{json .Config}}", image])?;
        let list = |v: &serde_json::Value| -> Vec<String> {
            v.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut argv = list(&cfg["Entrypoint"]);
        argv.extend(list(&cfg["Cmd"]));
        (
            argv,
            list(&cfg["Env"]),
            cfg["User"].as_str().unwrap_or("").to_owned(),
            cfg["WorkingDir"].as_str().unwrap_or("").to_owned(),
        )
    } else {
        let c = resolved(image)?.config;
        (c.argv, c.env, c.user, c.workdir)
    };
    if argv.is_empty() {
        argv = vec!["/bin/sh".into()];
    }
    Ok(Launch {
        argv,
        env,
        user,
        workdir,
    })
}

/// A file from the image's file system, as text (`None` if absent).
pub fn read_file(image: &str, path: &str) -> io::Result<Option<String>> {
    if !use_docker() {
        let img = resolved(image)?;
        return Ok(client()
            .read_file(&img, path)?
            .map(|d| String::from_utf8_lossy(&d).into_owned()));
    }
    let out = Command::new("docker")
        .args(["create", "--platform", "linux/amd64", image, "x"])
        .output()?;
    let cid = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let tar = Command::new("docker")
        .args(["cp", &format!("{cid}:{path}"), "-"])
        .output();
    let _ = Command::new("docker").args(["rm", "-f", &cid]).output();
    Ok(first_tar_member(&tar?.stdout, |_| true))
}

/// The image's final environment for `${{ kit.env.* }}`: its `Env`, plus `HOME`/`USER` of the
/// user it declares (resolved from its /etc/passwd, as sbx@1 asks the host to do).
pub fn image_env(image: &str) -> io::Result<BTreeMap<String, String>> {
    let launch = launch_of(image)?;
    let mut env: BTreeMap<String, String> = launch
        .env
        .iter()
        .filter_map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
        })
        .collect();
    let user = launch.user.split(':').next().unwrap_or("").to_owned();
    let who = if user.is_empty() {
        "0".to_owned()
    } else {
        user
    };
    let passwd = read_file(image, "/etc/passwd")?.unwrap_or_default();
    if let Some(f) = passwd
        .lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .find(|f| f.len() >= 7 && (f[0] == who || f[2] == who))
    {
        env.entry("HOME".into()).or_insert_with(|| f[5].to_owned());
        env.entry("USER".into()).or_insert_with(|| f[0].to_owned());
    }
    Ok(env)
}

/// The kit descriptor staged in an image at `/usr/share/sandbox/kit/<stem>/kit.yaml` (pulls
/// the image if needed). `None` when the image is not a kit.
pub fn staged_descriptor(image: &str) -> io::Result<Option<String>> {
    if !use_docker() {
        let img = resolved(image)?;
        return Ok(client()
            .find_file(&img, |p| {
                p.starts_with("usr/share/sandbox/kit/") && p.ends_with("/kit.yaml")
            })?
            .map(|(_, d)| String::from_utf8_lossy(&d).into_owned()));
    }
    docker_pull_if_missing(image)?;
    let out = Command::new("docker")
        .args(["create", "--platform", "linux/amd64", image, "x"])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "docker create {image}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let cid = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let tar = Command::new("docker")
        .args(["cp", &format!("{cid}:/usr/share/sandbox/kit/."), "-"])
        .output();
    let _ = Command::new("docker").args(["rm", "-f", &cid]).output();
    let tar = tar?;
    if !tar.status.success() {
        return Ok(None);
    }
    Ok(first_tar_member(&tar.stdout, |n| n.ends_with("kit.yaml")))
}

/// First regular-file member of a tar stream whose name matches.
fn first_tar_member(data: &[u8], want: impl Fn(&str) -> bool) -> Option<String> {
    let mut off = 0;
    while off + 512 <= data.len() {
        let hdr = &data[off..off + 512];
        if hdr.iter().all(|b| *b == 0) {
            break;
        }
        let name = String::from_utf8_lossy(&hdr[..100])
            .trim_end_matches('\0')
            .to_owned();
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&hdr[124..136]).trim_matches(|c: char| c == '\0' || c == ' '),
            8,
        )
        .unwrap_or(0);
        let body = off + 512;
        if hdr[156] != b'5' && want(&name) && body + size <= data.len() {
            return String::from_utf8(data[body..body + size].to_vec()).ok();
        }
        off = body + size.div_ceil(512) * 512;
    }
    None
}

/// Build the root filesystem `out` from `image` plus kit content images `overlays`, with the
/// guest agent (and `extra` binaries) injected.
pub fn build_base(
    image: &str,
    overlays: &[String],
    out: &Path,
    agent: &Path,
    extra: &[&Path],
) -> io::Result<()> {
    if use_docker() {
        let overlay_refs: Vec<&str> = overlays.iter().map(String::as_str).collect();
        return osbx_image::build_rootfs(
            &osbx_image::RootfsSpec {
                image,
                min_size_mib: 2048,
                agent,
                ca_pem: None,
                hostname: "osbx",
                extra_bins: extra,
                overlays: &overlay_refs,
            },
            out,
        )
        .map_err(|e| io::Error::other(e.to_string()));
    }
    let base = resolved(image)?;
    let overlays = overlays
        .iter()
        .map(|o| resolved(o))
        .collect::<io::Result<Vec<_>>>()?;
    let assets = assets_dir();
    let (kernel, initrd) = (assets.join("vmlinuz"), assets.join("initramfs.cpio.gz"));
    osbx_image::native::build_rootfs_native(
        client(),
        &osbx_image::native::NativeSpec {
            image: &base,
            overlays: &overlays,
            agent,
            extra_bins: extra,
            ca_pem: None,
            hostname: "osbx",
            kernel: &kernel,
            initrd: &initrd,
            min_size_mib: 2048,
        },
        out,
        &mut |l| eprintln!("  {l}"),
    )
    .map_err(|e| io::Error::other(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tar_member() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
        h.set_size(3);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "x/kit.yaml", &b"abc"[..]).unwrap();
        let data = b.into_inner().unwrap();
        assert_eq!(
            first_tar_member(&data, |n| n.ends_with("kit.yaml")).as_deref(),
            Some("abc")
        );
        assert_eq!(first_tar_member(&data, |n| n.ends_with("nope")), None);
    }
}
