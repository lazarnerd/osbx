//! Integration tests for Phase W3 Windows agent self-sufficiency & pluggable per-volume
//! file-sharing backends (`sync`, `projfs`, `dokany`, `winfsp`, `auto`).
//!
//! * CLI / compose schema integration tests always run (no VM prerequisites).
//! * `windows_guest_w3_backends_e2e` drives the real `osbx` binary against a sealed Windows
//!   template (auto-discovered from `$OSBX_WIN_TEMPLATE`, `$OSBX_HOME/templates/win11.*`, or the
//!   Flatpak data dir) when `/dev/kvm`, OVMF, and a Windows template are present, skipping cleanly
//!   with a note in environments without a Windows template.

use std::path::PathBuf;
use std::process::Command;

fn osbx_bin() -> &'static str {
    env!("CARGO_BIN_EXE_osbx")
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "osbx-w3-it-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn compose_check_and_config_per_volume_windows_backends() {
    let dir = TempDir::new("compose");
    let home = dir.0.join("home");
    let sync_dir = dir.0.join("ws-sync");
    let projfs_dir = dir.0.join("ro-projfs");
    let winfsp_dir = dir.0.join("rw-winfsp");
    let dokany_dir = dir.0.join("rw-dokany");
    for d in [&home, &sync_dir, &projfs_dir, &winfsp_dir, &dokany_dir] {
        std::fs::create_dir_all(d).unwrap();
    }

    let compose_file = dir.0.join("osbx-compose.yml");
    let yaml = format!(
        r#"version: "1"
name: win-backends-it
sandboxes:
  win:
    sandbox_name: win-it
    template: win11
    cpus: 4
    memory: 4G
    workspace:
      path: '{sync}'
      backend: sync
    volumes:
      - '{projfs}:C:\mnt\ro-projfs:ro,projfs'
      - '{winfsp}:C:\mnt\winfsp:winfsp'
      - type: bind
        source: '{dokany}'
        target: 'C:\mnt\dokany'
        backend: dokany
"#,
        sync = sync_dir.display(),
        projfs = projfs_dir.display(),
        winfsp = winfsp_dir.display(),
        dokany = dokany_dir.display(),
    );
    std::fs::write(&compose_file, yaml).unwrap();

    let check = Command::new(osbx_bin())
        .args([
            "compose",
            "--no-user-base",
            "-f",
            compose_file.to_str().unwrap(),
            "check",
        ])
        .env("OSBX_HOME", &home)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "compose check failed: {}{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );

    let cfg = Command::new(osbx_bin())
        .args([
            "compose",
            "--no-user-base",
            "-f",
            compose_file.to_str().unwrap(),
            "config",
            "--json",
        ])
        .env("OSBX_HOME", &home)
        .output()
        .unwrap();
    assert!(
        cfg.status.success(),
        "compose config --json failed: {}",
        String::from_utf8_lossy(&cfg.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&cfg.stdout).unwrap();
    let sb = &doc["sandboxes"]["win"];
    assert_eq!(sb["workspace"]["backend"], "sync");

    let mounts = sb["mounts"].as_array().unwrap();
    assert_eq!(mounts.len(), 3);
    assert_eq!(mounts[0]["target"], r"C:\mnt\ro-projfs");
    assert_eq!(mounts[0]["read_only"], true);
    assert_eq!(mounts[0]["backend"], "projfs");
    assert_eq!(mounts[1]["target"], r"C:\mnt\winfsp");
    assert_eq!(mounts[1]["read_only"], false);
    assert_eq!(mounts[1]["backend"], "winfsp");
    assert_eq!(mounts[2]["target"], r"C:\mnt\dokany");
    assert_eq!(mounts[2]["read_only"], false);
    assert_eq!(mounts[2]["backend"], "dokany");
}

#[test]
fn cli_exposes_share_backend_and_dokany_flags_and_rejects_unknown_backend() {
    let help_create = Command::new(osbx_bin())
        .args(["create", "--help"])
        .output()
        .unwrap();
    assert!(help_create.status.success());
    assert!(String::from_utf8_lossy(&help_create.stdout).contains("--share-backend"));

    let help_win = Command::new(osbx_bin())
        .args(["windows", "build-base", "--help"])
        .output()
        .unwrap();
    assert!(help_win.status.success());
    let win_help = String::from_utf8_lossy(&help_win.stdout);
    assert!(win_help.contains("--dokany"), "{win_help}");
    assert!(win_help.contains("--winfsp"), "{win_help}");
    assert!(win_help.contains("--vtpm"), "{win_help}");

    let bad = Command::new(osbx_bin())
        .args([
            "create",
            "--name",
            "bad-backend",
            "--no-workspace",
            "--share-backend",
            "smb-not-allowed",
            "shell",
        ])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    let stderr = String::from_utf8_lossy(&bad.stderr);
    assert!(
        stderr.contains("invalid value") && stderr.contains("virtiofs-native"),
        "unexpected stderr: {stderr}"
    );
}

#[cfg(target_os = "linux")]
mod live_win11 {
    use super::*;
    use std::path::Path;
    use std::process::Output;
    use std::time::Duration;

    struct WinEnv {
        base: PathBuf,
        home: PathBuf,
        assets: PathBuf,
        sandbox_name: String,
    }

    impl WinEnv {
        fn osbx(&self, args: &[&str]) -> Output {
            Command::new(osbx_bin())
                .args(args)
                .env("OSBX_HOME", &self.home)
                .env("OSBX_ASSETS", &self.assets)
                .stdin(std::process::Stdio::null())
                .output()
                .expect("run osbx")
        }

        fn ok(&self, args: &[&str]) -> String {
            let o = self.osbx(args);
            assert!(
                o.status.success(),
                "osbx {args:?} failed ({:?}):\nstdout: {}\nstderr: {}",
                o.status.code(),
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            String::from_utf8_lossy(&o.stdout).into_owned()
        }
    }

    impl Drop for WinEnv {
        fn drop(&mut self) {
            let _ = self.osbx(&["stop", &self.sandbox_name]);
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn find_sealed_windows_template() -> Option<(PathBuf, String)> {
        if let Ok(explicit) = std::env::var("OSBX_WIN_TEMPLATE") {
            let p = PathBuf::from(&explicit);
            if p.with_extension("qcow2").exists()
                && p.with_extension("vars.fd").exists()
                && p.with_extension("json").exists()
            {
                let name = p.file_stem()?.to_string_lossy().into_owned();
                return Some((p.parent()?.to_path_buf(), name));
            }
        }
        let user_home = std::env::var_os("HOME").map(PathBuf::from)?;
        let dirs = [
            user_home.join(".local/share/osbx/templates"),
            user_home.join(".var/app/io.github.lazarnerd.osbx/data/osbx/templates"),
        ];
        // Prefer `win11` across all template dirs so `Client-ProjFS` + `winfsp` + `sync` all run.
        for name in ["win11", "win-server-2025-core"] {
            for dir in &dirs {
                if dir.join(format!("{name}.qcow2")).exists()
                    && dir.join(format!("{name}.vars.fd")).exists()
                    && dir.join(format!("{name}.json")).exists()
                {
                    return Some((dir.clone(), name.to_owned()));
                }
            }
        }
        None
    }

    fn find_windows_assets() -> Option<PathBuf> {
        let user_home = std::env::var_os("HOME").map(PathBuf::from)?;
        [
            user_home.join(".local/share/osbx/guest"),
            user_home.join(".var/app/io.github.lazarnerd.osbx/data/osbx/guest"),
            PathBuf::from("/usr/share/OVMF"),
        ]
        .into_iter()
        .find(|dir| dir.join("OVMF_CODE_4M.fd").exists() && dir.join("OVMF_VARS_4M.fd").exists())
    }

    fn find_w3_agent_exe() -> Option<PathBuf> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        [
            "target/x86_64-pc-windows-gnu/release/osbx-agent.exe",
            "target/x86_64-pc-windows-gnu/debug/osbx-agent.exe",
        ]
        .into_iter()
        .map(|rel| root.join(rel))
        .find(|p| p.exists())
    }

    #[test]
    fn windows_guest_w3_backends_e2e() {
        if !Path::new("/dev/kvm").exists() {
            eprintln!("skipping windows_guest_w3_backends_e2e: /dev/kvm unavailable");
            return;
        }
        let Some((tpl_dir, tpl_name)) = find_sealed_windows_template() else {
            eprintln!("skipping windows_guest_w3_backends_e2e: no sealed Windows template found");
            return;
        };
        let Some(assets) = find_windows_assets() else {
            eprintln!("skipping windows_guest_w3_backends_e2e: OVMF firmware not found");
            return;
        };
        let Some(agent_exe) = find_w3_agent_exe() else {
            eprintln!(
                "skipping windows_guest_w3_backends_e2e: build osbx-agent.exe (`cargo build --release -p osbx-agent --target x86_64-pc-windows-gnu`) first"
            );
            return;
        };

        let base = std::env::temp_dir().join(format!("osbx-win-w3-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let tpl_dst = home.join("templates");
        let host_sync = base.join("host-sync");
        let host_projfs = base.join("host-projfs");
        let host_winfsp = base.join("host-winfsp");
        let cp_dir = base.join("cp-dir");
        for d in [
            &tpl_dst,
            &host_sync,
            &host_projfs,
            &host_winfsp,
            &cp_dir.join("nested"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        for ext in ["qcow2", "vars.fd", "json"] {
            std::os::unix::fs::symlink(
                tpl_dir.join(format!("{tpl_name}.{ext}")),
                tpl_dst.join(format!("{tpl_name}.{ext}")),
            )
            .unwrap();
        }

        std::fs::write(host_sync.join("init-sync.txt"), "host-sync-initial\n").unwrap();
        std::fs::write(host_projfs.join("init-projfs.txt"), "host-projfs-initial\n").unwrap();
        std::fs::write(host_winfsp.join("init-winfsp.txt"), "host-winfsp-initial\n").unwrap();
        std::fs::write(
            cp_dir.join("nested/payload.txt"),
            "native-tar-dir-payload\n",
        )
        .unwrap();

        let compose_file = base.join("osbx-compose.yml");
        std::fs::write(
            &compose_file,
            format!(
                r#"version: "1"
name: win-w3-e2e
sandboxes:
  win:
    sandbox_name: win-w3-e2e
    template: {tpl_name}
    memory: 4G
    cpus: 4
    workspace:
      path: '{sync}'
      backend: sync
    volumes:
      - '{projfs}:C:\mnt\ro-projfs:ro,projfs'
      - '{winfsp}:C:\mnt\winfsp:winfsp'
"#,
                sync = host_sync.display(),
                projfs = host_projfs.display(),
                winfsp = host_winfsp.display(),
            ),
        )
        .unwrap();

        let env = WinEnv {
            base: base.clone(),
            home: home.clone(),
            assets,
            sandbox_name: "win-w3-e2e".into(),
        };

        // Boot #1: create CoW clone, hot-install current W3 osbx-agent.exe + enable Client-ProjFS.
        env.ok(&[
            "compose",
            "--no-user-base",
            "-f",
            compose_file.to_str().unwrap(),
            "up",
            "-d",
        ]);
        env.ok(&[
            "cp",
            agent_exe.to_str().unwrap(),
            r"win-w3-e2e:C:\Windows\Temp\osbx-agent-w3.exe",
        ]);
        env.ok(&[
            "exec",
            "-u",
            "SYSTEM",
            "win-w3-e2e",
            "--",
            "powershell.exe",
            "-NoProfile",
            "-Command",
            r#"Move-Item -Force "C:\Program Files\osbx\osbx-agent.exe" "C:\Program Files\osbx\osbx-agent.old.exe"; Copy-Item -Force "C:\Windows\Temp\osbx-agent-w3.exe" "C:\Program Files\osbx\osbx-agent.exe"; dism /online /enable-feature /featurename:Client-ProjFS /all /norestart"#,
        ]);
        env.ok(&["stop", "win-w3-e2e"]);

        // Boot #2: full Phase W3 self-sufficient boot with 3 simultaneous sibling backends.
        env.ok(&["start", "win-w3-e2e"]);
        let sup_log =
            std::fs::read_to_string(home.join("sandboxes/win-w3-e2e/supervisor.log")).unwrap();
        assert!(
            sup_log.contains(r"windows mount workspace -> C:\workspace (sync)"),
            "missing sync mount in supervisor.log:\n{sup_log}"
        );
        assert!(
            sup_log.contains(r"C:\mnt\ro-projfs (projfs, ro)"),
            "missing projfs ro mount in supervisor.log:\n{sup_log}"
        );
        assert!(
            sup_log.contains(r"C:\mnt\winfsp (winfsp)"),
            "missing winfsp mount in supervisor.log:\n{sup_log}"
        );

        // 1. Passwordless S4U logon for agent, Administrator, and SYSTEM
        let who_default = env.ok(&["exec", "win-w3-e2e", "--", "whoami"]);
        assert!(
            who_default.to_ascii_lowercase().contains(r"\agent"),
            "expected agent user, got {who_default:?}"
        );
        let who_admin = env.ok(&["exec", "-u", "Administrator", "win-w3-e2e", "--", "whoami"]);
        assert!(
            who_admin.to_ascii_lowercase().contains(r"\administrator"),
            "expected Administrator user, got {who_admin:?}"
        );
        let who_sys = env.ok(&["exec", "-u", "SYSTEM", "win-w3-e2e", "--", "whoami"]);
        assert!(
            who_sys
                .to_ascii_lowercase()
                .contains(r"nt authority\system"),
            "expected SYSTEM user, got {who_sys:?}"
        );

        // 2. Native CP_PUT + rename + directory copy + CP_GET (zero tar.exe / powershell.exe)
        let in_file = base.join("cp-in.txt");
        let out_file = base.join("cp-out.txt");
        std::fs::write(&in_file, "native-cp-file-roundtrip\n").unwrap();
        env.ok(&[
            "cp",
            in_file.to_str().unwrap(),
            r"win-w3-e2e:C:\Windows\Temp\renamed-it.txt",
        ]);
        env.ok(&[
            "cp",
            r"win-w3-e2e:C:\Windows\Temp\renamed-it.txt",
            out_file.to_str().unwrap(),
        ]);
        assert_eq!(
            std::fs::read_to_string(&out_file).unwrap(),
            "native-cp-file-roundtrip\n"
        );
        env.ok(&[
            "cp",
            cp_dir.to_str().unwrap(),
            r"win-w3-e2e:C:\Windows\Temp\",
        ]);
        let back_dir = base.join("cp-dir-back");
        env.ok(&[
            "cp",
            r"win-w3-e2e:C:\Windows\Temp\cp-dir",
            back_dir.to_str().unwrap(),
        ]);
        assert_eq!(
            std::fs::read_to_string(back_dir.join("nested/payload.txt")).unwrap(),
            "native-tar-dir-payload\n"
        );

        // 3. `sync` backend (RW) at C:\workspace: initial + live host->guest + live guest->host + delete
        assert_eq!(
            env.ok(&[
                "exec",
                "win-w3-e2e",
                "--",
                "cmd",
                "/c",
                r"type C:\workspace\init-sync.txt"
            ])
            .trim(),
            "host-sync-initial"
        );
        std::fs::write(host_sync.join("from-host-live.txt"), "live-from-host\n").unwrap();
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(
            env.ok(&[
                "exec",
                "win-w3-e2e",
                "--",
                "cmd",
                "/c",
                r"type C:\workspace\from-host-live.txt"
            ])
            .trim(),
            "live-from-host"
        );
        env.ok(&[
            "exec",
            "win-w3-e2e",
            "--",
            "cmd",
            "/c",
            r"echo live-from-guest > C:\workspace\from-guest-live.txt",
        ]);
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(
            std::fs::read_to_string(host_sync.join("from-guest-live.txt"))
                .unwrap()
                .trim(),
            "live-from-guest"
        );
        std::fs::remove_file(host_sync.join("from-host-live.txt")).unwrap();
        std::thread::sleep(Duration::from_secs(2));
        let gone = env.osbx(&[
            "exec",
            "win-w3-e2e",
            "--",
            "cmd",
            "/c",
            r"if exist C:\workspace\from-host-live.txt (exit 0) else (exit 1)",
        ]);
        assert!(
            !gone.status.success(),
            "host deletion should propagate to sync guest"
        );

        // 4. `projfs` backend (RO) at C:\mnt\ro-projfs: lazy read succeeds, mutation denied
        assert_eq!(
            env.ok(&[
                "exec",
                "win-w3-e2e",
                "--",
                "cmd",
                "/c",
                r"type C:\mnt\ro-projfs\init-projfs.txt"
            ])
            .trim(),
            "host-projfs-initial"
        );
        let ro_write = env.osbx(&[
            "exec",
            "win-w3-e2e",
            "--",
            "cmd",
            "/c",
            r"echo illegal > C:\mnt\ro-projfs\init-projfs.txt",
        ]);
        assert!(!ro_write.status.success(), "projfs RO must reject writes");
        assert_eq!(
            std::fs::read_to_string(host_projfs.join("init-projfs.txt")).unwrap(),
            "host-projfs-initial\n"
        );

        // 5. `winfsp` backend (RW) at C:\mnt\winfsp coexisting with `sync` and `projfs`
        assert_eq!(
            env.ok(&[
                "exec",
                "win-w3-e2e",
                "--",
                "cmd",
                "/c",
                r"type C:\mnt\winfsp\init-winfsp.txt"
            ])
            .trim(),
            "host-winfsp-initial"
        );
        env.ok(&[
            "exec",
            "win-w3-e2e",
            "--",
            "cmd",
            "/c",
            r"echo from-winfsp-guest > C:\mnt\winfsp\guest-written.txt",
        ]);
        assert_eq!(
            std::fs::read_to_string(host_winfsp.join("guest-written.txt"))
                .unwrap()
                .trim(),
            "from-winfsp-guest"
        );

        // 6. Native WinHTTP proxy configured by SETUP_CA (no netsh.exe during setup)
        let proxy = env.ok(&[
            "exec",
            "-u",
            "SYSTEM",
            "win-w3-e2e",
            "--",
            "netsh",
            "winhttp",
            "show",
            "proxy",
        ]);
        assert!(proxy.contains("127.0.0.1:3128"), "{proxy}");

        env.ok(&["stop", "win-w3-e2e"]);
    }
}
