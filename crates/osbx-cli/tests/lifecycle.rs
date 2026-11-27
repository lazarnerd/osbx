//! End-to-end: drive the real `osbx` binary through the sandbox lifecycle.
//! Needs /dev/kvm, guest assets (guest/build-assets.sh --with-osbx), docker + fakeroot + mke2fs,
//! git, and a local ubuntu:24.04 image; skips with a note otherwise. No network is used.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Env {
    home: PathBuf,
    assets: PathBuf,
}

impl Drop for Env {
    fn drop(&mut self) {
        // stop anything still running, then remove the state dir
        for name in ["t-direct", "t-clone"] {
            let _ = self.osbx(&["rm", "-f", name]);
        }
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

impl Env {
    fn osbx(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_osbx"))
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
            "osbx {args:?} failed: {}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    }
}

fn have(cmd: &str, arg: &str) -> bool {
    Command::new(cmd)
        .arg(arg)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn setup(tag: &str) -> Option<(Env, PathBuf)> {
    let assets = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../guest/assets");
    let ready = assets.join("osbx-agent").exists()
        && Path::new("/dev/kvm").exists()
        && have("git", "--version")
        && have("fakeroot", "--version")
        && Command::new("docker")
            .args(["image", "inspect", "ubuntu:24.04"])
            .output()
            .is_ok_and(|o| o.status.success());
    if !ready {
        eprintln!(
            "prerequisites missing (kvm, assets, docker image ubuntu:24.04, fakeroot, git): skipping"
        );
        return None;
    }
    let base = std::env::temp_dir().join(format!("osbx-cli-{tag}-{}", std::process::id()));
    let repo = base.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("README.md"), "original\n").unwrap();
    let git = |args: &[&str]| {
        assert!(
            Command::new("git")
                .args(args)
                .current_dir(&repo)
                .output()
                .unwrap()
                .status
                .success(),
            "git {args:?}"
        )
    };
    git(&["init", "-q"]);
    git(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.invalid",
        "add",
        ".",
    ]);
    git(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.invalid",
        "commit",
        "-q",
        "-m",
        "init",
    ]);
    Some((
        Env {
            home: base.join("home"),
            assets,
        },
        repo,
    ))
}

#[test]
fn sandbox_lifecycle_through_the_cli() {
    let Some((env, repo)) = setup("lifecycle") else {
        return;
    };
    let repo_s = repo.to_string_lossy().into_owned();

    // ---- direct mode: the repository is shared read-write at the same path ----
    assert_eq!(
        env.ok(&[
            "create", "--name", "t-direct", "--mem", "512", "-w", &repo_s, "shell"
        ])
        .trim(),
        "t-direct"
    );
    assert!(env.ok(&["ls"]).contains("t-direct"));
    env.ok(&["start", "t-direct"]);
    assert!(env.ok(&["ls"]).contains("running"));
    let out = env.ok(&[
        "exec",
        "t-direct",
        "--",
        "sh",
        "-c",
        "pwd; hostname; cat README.md; echo from-guest > guest.txt",
    ]);
    assert_eq!(out, format!("{repo_s}\nt-direct\noriginal\n"));
    assert_eq!(
        std::fs::read_to_string(repo.join("guest.txt")).unwrap(),
        "from-guest\n"
    );
    std::fs::remove_file(repo.join("guest.txt")).unwrap();

    // exit status and stderr pass through
    let o = env.osbx(&[
        "exec",
        "t-direct",
        "--",
        "sh",
        "-c",
        "echo oops >&2; exit 3",
    ]);
    assert_eq!(
        (o.status.code(), String::from_utf8_lossy(&o.stderr).trim()),
        (Some(3), "oops")
    );

    // cp in both directions
    let src = repo.parent().unwrap().join("payload");
    std::fs::create_dir_all(src.join("d")).unwrap();
    std::fs::write(src.join("d/f"), "payload\n").unwrap();
    env.ok(&["cp", &src.to_string_lossy(), "t-direct:/root/"]);
    assert_eq!(
        env.ok(&["exec", "t-direct", "--", "cat", "/root/payload/d/f"]),
        "payload\n"
    );
    let back = repo.parent().unwrap().join("back");
    std::fs::create_dir_all(&back).unwrap();
    env.ok(&[
        "cp",
        "t-direct:/etc/hostname",
        &back.join("hn").to_string_lossy(),
    ]);
    assert_eq!(
        std::fs::read_to_string(back.join("hn")).unwrap(),
        "t-direct\n"
    );

    // the root disk survives a stop/start
    env.ok(&[
        "exec",
        "t-direct",
        "--",
        "sh",
        "-c",
        "echo kept > /root/persist",
    ]);
    env.ok(&["stop", "t-direct"]);
    assert!(env.ok(&["ls"]).contains("stopped"));
    env.ok(&["start", "t-direct"]);
    assert_eq!(
        env.ok(&["exec", "t-direct", "--", "cat", "/root/persist"]),
        "kept\n"
    );

    // a running sandbox is not removed without --force
    assert!(!env.osbx(&["rm", "t-direct"]).status.success());
    env.ok(&["rm", "-f", "t-direct"]);
    assert!(!env.ok(&["ls"]).contains("t-direct"));

    // ---- clone mode: private clone at the workspace path, original read-only ----
    env.ok(&[
        "create", "--name", "t-clone", "--mem", "512", "--clone", "-w", &repo_s, "shell",
    ]);
    let remotes = String::from_utf8(
        Command::new("git")
            .args(["remote"])
            .current_dir(&repo)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    assert!(remotes.contains("sandbox-t-clone"), "{remotes}");
    env.ok(&["start", "t-clone"]);
    let out = env.ok(&[
        "exec",
        "t-clone",
        "--",
        "sh",
        "-c",
        "cat README.md; echo changed-in-sandbox > README.md; cat /run/sandbox/source/README.md",
    ]);
    assert_eq!(out, "original\noriginal\n");
    assert_eq!(
        std::fs::read_to_string(repo.join("README.md")).unwrap(),
        "original\n",
        "the host repository must be untouched"
    );
    let ro = env.osbx(&[
        "exec",
        "t-clone",
        "--",
        "sh",
        "-c",
        "touch /run/sandbox/source/x",
    ]);
    assert!(!ro.status.success(), "the source share must be read-only");
    assert!(!repo.join("x").exists());
    env.ok(&["rm", "-f", "t-clone"]);
    let remotes = String::from_utf8(
        Command::new("git")
            .args(["remote"])
            .current_dir(&repo)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    assert!(
        !remotes.contains("sandbox-t-clone"),
        "rm removes the remote: {remotes}"
    );
    let _ = std::fs::remove_dir_all(repo.parent().unwrap());
}

#[test]
fn kits_compose_and_apply_through_the_cli() {
    let Some((env, repo)) = setup("kits") else {
        return;
    };
    let base = repo.parent().unwrap().to_path_buf();
    let kvm = Command::new(env!("CARGO_BIN_EXE_osbx"))
        .args(["vmm", "probe", "--require-nested"])
        .output()
        .unwrap()
        .status
        .success();
    let kit_dir = base.join("kits/testkit");
    std::fs::create_dir_all(&kit_dir).unwrap();
    std::fs::write(
        kit_dir.join("testkit.yaml"),
        format!(
            "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n  - type: com.docker.sandbox/host-mount@1\n    config: {{path: /data/shared}}\n  - type: com.docker.sandbox/lifecycle@1\n    config:\n      install: [{{command: \"echo once >> /root/installed\"}}]\n      startup: [{{command: [/bin/sh, -c, \"echo boot >> /root/started\"]}}]\n      files: [{{path: /etc/kit/hello, content: \"hi from kit\\n\", mode: \"0640\"}}]\n  - type: com.docker.sandbox/agent-context@2\n    optional: true\n    config: {{content: skipped}}\n{}",
            if kvm { "  - type: com.docker.sandbox/kvm@1\n" } else { "" }
        ),
    )
    .unwrap();
    // a kit that cannot compose is refused at create, naming the problem
    let bad = base.join("kits/needy");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(
        bad.join("needy.yaml"),
        "schemaVersion: \"3\"\nkind: mixin\nrequires: [claude]\n",
    )
    .unwrap();
    let o = env.osbx(&[
        "create",
        "--name",
        "t-bad",
        "--no-workspace",
        "--kit",
        &bad.to_string_lossy(),
        "shell",
    ]);
    assert!(
        !o.status.success() && String::from_utf8_lossy(&o.stderr).contains("claude"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );

    let kit = kit_dir.to_string_lossy().into_owned();
    env.ok(&[
        "create",
        "--name",
        "t-direct",
        "--mem",
        "512",
        "--no-workspace",
        "--kit",
        &kit,
        "shell",
    ]);
    env.ok(&["start", "t-direct"]);
    let out = env.ok(&["exec", "t-direct", "--", "sh", "-c", "cat /root/installed /root/started /etc/kit/hello; stat -c %a /etc/kit/hello; echo m > /data/shared/x"]);
    assert_eq!(out, "once\nboot\nhi from kit\n640\n");
    assert_eq!(
        std::fs::read_to_string(env.home.join("kit-mounts/testkit/data_shared/x")).unwrap(),
        "m\n"
    );
    if kvm {
        let probe = env.ok(&[
            "exec",
            "-u",
            "ubuntu",
            "t-direct",
            "--",
            "osbx-probe",
            "--run-guest",
            "--require-nested",
        ]);
        assert!(probe.contains("guest boot test           : ok"), "{probe}");
    } else {
        eprintln!("host cannot nest: kvm@1 part skipped");
    }
    // install hooks run once per sandbox, startup hooks every boot
    env.ok(&["stop", "t-direct"]);
    env.ok(&["start", "t-direct"]);
    assert_eq!(
        env.ok(&[
            "exec",
            "t-direct",
            "--",
            "sh",
            "-c",
            "wc -l < /root/installed; wc -l < /root/started"
        ]),
        "1\n2\n"
    );
    env.ok(&["rm", "-f", "t-direct"]);
    let _ = std::fs::remove_dir_all(&base);
}
