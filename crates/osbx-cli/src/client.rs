//! Client side of the supervisor protocol: interactive exec and file copy.

use crate::state::{GuestOs, Record, control_socket};
pub use crate::sys::is_tty;
use crate::sys::{LocalStream as UnixStream, RawMode, term_size};
use osbx_proto::{
    CHUNK, ERROR, EXEC, EXIT, ExecRequest, RESIZE, STDERR, STDIN, STDIN_EOF, STDOUT, read_frame,
    resize_payload, write_frame,
};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How to attach to a command.
#[derive(Debug, Clone, Copy)]
pub struct Attach {
    /// Forward our stdin.
    pub stdin: bool,
    /// Allocate a terminal (implies raw mode locally if stdin is a tty).
    pub tty: bool,
}

/// Run `req` in sandbox `name`. Output goes to our stdout/stderr; returns the exit status.
pub fn exec(name: &str, mut req: ExecRequest, attach: Attach) -> io::Result<i32> {
    let mut s = UnixStream::connect(control_socket(name))
        .map_err(|e| io::Error::new(e.kind(), format!("sandbox {name:?} is not running ({e})")))?;
    writeln!(s, "{{\"op\":\"exec\"}}")?;
    if attach.tty {
        req.tty = true;
        if let Some((r, c)) = term_size() {
            req.rows = r;
            req.cols = c;
        }
    }
    write_frame(
        &mut s,
        EXEC,
        &serde_json::to_vec(&req).map_err(io::Error::other)?,
    )?;
    let writer = Arc::new(Mutex::new(s.try_clone()?));
    let done = Arc::new(AtomicBool::new(false));
    let _raw = if attach.tty && is_tty(0) {
        RawMode::enter()
    } else {
        None
    };

    if attach.stdin {
        let w = writer.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; CHUNK];
            let mut stdin = io::stdin();
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if write_frame(&mut *w.lock().unwrap(), STDIN, &buf[..n]).is_err() {
                            return;
                        }
                    }
                }
            }
            let _ = write_frame(&mut *w.lock().unwrap(), STDIN_EOF, &[]);
        });
    } else {
        write_frame(&mut *writer.lock().unwrap(), STDIN_EOF, &[])?;
    }
    if attach.tty {
        let (w, done) = (writer.clone(), done.clone());
        std::thread::spawn(move || {
            let mut last = term_size();
            while !done.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(250));
                let now = term_size();
                if now != last
                    && let Some((r, c)) = now
                {
                    let _ = write_frame(&mut *w.lock().unwrap(), RESIZE, &resize_payload(r, c));
                }
                last = now;
            }
        });
    }

    let (mut out, mut err) = (io::stdout(), io::stderr());
    let code = loop {
        match read_frame(&mut s)? {
            Some((STDOUT, d)) => {
                out.write_all(&d)?;
                out.flush()?;
            }
            Some((STDERR, d)) => {
                err.write_all(&d)?;
                err.flush()?;
            }
            Some((EXIT, d)) if d.len() == 4 => break i32::from_le_bytes(d.try_into().unwrap()),
            Some((ERROR, d)) => {
                done.store(true, Ordering::SeqCst);
                return Err(io::Error::other(String::from_utf8_lossy(&d).into_owned()));
            }
            Some(_) => {}
            None => break 255,
        }
    };
    done.store(true, Ordering::SeqCst);
    Ok(code)
}

/// Run a command in the guest with `input` as stdin and return its stdout (for cp and helpers).
fn exec_capture(
    name: &str,
    argv: Vec<String>,
    user: Option<String>,
    input: Option<Box<dyn Read + Send>>,
) -> io::Result<(i32, Vec<u8>, Vec<u8>)> {
    let mut s = UnixStream::connect(control_socket(name))?;
    writeln!(s, "{{\"op\":\"exec\"}}")?;
    let req = ExecRequest {
        argv,
        user,
        ..Default::default()
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    // the supervisor already received the op line; the rest is the agent protocol
    let code = osbx_proto::run_exec(s.try_clone()?, s, &req, input, &mut out, &mut err)?.code;
    Ok((code, out, err))
}

/// Parse `NAME:/abs/path` or `NAME:C:\abs\path`, ignoring local Windows drive paths (`C:\foo`).
fn parse_sandbox_spec(s: &str) -> Option<(String, String)> {
    let (name, rest) = s.split_once(':')?;
    if name.is_empty() {
        return None;
    }
    // Single ASCII letter followed by `\` or `/` is a local Windows drive path (`C:\...`, `C:/...`).
    if name.len() == 1
        && name.as_bytes()[0].is_ascii_alphabetic()
        && (rest.starts_with('\\') || rest.starts_with('/'))
    {
        return None;
    }
    let is_unix_abs = rest.starts_with('/');
    let is_win_abs = rest.len() >= 3
        && rest.as_bytes()[0].is_ascii_alphabetic()
        && rest.as_bytes()[1] == b':'
        && (rest.as_bytes()[2] == b'\\' || rest.as_bytes()[2] == b'/');
    if is_unix_abs || is_win_abs {
        Some((name.to_owned(), rest.to_owned()))
    } else {
        None
    }
}

fn is_windows_sandbox(name: &str) -> bool {
    Record::load(name).is_ok_and(|r| r.guest_os == GuestOs::Windows)
}

/// Normalize a guest path for a Windows sandbox (`C:/foo/bar` -> `C:\foo\bar`, `/foo` -> `C:\foo`).
fn normalize_win_guest_path(p: &str) -> String {
    if p.starts_with('/') {
        format!(r"C:\{}", p.trim_start_matches('/').replace('/', "\\"))
    } else {
        p.replace('/', "\\")
    }
}

fn win_parent_and_base(p: &str) -> (String, String) {
    let trimmed = p.trim_end_matches('\\');
    match trimmed.rfind('\\') {
        Some(i) if i >= 2 => {
            let parent = if i == 2 && trimmed.as_bytes().get(1) == Some(&b':') {
                format!("{}\\", &trimmed[..2])
            } else {
                trimmed[..i].to_owned()
            };
            (parent, trimmed[i + 1..].to_owned())
        }
        _ => (r"C:\".into(), trimmed.to_owned()),
    }
}

/// `osbx cp`: `src` or `dst` (exactly one) is `NAME:/abs/path` (or `NAME:C:\path` for Windows).
pub fn cp(src: &str, dst: &str) -> io::Result<()> {
    match (parse_sandbox_spec(src), parse_sandbox_spec(dst)) {
        (None, Some((name, guest))) => {
            // host -> guest: tar on the host, untar in the guest
            let host = std::path::Path::new(src);
            let (parent, base) = parent_and_base(host)?;
            let mut tar = std::process::Command::new("tar")
                .arg("-c")
                .arg("-C")
                .arg(parent)
                .arg(base)
                .stdout(std::process::Stdio::piped())
                .spawn()?;
            let stdout = tar.stdout.take().unwrap();
            let (code, _, err) = if is_windows_sandbox(&name) {
                let win_guest = normalize_win_guest_path(&guest);
                let is_dir_dst = guest.ends_with('/') || guest.ends_with('\\');
                let (target, rename) = if is_dir_dst {
                    (win_guest.trim_end_matches('\\').to_owned(), String::new())
                } else {
                    let (par, leaf) = win_parent_and_base(&win_guest);
                    (par, leaf)
                };
                let base_str = base.to_string_lossy();
                let ps_esc = |s: &str| s.replace('\'', "''");
                if rename.is_empty() || rename.eq_ignore_ascii_case(&base_str) {
                    let _ = exec_capture(
                        &name,
                        vec![
                            "powershell.exe".into(),
                            "-NoProfile".into(),
                            "-Command".into(),
                            format!(
                                "New-Item -ItemType Directory -Force -Path '{}' | Out-Null",
                                ps_esc(&target)
                            ),
                        ],
                        Some("SYSTEM".into()),
                        None,
                    );
                    exec_capture(
                        &name,
                        vec![
                            r"C:\Windows\System32\tar.exe".into(),
                            "-xf".into(),
                            "-".into(),
                            "-C".into(),
                            target,
                        ],
                        Some("SYSTEM".into()),
                        Some(Box::new(stdout)),
                    )?
                } else {
                    let tmp = format!(r"C:\Windows\Temp\osbx-cp-{}", std::process::id());
                    let _ = exec_capture(
                        &name,
                        vec![
                            "powershell.exe".into(),
                            "-NoProfile".into(),
                            "-Command".into(),
                            format!(
                                "New-Item -ItemType Directory -Force -Path '{}' | Out-Null",
                                ps_esc(&tmp)
                            ),
                        ],
                        Some("SYSTEM".into()),
                        None,
                    );
                    let (code, out, err) = exec_capture(
                        &name,
                        vec![
                            r"C:\Windows\System32\tar.exe".into(),
                            "-xf".into(),
                            "-".into(),
                            "-C".into(),
                            tmp.clone(),
                        ],
                        Some("SYSTEM".into()),
                        Some(Box::new(stdout)),
                    )?;
                    if code != 0 {
                        (code, out, err)
                    } else {
                        let mv = format!(
                            "New-Item -ItemType Directory -Force -Path '{}' | Out-Null; if (Test-Path '{}') {{ Remove-Item -Recurse -Force '{}' }}; Move-Item -Force '{}\\{}' '{}'; Remove-Item -Recurse -Force '{}' -ErrorAction SilentlyContinue",
                            ps_esc(&target),
                            ps_esc(&win_guest),
                            ps_esc(&win_guest),
                            ps_esc(&tmp),
                            ps_esc(&base_str),
                            ps_esc(&win_guest),
                            ps_esc(&tmp),
                        );
                        exec_capture(
                            &name,
                            vec![
                                "powershell.exe".into(),
                                "-NoProfile".into(),
                                "-Command".into(),
                                mv,
                            ],
                            Some("SYSTEM".into()),
                            None,
                        )?
                    }
                }
            } else {
                let target = if guest.ends_with('/') {
                    guest.clone()
                } else {
                    format!("{}/", parent_of(&guest))
                };
                let rename = if guest.ends_with('/') {
                    String::new()
                } else {
                    guest.rsplit('/').next().unwrap_or("").to_owned()
                };
                let script = if rename.is_empty() || rename == base.to_string_lossy() {
                    format!("mkdir -p '{target}' && tar -x -C '{target}'")
                } else {
                    // copy under a new name: extract to a temp dir, then move
                    format!(
                        "t=$(mktemp -d) && tar -x -C \"$t\" && mkdir -p '{target}' && rm -rf '{guest}' && mv \"$t\"/'{}' '{guest}' && rmdir \"$t\"",
                        base.to_string_lossy()
                    )
                };
                exec_capture(
                    &name,
                    vec!["/bin/sh".into(), "-c".into(), script],
                    None,
                    Some(Box::new(stdout)),
                )?
            };
            let _ = tar.wait();
            if code != 0 {
                return Err(io::Error::other(format!(
                    "copy into sandbox failed: {}",
                    String::from_utf8_lossy(&err).trim()
                )));
            }
            Ok(())
        }
        (Some((name, guest)), None) => {
            // guest -> host: tar in the guest, untar on the host
            let (gbase, code, data, err) = if is_windows_sandbox(&name) {
                let win_guest = normalize_win_guest_path(&guest);
                let (gparent, gbase) = win_parent_and_base(&win_guest);
                let (code, data, err) = exec_capture(
                    &name,
                    vec![
                        r"C:\Windows\System32\tar.exe".into(),
                        "-cf".into(),
                        "-".into(),
                        "-C".into(),
                        gparent,
                        gbase.clone(),
                    ],
                    Some("SYSTEM".into()),
                    None,
                )?;
                (gbase, code, data, err)
            } else {
                let (gparent, gbase) = (
                    parent_of(&guest),
                    guest
                        .trim_end_matches('/')
                        .rsplit('/')
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                );
                let (code, data, err) = exec_capture(
                    &name,
                    vec![
                        "tar".into(),
                        "-c".into(),
                        "-C".into(),
                        gparent,
                        gbase.clone(),
                    ],
                    None,
                    None,
                )?;
                (gbase, code, data, err)
            };
            if code != 0 {
                return Err(io::Error::other(format!(
                    "copy out of sandbox failed: {}",
                    String::from_utf8_lossy(&err).trim()
                )));
            }
            let dst_path = std::path::Path::new(dst);
            let (into, rename) = if dst_path.is_dir() {
                (dst_path.to_path_buf(), None)
            } else {
                (
                    dst_path
                        .parent()
                        .map(|p| {
                            if p.as_os_str().is_empty() {
                                std::path::Path::new(".")
                            } else {
                                p
                            }
                        })
                        .unwrap()
                        .to_path_buf(),
                    dst_path.file_name().map(|f| f.to_owned()),
                )
            };
            let tmp = into.join(format!(".osbx-cp-{}", std::process::id()));
            std::fs::create_dir_all(&tmp)?;
            let mut untar = std::process::Command::new("tar")
                .arg("-x")
                .arg("-C")
                .arg(&tmp)
                .stdin(std::process::Stdio::piped())
                .spawn()?;
            untar.stdin.take().unwrap().write_all(&data)?;
            let ok = untar.wait()?.success();
            let result = if ok {
                let final_name = rename.unwrap_or_else(|| gbase.clone().into());
                let target = into.join(&final_name);
                if target.exists() && target.is_dir() {
                    let _ = std::fs::remove_dir_all(&target);
                }
                std::fs::rename(tmp.join(&gbase), target)
            } else {
                Err(io::Error::other("tar failed"))
            };
            let _ = std::fs::remove_dir_all(&tmp);
            result
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "exactly one of SRC/DST must be NAME:/absolute/path or NAME:C:\\path",
        )),
    }
}

fn parent_of(p: &str) -> String {
    let t = p.trim_end_matches('/');
    match t.rfind('/') {
        Some(0) | None => "/".into(),
        Some(i) => t[..i].to_owned(),
    }
}

fn parent_and_base(p: &std::path::Path) -> io::Result<(&std::path::Path, &std::ffi::OsStr)> {
    let base = p
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "source has no file name"))?;
    let parent = p
        .parent()
        .filter(|x| !x.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    Ok((parent, base))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parents() {
        assert_eq!(parent_of("/a/b/c"), "/a/b");
        assert_eq!(parent_of("/a"), "/");
        assert_eq!(parent_of("/a/b/"), "/a");
    }

    #[test]
    fn parses_linux_and_windows_sandbox_specs() {
        assert_eq!(
            parse_sandbox_spec("box1:/tmp/a.txt"),
            Some(("box1".into(), "/tmp/a.txt".into()))
        );
        assert_eq!(
            parse_sandbox_spec(r"winbox:C:\workspace\a.txt"),
            Some(("winbox".into(), r"C:\workspace\a.txt".into()))
        );
        assert_eq!(
            parse_sandbox_spec("winbox:C:/workspace/a.txt"),
            Some(("winbox".into(), "C:/workspace/a.txt".into()))
        );
        // Local Windows drive paths must NOT be treated as sandbox specs!
        assert_eq!(parse_sandbox_spec(r"C:\Users\me\file.txt"), None);
        assert_eq!(parse_sandbox_spec("D:/data/file.txt"), None);
        assert_eq!(parse_sandbox_spec("./local.txt"), None);
    }

    #[test]
    fn normalizes_windows_guest_paths() {
        assert_eq!(normalize_win_guest_path("/temp/a.txt"), r"C:\temp\a.txt");
        assert_eq!(
            normalize_win_guest_path("C:/workspace/a.txt"),
            r"C:\workspace\a.txt"
        );
        assert_eq!(
            win_parent_and_base(r"C:\workspace\a.txt"),
            (r"C:\workspace".into(), "a.txt".into())
        );
        assert_eq!(
            win_parent_and_base(r"C:\a.txt"),
            (r"C:\".into(), "a.txt".into())
        );
    }
}
