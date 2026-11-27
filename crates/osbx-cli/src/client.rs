//! Client side of the supervisor protocol: interactive exec and file copy.

use crate::state::control_socket;
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
    input: Option<Box<dyn Read + Send>>,
) -> io::Result<(i32, Vec<u8>, Vec<u8>)> {
    let mut s = UnixStream::connect(control_socket(name))?;
    writeln!(s, "{{\"op\":\"exec\"}}")?;
    let req = ExecRequest {
        argv,
        ..Default::default()
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    // the supervisor already received the op line; the rest is the agent protocol
    let code = osbx_proto::run_exec(s.try_clone()?, s, &req, input, &mut out, &mut err)?.code;
    Ok((code, out, err))
}

/// `osbx cp`: `src` or `dst` (exactly one) is `NAME:/abs/path`.
pub fn cp(src: &str, dst: &str) -> io::Result<()> {
    let split = |s: &str| {
        s.split_once(':')
            .filter(|(n, p)| !n.is_empty() && p.starts_with('/'))
            .map(|(n, p)| (n.to_owned(), p.to_owned()))
    };
    match (split(src), split(dst)) {
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
            let (code, _, err) = exec_capture(
                &name,
                vec!["/bin/sh".into(), "-c".into(), script],
                Some(Box::new(stdout)),
            )?;
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
                    gparent.clone(),
                    gbase.clone(),
                ],
                None,
            )?;
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
            "exactly one of SRC/DST must be NAME:/absolute/path",
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
}
