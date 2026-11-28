//! Host-side file RPC and change-watch service served over vsock (`FILE_SYNC_PORT = 1027`).
//!
//! Powers Windows guest `sync` and `projfs` file-sharing backends without requiring any third-party
//! kernel drivers in the guest. Every request is strictly confined to the registered share root
//! (rejecting `..`, drive prefixes, NULs, and symlink escapes), and every mutating operation is
//! hard-rejected with [`FileSyncResp::ReadOnly`] (`EROFS`) when `read_only == true`.

use osbx_proto::{
    FS_DATA, FS_EVENT, FS_REQ, FS_RESP, FileEntry, FileSyncEvent, FileSyncReq, FileSyncResp,
    MAX_FRAME, read_frame, write_frame,
};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, UNIX_EPOCH};

/// Maximum single read/write payload chunk over `FILE_SYNC_PORT` (1 MiB).
const MAX_IO_CHUNK: usize = 1 << 20;

/// One host directory registered on [`osbx_proto::FILE_SYNC_PORT`].
#[derive(Debug, Clone)]
pub struct FileSyncShare {
    /// Share tag (e.g. `"workspace"`, `"source"`, `"mnt0_models"`).
    pub tag: String,
    /// Canonical host root directory.
    pub host_dir: PathBuf,
    /// When true, all mutating RPCs return [`FileSyncResp::ReadOnly`].
    pub read_only: bool,
}

/// Thread-safe registry of host shares served on `FILE_SYNC_PORT`.
#[derive(Debug, Clone)]
pub struct FileSyncServer {
    shares: Arc<BTreeMap<String, FileSyncShare>>,
    closed: Arc<AtomicBool>,
}

impl FileSyncServer {
    /// Create a new file-sync server from `shares`, canonicalizing each existing root directory.
    pub fn new(shares: Vec<FileSyncShare>, closed: Arc<AtomicBool>) -> Self {
        let mut map = BTreeMap::new();
        for mut sh in shares {
            if let Ok(canon) = fs::canonicalize(&sh.host_dir) {
                sh.host_dir = canon;
            }
            map.insert(sh.tag.clone(), sh);
        }
        Self {
            shares: Arc::new(map),
            closed,
        }
    }

    /// Handle one vsock client stream until EOF or shutdown.
    pub fn serve<S: Read + Write>(&self, mut stream: S) {
        while !self.closed.load(Ordering::SeqCst) {
            let (ty, payload) = match read_frame(&mut stream) {
                Ok(Some(f)) => f,
                _ => break,
            };
            if ty != FS_REQ {
                let _ = send_resp(
                    &mut stream,
                    &FileSyncResp::Error {
                        message: format!("unexpected frame type 0x{ty:02x}"),
                    },
                );
                break;
            }
            let req: FileSyncReq = match serde_json::from_slice(&payload) {
                Ok(r) => r,
                Err(e) => {
                    let _ = send_resp(
                        &mut stream,
                        &FileSyncResp::Error {
                            message: format!("malformed request: {e}"),
                        },
                    );
                    continue;
                }
            };
            match req {
                FileSyncReq::Watch { tag } => {
                    self.handle_watch(&tag, &mut stream);
                    break;
                }
                FileSyncReq::ReadFile {
                    tag,
                    path,
                    offset,
                    len,
                } => {
                    if self
                        .handle_read(&tag, &path, offset, len, &mut stream)
                        .is_err()
                    {
                        break;
                    }
                }
                FileSyncReq::WriteFile {
                    tag,
                    path,
                    offset,
                    truncate,
                } => {
                    // Always consume the accompanying FS_DATA frame before replying so framing stays aligned.
                    let data = match read_frame(&mut stream) {
                        Ok(Some((FS_DATA, d))) => d,
                        _ => break,
                    };
                    let resp = self.handle_write(&tag, &path, offset, truncate, &data);
                    if send_resp(&mut stream, &resp).is_err() {
                        break;
                    }
                }
                other => {
                    let resp = self.dispatch_simple(other);
                    if send_resp(&mut stream, &resp).is_err() {
                        break;
                    }
                }
            }
        }
    }

    fn lookup(&self, tag: &str) -> Result<&FileSyncShare, FileSyncResp> {
        self.shares.get(tag).ok_or_else(|| FileSyncResp::Error {
            message: format!("unknown share tag {tag:?}"),
        })
    }

    fn dispatch_simple(&self, req: FileSyncReq) -> FileSyncResp {
        match req {
            FileSyncReq::ListDir { tag, path } => {
                let share = match self.lookup(&tag) {
                    Ok(s) => s,
                    Err(e) => return e,
                };
                let target = match resolve_safe_path(&share.host_dir, &path) {
                    Ok(p) => p,
                    Err(e) => return e,
                };
                let rd = match fs::read_dir(&target) {
                    Ok(r) => r,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return FileSyncResp::NotFound,
                    Err(e) => {
                        return FileSyncResp::Error {
                            message: e.to_string(),
                        };
                    }
                };
                let mut entries = Vec::new();
                for item in rd.flatten() {
                    let name = item.file_name().to_string_lossy().into_owned();
                    // Never expose symlinks pointing outside the share root.
                    let item_path = item.path();
                    if let Ok(canon) = fs::canonicalize(&item_path)
                        && !canon.starts_with(&share.host_dir)
                    {
                        continue;
                    }
                    if let Ok(meta) = fs::metadata(&item_path) {
                        entries.push(meta_to_entry(name, &meta, share.read_only));
                    }
                }
                entries.sort_by_key(|a| a.name.to_lowercase());
                FileSyncResp::Entries { entries }
            }
            FileSyncReq::Stat { tag, path } => {
                let share = match self.lookup(&tag) {
                    Ok(s) => s,
                    Err(e) => return e,
                };
                let target = match resolve_safe_path(&share.host_dir, &path) {
                    Ok(p) => p,
                    Err(e) => return e,
                };
                match fs::metadata(&target) {
                    Ok(meta) => {
                        let name = target
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        FileSyncResp::Meta {
                            entry: meta_to_entry(name, &meta, share.read_only),
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => FileSyncResp::NotFound,
                    Err(e) => FileSyncResp::Error {
                        message: e.to_string(),
                    },
                }
            }
            FileSyncReq::Mkdir { tag, path } => {
                let share = match self.lookup(&tag) {
                    Ok(s) => s,
                    Err(e) => return e,
                };
                if share.read_only {
                    return FileSyncResp::ReadOnly;
                }
                let target = match resolve_safe_path(&share.host_dir, &path) {
                    Ok(p) => p,
                    Err(e) => return e,
                };
                match fs::create_dir_all(&target) {
                    Ok(()) => FileSyncResp::Ok,
                    Err(e) => FileSyncResp::Error {
                        message: e.to_string(),
                    },
                }
            }
            FileSyncReq::Remove {
                tag,
                path,
                recursive,
            } => {
                let share = match self.lookup(&tag) {
                    Ok(s) => s,
                    Err(e) => return e,
                };
                if share.read_only {
                    return FileSyncResp::ReadOnly;
                }
                let target = match resolve_safe_path(&share.host_dir, &path) {
                    Ok(p) => p,
                    Err(e) => return e,
                };
                if target == share.host_dir {
                    return FileSyncResp::InvalidPath {
                        message: "cannot remove share root".into(),
                    };
                }
                let res = match fs::symlink_metadata(&target) {
                    Ok(m) if m.is_dir() => {
                        if recursive {
                            fs::remove_dir_all(&target)
                        } else {
                            fs::remove_dir(&target)
                        }
                    }
                    Ok(_) => fs::remove_file(&target),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return FileSyncResp::NotFound,
                    Err(e) => Err(e),
                };
                match res {
                    Ok(()) => FileSyncResp::Ok,
                    Err(e) => FileSyncResp::Error {
                        message: e.to_string(),
                    },
                }
            }
            FileSyncReq::Rename { tag, from, to } => {
                let share = match self.lookup(&tag) {
                    Ok(s) => s,
                    Err(e) => return e,
                };
                if share.read_only {
                    return FileSyncResp::ReadOnly;
                }
                let src = match resolve_safe_path(&share.host_dir, &from) {
                    Ok(p) => p,
                    Err(e) => return e,
                };
                let dst = match resolve_safe_path(&share.host_dir, &to) {
                    Ok(p) => p,
                    Err(e) => return e,
                };
                if src == share.host_dir || dst == share.host_dir {
                    return FileSyncResp::InvalidPath {
                        message: "cannot rename share root".into(),
                    };
                }
                if let Some(parent) = dst.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                match fs::rename(&src, &dst) {
                    Ok(()) => FileSyncResp::Ok,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => FileSyncResp::NotFound,
                    Err(e) => FileSyncResp::Error {
                        message: e.to_string(),
                    },
                }
            }
            FileSyncReq::ReadFile { .. }
            | FileSyncReq::WriteFile { .. }
            | FileSyncReq::Watch { .. } => unreachable!(),
        }
    }

    fn handle_read<W: Write>(
        &self,
        tag: &str,
        path: &str,
        offset: u64,
        len: u32,
        w: &mut W,
    ) -> io::Result<()> {
        let share = match self.lookup(tag) {
            Ok(s) => s,
            Err(e) => return send_resp(w, &e),
        };
        let target = match resolve_safe_path(&share.host_dir, path) {
            Ok(p) => p,
            Err(e) => return send_resp(w, &e),
        };
        let mut f = match File::open(&target) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return send_resp(w, &FileSyncResp::NotFound);
            }
            Err(e) => {
                return send_resp(
                    w,
                    &FileSyncResp::Error {
                        message: e.to_string(),
                    },
                );
            }
        };
        if let Err(e) = f.seek(SeekFrom::Start(offset)) {
            return send_resp(
                w,
                &FileSyncResp::Error {
                    message: e.to_string(),
                },
            );
        }
        let want = (len as usize).min(MAX_IO_CHUNK).min(MAX_FRAME);
        let mut buf = vec![0u8; want];
        let mut got = 0usize;
        while got < want {
            match f.read(&mut buf[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) => {
                    return send_resp(
                        w,
                        &FileSyncResp::Error {
                            message: e.to_string(),
                        },
                    );
                }
            }
        }
        send_resp(w, &FileSyncResp::Data { len: got as u32 })?;
        write_frame(w, FS_DATA, &buf[..got])
    }

    fn handle_write(
        &self,
        tag: &str,
        path: &str,
        offset: u64,
        truncate: bool,
        data: &[u8],
    ) -> FileSyncResp {
        let share = match self.lookup(tag) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if share.read_only {
            return FileSyncResp::ReadOnly;
        }
        let target = match resolve_safe_path(&share.host_dir, path) {
            Ok(p) => p,
            Err(e) => return e,
        };
        if target == share.host_dir {
            return FileSyncResp::InvalidPath {
                message: "cannot write to share root as a file".into(),
            };
        }
        if let Some(parent) = target.parent()
            && let Err(e) = fs::create_dir_all(parent)
        {
            return FileSyncResp::Error {
                message: e.to_string(),
            };
        }
        let mut opts = OpenOptions::new();
        opts.create(true).write(true);
        if truncate && offset == 0 {
            opts.truncate(true);
        }
        let mut f = match opts.open(&target) {
            Ok(f) => f,
            Err(e) => {
                return FileSyncResp::Error {
                    message: e.to_string(),
                };
            }
        };
        if offset > 0
            && let Err(e) = f.seek(SeekFrom::Start(offset))
        {
            return FileSyncResp::Error {
                message: e.to_string(),
            };
        }
        if let Err(e) = f.write_all(data) {
            return FileSyncResp::Error {
                message: e.to_string(),
            };
        }
        if truncate
            && offset > 0
            && let Err(e) = f.set_len(offset + data.len() as u64)
        {
            return FileSyncResp::Error {
                message: e.to_string(),
            };
        }
        FileSyncResp::Ok
    }

    fn handle_watch<W: Write>(&self, tag: &str, w: &mut W) {
        let share = match self.lookup(tag) {
            Ok(s) => s.clone(),
            Err(e) => {
                let _ = send_resp(w, &e);
                return;
            }
        };
        let mut prev = snapshot_tree(&share.host_dir);
        if send_resp(w, &FileSyncResp::Ok).is_err() {
            return;
        }
        while !self.closed.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(400));
            let cur = snapshot_tree(&share.host_dir);
            // Removed paths
            for rel in prev.keys() {
                if !cur.contains_key(rel) {
                    let ev = FileSyncEvent {
                        path: rel.clone(),
                        removed: true,
                        is_dir: false,
                    };
                    if send_event(w, &ev).is_err() {
                        return;
                    }
                }
            }
            // Created or modified paths
            for (rel, st) in &cur {
                if prev.get(rel) != Some(st) {
                    let ev = FileSyncEvent {
                        path: rel.clone(),
                        removed: false,
                        is_dir: st.0,
                    };
                    if send_event(w, &ev).is_err() {
                        return;
                    }
                }
            }
            prev = cur;
        }
    }
}

/// Resolve `rel` safely inside canonical `root`, rejecting traversal (`..`), drive prefixes, NUL
/// bytes, and symlink escapes outside `root`.
pub fn resolve_safe_path(root: &Path, rel: &str) -> Result<PathBuf, FileSyncResp> {
    if rel.contains('\0') {
        return Err(FileSyncResp::InvalidPath {
            message: "NUL byte in path".into(),
        });
    }
    let normalized = rel.replace('\\', "/");
    let trimmed = normalized.trim_start_matches('/');
    if trimmed.is_empty() || trimmed == "." {
        return Ok(root.to_path_buf());
    }
    let mut joined = root.to_path_buf();
    for comp in Path::new(trimmed).components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s.contains(':') {
                    return Err(FileSyncResp::InvalidPath {
                        message: format!("invalid path segment {s:?}"),
                    });
                }
                joined.push(seg);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(FileSyncResp::InvalidPath {
                    message: format!("path traversal rejected: {rel:?}"),
                });
            }
        }
    }
    // Walk up to the deepest existing ancestor and verify canonical containment inside `root`.
    let mut probe = joined.as_path();
    while !probe.exists() {
        let Some(p) = probe.parent() else {
            break;
        };
        probe = p;
    }
    if let Ok(canon) = fs::canonicalize(probe)
        && !canon.starts_with(root)
    {
        return Err(FileSyncResp::InvalidPath {
            message: format!("symlink escape outside share root: {rel:?}"),
        });
    }
    Ok(joined)
}

fn meta_to_entry(name: String, meta: &fs::Metadata, share_ro: bool) -> FileEntry {
    let (mtime_secs, mtime_nanos) = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or((0, 0), |d| (d.as_secs() as i64, d.subsec_nanos()));
    FileEntry {
        name,
        is_dir: meta.is_dir(),
        size: if meta.is_dir() { 0 } else { meta.len() },
        mtime_secs,
        mtime_nanos,
        read_only: share_ro || meta.permissions().readonly(),
    }
}

/// `(is_dir, len, mtime_secs, mtime_nanos)`
type EntryStamp = (bool, u64, i64, u32);

fn snapshot_tree(root: &Path) -> BTreeMap<String, EntryStamp> {
    let mut out = BTreeMap::new();
    walk_snapshot(root, root, "", &mut out, 0);
    out
}

fn walk_snapshot(
    root: &Path,
    dir: &Path,
    prefix: &str,
    out: &mut BTreeMap<String, EntryStamp>,
    depth: usize,
) {
    if depth > 24 || out.len() > 25_000 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for item in rd.flatten() {
        let name = item.file_name().to_string_lossy().into_owned();
        if name == ".git" || name == "target" || name == "node_modules" {
            continue;
        }
        let path = item.path();
        if let Ok(canon) = fs::canonicalize(&path)
            && !canon.starts_with(root)
        {
            continue;
        }
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let (secs, nanos) = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or((0, 0), |d| (d.as_secs() as i64, d.subsec_nanos()));
        let is_dir = meta.is_dir();
        out.insert(
            rel.clone(),
            (is_dir, if is_dir { 0 } else { meta.len() }, secs, nanos),
        );
        if is_dir {
            walk_snapshot(root, &path, &rel, out, depth + 1);
        }
    }
}

fn send_resp<W: Write>(w: &mut W, resp: &FileSyncResp) -> io::Result<()> {
    let bytes = serde_json::to_vec(resp).map_err(io::Error::other)?;
    write_frame(w, FS_RESP, &bytes)
}

fn send_event<W: Write>(w: &mut W, ev: &FileSyncEvent) -> io::Result<()> {
    let bytes = serde_json::to_vec(ev).map_err(io::Error::other)?;
    write_frame(w, FS_EVENT, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "osbx-filesync-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        fs::canonicalize(p).unwrap()
    }

    #[test]
    fn rejects_path_traversal_and_enforces_read_only() {
        let rw_dir = temp_dir("rw");
        let ro_dir = temp_dir("ro");
        fs::write(ro_dir.join("seed.txt"), b"immutable").unwrap();

        let srv = FileSyncServer::new(
            vec![
                FileSyncShare {
                    tag: "rw".into(),
                    host_dir: rw_dir.clone(),
                    read_only: false,
                },
                FileSyncShare {
                    tag: "ro".into(),
                    host_dir: ro_dir.clone(),
                    read_only: true,
                },
            ],
            Arc::new(AtomicBool::new(false)),
        );

        // Traversal attacks rejected
        assert!(matches!(
            resolve_safe_path(&rw_dir, "../etc/passwd"),
            Err(FileSyncResp::InvalidPath { .. })
        ));
        assert!(matches!(
            resolve_safe_path(&rw_dir, r"a\..\..\outside"),
            Err(FileSyncResp::InvalidPath { .. })
        ));
        assert!(matches!(
            resolve_safe_path(&rw_dir, "C:/Windows/System32"),
            Err(FileSyncResp::InvalidPath { .. })
        ));

        // RO share rejects every mutation with ReadOnly (EROFS)
        assert_eq!(
            srv.handle_write("ro", "seed.txt", 0, true, b"pwned"),
            FileSyncResp::ReadOnly
        );
        assert_eq!(
            srv.dispatch_simple(FileSyncReq::Mkdir {
                tag: "ro".into(),
                path: "sub".into(),
            }),
            FileSyncResp::ReadOnly
        );
        assert_eq!(
            srv.dispatch_simple(FileSyncReq::Remove {
                tag: "ro".into(),
                path: "seed.txt".into(),
                recursive: false,
            }),
            FileSyncResp::ReadOnly
        );
        assert_eq!(fs::read(ro_dir.join("seed.txt")).unwrap(), b"immutable");

        // RW share creates, lists, writes, renames, and removes cleanly
        assert_eq!(
            srv.handle_write("rw", "sub/hello.txt", 0, true, b"hello-sync"),
            FileSyncResp::Ok
        );
        assert_eq!(
            fs::read(rw_dir.join("sub/hello.txt")).unwrap(),
            b"hello-sync"
        );
        assert_eq!(
            srv.dispatch_simple(FileSyncReq::Rename {
                tag: "rw".into(),
                from: "sub/hello.txt".into(),
                to: "sub/world.txt".into(),
            }),
            FileSyncResp::Ok
        );
        assert_eq!(
            fs::read(rw_dir.join("sub/world.txt")).unwrap(),
            b"hello-sync"
        );
        assert_eq!(
            srv.dispatch_simple(FileSyncReq::Remove {
                tag: "rw".into(),
                path: "sub".into(),
                recursive: true,
            }),
            FileSyncResp::Ok
        );
        assert!(!rw_dir.join("sub").exists());

        let _ = fs::remove_dir_all(&rw_dir);
        let _ = fs::remove_dir_all(&ro_dir);
    }
}
