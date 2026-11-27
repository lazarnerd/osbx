//! A FUSE file server over `std::fs`, for virtio-fs on hosts where the Linux passthrough file
//! system (`fuse-backend-rs`) is not available (Windows).
//!
//! Semantics, where the host file system differs from POSIX:
//! - **Ownership**: every file appears owned by the caller (the uid/gid in the request), so the
//!   sandbox user may write anywhere in the share and tools that check ownership (git's
//!   `safe.directory`) are satisfied. `chown` succeeds and changes nothing.
//! - **Permissions**: directories are 0755; files 0644, or 0755 when they start with `#!` or
//!   an ELF header. `chmod` is kept in an NTFS alternate data stream (`<file>:osbx.mode`), so it
//!   survives restarts and travels with the file.
//! - **Names** containing `\`, `:` or NUL, and `.`/`..`, are refused (`EINVAL`): they would
//!   escape the share or address alternate data streams.
//! - **Symlinks** are created only if the host allows it (Windows: Developer Mode or admin),
//!   otherwise `EPERM`. Special files (devices, FIFOs, sockets) cannot be created.
//! - **Inode numbers** are stable hashes of the path (they change on rename).
//!
//! Protocol: FUSE 7.31 subset (no DAX, no locks, no xattrs, no READDIRPLUS); everything else
//! answers `ENOSYS`.

use std::collections::HashMap;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// opcodes
const LOOKUP: u32 = 1;
const FORGET: u32 = 2;
const GETATTR: u32 = 3;
const SETATTR: u32 = 4;
const READLINK: u32 = 5;
const SYMLINK: u32 = 6;
const MKNOD: u32 = 8;
const MKDIR: u32 = 9;
const UNLINK: u32 = 10;
const RMDIR: u32 = 11;
const RENAME: u32 = 12;
const LINK: u32 = 13;
const OPEN: u32 = 14;
const READ: u32 = 15;
const WRITE: u32 = 16;
const STATFS: u32 = 17;
const RELEASE: u32 = 18;
const FSYNC: u32 = 20;
const SETXATTR: u32 = 21;
const GETXATTR: u32 = 22;
const LISTXATTR: u32 = 23;
const REMOVEXATTR: u32 = 24;
const FLUSH: u32 = 25;
const INIT: u32 = 26;
const OPENDIR: u32 = 27;
const READDIR: u32 = 28;
const RELEASEDIR: u32 = 29;
const FSYNCDIR: u32 = 30;
const ACCESS: u32 = 34;
const CREATE: u32 = 35;
const INTERRUPT: u32 = 36;
const DESTROY: u32 = 38;
const BATCH_FORGET: u32 = 42;
const FALLOCATE: u32 = 43;
const RENAME2: u32 = 45;
const LSEEK: u32 = 46;

// errno
const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EIO: i32 = 5;
const EBADF: i32 = 9;
const EACCES: i32 = 13;
const EBUSY: i32 = 16;
const EEXIST: i32 = 17;
const EXDEV: i32 = 18;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const EINVAL: i32 = 22;
const ENOSPC: i32 = 28;
const EROFS: i32 = 30;
const ENAMETOOLONG: i32 = 36;
const ENOSYS: i32 = 38;
const ENOTEMPTY: i32 = 39;
const ENODATA: i32 = 61;
const ESTALE: i32 = 116;
const EOPNOTSUPP: i32 = 95;

const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;
const DT_DIR: u32 = 4;
const DT_REG: u32 = 8;
const DT_LNK: u32 = 10;

const FATTR_MODE: u32 = 1;
const FATTR_SIZE: u32 = 8;
const FATTR_ATIME: u32 = 16;
const FATTR_MTIME: u32 = 32;
const FATTR_FH: u32 = 64;
const FATTR_ATIME_NOW: u32 = 128;
const FATTR_MTIME_NOW: u32 = 256;

const O_ACCMODE: u32 = 3;
const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_EXCL: u32 = 0o200;
const O_TRUNC: u32 = 0o1000;
const O_APPEND: u32 = 0o2000;

const FUSE_ASYNC_READ: u32 = 1;
const FUSE_BIG_WRITES: u32 = 1 << 5;
const FUSE_MAX_PAGES: u32 = 1 << 22;
const MAX_PAGES: u16 = 256; // 1 MiB requests
const ROOT: u64 = 1;
/// How long the guest may cache entries and attributes. Short: the host side changes too.
const TTL: Duration = Duration::from_secs(1);

type Reply = Result<Vec<u8>, i32>;

fn errno(e: &io::Error) -> i32 {
    #[cfg(windows)]
    if let Some(code) = e.raw_os_error() {
        match code {
            2 | 3 => return ENOENT,
            5 => return EACCES,
            32 | 33 => return EBUSY,
            80 | 183 => return EEXIST,
            112 => return ENOSPC,
            123 | 161 => return EINVAL,
            145 => return ENOTEMPTY,
            206 => return ENAMETOOLONG,
            267 => return ENOTDIR,
            1314 => return EPERM, // symlink privilege not held
            _ => {}
        }
    }
    use io::ErrorKind::*;
    match e.kind() {
        NotFound => ENOENT,
        PermissionDenied => EACCES,
        AlreadyExists => EEXIST,
        DirectoryNotEmpty => ENOTEMPTY,
        NotADirectory => ENOTDIR,
        IsADirectory => EISDIR,
        InvalidInput | InvalidFilename => EINVAL,
        ReadOnlyFilesystem => EROFS,
        StorageFull => ENOSPC,
        CrossesDevices => EXDEV,
        ResourceBusy => EBUSY,
        Unsupported => EOPNOTSUPP,
        _ => EIO,
    }
}

/// Little-endian reader over a request body.
struct In<'a>(&'a [u8]);
impl<'a> In<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], i32> {
        if self.0.len() < n {
            return Err(EINVAL);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<u32, i32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, i32> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    /// A NUL-terminated name.
    fn name(&mut self) -> Result<&'a str, i32> {
        let end = self.0.iter().position(|&b| b == 0).ok_or(EINVAL)?;
        let s = std::str::from_utf8(&self.0[..end]).map_err(|_| EINVAL)?;
        self.0 = &self.0[end + 1..];
        Ok(s)
    }
}

/// Little-endian writer for replies.
#[derive(Default)]
struct Out(Vec<u8>);
impl Out {
    fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
}

fn valid_name(n: &str) -> Result<(), i32> {
    if n.is_empty() || n == "." || n == ".." || n.contains(['\\', ':', '\0', '/']) {
        return Err(EINVAL);
    }
    if n.len() > 255 {
        return Err(ENAMETOOLONG);
    }
    Ok(())
}

fn split_time(t: Option<SystemTime>) -> (u64, u32) {
    match t.and_then(|t| t.duration_since(UNIX_EPOCH).ok()) {
        Some(d) => (d.as_secs(), d.subsec_nanos()),
        None => (0, 0),
    }
}

fn hash_ino(rel: &Path) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in rel.to_string_lossy().to_lowercase().bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    h.max(2) // 1 is the root
}

enum Handle {
    File { file: File, append: bool },
    Dir(Vec<(u64, u32, String)>),
}

#[derive(Default)]
struct Tables {
    /// nodeid -> (path relative to the root, lookup count)
    nodes: HashMap<u64, (PathBuf, u64)>,
    by_path: HashMap<PathBuf, u64>,
    next_node: u64,
    handles: HashMap<u64, Handle>,
    next_fh: u64,
    /// path -> (len, mtime, permission bits): cached mode of regular files
    modes: HashMap<PathBuf, (u64, Option<SystemTime>, u32)>,
}

/// One exported directory.
pub struct Server {
    root: PathBuf,
    read_only: bool,
    t: Mutex<Tables>,
}

impl Server {
    /// Serve `root` (`read_only` refuses every modification with `EROFS`).
    pub fn new(root: &Path, read_only: bool) -> io::Result<Self> {
        let root = std::fs::canonicalize(root)?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a directory", root.display()),
            ));
        }
        let mut t = Tables {
            next_node: 2,
            next_fh: 1,
            ..Default::default()
        };
        t.nodes.insert(ROOT, (PathBuf::new(), 1));
        t.by_path.insert(PathBuf::new(), ROOT);
        Ok(Self {
            root,
            read_only,
            t: Mutex::new(t),
        })
    }

    fn rel(&self, node: u64) -> Result<PathBuf, i32> {
        self.t
            .lock()
            .unwrap()
            .nodes
            .get(&node)
            .map(|(p, _)| p.clone())
            .ok_or(ESTALE)
    }

    fn abs(&self, rel: &Path) -> PathBuf {
        if rel.as_os_str().is_empty() {
            self.root.clone()
        } else {
            self.root.join(rel)
        }
    }

    fn child(&self, parent: u64, name: &str) -> Result<PathBuf, i32> {
        valid_name(name)?;
        Ok(self.rel(parent)?.join(name))
    }

    fn writable(&self) -> Result<(), i32> {
        if self.read_only { Err(EROFS) } else { Ok(()) }
    }

    /// Remember `rel` (one more lookup) and return its node id.
    fn remember(&self, rel: &Path) -> u64 {
        let mut t = self.t.lock().unwrap();
        if let Some(&id) = t.by_path.get(rel) {
            if let Some(e) = t.nodes.get_mut(&id) {
                e.1 += 1;
            }
            return id;
        }
        let id = t.next_node;
        t.next_node += 1;
        t.nodes.insert(id, (rel.to_path_buf(), 1));
        t.by_path.insert(rel.to_path_buf(), id);
        id
    }

    fn forget(&self, node: u64, n: u64) {
        if node == ROOT {
            return;
        }
        let mut t = self.t.lock().unwrap();
        let gone = match t.nodes.get_mut(&node) {
            Some(e) => {
                e.1 = e.1.saturating_sub(n);
                (e.1 == 0).then(|| e.0.clone())
            }
            None => None,
        };
        if let Some(p) = gone {
            t.nodes.remove(&node);
            if t.by_path.get(&p) == Some(&node) {
                t.by_path.remove(&p);
            }
        }
    }

    /// Permission bits of a regular file: the stored chmod, else shebang/ELF detection.
    fn file_mode(&self, rel: &Path, m: &Metadata) -> u32 {
        let key = (m.len(), m.modified().ok());
        if let Some(&(len, mt, mode)) = self.t.lock().unwrap().modes.get(rel)
            && (len, mt) == key
        {
            return mode;
        }
        let abs = self.abs(rel);
        let mode = read_mode_stream(&abs).unwrap_or_else(|| {
            let mut magic = [0u8; 4];
            let n = File::open(&abs)
                .and_then(|mut f| f.read(&mut magic))
                .unwrap_or(0);
            if magic[..n].starts_with(b"#!") || magic[..n] == *b"\x7fELF" {
                0o755
            } else {
                0o644
            }
        });
        self.t
            .lock()
            .unwrap()
            .modes
            .insert(rel.to_path_buf(), (key.0, key.1, mode));
        mode
    }

    fn attr(&self, out: &mut Out, rel: &Path, m: &Metadata, uid: u32, gid: u32) {
        let ft = m.file_type();
        let (kind, perm, nlink) = if ft.is_symlink() {
            (S_IFLNK, 0o777, 1)
        } else if ft.is_dir() {
            (S_IFDIR, 0o755, 2)
        } else {
            (S_IFREG, self.file_mode(rel, m), 1)
        };
        let perm = if m.permissions().readonly() && kind == S_IFREG {
            perm & !0o222
        } else {
            perm
        };
        let (at, atn) = split_time(m.accessed().ok());
        let (mt, mtn) = split_time(m.modified().ok());
        let size = if ft.is_dir() { 4096 } else { m.len() };
        out.u64(if rel.as_os_str().is_empty() {
            ROOT
        } else {
            hash_ino(rel)
        })
        .u64(size)
        .u64(size.div_ceil(512))
        .u64(at)
        .u64(mt)
        .u64(mt)
        .u32(atn)
        .u32(mtn)
        .u32(mtn)
        .u32(kind | perm)
        .u32(nlink)
        .u32(uid)
        .u32(gid)
        .u32(0) // rdev
        .u32(4096) // blksize
        .u32(0); // flags
    }

    fn entry(&self, rel: &Path, uid: u32, gid: u32) -> Reply {
        let m = std::fs::symlink_metadata(self.abs(rel)).map_err(|e| errno(&e))?;
        let id = self.remember(rel);
        let mut o = Out::default();
        o.u64(id)
            .u64(0)
            .u64(TTL.as_secs())
            .u64(TTL.as_secs())
            .u32(0)
            .u32(0);
        self.attr(&mut o, rel, &m, uid, gid);
        Ok(o.0)
    }

    fn attr_reply(&self, rel: &Path, uid: u32, gid: u32) -> Reply {
        let m = std::fs::symlink_metadata(self.abs(rel)).map_err(|e| errno(&e))?;
        let mut o = Out::default();
        o.u64(TTL.as_secs()).u32(0).u32(0);
        self.attr(&mut o, rel, &m, uid, gid);
        Ok(o.0)
    }

    fn new_handle(&self, h: Handle) -> u64 {
        let mut t = self.t.lock().unwrap();
        let fh = t.next_fh;
        t.next_fh += 1;
        t.handles.insert(fh, h);
        fh
    }

    fn set_mode(&self, rel: &Path, mode: u32) -> Result<(), i32> {
        let abs = self.abs(rel);
        let m = std::fs::symlink_metadata(&abs).map_err(|e| errno(&e))?;
        if !m.is_file() {
            return Ok(()); // directories/symlinks: fixed modes
        }
        let bits = mode & 0o7777;
        write_mode_stream(&abs, bits);
        let m = std::fs::symlink_metadata(&abs).map_err(|e| errno(&e))?;
        self.t
            .lock()
            .unwrap()
            .modes
            .insert(rel.to_path_buf(), (m.len(), m.modified().ok(), bits));
        Ok(())
    }

    /// Re-key everything under `from` to `to` after a rename.
    fn renamed(&self, from: &Path, to: &Path) {
        let mut t = self.t.lock().unwrap();
        let moved: Vec<(u64, PathBuf)> = t
            .nodes
            .iter()
            .filter(|(_, (p, _))| p.starts_with(from))
            .map(|(&id, (p, _))| (id, to.join(p.strip_prefix(from).unwrap())))
            .collect();
        for (id, newp) in moved {
            let old = t.nodes.get(&id).unwrap().0.clone();
            if t.by_path.get(&old) == Some(&id) {
                t.by_path.remove(&old);
            }
            // whatever was at the target is gone (replaced)
            if let Some(prev) = t.by_path.insert(newp.clone(), id)
                && prev != id
                && let Some(e) = t.nodes.get_mut(&prev)
            {
                e.0 = PathBuf::from(format!("\0replaced-{prev}"));
            }
            t.nodes.get_mut(&id).unwrap().0 = newp;
        }
        let keys: Vec<PathBuf> = t
            .modes
            .keys()
            .filter(|p| p.starts_with(from))
            .cloned()
            .collect();
        for k in keys {
            let v = t.modes.remove(&k).unwrap();
            t.modes.insert(to.join(k.strip_prefix(from).unwrap()), v);
        }
    }

    /// Handle one FUSE request (`req` = header + body). Returns the reply bytes, or `None` for
    /// requests that get no reply (FORGET, BATCH_FORGET, INTERRUPT).
    pub fn handle(&self, req: &[u8]) -> Option<Vec<u8>> {
        let mut r = In(req);
        let hdr = (|| -> Result<_, i32> {
            let _len = r.u32()?;
            let opcode = r.u32()?;
            let unique = r.u64()?;
            let node = r.u64()?;
            let uid = r.u32()?;
            let gid = r.u32()?;
            let _pid = r.u32()?;
            let _ext = r.u32()?;
            Ok((opcode, unique, node, uid, gid))
        })();
        let Ok((opcode, unique, node, uid, gid)) = hdr else {
            return None;
        };
        let body = r.0;
        let result = match opcode {
            FORGET => {
                let n = In(body).u64().unwrap_or(0);
                self.forget(node, n);
                return None;
            }
            BATCH_FORGET => {
                let mut b = In(body);
                let count = b.u32().unwrap_or(0);
                let _ = b.u32();
                for _ in 0..count {
                    let (Ok(id), Ok(n)) = (b.u64(), b.u64()) else {
                        break;
                    };
                    self.forget(id, n);
                }
                return None;
            }
            INTERRUPT => return None,
            _ => self.dispatch(opcode, node, uid, gid, body),
        };
        let (err, payload) = match result {
            Ok(p) => (0, p),
            Err(e) => (-e, Vec::new()),
        };
        let mut o = Out::default();
        o.u32((16 + payload.len()) as u32)
            .u32(err as u32)
            .u64(unique);
        o.0.extend_from_slice(&payload);
        Some(o.0)
    }

    fn dispatch(&self, op: u32, node: u64, uid: u32, gid: u32, body: &[u8]) -> Reply {
        let mut b = In(body);
        match op {
            INIT => {
                let major = b.u32()?;
                let _minor = b.u32()?;
                let max_readahead = b.u32()?;
                let flags = b.u32()?;
                if major < 7 {
                    return Err(EPROTO_OLD);
                }
                let mut o = Out::default();
                o.u32(7)
                    .u32(31)
                    .u32(max_readahead)
                    .u32(flags & (FUSE_ASYNC_READ | FUSE_BIG_WRITES | FUSE_MAX_PAGES))
                    .u16(16) // max_background
                    .u16(12) // congestion_threshold
                    .u32(u32::from(MAX_PAGES) * 4096) // max_write
                    .u32(1) // time_gran (ns)
                    .u16(MAX_PAGES)
                    .u16(0) // map_alignment
                    .u32(0) // flags2
                    .u32(0); // max_stack_depth
                o.0.resize(64, 0);
                Ok(o.0)
            }
            DESTROY => {
                let mut t = self.t.lock().unwrap();
                t.handles.clear();
                Ok(Vec::new())
            }
            LOOKUP => {
                let name = b.name()?;
                let rel = self.child(node, name)?;
                self.entry(&rel, uid, gid)
            }
            GETATTR => self.attr_reply(&self.rel(node)?, uid, gid),
            SETATTR => {
                let valid = b.u32()?;
                let _pad = b.u32()?;
                let fh = b.u64()?;
                let size = b.u64()?;
                let _lock_owner = b.u64()?;
                let atime = b.u64()?;
                let mtime = b.u64()?;
                let _ctime = b.u64()?;
                let atimensec = b.u32()?;
                let mtimensec = b.u32()?;
                let _ctimensec = b.u32()?;
                let mode = b.u32()?;
                let rel = self.rel(node)?;
                let abs = self.abs(&rel);
                if valid & (FATTR_SIZE | FATTR_ATIME | FATTR_MTIME | FATTR_MODE) != 0 {
                    self.writable()?;
                }
                if valid & FATTR_SIZE != 0 {
                    let via_fh = valid & FATTR_FH != 0;
                    let t = self.t.lock().unwrap();
                    match t.handles.get(&fh) {
                        Some(Handle::File { file, .. }) if via_fh => {
                            file.set_len(size).map_err(|e| errno(&e))?
                        }
                        _ => {
                            drop(t);
                            OpenOptions::new()
                                .write(true)
                                .open(&abs)
                                .and_then(|f| f.set_len(size))
                                .map_err(|e| errno(&e))?
                        }
                    }
                }
                if valid & (FATTR_ATIME | FATTR_MTIME) != 0 {
                    let pick = |set: u32, now: u32, s: u64, ns: u32| -> Option<SystemTime> {
                        if valid & now != 0 {
                            Some(SystemTime::now())
                        } else if valid & set != 0 {
                            Some(UNIX_EPOCH + Duration::new(s, ns))
                        } else {
                            None
                        }
                    };
                    let mut times = std::fs::FileTimes::new();
                    if let Some(a) = pick(FATTR_ATIME, FATTR_ATIME_NOW, atime, atimensec) {
                        times = times.set_accessed(a);
                    }
                    if let Some(m) = pick(FATTR_MTIME, FATTR_MTIME_NOW, mtime, mtimensec) {
                        times = times.set_modified(m);
                    }
                    // directories cannot be opened for writing here: their times are left alone
                    if let Ok(f) = OpenOptions::new().write(true).open(&abs) {
                        let _ = f.set_times(times);
                    }
                }
                if valid & FATTR_MODE != 0 {
                    self.set_mode(&rel, mode)?;
                }
                self.attr_reply(&rel, uid, gid)
            }
            READLINK => {
                let target =
                    std::fs::read_link(self.abs(&self.rel(node)?)).map_err(|e| errno(&e))?;
                Ok(target.to_string_lossy().replace('\\', "/").into_bytes())
            }
            SYMLINK => {
                self.writable()?;
                let name = b.name()?;
                let target = b.name()?;
                let rel = self.child(node, name)?;
                make_symlink(&self.abs(&rel), target).map_err(|e| errno(&e))?;
                self.entry(&rel, uid, gid)
            }
            MKNOD => {
                self.writable()?;
                let mode = b.u32()?;
                let _rdev = b.u32()?;
                let _umask = b.u32()?;
                let _pad = b.u32()?;
                let name = b.name()?;
                if mode & 0o170_000 != S_IFREG {
                    return Err(EPERM);
                }
                let rel = self.child(node, name)?;
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(self.abs(&rel))
                    .map_err(|e| errno(&e))?;
                if mode & 0o111 != 0 {
                    self.set_mode(&rel, mode)?;
                }
                self.entry(&rel, uid, gid)
            }
            MKDIR => {
                self.writable()?;
                let _mode = b.u32()?;
                let _umask = b.u32()?;
                let name = b.name()?;
                let rel = self.child(node, name)?;
                std::fs::create_dir(self.abs(&rel)).map_err(|e| errno(&e))?;
                self.entry(&rel, uid, gid)
            }
            UNLINK => {
                self.writable()?;
                let rel = self.child(node, b.name()?)?;
                let abs = self.abs(&rel);
                let m = std::fs::symlink_metadata(&abs).map_err(|e| errno(&e))?;
                if m.is_dir() {
                    return Err(EISDIR);
                }
                // a Windows directory symlink is removed like a directory
                let r = std::fs::remove_file(&abs).or_else(|e| {
                    if m.file_type().is_symlink() {
                        std::fs::remove_dir(&abs)
                    } else {
                        Err(e)
                    }
                });
                r.map_err(|e| errno(&e))?;
                self.t.lock().unwrap().modes.remove(&rel);
                Ok(Vec::new())
            }
            RMDIR => {
                self.writable()?;
                let rel = self.child(node, b.name()?)?;
                std::fs::remove_dir(self.abs(&rel)).map_err(|e| errno(&e))?;
                Ok(Vec::new())
            }
            RENAME | RENAME2 => {
                self.writable()?;
                let newdir = b.u64()?;
                let flags = if op == RENAME2 {
                    let f = b.u32()?;
                    let _pad = b.u32()?;
                    f
                } else {
                    0
                };
                let from = self.child(node, b.name()?)?;
                let to = self.child(newdir, b.name()?)?;
                let (afrom, ato) = (self.abs(&from), self.abs(&to));
                if flags & 2 != 0 {
                    return Err(EINVAL); // RENAME_EXCHANGE
                }
                let target = std::fs::symlink_metadata(&ato).ok();
                if flags & 1 != 0 && target.is_some() {
                    return Err(EEXIST); // RENAME_NOREPLACE
                }
                // POSIX rename replaces an empty directory; Windows refuses: remove it first
                if let Some(t) = &target
                    && t.is_dir()
                    && std::fs::symlink_metadata(&afrom).is_ok_and(|m| m.is_dir())
                {
                    std::fs::remove_dir(&ato).map_err(|e| errno(&e))?;
                }
                std::fs::rename(&afrom, &ato).map_err(|e| errno(&e))?;
                self.renamed(&from, &to);
                Ok(Vec::new())
            }
            LINK => {
                self.writable()?;
                let old = self.rel(b.u64()?)?;
                let rel = self.child(node, b.name()?)?;
                std::fs::hard_link(self.abs(&old), self.abs(&rel)).map_err(|e| errno(&e))?;
                self.entry(&rel, uid, gid)
            }
            OPEN => {
                let flags = b.u32()?;
                let acc = flags & O_ACCMODE;
                if acc != 0 || flags & O_TRUNC != 0 {
                    self.writable()?;
                }
                let rel = self.rel(node)?;
                let file = OpenOptions::new()
                    .read(acc != O_WRONLY)
                    .write(acc == O_WRONLY || acc == O_RDWR)
                    .truncate(flags & O_TRUNC != 0 && acc != 0)
                    .open(self.abs(&rel))
                    .map_err(|e| errno(&e))?;
                let fh = self.new_handle(Handle::File {
                    file,
                    append: flags & O_APPEND != 0,
                });
                let mut o = Out::default();
                o.u64(fh).u32(0).u32(0);
                Ok(o.0)
            }
            CREATE => {
                self.writable()?;
                let flags = b.u32()?;
                let mode = b.u32()?;
                let _umask = b.u32()?;
                let _open_flags = b.u32()?;
                let rel = self.child(node, b.name()?)?;
                let acc = flags & O_ACCMODE;
                let mut oo = OpenOptions::new();
                oo.read(acc != O_WRONLY).write(true);
                if flags & O_EXCL != 0 {
                    oo.create_new(true);
                } else {
                    oo.create(true).truncate(flags & O_TRUNC != 0);
                }
                let file = oo.open(self.abs(&rel)).map_err(|e| errno(&e))?;
                if mode & 0o111 != 0 {
                    self.set_mode(&rel, mode)?;
                }
                let mut entry = self.entry(&rel, uid, gid)?;
                let fh = self.new_handle(Handle::File {
                    file,
                    append: flags & O_APPEND != 0,
                });
                let mut o = Out::default();
                o.u64(fh).u32(0).u32(0);
                entry.extend_from_slice(&o.0);
                Ok(entry)
            }
            READ => {
                let fh = b.u64()?;
                let offset = b.u64()?;
                let size = b.u32()? as usize;
                let t = self.t.lock().unwrap();
                let Some(Handle::File { file, .. }) = t.handles.get(&fh) else {
                    return Err(EBADF);
                };
                let mut buf = vec![0u8; size.min(u32::from(MAX_PAGES) as usize * 4096)];
                let mut got = 0;
                while got < buf.len() {
                    match read_at(file, &mut buf[got..], offset + got as u64) {
                        Ok(0) => break,
                        Ok(n) => got += n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(errno(&e)),
                    }
                }
                buf.truncate(got);
                Ok(buf)
            }
            WRITE => {
                self.writable()?;
                let fh = b.u64()?;
                let offset = b.u64()?;
                let size = b.u32()? as usize;
                let _write_flags = b.u32()?;
                let _lock_owner = b.u64()?;
                let _flags = b.u32()?;
                let _pad = b.u32()?;
                let data = b.take(size)?;
                let t = self.t.lock().unwrap();
                let Some(Handle::File { file, append }) = t.handles.get(&fh) else {
                    return Err(EBADF);
                };
                let at = if *append {
                    file.metadata().map_err(|e| errno(&e))?.len()
                } else {
                    offset
                };
                let mut done = 0;
                while done < data.len() {
                    match write_at(file, &data[done..], at + done as u64) {
                        Ok(0) => return Err(EIO),
                        Ok(n) => done += n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(errno(&e)),
                    }
                }
                let mut o = Out::default();
                o.u32(done as u32).u32(0);
                Ok(o.0)
            }
            STATFS => {
                let (total, free) = disk_space(&self.root);
                let bsize = 4096u64;
                let mut o = Out::default();
                o.u64(total / bsize)
                    .u64(free / bsize)
                    .u64(free / bsize)
                    .u64(1 << 20)
                    .u64(1 << 20)
                    .u32(bsize as u32)
                    .u32(255)
                    .u32(bsize as u32)
                    .u32(0);
                o.0.resize(80, 0);
                Ok(o.0)
            }
            RELEASE | RELEASEDIR => {
                let fh = b.u64()?;
                self.t.lock().unwrap().handles.remove(&fh);
                Ok(Vec::new())
            }
            FLUSH | FSYNCDIR => Ok(Vec::new()),
            FSYNC => {
                let fh = b.u64()?;
                let t = self.t.lock().unwrap();
                if let Some(Handle::File { file, .. }) = t.handles.get(&fh) {
                    file.sync_all().map_err(|e| errno(&e))?;
                }
                Ok(Vec::new())
            }
            OPENDIR => {
                let rel = self.rel(node)?;
                let abs = self.abs(&rel);
                let mut entries = vec![
                    (
                        if rel.as_os_str().is_empty() {
                            ROOT
                        } else {
                            hash_ino(&rel)
                        },
                        DT_DIR,
                        ".".to_owned(),
                    ),
                    (2, DT_DIR, "..".to_owned()),
                ];
                for e in std::fs::read_dir(&abs).map_err(|e| errno(&e))? {
                    let Ok(e) = e else { continue };
                    let name = e.file_name().to_string_lossy().into_owned();
                    if valid_name(&name).is_err() {
                        continue;
                    }
                    let kind = match e.file_type() {
                        Ok(t) if t.is_symlink() => DT_LNK,
                        Ok(t) if t.is_dir() => DT_DIR,
                        _ => DT_REG,
                    };
                    entries.push((hash_ino(&rel.join(&name)), kind, name));
                }
                let fh = self.new_handle(Handle::Dir(entries));
                let mut o = Out::default();
                o.u64(fh).u32(0).u32(0);
                Ok(o.0)
            }
            READDIR => {
                let fh = b.u64()?;
                let offset = b.u64()? as usize;
                let size = b.u32()? as usize;
                let t = self.t.lock().unwrap();
                let Some(Handle::Dir(entries)) = t.handles.get(&fh) else {
                    return Err(EBADF);
                };
                let mut o = Out::default();
                for (i, (ino, kind, name)) in entries.iter().enumerate().skip(offset) {
                    let rec = (24 + name.len()).div_ceil(8) * 8;
                    if o.0.len() + rec > size {
                        break;
                    }
                    o.u64(*ino)
                        .u64(i as u64 + 1)
                        .u32(name.len() as u32)
                        .u32(*kind);
                    o.0.extend_from_slice(name.as_bytes());
                    o.0.resize(o.0.len() + (rec - 24 - name.len()), 0);
                }
                Ok(o.0)
            }
            ACCESS => {
                let mask = b.u32()?;
                let rel = self.rel(node)?;
                std::fs::symlink_metadata(self.abs(&rel)).map_err(|e| errno(&e))?;
                if mask & 2 != 0 && self.read_only {
                    return Err(EROFS);
                }
                Ok(Vec::new())
            }
            GETXATTR => Err(ENODATA),
            LISTXATTR => {
                let size = b.u32()?;
                if size == 0 {
                    let mut o = Out::default();
                    o.u32(0).u32(0);
                    Ok(o.0)
                } else {
                    Ok(Vec::new())
                }
            }
            SETXATTR | REMOVEXATTR => Err(EOPNOTSUPP),
            LSEEK => {
                let fh = b.u64()?;
                let offset = b.u64()?;
                let whence = b.u32()?;
                let t = self.t.lock().unwrap();
                let Some(Handle::File { file, .. }) = t.handles.get(&fh) else {
                    return Err(EBADF);
                };
                let len = file.metadata().map_err(|e| errno(&e))?.len();
                let pos = match whence {
                    3 if offset < len => offset, // SEEK_DATA: no holes reported
                    4 if offset <= len => len,   // SEEK_HOLE: the end
                    3 | 4 => return Err(6),      // ENXIO
                    _ => return Err(EINVAL),
                };
                let mut o = Out::default();
                o.u64(pos);
                Ok(o.0)
            }
            FALLOCATE => {
                self.writable()?;
                let fh = b.u64()?;
                let offset = b.u64()?;
                let length = b.u64()?;
                let mode = b.u32()?;
                if mode != 0 {
                    return Err(EOPNOTSUPP);
                }
                let t = self.t.lock().unwrap();
                let Some(Handle::File { file, .. }) = t.handles.get(&fh) else {
                    return Err(EBADF);
                };
                let len = file.metadata().map_err(|e| errno(&e))?.len();
                if offset + length > len {
                    file.set_len(offset + length).map_err(|e| errno(&e))?;
                }
                Ok(Vec::new())
            }
            _ => Err(ENOSYS),
        }
    }
}

/// "Protocol too old": any major version below 7 cannot be served.
const EPROTO_OLD: i32 = 71;

fn read_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_at(f, buf, off)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_read(f, buf, off)
    }
}

fn write_at(f: &File, buf: &[u8], off: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::write_at(f, buf, off)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_write(f, buf, off)
    }
}

/// The chmod stored with a file (NTFS alternate data stream), if any.
fn read_mode_stream(abs: &Path) -> Option<u32> {
    if !cfg!(windows) {
        return None;
    }
    let mut s = String::new();
    File::open(format!("{}:osbx.mode", abs.display()))
        .ok()?
        .read_to_string(&mut s)
        .ok()?;
    u32::from_str_radix(s.trim(), 8).ok().map(|m| m & 0o7777)
}

fn write_mode_stream(abs: &Path, mode: u32) {
    if !cfg!(windows) {
        return;
    }
    if let Ok(mut f) = File::create(format!("{}:osbx.mode", abs.display())) {
        let _ = write!(f, "{mode:o}");
    }
}

fn make_symlink(link: &Path, target: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        let t = target.replace('/', "\\");
        let resolved = link.parent().map(|p| p.join(&t));
        if resolved.is_some_and(|r| r.is_dir()) {
            std::os::windows::fs::symlink_dir(&t, link)
        } else {
            std::os::windows::fs::symlink_file(&t, link)
        }
    }
}

/// (total, free) bytes of the volume holding `root`.
#[allow(unsafe_code)]
fn disk_space(root: &Path) -> (u64, u64) {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let wide: Vec<u16> = root
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
        // SAFETY: NUL-terminated wide path and valid out-pointers.
        if unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut avail, &mut total, &mut free) } != 0 {
            return (total, avail);
        }
    }
    let _ = root;
    (1 << 40, 1 << 39)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Req {
        unique: u64,
    }
    impl Req {
        fn call(&mut self, s: &Server, op: u32, node: u64, body: &[u8]) -> (i32, Vec<u8>) {
            self.unique += 1;
            let mut o = Out::default();
            o.u32((40 + body.len()) as u32)
                .u32(op)
                .u64(self.unique)
                .u64(node)
                .u32(1000)
                .u32(1000)
                .u32(1)
                .u32(0);
            o.0.extend_from_slice(body);
            let rep = s.handle(&o.0).expect("reply");
            let err = i32::from_le_bytes(rep[4..8].try_into().unwrap());
            assert_eq!(
                u64::from_le_bytes(rep[8..16].try_into().unwrap()),
                self.unique
            );
            (err, rep[16..].to_vec())
        }
    }
    fn name(n: &str) -> Vec<u8> {
        let mut v = n.as_bytes().to_vec();
        v.push(0);
        v
    }
    fn le64(b: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
    }
    fn le32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn create_write_read_rename_readdir_unlink() {
        let dir = std::env::temp_dir().join(format!("osbx-fuse-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("script.sh"), b"#!/bin/sh\necho hi\n").unwrap();
        let s = Server::new(&dir, false).unwrap();
        let mut r = Req { unique: 0 };

        // INIT
        let mut init = Out::default();
        init.u32(7)
            .u32(39)
            .u32(1 << 17)
            .u32(FUSE_ASYNC_READ | FUSE_MAX_PAGES);
        init.0.resize(64, 0);
        let (e, rep) = r.call(&s, INIT, 0, &init.0);
        assert_eq!(e, 0);
        assert_eq!((le32(&rep, 0), le32(&rep, 4)), (7, 31));

        // shebang file is executable, owned by the caller
        let (e, rep) = r.call(&s, LOOKUP, ROOT, &name("script.sh"));
        assert_eq!(e, 0);
        let attr = &rep[40..];
        assert_eq!(le32(attr, 60) & 0o777, 0o755);
        assert_eq!((le32(attr, 68), le32(attr, 72)), (1000, 1000));

        // CREATE + WRITE + READ
        let mut c = Out::default();
        c.u32(O_RDWR | O_TRUNC).u32(0o100_644).u32(0o022).u32(0);
        c.0.extend_from_slice(&name("a.txt"));
        let (e, rep) = r.call(&s, CREATE, ROOT, &c.0);
        assert_eq!(e, 0);
        let node = le64(&rep, 0);
        let fh = le64(&rep, 128);
        let mut w = Out::default();
        w.u64(fh).u64(0).u32(5).u32(0).u64(0).u32(0).u32(0);
        w.0.extend_from_slice(b"hello");
        let (e, rep) = r.call(&s, WRITE, node, &w.0);
        assert_eq!((e, le32(&rep, 0)), (0, 5));
        let mut rd = Out::default();
        rd.u64(fh).u64(1).u32(100).u32(0).u64(0).u32(0).u32(0);
        let (e, rep) = r.call(&s, READ, node, &rd.0);
        assert_eq!((e, rep.as_slice()), (0, &b"ello"[..]));
        let mut rel = Out::default();
        rel.u64(fh).u32(0).u32(0).u64(0);
        assert_eq!(r.call(&s, RELEASE, node, &rel.0).0, 0);

        // chmod +x persists (alternate data stream on Windows) and shows in GETATTR
        let mut sa = Out::default();
        sa.u32(FATTR_MODE)
            .u32(0)
            .u64(0)
            .u64(0)
            .u64(0)
            .u64(0)
            .u64(0)
            .u64(0)
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(0o100_755);
        sa.0.resize(88, 0);
        let (e, rep) = r.call(&s, SETATTR, node, &sa.0);
        assert_eq!(e, 0);
        assert_eq!(le32(&rep[16..], 60) & 0o777, 0o755);

        // RENAME into sub/, then the old node id follows the file
        let sub = le64(&r.call(&s, LOOKUP, ROOT, &name("sub")).1, 0);
        let mut rn = Out::default();
        rn.u64(sub);
        rn.0.extend_from_slice(&name("a.txt"));
        rn.0.extend_from_slice(&name("b.txt"));
        assert_eq!(r.call(&s, RENAME, ROOT, &rn.0).0, 0);
        assert!(dir.join("sub").join("b.txt").exists());
        let (e, rep) = r.call(&s, GETATTR, node, &[0u8; 16]);
        assert_eq!((e, le64(&rep[16..], 8)), (0, 5));

        // READDIR lists . .. and the file
        let (e, rep) = r.call(&s, OPENDIR, sub, &[0u8; 8]);
        assert_eq!(e, 0);
        let dfh = le64(&rep, 0);
        let mut rdd = Out::default();
        rdd.u64(dfh).u64(0).u32(4096).u32(0).u64(0).u32(0).u32(0);
        let (e, rep) = r.call(&s, READDIR, sub, &rdd.0);
        assert_eq!(e, 0);
        let listing = String::from_utf8_lossy(&rep);
        assert!(listing.contains("b.txt"));

        // escapes and alternate streams are refused; UNLINK; missing files are ENOENT
        assert_eq!(r.call(&s, LOOKUP, ROOT, &name("..")).0, -EINVAL);
        assert_eq!(r.call(&s, LOOKUP, ROOT, &name("x:stream")).0, -EINVAL);
        assert_eq!(r.call(&s, UNLINK, sub, &name("b.txt")).0, 0);
        assert_eq!(r.call(&s, LOOKUP, sub, &name("b.txt")).0, -ENOENT);
        assert_eq!(r.call(&s, 9999, ROOT, &[]).0, -ENOSYS);

        // read-only shares refuse changes
        let ro = Server::new(&dir, true).unwrap();
        assert_eq!(
            r.call(
                &ro,
                MKDIR,
                ROOT,
                &[[0u8; 8].as_slice(), &name("x")].concat()
            )
            .0,
            -EROFS
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
