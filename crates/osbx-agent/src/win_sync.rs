//! Pure-Rust bidirectional `sync` backend and shared `FILE_SYNC_PORT` RPC client for Windows guests.
//!
//! Zero external kernel drivers, zero WinFsp/Dokany dependencies: mirrors a host directory exposed
//! over vsock [`FILE_SYNC_PORT`] onto a native NTFS directory inside the guest, keeping changes in
//! sync both ways (host -> guest via `Watch` events, guest -> host via `ReadDirectoryChangesW` on
//! read-write shares).

#![allow(unsafe_code)]

use crate::windows::{HOST_CID, OwnedHandle, VsockConn, vsock_connect, wide};
use osbx_proto::{
    FILE_SYNC_PORT, FS_DATA, FS_EVENT, FS_REQ, FS_RESP, FileEntry, FileSyncEvent, FileSyncReq,
    FileSyncResp, read_frame, write_frame,
};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_REMOVED,
    FILE_ACTION_RENAMED_NEW_NAME, FILE_ACTION_RENAMED_OLD_NAME, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_READONLY, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE,
    FILE_NOTIFY_CHANGE_SIZE, FILE_NOTIFY_INFORMATION, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetFileAttributesW, INVALID_FILE_ATTRIBUTES, OPEN_EXISTING,
    ReadDirectoryChangesW, SetFileAttributesW,
};

const SYNC_CHUNK: usize = 256 * 1024;
const ECHO_SUPPRESS_TTL: Duration = Duration::from_millis(1500);

/// Client for the host's [`FILE_SYNC_PORT`] RPC service.
pub(crate) struct FileSyncClient {
    conn: VsockConn,
}

impl FileSyncClient {
    /// Connect to the host file-sync service over `AF_VSOCK`.
    pub(crate) fn connect(af: u16) -> io::Result<Self> {
        let conn = vsock_connect(af, HOST_CID, FILE_SYNC_PORT)?;
        Ok(Self { conn })
    }

    fn send_req(&mut self, req: &FileSyncReq) -> io::Result<()> {
        let payload = serde_json::to_vec(req).map_err(io::Error::other)?;
        write_frame(&mut self.conn, FS_REQ, &payload)
    }

    fn recv_resp(&mut self) -> io::Result<FileSyncResp> {
        match read_frame(&mut self.conn)? {
            Some((FS_RESP, payload)) => serde_json::from_slice(&payload).map_err(io::Error::other),
            Some((ty, _)) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected file-sync frame 0x{ty:02x}"),
            )),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "host closed file-sync connection",
            )),
        }
    }

    /// List immediate children of `path` (empty string for share root).
    pub(crate) fn list_dir(&mut self, tag: &str, path: &str) -> io::Result<Vec<FileEntry>> {
        self.send_req(&FileSyncReq::ListDir {
            tag: tag.to_owned(),
            path: path.to_owned(),
        })?;
        match self.recv_resp()? {
            FileSyncResp::Entries { entries } => Ok(entries),
            FileSyncResp::NotFound => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
            FileSyncResp::ReadOnly => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read-only share",
            )),
            FileSyncResp::InvalidPath { message } | FileSyncResp::Error { message } => {
                Err(io::Error::other(message))
            }
            other => Err(io::Error::other(format!("unexpected response: {other:?}"))),
        }
    }

    /// Fetch metadata for `path`; returns `Ok(None)` if not found.
    pub(crate) fn stat(&mut self, tag: &str, path: &str) -> io::Result<Option<FileEntry>> {
        self.send_req(&FileSyncReq::Stat {
            tag: tag.to_owned(),
            path: path.to_owned(),
        })?;
        match self.recv_resp()? {
            FileSyncResp::Meta { entry } => Ok(Some(entry)),
            FileSyncResp::NotFound => Ok(None),
            FileSyncResp::ReadOnly => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read-only share",
            )),
            FileSyncResp::InvalidPath { message } | FileSyncResp::Error { message } => {
                Err(io::Error::other(message))
            }
            other => Err(io::Error::other(format!("unexpected response: {other:?}"))),
        }
    }

    /// Read up to `len` bytes from `path` starting at `offset`.
    pub(crate) fn read_file(
        &mut self,
        tag: &str,
        path: &str,
        offset: u64,
        len: u32,
    ) -> io::Result<Vec<u8>> {
        self.send_req(&FileSyncReq::ReadFile {
            tag: tag.to_owned(),
            path: path.to_owned(),
            offset,
            len,
        })?;
        match self.recv_resp()? {
            FileSyncResp::Data { len: expected } => match read_frame(&mut self.conn)? {
                Some((FS_DATA, data)) if data.len() == expected as usize => Ok(data),
                Some((FS_DATA, data)) => Ok(data),
                other => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected FS_DATA, got {other:?}"),
                )),
            },
            FileSyncResp::NotFound => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
            FileSyncResp::InvalidPath { message } | FileSyncResp::Error { message } => {
                Err(io::Error::other(message))
            }
            other => Err(io::Error::other(format!("unexpected response: {other:?}"))),
        }
    }

    /// Write `data` to `path` at `offset`, optionally truncating to `offset + data.len()`.
    pub(crate) fn write_file(
        &mut self,
        tag: &str,
        path: &str,
        offset: u64,
        data: &[u8],
        truncate: bool,
    ) -> io::Result<()> {
        self.send_req(&FileSyncReq::WriteFile {
            tag: tag.to_owned(),
            path: path.to_owned(),
            offset,
            truncate,
        })?;
        write_frame(&mut self.conn, FS_DATA, data)?;
        match self.recv_resp()? {
            FileSyncResp::Ok => Ok(()),
            FileSyncResp::ReadOnly => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read-only share",
            )),
            FileSyncResp::InvalidPath { message } | FileSyncResp::Error { message } => {
                Err(io::Error::other(message))
            }
            other => Err(io::Error::other(format!("unexpected response: {other:?}"))),
        }
    }

    /// Create directory `path` (and parents) on the host.
    pub(crate) fn mkdir(&mut self, tag: &str, path: &str) -> io::Result<()> {
        self.send_req(&FileSyncReq::Mkdir {
            tag: tag.to_owned(),
            path: path.to_owned(),
        })?;
        match self.recv_resp()? {
            FileSyncResp::Ok => Ok(()),
            FileSyncResp::ReadOnly => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read-only share",
            )),
            FileSyncResp::InvalidPath { message } | FileSyncResp::Error { message } => {
                Err(io::Error::other(message))
            }
            other => Err(io::Error::other(format!("unexpected response: {other:?}"))),
        }
    }

    /// Remove `path` on the host.
    pub(crate) fn remove(&mut self, tag: &str, path: &str, recursive: bool) -> io::Result<()> {
        self.send_req(&FileSyncReq::Remove {
            tag: tag.to_owned(),
            path: path.to_owned(),
            recursive,
        })?;
        match self.recv_resp()? {
            FileSyncResp::Ok | FileSyncResp::NotFound => Ok(()),
            FileSyncResp::ReadOnly => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read-only share",
            )),
            FileSyncResp::InvalidPath { message } | FileSyncResp::Error { message } => {
                Err(io::Error::other(message))
            }
            other => Err(io::Error::other(format!("unexpected response: {other:?}"))),
        }
    }

    /// Rename `from` -> `to` on the host.
    pub(crate) fn rename(&mut self, tag: &str, from: &str, to: &str) -> io::Result<()> {
        self.send_req(&FileSyncReq::Rename {
            tag: tag.to_owned(),
            from: from.to_owned(),
            to: to.to_owned(),
        })?;
        match self.recv_resp()? {
            FileSyncResp::Ok => Ok(()),
            FileSyncResp::ReadOnly => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read-only share",
            )),
            FileSyncResp::NotFound => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
            FileSyncResp::InvalidPath { message } | FileSyncResp::Error { message } => {
                Err(io::Error::other(message))
            }
            other => Err(io::Error::other(format!("unexpected response: {other:?}"))),
        }
    }

    /// Subscribe to host-side watch events, consuming `self` and returning the underlying stream.
    pub(crate) fn into_watch(mut self, tag: &str) -> io::Result<VsockConn> {
        self.send_req(&FileSyncReq::Watch {
            tag: tag.to_owned(),
        })?;
        match self.recv_resp()? {
            FileSyncResp::Ok => Ok(self.conn),
            FileSyncResp::NotFound => Err(io::Error::new(io::ErrorKind::NotFound, "unknown tag")),
            FileSyncResp::InvalidPath { message } | FileSyncResp::Error { message } => {
                Err(io::Error::other(message))
            }
            other => Err(io::Error::other(format!("unexpected response: {other:?}"))),
        }
    }
}

/// Start a pure-Rust bidirectional `sync` mount on native NTFS.
///
/// Performs the initial host -> guest sync synchronously before returning so the target directory
/// is immediately populated when the `MOUNT` RPC replies `OK`.
pub(crate) fn start_sync_mount(
    af: u16,
    tag: String,
    target: String,
    read_only: bool,
) -> io::Result<Arc<AtomicBool>> {
    let root = PathBuf::from(&target);
    fs::create_dir_all(&root)?;

    let mut init_client = FileSyncClient::connect(af)?;
    sync_dir_from_host(&mut init_client, &tag, "", &root, read_only)?;
    drop(init_client);

    let stop = Arc::new(AtomicBool::new(false));
    let recent_from_host: Arc<Mutex<HashMap<String, Instant>>> = Arc::default();

    // Thread 1: Host -> Guest live watch consumer.
    {
        let (tag, root, stop, recent) = (
            tag.clone(),
            root.clone(),
            stop.clone(),
            recent_from_host.clone(),
        );
        thread::spawn(move || host_to_guest_loop(af, &tag, &root, read_only, &stop, &recent));
    }

    // Thread 2: Guest -> Host live NTFS watcher (read-write mounts only).
    if !read_only {
        let (tag, root, stop, recent) = (tag, root, stop.clone(), recent_from_host);
        thread::spawn(move || guest_to_host_loop(af, &tag, &root, &stop, &recent));
    }

    Ok(stop)
}

fn set_readonly_attr(path: &Path, ro: bool) {
    let w = wide(&path.to_string_lossy());
    // SAFETY: queries Win32 file attributes for a NUL-terminated UTF-16 path.
    let attrs = unsafe { GetFileAttributesW(w.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return;
    }
    let next = if ro {
        attrs | FILE_ATTRIBUTE_READONLY
    } else {
        let cleared = attrs & !FILE_ATTRIBUTE_READONLY;
        if cleared == 0 {
            FILE_ATTRIBUTE_NORMAL
        } else {
            cleared
        }
    };
    if next != attrs {
        // SAFETY: updates Win32 read-only attribute bit on existing path.
        unsafe {
            SetFileAttributesW(w.as_ptr(), next);
        }
    }
}

fn remove_local_path(path: &Path) {
    if !path.exists() {
        return;
    }
    if path.is_dir() {
        if let Ok(rd) = fs::read_dir(path) {
            for e in rd.flatten() {
                remove_local_path(&e.path());
            }
        }
        set_readonly_attr(path, false);
        let _ = fs::remove_dir_all(path);
    } else {
        set_readonly_attr(path, false);
        let _ = fs::remove_file(path);
    }
}

fn pull_file_from_host(
    client: &mut FileSyncClient,
    tag: &str,
    rel: &str,
    local: &Path,
    size: u64,
    mark_ro: bool,
) -> io::Result<()> {
    if let Some(parent) = local.parent() {
        fs::create_dir_all(parent)?;
    }
    if local.exists() {
        set_readonly_attr(local, false);
    }
    let mut f = File::create(local)?;
    let mut offset = 0u64;
    while offset < size {
        let to_read = (size - offset).min(SYNC_CHUNK as u64) as u32;
        let data = client.read_file(tag, rel, offset, to_read)?;
        if data.is_empty() {
            break;
        }
        f.write_all(&data)?;
        offset += data.len() as u64;
    }
    f.flush()?;
    drop(f);
    if mark_ro {
        set_readonly_attr(local, true);
    }
    Ok(())
}

fn sync_dir_from_host(
    client: &mut FileSyncClient,
    tag: &str,
    rel_dir: &str,
    local_dir: &Path,
    share_ro: bool,
) -> io::Result<()> {
    fs::create_dir_all(local_dir)?;
    let entries = client.list_dir(tag, rel_dir)?;
    let mut seen: HashSet<String> = HashSet::with_capacity(entries.len());

    for entry in &entries {
        seen.insert(entry.name.to_ascii_lowercase());
        let child_rel = if rel_dir.is_empty() {
            entry.name.clone()
        } else {
            format!("{rel_dir}/{}", entry.name)
        };
        let child_local = local_dir.join(&entry.name);
        if entry.is_dir {
            if child_local.is_file() {
                remove_local_path(&child_local);
            }
            sync_dir_from_host(client, tag, &child_rel, &child_local, share_ro)?;
        } else {
            if child_local.is_dir() {
                remove_local_path(&child_local);
            }
            let up_to_date = fs::metadata(&child_local).ok().is_some_and(|m| {
                let mtime_secs = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_secs() as i64);
                m.is_file() && m.len() == entry.size && (mtime_secs - entry.mtime_secs).abs() <= 2
            });
            if !up_to_date {
                pull_file_from_host(
                    client,
                    tag,
                    &child_rel,
                    &child_local,
                    entry.size,
                    share_ro || entry.read_only,
                )?;
            } else if share_ro || entry.read_only {
                set_readonly_attr(&child_local, true);
            }
        }
    }

    // Remove local entries that do not exist on the host.
    if let Ok(rd) = fs::read_dir(local_dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_ascii_lowercase();
            if !seen.contains(&name) {
                remove_local_path(&e.path());
            }
        }
    }
    Ok(())
}

fn record_host_echo(recent: &Mutex<HashMap<String, Instant>>, rel: &str) {
    let mut map = recent.lock().unwrap();
    let now = Instant::now();
    map.retain(|_, t| now.duration_since(*t) < ECHO_SUPPRESS_TTL);
    map.insert(rel.to_ascii_lowercase(), now);
}

fn is_host_echo(recent: &Mutex<HashMap<String, Instant>>, rel: &str) -> bool {
    let mut map = recent.lock().unwrap();
    let now = Instant::now();
    map.retain(|_, t| now.duration_since(*t) < ECHO_SUPPRESS_TTL);
    map.contains_key(&rel.to_ascii_lowercase())
}

fn host_to_guest_loop(
    af: u16,
    tag: &str,
    root: &Path,
    read_only: bool,
    stop: &AtomicBool,
    recent: &Mutex<HashMap<String, Instant>>,
) {
    while !stop.load(Ordering::Relaxed) {
        let Ok(watch_client) = FileSyncClient::connect(af) else {
            thread::sleep(Duration::from_secs(1));
            continue;
        };
        let Ok(mut watch_stream) = watch_client.into_watch(tag) else {
            thread::sleep(Duration::from_secs(1));
            continue;
        };
        let Ok(mut rpc) = FileSyncClient::connect(af) else {
            thread::sleep(Duration::from_secs(1));
            continue;
        };
        while !stop.load(Ordering::Relaxed) {
            match read_frame(&mut watch_stream) {
                Ok(Some((FS_EVENT, payload))) => {
                    let Ok(ev) = serde_json::from_slice::<FileSyncEvent>(&payload) else {
                        continue;
                    };
                    apply_host_event(&mut rpc, tag, root, read_only, recent, &ev);
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn apply_host_event(
    rpc: &mut FileSyncClient,
    tag: &str,
    root: &Path,
    share_ro: bool,
    recent: &Mutex<HashMap<String, Instant>>,
    ev: &FileSyncEvent,
) {
    if ev.path.is_empty() {
        return;
    }
    let local = root.join(ev.path.replace('/', "\\"));
    record_host_echo(recent, &ev.path);
    if ev.removed {
        remove_local_path(&local);
        return;
    }
    if ev.is_dir {
        let _ = fs::create_dir_all(&local);
        return;
    }
    if let Ok(Some(meta)) = rpc.stat(tag, &ev.path) {
        if meta.is_dir {
            let _ = fs::create_dir_all(&local);
        } else {
            let _ = pull_file_from_host(
                rpc,
                tag,
                &ev.path,
                &local,
                meta.size,
                share_ro || meta.read_only,
            );
        }
    }
}

fn push_file_to_host(client: &mut FileSyncClient, tag: &str, rel: &str, local: &Path) {
    let Ok(mut f) = File::open(local) else {
        return;
    };
    let mut buf = vec![0u8; SYNC_CHUNK];
    let mut offset = 0u64;
    let mut wrote_any = false;
    loop {
        match f.read(&mut buf) {
            Ok(0) => {
                if !wrote_any {
                    let _ = client.write_file(tag, rel, 0, &[], true);
                }
                break;
            }
            Ok(n) => {
                wrote_any = true;
                let is_last = n < buf.len();
                if client
                    .write_file(tag, rel, offset, &buf[..n], is_last)
                    .is_err()
                {
                    break;
                }
                offset += n as u64;
                if is_last {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn guest_to_host_loop(
    af: u16,
    tag: &str,
    root: &Path,
    stop: &AtomicBool,
    recent: &Mutex<HashMap<String, Instant>>,
) {
    let dir_w = wide(&root.to_string_lossy());
    // SAFETY: opens target NTFS directory for ReadDirectoryChangesW notifications.
    let h = unsafe {
        CreateFileW(
            dir_w.as_ptr(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        eprintln!(
            "osbx-agent sync: ReadDirectoryChangesW open failed for {}: {}",
            root.display(),
            io::Error::last_os_error()
        );
        return;
    }
    let dir_handle = OwnedHandle(h);
    let mut buf = vec![0u8; 64 * 1024];
    let mut client: Option<FileSyncClient> = None;

    while !stop.load(Ordering::Relaxed) {
        let mut bytes_returned: u32 = 0;
        // SAFETY: `buf` is 64 KiB writable memory aligned to at least 4 bytes via Vec<u8> allocation.
        let ok = unsafe {
            ReadDirectoryChangesW(
                dir_handle.0,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                1, // bWatchSubtree = TRUE
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE,
                &mut bytes_returned,
                null_mut(),
                None,
            )
        };
        if ok == 0 || bytes_returned == 0 {
            thread::sleep(Duration::from_millis(200));
            continue;
        }
        // Collect unique changed paths from this notification batch.
        let mut changes: Vec<(String, u32)> = Vec::new();
        let mut offset = 0usize;
        while offset + std::mem::size_of::<FILE_NOTIFY_INFORMATION>() <= bytes_returned as usize {
            // SAFETY: kernel-written `FILE_NOTIFY_INFORMATION` within `bytes_returned`.
            let info = unsafe { &*(buf.as_ptr().add(offset) as *const FILE_NOTIFY_INFORMATION) };
            let name_bytes = info.FileNameLength as usize;
            let name_off = offset + std::mem::offset_of!(FILE_NOTIFY_INFORMATION, FileName);
            if name_off + name_bytes <= bytes_returned as usize && name_bytes >= 2 {
                // SAFETY: UTF-16 slice inside `buf[name_off..name_off + name_bytes]`.
                let wide_slice = unsafe {
                    std::slice::from_raw_parts(
                        buf.as_ptr().add(name_off) as *const u16,
                        name_bytes / 2,
                    )
                };
                let rel = String::from_utf16_lossy(wide_slice).replace('\\', "/");
                changes.push((rel, info.Action));
            }
            if info.NextEntryOffset == 0 {
                break;
            }
            offset += info.NextEntryOffset as usize;
        }

        if changes.is_empty() {
            continue;
        }
        // Small debounce so writes finish before we stream bytes to the host.
        thread::sleep(Duration::from_millis(120));

        if client.is_none() {
            client = FileSyncClient::connect(af).ok();
        }
        let Some(c) = client.as_mut() else {
            continue;
        };

        let mut seen_batch: HashSet<String> = HashSet::new();
        for (rel, action) in changes {
            if rel.is_empty() || is_host_echo(recent, &rel) {
                continue;
            }
            let key = rel.to_ascii_lowercase();
            if !seen_batch.insert(key) {
                continue;
            }
            let local = root.join(rel.replace('/', "\\"));
            match action {
                FILE_ACTION_REMOVED | FILE_ACTION_RENAMED_OLD_NAME => {
                    if !local.exists() && c.remove(tag, &rel, true).is_err() {
                        client = None;
                        break;
                    }
                }
                FILE_ACTION_ADDED | FILE_ACTION_MODIFIED | FILE_ACTION_RENAMED_NEW_NAME => {
                    if let Ok(meta) = fs::metadata(&local) {
                        if meta.is_dir() {
                            if c.mkdir(tag, &rel).is_err() {
                                client = None;
                                break;
                            }
                        } else {
                            push_file_to_host(c, tag, &rel, &local);
                        }
                    } else if c.remove(tag, &rel, true).is_err() {
                        client = None;
                        break;
                    }
                }
                _ => {}
            }
        }
    }
}

/// Convert UNIX timestamp (`secs`, `nanos`) to Windows `FILETIME` ticks (100ns since 1601-01-01).
pub(crate) fn unix_to_filetime(secs: i64, nanos: u32) -> i64 {
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    let total_secs = secs.saturating_add(EPOCH_DIFF_SECS);
    total_secs
        .saturating_mul(10_000_000)
        .saturating_add(i64::from(nanos / 100))
}

/// Current time as Windows FILETIME ticks.
#[allow(dead_code)]
pub(crate) fn now_filetime() -> i64 {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    unix_to_filetime(d.as_secs() as i64, d.subsec_nanos())
}
