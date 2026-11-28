//! Windows inbox Projected File System (`ProjFS`) backend (`ProjectedFSLib.dll`).
//!
//! Dynamically loads `ProjectedFSLib.dll` via `LoadLibraryW`/`GetProcAddress` (zero third-party
//! kernel drivers, zero GPL/LGPL dependencies) and serves host files lazily on demand over
//! [`FILE_SYNC_PORT`]. Read-only shares deny `PRE_DELETE`/`PRE_RENAME`/`PRE_CONVERT_TO_FULL` at
//! the ProjFS filter boundary; read-write shares flush hydrated mutations back to the host and
//! invalidate stale placeholders on host `Watch` events.

#![allow(unsafe_code)]

use crate::win_sync::{FileSyncClient, unix_to_filetime};
use crate::windows::{wide, win_err_to_io};
use osbx_proto::{FS_EVENT, FileEntry, FileSyncEvent, read_frame};
use std::collections::HashMap;
use std::ffi::c_void;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY,
};
use windows_sys::Win32::Storage::ProjectedFileSystem::{
    PRJ_CALLBACK_DATA, PRJ_CALLBACKS, PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN,
    PRJ_DIR_ENTRY_BUFFER_HANDLE, PRJ_FILE_BASIC_INFO, PRJ_FLAG_NONE,
    PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT, PRJ_NOTIFICATION,
    PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_DELETED,
    PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED, PRJ_NOTIFICATION_FILE_OVERWRITTEN,
    PRJ_NOTIFICATION_FILE_PRE_CONVERT_TO_FULL, PRJ_NOTIFICATION_FILE_RENAMED,
    PRJ_NOTIFICATION_MAPPING, PRJ_NOTIFICATION_NEW_FILE_CREATED, PRJ_NOTIFICATION_PARAMETERS,
    PRJ_NOTIFICATION_PRE_DELETE, PRJ_NOTIFICATION_PRE_RENAME, PRJ_NOTIFICATION_PRE_SET_HARDLINK,
    PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_DELETED, PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_MODIFIED,
    PRJ_NOTIFY_FILE_OVERWRITTEN, PRJ_NOTIFY_FILE_PRE_CONVERT_TO_FULL, PRJ_NOTIFY_FILE_RENAMED,
    PRJ_NOTIFY_NEW_FILE_CREATED, PRJ_NOTIFY_PRE_DELETE, PRJ_NOTIFY_PRE_RENAME,
    PRJ_NOTIFY_PRE_SET_HARDLINK, PRJ_PLACEHOLDER_INFO, PRJ_PLACEHOLDER_VERSION_INFO,
    PRJ_STARTVIRTUALIZING_OPTIONS, PRJ_UPDATE_ALLOW_DIRTY_DATA, PRJ_UPDATE_ALLOW_DIRTY_METADATA,
    PRJ_UPDATE_ALLOW_READ_ONLY, PRJ_UPDATE_ALLOW_TOMBSTONE, PRJ_UPDATE_FAILURE_CAUSES,
    PRJ_UPDATE_TYPES,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW,
};
use windows_sys::core::{GUID, HRESULT, PCWSTR};

const S_OK: HRESULT = 0;
const HRESULT_FILE_NOT_FOUND: HRESULT = 0x8007_0002u32 as i32;
const HRESULT_ACCESS_DENIED: HRESULT = 0x8007_0005u32 as i32;
const HRESULT_INSUFFICIENT_BUFFER: HRESULT = 0x8007_007Au32 as i32;
const HRESULT_REPARSE_POINT_ENCOUNTERED: HRESULT = 0x8007_112Bu32 as i32;
const E_FAIL: HRESULT = 0x8000_4005u32 as i32;

type FnPrjMarkDirectoryAsPlaceholder = unsafe extern "system" fn(
    rootpathname: PCWSTR,
    targetpathname: PCWSTR,
    versioninfo: *const PRJ_PLACEHOLDER_VERSION_INFO,
    virtualizationinstanceid: *const GUID,
) -> HRESULT;
type FnPrjStartVirtualizing = unsafe extern "system" fn(
    virtualizationrootpath: PCWSTR,
    callbacks: *const PRJ_CALLBACKS,
    instancecontext: *const c_void,
    options: *const PRJ_STARTVIRTUALIZING_OPTIONS,
    namespacevirtualizationcontext: *mut PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
) -> HRESULT;
type FnPrjStopVirtualizing =
    unsafe extern "system" fn(namespacevirtualizationcontext: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT);
type FnPrjFillDirEntryBuffer = unsafe extern "system" fn(
    filename: PCWSTR,
    filebasicinfo: *const PRJ_FILE_BASIC_INFO,
    direntrybufferhandle: PRJ_DIR_ENTRY_BUFFER_HANDLE,
) -> HRESULT;
type FnPrjWritePlaceholderInfo = unsafe extern "system" fn(
    namespacevirtualizationcontext: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    destinationfilename: PCWSTR,
    placeholderinfo: *const PRJ_PLACEHOLDER_INFO,
    placeholderinfosize: u32,
) -> HRESULT;
type FnPrjWriteFileData = unsafe extern "system" fn(
    namespacevirtualizationcontext: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    datastreamid: *const GUID,
    buffer: *const c_void,
    byteoffset: u64,
    length: u32,
) -> HRESULT;
type FnPrjAllocateAlignedBuffer = unsafe extern "system" fn(
    namespacevirtualizationcontext: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    size: usize,
) -> *mut c_void;
type FnPrjFreeAlignedBuffer = unsafe extern "system" fn(buffer: *const c_void);
type FnPrjDeleteFile = unsafe extern "system" fn(
    namespacevirtualizationcontext: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    destinationfilename: PCWSTR,
    updateflags: PRJ_UPDATE_TYPES,
    failurereason: *mut PRJ_UPDATE_FAILURE_CAUSES,
) -> HRESULT;
type FnPrjClearNegativePathCache = unsafe extern "system" fn(
    namespacevirtualizationcontext: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT,
    totalentrynumber: *mut u32,
) -> HRESULT;
type FnPrjFileNameMatch =
    unsafe extern "system" fn(filenametocheck: PCWSTR, pattern: PCWSTR) -> bool;
type FnPrjFileNameCompare = unsafe extern "system" fn(filename1: PCWSTR, filename2: PCWSTR) -> i32;

struct ProjFsApi {
    mark_dir: FnPrjMarkDirectoryAsPlaceholder,
    start: FnPrjStartVirtualizing,
    #[allow(dead_code)]
    stop: FnPrjStopVirtualizing,
    fill_dir: FnPrjFillDirEntryBuffer,
    write_placeholder: FnPrjWritePlaceholderInfo,
    write_data: FnPrjWriteFileData,
    alloc_aligned: FnPrjAllocateAlignedBuffer,
    free_aligned: FnPrjFreeAlignedBuffer,
    delete_file: FnPrjDeleteFile,
    clear_neg_cache: FnPrjClearNegativePathCache,
    name_match: FnPrjFileNameMatch,
    name_compare: FnPrjFileNameCompare,
}

// SAFETY: `ProjFsApi` holds immutable process-wide DLL function pointers loaded once.
unsafe impl Send for ProjFsApi {}
// SAFETY: `ProjFsApi` holds immutable process-wide DLL function pointers loaded once.
unsafe impl Sync for ProjFsApi {}

static PROJFS_API: OnceLock<Option<ProjFsApi>> = OnceLock::new();

fn load_projfs_api() -> Option<&'static ProjFsApi> {
    PROJFS_API
        .get_or_init(|| {
            // Verify `PrjFlt` kernel minifilter is enabled (`Client-ProjFS` feature installed).
            if !service_key_exists(r"SYSTEM\CurrentControlSet\Services\PrjFlt") {
                return None;
            }
            let dll = wide("ProjectedFSLib.dll");
            // SAFETY: dynamically loads the Windows inbox ProjectedFSLib.dll.
            let module = unsafe { LoadLibraryW(dll.as_ptr()) };
            if module.is_null() {
                return None;
            }
            macro_rules! sym {
                ($name:literal, $ty:ty) => {{
                    // SAFETY: resolves exported symbol from valid loaded DLL module.
                    let p = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) }?;
                    // SAFETY: function signature matches `projectedfslib.h`.
                    unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(p) }
                }};
            }
            Some(ProjFsApi {
                mark_dir: sym!(
                    "PrjMarkDirectoryAsPlaceholder",
                    FnPrjMarkDirectoryAsPlaceholder
                ),
                start: sym!("PrjStartVirtualizing", FnPrjStartVirtualizing),
                stop: sym!("PrjStopVirtualizing", FnPrjStopVirtualizing),
                fill_dir: sym!("PrjFillDirEntryBuffer", FnPrjFillDirEntryBuffer),
                write_placeholder: sym!("PrjWritePlaceholderInfo", FnPrjWritePlaceholderInfo),
                write_data: sym!("PrjWriteFileData", FnPrjWriteFileData),
                alloc_aligned: sym!("PrjAllocateAlignedBuffer", FnPrjAllocateAlignedBuffer),
                free_aligned: sym!("PrjFreeAlignedBuffer", FnPrjFreeAlignedBuffer),
                delete_file: sym!("PrjDeleteFile", FnPrjDeleteFile),
                clear_neg_cache: sym!("PrjClearNegativePathCache", FnPrjClearNegativePathCache),
                name_match: sym!("PrjFileNameMatch", FnPrjFileNameMatch),
                name_compare: sym!("PrjFileNameCompare", FnPrjFileNameCompare),
            })
        })
        .as_ref()
}

fn service_key_exists(subkey: &str) -> bool {
    let sub = wide(subkey);
    let mut hkey: HKEY = null_mut();
    // SAFETY: probes whether a Windows service registry key exists.
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut hkey) };
    if rc == 0 {
        // SAFETY: closes opened registry key.
        unsafe {
            RegCloseKey(hkey);
        }
        true
    } else {
        false
    }
}

/// True if Windows `Client-ProjFS` (`PrjFlt` + `ProjectedFSLib.dll`) is enabled and loadable.
pub(crate) fn is_projfs_available() -> bool {
    load_projfs_api().is_some()
}

struct EnumState {
    entries: Vec<FileEntry>,
    index: usize,
    loaded: bool,
    search_expr: Option<Vec<u16>>,
}

struct ProjFsInstance {
    api: &'static ProjFsApi,
    af: u16,
    tag: String,
    root: PathBuf,
    read_only: bool,
    rpc: Mutex<Option<FileSyncClient>>,
    enums: Mutex<HashMap<u128, EnumState>>,
    ns_ctx: AtomicUsize,
}

impl ProjFsInstance {
    fn with_rpc<T>(
        &self,
        mut f: impl FnMut(&mut FileSyncClient) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut guard = self.rpc.lock().unwrap();
        if guard.is_none() {
            *guard = Some(FileSyncClient::connect(self.af)?);
        }
        let res = f(guard.as_mut().unwrap());
        if res.is_err() {
            // Reconnect once in case the vsock connection reset.
            if let Ok(mut fresh) = FileSyncClient::connect(self.af) {
                let retry = f(&mut fresh);
                if retry.is_ok() {
                    *guard = Some(fresh);
                    return retry;
                }
            }
            *guard = None;
        }
        res
    }
}

fn guid_key(g: &GUID) -> u128 {
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&g.data1.to_le_bytes());
    b[4..6].copy_from_slice(&g.data2.to_le_bytes());
    b[6..8].copy_from_slice(&g.data3.to_le_bytes());
    b[8..16].copy_from_slice(&g.data4);
    u128::from_le_bytes(b)
}

fn make_instance_guid(tag: &str, target: &str) -> GUID {
    let mut h1: u64 = 0xcbf2_9ce4_8422_2325;
    let mut h2: u64 = 0x8422_2325_cbf2_9ce4;
    for b in tag.bytes().chain(Some(0)).chain(target.bytes()) {
        h1 = (h1 ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        h2 = (h2.wrapping_mul(0x0100_0000_01b3)) ^ u64::from(b);
    }
    GUID {
        data1: (h1 >> 32) as u32,
        data2: (h1 >> 16) as u16,
        data3: ((h1 as u16) & 0x0FFF) | 0x4000,
        data4: h2.to_le_bytes(),
    }
}

fn pcwstr_to_string(p: PCWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: `p` is a valid NUL-terminated UTF-16 string supplied by ProjFS.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` UTF-16 code units before NUL.
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(slice)
}

fn rel_from_cb(data: &PRJ_CALLBACK_DATA) -> String {
    pcwstr_to_string(data.FilePathName)
        .replace('\\', "/")
        .trim_matches('/')
        .to_owned()
}

fn entry_to_basic_info(entry: &FileEntry, share_ro: bool) -> PRJ_FILE_BASIC_INFO {
    let ft = unix_to_filetime(entry.mtime_secs, entry.mtime_nanos);
    let mut attrs = if entry.is_dir {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    if share_ro || entry.read_only {
        attrs |= FILE_ATTRIBUTE_READONLY;
    }
    PRJ_FILE_BASIC_INFO {
        IsDirectory: entry.is_dir,
        FileSize: if entry.is_dir { 0 } else { entry.size as i64 },
        CreationTime: ft,
        LastAccessTime: ft,
        LastWriteTime: ft,
        ChangeTime: ft,
        FileAttributes: attrs,
    }
}

unsafe fn instance_from_cb(data: *const PRJ_CALLBACK_DATA) -> &'static ProjFsInstance {
    // SAFETY: `InstanceContext` was passed as a leaked `&'static ProjFsInstance` to `PrjStartVirtualizing`.
    unsafe { &*((*data).InstanceContext as *const ProjFsInstance) }
}

unsafe extern "system" fn cb_start_dir_enum(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
) -> HRESULT {
    // SAFETY: ProjFS passes valid `callback_data` and `enumeration_id` pointers.
    let inst = unsafe { instance_from_cb(callback_data) };
    // SAFETY: `enumeration_id` is non-null.
    let key = guid_key(unsafe { &*enumeration_id });
    inst.enums.lock().unwrap().insert(
        key,
        EnumState {
            entries: Vec::new(),
            index: 0,
            loaded: false,
            search_expr: None,
        },
    );
    S_OK
}

unsafe extern "system" fn cb_end_dir_enum(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
) -> HRESULT {
    // SAFETY: ProjFS passes valid pointers.
    let inst = unsafe { instance_from_cb(callback_data) };
    // SAFETY: `enumeration_id` is non-null.
    let key = guid_key(unsafe { &*enumeration_id });
    inst.enums.lock().unwrap().remove(&key);
    S_OK
}

unsafe extern "system" fn cb_get_dir_enum(
    callback_data: *const PRJ_CALLBACK_DATA,
    enumeration_id: *const GUID,
    search_expression: PCWSTR,
    dir_entry_buffer_handle: PRJ_DIR_ENTRY_BUFFER_HANDLE,
) -> HRESULT {
    // SAFETY: ProjFS passes valid pointers.
    let data = unsafe { &*callback_data };
    // SAFETY: `InstanceContext` points to `ProjFsInstance`.
    let inst = unsafe { instance_from_cb(callback_data) };
    // SAFETY: `enumeration_id` is non-null.
    let key = guid_key(unsafe { &*enumeration_id });
    let restart = (data.Flags & PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN) != 0;

    let mut enums = inst.enums.lock().unwrap();
    let Some(state) = enums.get_mut(&key) else {
        return E_FAIL;
    };

    if restart || !state.loaded {
        let rel = rel_from_cb(data);
        let mut entries = match inst.with_rpc(|c| c.list_dir(&inst.tag, &rel)) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return HRESULT_FILE_NOT_FOUND,
            Err(_) => return E_FAIL,
        };
        // Sort using ProjFS's own Windows case-insensitive filename collation.
        entries.sort_by(|a, b| {
            let aw = wide(&a.name);
            let bw = wide(&b.name);
            // SAFETY: valid NUL-terminated UTF-16 strings passed to `PrjFileNameCompare`.
            let ord = unsafe { (inst.api.name_compare)(aw.as_ptr(), bw.as_ptr()) };
            ord.cmp(&0)
        });
        state.entries = entries;
        state.index = 0;
        state.loaded = true;
        state.search_expr = if !search_expression.is_null() {
            let s = pcwstr_to_string(search_expression);
            if s.is_empty() || s == "*" {
                None
            } else {
                Some(wide(&s))
            }
        } else {
            None
        };
    }

    while state.index < state.entries.len() {
        let entry = &state.entries[state.index];
        let name_w = wide(&entry.name);
        if let Some(pat) = &state.search_expr {
            // SAFETY: both `name_w` and `pat` are NUL-terminated UTF-16 strings.
            if !unsafe { (inst.api.name_match)(name_w.as_ptr(), pat.as_ptr()) } {
                state.index += 1;
                continue;
            }
        }
        let info = entry_to_basic_info(entry, inst.read_only);
        // SAFETY: fills one directory entry into ProjFS's buffer.
        let hr = unsafe { (inst.api.fill_dir)(name_w.as_ptr(), &info, dir_entry_buffer_handle) };
        if hr == HRESULT_INSUFFICIENT_BUFFER {
            // Return S_OK so ProjFS flushes the current buffer and asks for the remainder next call.
            break;
        }
        if hr < 0 {
            return hr;
        }
        state.index += 1;
    }

    S_OK
}

unsafe extern "system" fn cb_get_placeholder_info(
    callback_data: *const PRJ_CALLBACK_DATA,
) -> HRESULT {
    // SAFETY: ProjFS passes valid `callback_data`.
    let data = unsafe { &*callback_data };
    // SAFETY: `InstanceContext` points to `ProjFsInstance`.
    let inst = unsafe { instance_from_cb(callback_data) };
    let rel = rel_from_cb(data);
    let entry = match inst.with_rpc(|c| c.stat(&inst.tag, &rel)) {
        Ok(Some(e)) => e,
        Ok(None) => return HRESULT_FILE_NOT_FOUND,
        Err(_) => return E_FAIL,
    };
    let info = PRJ_PLACEHOLDER_INFO {
        FileBasicInfo: entry_to_basic_info(&entry, inst.read_only),
        ..Default::default()
    };
    // SAFETY: writes placeholder metadata for `data.FilePathName`.
    unsafe {
        (inst.api.write_placeholder)(
            data.NamespaceVirtualizationContext,
            data.FilePathName,
            &info,
            std::mem::size_of::<PRJ_PLACEHOLDER_INFO>() as u32,
        )
    }
}

unsafe extern "system" fn cb_get_file_data(
    callback_data: *const PRJ_CALLBACK_DATA,
    byte_offset: u64,
    length: u32,
) -> HRESULT {
    // SAFETY: ProjFS passes valid `callback_data`.
    let data = unsafe { &*callback_data };
    // SAFETY: `InstanceContext` points to `ProjFsInstance`.
    let inst = unsafe { instance_from_cb(callback_data) };
    let rel = rel_from_cb(data);

    let chunk_max = 256 * 1024u32;
    let alloc_len = (length as usize).min(chunk_max as usize).max(4096);
    // SAFETY: allocates a sector-aligned buffer for `PrjWriteFileData`.
    let aligned =
        unsafe { (inst.api.alloc_aligned)(data.NamespaceVirtualizationContext, alloc_len) };
    if aligned.is_null() {
        return E_FAIL;
    }

    let mut remaining = length;
    let mut cur_offset = byte_offset;
    let mut status = S_OK;
    while remaining > 0 {
        let want = remaining.min(alloc_len as u32);
        let bytes = match inst.with_rpc(|c| c.read_file(&inst.tag, &rel, cur_offset, want)) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                status = HRESULT_FILE_NOT_FOUND;
                break;
            }
            Err(_) => {
                status = E_FAIL;
                break;
            }
        };
        if bytes.is_empty() {
            break;
        }
        let n = bytes.len().min(alloc_len);
        // SAFETY: copies `n <= alloc_len` bytes into the aligned ProjFS buffer.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), aligned.cast::<u8>(), n);
        }
        // SAFETY: commits hydrated bytes to the ProjFS stream.
        let hr = unsafe {
            (inst.api.write_data)(
                data.NamespaceVirtualizationContext,
                &data.DataStreamId,
                aligned,
                cur_offset,
                n as u32,
            )
        };
        if hr < 0 {
            status = hr;
            break;
        }
        cur_offset += n as u64;
        remaining = remaining.saturating_sub(n as u32);
    }

    // SAFETY: frees aligned buffer allocated above.
    unsafe {
        (inst.api.free_aligned)(aligned);
    }
    status
}

unsafe extern "system" fn cb_notification(
    callback_data: *const PRJ_CALLBACK_DATA,
    is_directory: bool,
    notification: PRJ_NOTIFICATION,
    destination_file_name: PCWSTR,
    _operation_parameters: *mut PRJ_NOTIFICATION_PARAMETERS,
) -> HRESULT {
    // SAFETY: ProjFS passes valid `callback_data`.
    let data = unsafe { &*callback_data };
    // SAFETY: `InstanceContext` points to `ProjFsInstance`.
    let inst = unsafe { instance_from_cb(callback_data) };

    if inst.read_only {
        if matches!(
            notification,
            PRJ_NOTIFICATION_PRE_DELETE
                | PRJ_NOTIFICATION_PRE_RENAME
                | PRJ_NOTIFICATION_PRE_SET_HARDLINK
                | PRJ_NOTIFICATION_FILE_PRE_CONVERT_TO_FULL
        ) {
            return HRESULT_ACCESS_DENIED;
        }
        return S_OK;
    }

    let rel = rel_from_cb(data);
    match notification {
        PRJ_NOTIFICATION_NEW_FILE_CREATED
        | PRJ_NOTIFICATION_FILE_OVERWRITTEN
        | PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED => {
            if is_directory {
                let _ = inst.with_rpc(|c| c.mkdir(&inst.tag, &rel));
            } else {
                let local = inst.root.join(rel.replace('/', "\\"));
                flush_local_file_to_host(inst, &rel, &local);
            }
        }
        PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_DELETED => {
            let _ = inst.with_rpc(|c| c.remove(&inst.tag, &rel, is_directory));
        }
        PRJ_NOTIFICATION_FILE_RENAMED => {
            let dst = pcwstr_to_string(destination_file_name)
                .replace('\\', "/")
                .trim_matches('/')
                .to_owned();
            if !rel.is_empty() && !dst.is_empty() {
                let _ = inst.with_rpc(|c| c.rename(&inst.tag, &rel, &dst));
            }
        }
        _ => {}
    }
    S_OK
}

fn flush_local_file_to_host(inst: &ProjFsInstance, rel: &str, local: &Path) {
    let Ok(mut f) = File::open(local) else {
        return;
    };
    let mut buf = vec![0u8; 256 * 1024];
    let mut offset = 0u64;
    let mut wrote_any = false;
    loop {
        match f.read(&mut buf) {
            Ok(0) => {
                if !wrote_any {
                    let _ = inst.with_rpc(|c| c.write_file(&inst.tag, rel, 0, &[], true));
                }
                break;
            }
            Ok(n) => {
                wrote_any = true;
                let last = n < buf.len();
                if inst
                    .with_rpc(|c| c.write_file(&inst.tag, rel, offset, &buf[..n], last))
                    .is_err()
                {
                    break;
                }
                offset += n as u64;
                if last {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// Mount a host share via Windows inbox `ProjFS` (`ProjectedFSLib.dll`) over [`FILE_SYNC_PORT`].
pub(crate) fn start_projfs_mount(
    af: u16,
    tag: String,
    target: String,
    read_only: bool,
) -> io::Result<Arc<AtomicBool>> {
    let api = load_projfs_api().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Windows ProjFS (Client-ProjFS / ProjectedFSLib.dll) is not enabled in this guest",
        )
    })?;

    // Verify the host file-sync share is reachable before marking the directory.
    let mut probe = FileSyncClient::connect(af)?;
    let _ = probe.list_dir(&tag, "")?;

    let root = PathBuf::from(&target);
    fs::create_dir_all(&root)?;
    let root_w = wide(&target);
    let guid = make_instance_guid(&tag, &target);

    // SAFETY: marks `target` as a ProjFS virtualization root.
    let hr_mark = unsafe { (api.mark_dir)(root_w.as_ptr(), null(), null(), &guid) };
    if hr_mark < 0 && hr_mark != HRESULT_REPARSE_POINT_ENCOUNTERED {
        return Err(win_err_to_io("PrjMarkDirectoryAsPlaceholder", hr_mark));
    }

    let inst = Box::leak(Box::new(ProjFsInstance {
        api,
        af,
        tag: tag.clone(),
        root,
        read_only,
        rpc: Mutex::new(Some(probe)),
        enums: Mutex::new(HashMap::new()),
        ns_ctx: AtomicUsize::new(0),
    }));

    let callbacks = PRJ_CALLBACKS {
        StartDirectoryEnumerationCallback: Some(cb_start_dir_enum),
        EndDirectoryEnumerationCallback: Some(cb_end_dir_enum),
        GetDirectoryEnumerationCallback: Some(cb_get_dir_enum),
        GetPlaceholderInfoCallback: Some(cb_get_placeholder_info),
        GetFileDataCallback: Some(cb_get_file_data),
        QueryFileNameCallback: None,
        NotificationCallback: Some(cb_notification),
        CancelCommandCallback: None,
    };

    let empty_root = wide("");
    let notify_mask = if read_only {
        PRJ_NOTIFY_PRE_DELETE
            | PRJ_NOTIFY_PRE_RENAME
            | PRJ_NOTIFY_PRE_SET_HARDLINK
            | PRJ_NOTIFY_FILE_PRE_CONVERT_TO_FULL
    } else {
        PRJ_NOTIFY_NEW_FILE_CREATED
            | PRJ_NOTIFY_FILE_OVERWRITTEN
            | PRJ_NOTIFY_FILE_RENAMED
            | PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_MODIFIED
            | PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_DELETED
    };
    let mut mapping = PRJ_NOTIFICATION_MAPPING {
        NotificationBitMask: notify_mask,
        NotificationRoot: empty_root.as_ptr(),
    };
    let opts = PRJ_STARTVIRTUALIZING_OPTIONS {
        Flags: PRJ_FLAG_NONE,
        PoolThreadCount: 4,
        ConcurrentThreadCount: 4,
        NotificationMappings: &mut mapping,
        NotificationMappingsCount: 1,
    };

    let mut ns_ctx: PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT = null_mut();
    // SAFETY: starts the ProjFS virtualization instance bound to `inst`.
    let hr_start = unsafe {
        (api.start)(
            root_w.as_ptr(),
            &callbacks,
            (inst as *const ProjFsInstance).cast(),
            &opts,
            &mut ns_ctx,
        )
    };
    if hr_start < 0 {
        return Err(win_err_to_io("PrjStartVirtualizing", hr_start));
    }
    inst.ns_ctx.store(ns_ctx as usize, Ordering::SeqCst);

    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = stop.clone();
    thread::spawn(move || projfs_watch_invalidator(inst, &stop_bg));
    Ok(stop)
}

fn projfs_watch_invalidator(inst: &'static ProjFsInstance, stop: &AtomicBool) {
    while !stop.load(Ordering::Relaxed) {
        let Ok(client) = FileSyncClient::connect(inst.af) else {
            thread::sleep(Duration::from_secs(1));
            continue;
        };
        let Ok(mut stream) = client.into_watch(&inst.tag) else {
            thread::sleep(Duration::from_secs(1));
            continue;
        };
        while !stop.load(Ordering::Relaxed) {
            match read_frame(&mut stream) {
                Ok(Some((FS_EVENT, payload))) => {
                    let Ok(ev) = serde_json::from_slice::<FileSyncEvent>(&payload) else {
                        continue;
                    };
                    let ctx =
                        inst.ns_ctx.load(Ordering::SeqCst) as PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT;
                    if ctx.is_null() {
                        continue;
                    }
                    let rel_w = wide(&ev.path.replace('/', "\\"));
                    let mut reason: PRJ_UPDATE_FAILURE_CAUSES = 0;
                    // SAFETY: invalidates stale placeholder so next access fetches fresh host data.
                    unsafe {
                        (inst.api.delete_file)(
                            ctx,
                            rel_w.as_ptr(),
                            PRJ_UPDATE_ALLOW_DIRTY_METADATA
                                | PRJ_UPDATE_ALLOW_DIRTY_DATA
                                | PRJ_UPDATE_ALLOW_TOMBSTONE
                                | PRJ_UPDATE_ALLOW_READ_ONLY,
                            &mut reason,
                        );
                        let mut cleared: u32 = 0;
                        (inst.api.clear_neg_cache)(ctx, &mut cleared);
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
}
