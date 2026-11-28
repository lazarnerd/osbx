//! Runtime-loaded Dokany 2 (`dokan2.dll`) backend speaking FUSE over Red Hat `viofs.sys`.
//!
//! Zero compile-time linking against Dokany (LGPL-3.0): `dokan2.dll` is probed and loaded at
//! runtime via `LoadLibraryW`/`GetProcAddress` only when installed inside the Windows guest.
//! Translates Windows filesystem callbacks into standard FUSE v7 requests sent to the host's
//! PCIe `virtio-fs` device via `viofs.sys`'s `IOCTL_VIRTFS_FUSE_REQUEST` interface.

#![allow(unsafe_code)]

use crate::win_sync::unix_to_filetime;
use crate::windows::{OwnedHandle, wide};
use std::collections::HashMap;
use std::ffi::c_void;
use std::fs;
use std::io;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, SP_DEVICE_INTERFACE_DATA,
    SP_DEVICE_INTERFACE_DETAIL_DATA_W, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces,
    SetupDiGetClassDevsW, SetupDiGetDeviceInterfaceDetailW,
};
use windows_sys::Win32::Foundation::{
    FILETIME, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, NTSTATUS,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_READONLY, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, WIN32_FIND_DATAW,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::core::{GUID, PCWSTR, PWSTR};

// ---- Red Hat `viofs.sys` device interface & IOCTLs (`viofs/shared/virtiofs.h`) --------------

/// `{a1b0cbf2-f488-4b29-b89f-16c78e68c737}`
const GUID_DEVINTERFACE_VIRT_FS: GUID = GUID {
    data1: 0xa1b0_cbf2,
    data2: 0xf488,
    data3: 0x4b29,
    data4: [0xb8, 0x9f, 0x16, 0xc7, 0x8e, 0x68, 0xc7, 0x37],
};
/// `CTL_CODE(FILE_DEVICE_UNKNOWN (0x22), 0x800, METHOD_BUFFERED (0), FILE_READ_ACCESS (1))`
const IOCTL_VIRTFS_GET_VOLUME_NAME: u32 = 0x0022_6000;
/// `CTL_CODE(FILE_DEVICE_UNKNOWN (0x22), 0x801, METHOD_OUT_DIRECT (2), FILE_READ_ACCESS | FILE_WRITE_ACCESS (3))`
const IOCTL_VIRTFS_FUSE_REQUEST: u32 = 0x0022_E006;

// ---- FUSE v7 wire protocol constants & structs ----------------------------------------------

const FUSE_KERNEL_VERSION: u32 = 7;
const FUSE_KERNEL_MINOR_VERSION: u32 = 31;
const FUSE_ROOT_ID: u64 = 1;

const FUSE_LOOKUP: u32 = 1;
const FUSE_GETATTR: u32 = 3;
const FUSE_SETATTR: u32 = 4;
const FUSE_MKDIR: u32 = 9;
const FUSE_UNLINK: u32 = 10;
const FUSE_RMDIR: u32 = 11;
const FUSE_RENAME: u32 = 12;
const FUSE_OPEN: u32 = 14;
const FUSE_READ: u32 = 15;
const FUSE_WRITE: u32 = 16;
const FUSE_STATFS: u32 = 17;
const FUSE_RELEASE: u32 = 18;
const FUSE_INIT: u32 = 26;
const FUSE_OPENDIR: u32 = 27;
const FUSE_READDIR: u32 = 28;
const FUSE_RELEASEDIR: u32 = 29;
const FUSE_CREATE: u32 = 35;

const FATTR_SIZE: u32 = 1 << 3;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const O_RDONLY: u32 = 0;
const O_RDWR: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseInHeader {
    len: u32,
    opcode: u32,
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseOutHeader {
    len: u32,
    error: i32,
    unique: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseInitIn {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseAttr {
    ino: u64,
    size: u64,
    blocks: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    atimensec: u32,
    mtimensec: u32,
    ctimensec: u32,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    blksize: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseEntryOut {
    nodeid: u64,
    generation: u64,
    entry_valid: u64,
    attr_valid: u64,
    entry_valid_nsec: u32,
    attr_valid_nsec: u32,
    attr: FuseAttr,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseAttrOut {
    attr_valid: u64,
    attr_valid_nsec: u32,
    dummy: u32,
    attr: FuseAttr,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseGetattrIn {
    getattr_flags: u32,
    dummy: u32,
    fh: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseSetattrIn {
    valid: u32,
    padding: u32,
    fh: u64,
    size: u64,
    lock_owner: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    atimensec: u32,
    mtimensec: u32,
    ctimensec: u32,
    mode: u32,
    unused4: u32,
    uid: u32,
    gid: u32,
    unused5: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseOpenIn {
    flags: u32,
    unused: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseOpenOut {
    fh: u64,
    open_flags: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseCreateIn {
    flags: u32,
    mode: u32,
    umask: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseMkdirIn {
    mode: u32,
    umask: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseReadIn {
    fh: u64,
    offset: u64,
    size: u32,
    read_flags: u32,
    lock_owner: u64,
    flags: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseWriteIn {
    fh: u64,
    offset: u64,
    size: u32,
    write_flags: u32,
    lock_owner: u64,
    flags: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseWriteOut {
    size: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseReleaseIn {
    fh: u64,
    flags: u32,
    release_flags: u32,
    lock_owner: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseRenameIn {
    newdir: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseDirent {
    ino: u64,
    off: u64,
    namelen: u32,
    typ: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FuseKstatfs {
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    bsize: u32,
    namelen: u32,
    frsize: u32,
    padding: u32,
    spare: [u32; 6],
}

// ---- Dokan 2 (`dokan2.dll`) ABI definitions (`dokan/dokan.h` v2.x) --------------------------

const DOKAN_VERSION_200: u16 = 200;
const DOKAN_OPTION_WRITE_PROTECT: u32 = 1 << 3;
const VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE: usize = 16 * 1024;

const STATUS_SUCCESS: NTSTATUS = 0;
const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = 0xC000_0034u32 as i32;
const STATUS_OBJECT_NAME_COLLISION: NTSTATUS = 0xC000_0035u32 as i32;
const STATUS_MEDIA_WRITE_PROTECTED: NTSTATUS = 0xC000_00A2u32 as i32;
const STATUS_FILE_IS_A_DIRECTORY: NTSTATUS = 0xC000_00BAu32 as i32;
const STATUS_DIRECTORY_NOT_EMPTY: NTSTATUS = 0xC000_0101u32 as i32;
const STATUS_NOT_A_DIRECTORY: NTSTATUS = 0xC000_0103u32 as i32;
const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000_000Du32 as i32;
const STATUS_NOT_IMPLEMENTED: NTSTATUS = 0xC000_0002u32 as i32;
const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC000_0001u32 as i32;

const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

#[repr(C)]
struct DokanOptions {
    version: u16,
    single_thread: u8,
    options: u32,
    global_context: u64,
    mount_point: PCWSTR,
    unc_name: PCWSTR,
    timeout: u32,
    allocation_unit_size: u32,
    sector_size: u32,
    volume_security_descriptor_length: u32,
    volume_security_descriptor: [u8; VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE],
}

#[repr(C)]
struct DokanFileInfo {
    context: u64,
    dokan_context: u64,
    dokan_options: *mut DokanOptions,
    processing_context: *mut c_void,
    process_id: u32,
    is_directory: u8,
    delete_pending: u8,
    paging_io: u8,
    synchronous_io: u8,
    nocache: u8,
    write_to_end_of_file: u8,
}

type PFillFindData = unsafe extern "system" fn(*const WIN32_FIND_DATAW, *mut DokanFileInfo) -> i32;

#[repr(C)]
struct DokanOperations {
    zw_create_file: Option<
        unsafe extern "system" fn(
            PCWSTR,
            *mut c_void,
            u32,
            u32,
            u32,
            u32,
            u32,
            *mut DokanFileInfo,
        ) -> NTSTATUS,
    >,
    cleanup: Option<unsafe extern "system" fn(PCWSTR, *mut DokanFileInfo)>,
    close_file: Option<unsafe extern "system" fn(PCWSTR, *mut DokanFileInfo)>,
    read_file: Option<
        unsafe extern "system" fn(
            PCWSTR,
            *mut c_void,
            u32,
            *mut u32,
            i64,
            *mut DokanFileInfo,
        ) -> NTSTATUS,
    >,
    write_file: Option<
        unsafe extern "system" fn(
            PCWSTR,
            *const c_void,
            u32,
            *mut u32,
            i64,
            *mut DokanFileInfo,
        ) -> NTSTATUS,
    >,
    flush_file_buffers: Option<unsafe extern "system" fn(PCWSTR, *mut DokanFileInfo) -> NTSTATUS>,
    get_file_information: Option<
        unsafe extern "system" fn(
            PCWSTR,
            *mut BY_HANDLE_FILE_INFORMATION,
            *mut DokanFileInfo,
        ) -> NTSTATUS,
    >,
    find_files:
        Option<unsafe extern "system" fn(PCWSTR, PFillFindData, *mut DokanFileInfo) -> NTSTATUS>,
    find_files_with_pattern: Option<
        unsafe extern "system" fn(PCWSTR, PCWSTR, PFillFindData, *mut DokanFileInfo) -> NTSTATUS,
    >,
    set_file_attributes:
        Option<unsafe extern "system" fn(PCWSTR, u32, *mut DokanFileInfo) -> NTSTATUS>,
    set_file_time: Option<
        unsafe extern "system" fn(
            PCWSTR,
            *const FILETIME,
            *const FILETIME,
            *const FILETIME,
            *mut DokanFileInfo,
        ) -> NTSTATUS,
    >,
    delete_file: Option<unsafe extern "system" fn(PCWSTR, *mut DokanFileInfo) -> NTSTATUS>,
    delete_directory: Option<unsafe extern "system" fn(PCWSTR, *mut DokanFileInfo) -> NTSTATUS>,
    move_file:
        Option<unsafe extern "system" fn(PCWSTR, PCWSTR, i32, *mut DokanFileInfo) -> NTSTATUS>,
    set_end_of_file: Option<unsafe extern "system" fn(PCWSTR, i64, *mut DokanFileInfo) -> NTSTATUS>,
    set_allocation_size:
        Option<unsafe extern "system" fn(PCWSTR, i64, *mut DokanFileInfo) -> NTSTATUS>,
    lock_file: Option<unsafe extern "system" fn(PCWSTR, i64, i64, *mut DokanFileInfo) -> NTSTATUS>,
    unlock_file:
        Option<unsafe extern "system" fn(PCWSTR, i64, i64, *mut DokanFileInfo) -> NTSTATUS>,
    get_disk_free_space: Option<
        unsafe extern "system" fn(*mut u64, *mut u64, *mut u64, *mut DokanFileInfo) -> NTSTATUS,
    >,
    get_volume_information: Option<
        unsafe extern "system" fn(
            PWSTR,
            u32,
            *mut u32,
            *mut u32,
            *mut u32,
            PWSTR,
            u32,
            *mut DokanFileInfo,
        ) -> NTSTATUS,
    >,
    mounted: Option<unsafe extern "system" fn(PCWSTR, *mut DokanFileInfo) -> NTSTATUS>,
    unmounted: Option<unsafe extern "system" fn(*mut DokanFileInfo) -> NTSTATUS>,
    get_file_security: Option<
        unsafe extern "system" fn(
            PCWSTR,
            *mut u32,
            *mut c_void,
            u32,
            *mut u32,
            *mut DokanFileInfo,
        ) -> NTSTATUS,
    >,
    set_file_security: Option<
        unsafe extern "system" fn(
            PCWSTR,
            *mut u32,
            *mut c_void,
            u32,
            *mut DokanFileInfo,
        ) -> NTSTATUS,
    >,
    find_streams: Option<
        unsafe extern "system" fn(PCWSTR, *mut c_void, *mut c_void, *mut DokanFileInfo) -> NTSTATUS,
    >,
}

type FnDokanInit = unsafe extern "system" fn();
type FnDokanShutdown = unsafe extern "system" fn();
type FnDokanMain = unsafe extern "system" fn(*mut DokanOptions, *mut DokanOperations) -> i32;
type FnDokanRemoveMountPoint = unsafe extern "system" fn(PCWSTR) -> i32;

struct DokanApi {
    init: FnDokanInit,
    #[allow(dead_code)]
    shutdown: FnDokanShutdown,
    main: FnDokanMain,
    #[allow(dead_code)]
    remove_mount: FnDokanRemoveMountPoint,
}

// SAFETY: immutable process-wide DLL function pointers loaded once.
unsafe impl Send for DokanApi {}
// SAFETY: immutable process-wide DLL function pointers loaded once.
unsafe impl Sync for DokanApi {}

static DOKAN_API: OnceLock<Option<DokanApi>> = OnceLock::new();

fn load_dokan_api() -> Option<&'static DokanApi> {
    DOKAN_API
        .get_or_init(|| {
            let mut candidates = vec![
                "dokan2.dll".to_owned(),
                r"C:\Windows\System32\dokan2.dll".to_owned(),
            ];
            if let Ok(rd) = fs::read_dir(r"C:\Program Files\Dokan") {
                for e in rd.flatten() {
                    let p = e.path().join("dokan2.dll");
                    if p.exists() {
                        candidates.push(p.to_string_lossy().into_owned());
                    }
                }
            }
            let mut module = null_mut();
            for cand in &candidates {
                let w = wide(cand);
                // SAFETY: attempts to dynamically load Dokany 2 (`dokan2.dll`).
                let m = unsafe { LoadLibraryW(w.as_ptr()) };
                if !m.is_null() {
                    module = m;
                    break;
                }
            }
            if module.is_null() {
                return None;
            }
            macro_rules! sym {
                ($name:literal, $ty:ty) => {{
                    // SAFETY: resolves exported function from loaded `dokan2.dll`.
                    let p = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) }?;
                    // SAFETY: signature matches `dokan/dokan.h` v2.x.
                    unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(p) }
                }};
            }
            let api = DokanApi {
                init: sym!("DokanInit", FnDokanInit),
                shutdown: sym!("DokanShutdown", FnDokanShutdown),
                main: sym!("DokanMain", FnDokanMain),
                remove_mount: sym!("DokanRemoveMountPoint", FnDokanRemoveMountPoint),
            };
            // SAFETY: initializes Dokan library global state once.
            unsafe {
                (api.init)();
            }
            Some(api)
        })
        .as_ref()
}

/// True if both `dokan2.dll` and at least one `viofs.sys` device are available in the guest.
pub(crate) fn is_dokany_available() -> bool {
    load_dokan_api().is_some() && !enumerate_viofs_devices().is_empty()
}

// ---- `viofs.sys` device discovery + FUSE transport ------------------------------------------

fn enumerate_viofs_devices() -> Vec<String> {
    let mut paths = Vec::new();
    // SAFETY: enumerates present `GUID_DEVINTERFACE_VIRT_FS` device interfaces.
    let dev_info = unsafe {
        SetupDiGetClassDevsW(
            &GUID_DEVINTERFACE_VIRT_FS,
            null(),
            null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    };
    if dev_info == -1 || dev_info == 0 {
        return paths;
    }

    let mut idx = 0u32;
    loop {
        // SAFETY: zeroed `SP_DEVICE_INTERFACE_DATA` with `cbSize` set.
        let mut iface: SP_DEVICE_INTERFACE_DATA = unsafe { std::mem::zeroed() };
        iface.cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
        // SAFETY: queries next `viofs` device interface.
        let ok = unsafe {
            SetupDiEnumDeviceInterfaces(
                dev_info,
                null(),
                &GUID_DEVINTERFACE_VIRT_FS,
                idx,
                &mut iface,
            )
        };
        if ok == 0 {
            break;
        }
        idx += 1;

        let mut required: u32 = 0;
        // SAFETY: queries required detail buffer byte size.
        unsafe {
            SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                &iface,
                null_mut(),
                0,
                &mut required,
                null_mut(),
            );
        }
        if required < std::mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32 {
            continue;
        }
        let mut buf = vec![0u8; required as usize];
        let detail = buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
        // SAFETY: `cbSize` must be the struct size (8 on x64).
        unsafe {
            (*detail).cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
        }
        // SAFETY: retrieves the device path string.
        let ok2 = unsafe {
            SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                &iface,
                detail,
                required,
                null_mut(),
                null_mut(),
            )
        };
        if ok2 != 0 {
            let path_off = std::mem::offset_of!(SP_DEVICE_INTERFACE_DETAIL_DATA_W, DevicePath);
            // SAFETY: reads NUL-terminated UTF-16 DevicePath inside `buf`.
            let ptr = unsafe { buf.as_ptr().add(path_off) as *const u16 };
            let mut len = 0usize;
            while path_off + (len + 1) * 2 <= buf.len() {
                // SAFETY: bounded within `buf`.
                if unsafe { *ptr.add(len) } == 0 {
                    break;
                }
                len += 1;
            }
            // SAFETY: valid UTF-16 slice of length `len`.
            let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
            paths.push(String::from_utf16_lossy(slice));
        }
    }

    // SAFETY: destroys device info set allocated by `SetupDiGetClassDevsW`.
    unsafe {
        SetupDiDestroyDeviceInfoList(dev_info);
    }
    paths
}

fn open_viofs_device_for_tag(tag: &str) -> io::Result<OwnedHandle> {
    for dev_path in enumerate_viofs_devices() {
        let w = wide(&dev_path);
        // SAFETY: opens `viofs.sys` device interface handle.
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            continue;
        }
        let guard = OwnedHandle(h);
        let mut name_buf = [0u8; 64];
        let mut returned: u32 = 0;
        // SAFETY: queries `virtio-fs` volume tag via `IOCTL_VIRTFS_GET_VOLUME_NAME`.
        let ok = unsafe {
            DeviceIoControl(
                guard.0,
                IOCTL_VIRTFS_GET_VOLUME_NAME,
                null(),
                0,
                name_buf.as_mut_ptr().cast(),
                name_buf.len() as u32,
                &mut returned,
                null_mut(),
            )
        };
        if ok != 0 && returned > 0 {
            let raw = &name_buf[..returned as usize];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            let vol = String::from_utf8_lossy(&raw[..end]);
            if vol == tag {
                return Ok(guard);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("viofs.sys device with tag {tag:?} not found"),
    ))
}

struct ViofsClient {
    handle: OwnedHandle,
    next_unique: AtomicU64,
    io_lock: Mutex<()>,
}

impl ViofsClient {
    fn open(tag: &str) -> io::Result<Self> {
        let handle = open_viofs_device_for_tag(tag)?;
        let client = Self {
            handle,
            next_unique: AtomicU64::new(1),
            io_lock: Mutex::new(()),
        };
        let init = FuseInitIn {
            major: FUSE_KERNEL_VERSION,
            minor: FUSE_KERNEL_MINOR_VERSION,
            max_readahead: 128 * 1024,
            flags: 0,
        };
        let _ = client
            .fuse_call(FUSE_INIT, 0, as_bytes(&init), 128)
            .map_err(|e| io::Error::other(format!("FUSE_INIT failed: {e}")))?;
        Ok(client)
    }

    fn fuse_call(
        &self,
        opcode: u32,
        nodeid: u64,
        body: &[u8],
        out_cap: usize,
    ) -> Result<Vec<u8>, i32> {
        let _guard = self.io_lock.lock().unwrap();
        let unique = self.next_unique.fetch_add(1, Ordering::Relaxed);
        let total_in = std::mem::size_of::<FuseInHeader>() + body.len();
        let hdr = FuseInHeader {
            len: total_in as u32,
            opcode,
            unique,
            nodeid,
            uid: 0,
            gid: 0,
            pid: std::process::id(),
            padding: 0,
        };
        let mut req = Vec::with_capacity(total_in);
        req.extend_from_slice(as_bytes(&hdr));
        req.extend_from_slice(body);

        let mut resp = vec![0u8; std::mem::size_of::<FuseOutHeader>() + out_cap];
        let mut returned: u32 = 0;
        // SAFETY: sends serialized FUSE request to `viofs.sys` via `IOCTL_VIRTFS_FUSE_REQUEST`.
        let ok = unsafe {
            DeviceIoControl(
                self.handle.0,
                IOCTL_VIRTFS_FUSE_REQUEST,
                req.as_ptr().cast(),
                req.len() as u32,
                resp.as_mut_ptr().cast(),
                resp.len() as u32,
                &mut returned,
                null_mut(),
            )
        };
        if ok == 0 || (returned as usize) < std::mem::size_of::<FuseOutHeader>() {
            return Err(-5); // EIO
        }
        let out_hdr: FuseOutHeader = read_pod(&resp);
        if out_hdr.error != 0 {
            return Err(out_hdr.error);
        }
        let payload_len = (out_hdr.len as usize)
            .min(returned as usize)
            .saturating_sub(std::mem::size_of::<FuseOutHeader>());
        Ok(resp[std::mem::size_of::<FuseOutHeader>()
            ..std::mem::size_of::<FuseOutHeader>() + payload_len]
            .to_vec())
    }

    fn lookup(&self, parent: u64, name: &str) -> Result<FuseEntryOut, i32> {
        let mut body = name.as_bytes().to_vec();
        body.push(0);
        let out = self.fuse_call(
            FUSE_LOOKUP,
            parent,
            &body,
            std::mem::size_of::<FuseEntryOut>(),
        )?;
        if out.len() < std::mem::size_of::<FuseEntryOut>() {
            return Err(-5);
        }
        Ok(read_pod(&out))
    }

    fn getattr(&self, nodeid: u64) -> Result<FuseAttr, i32> {
        let inp = FuseGetattrIn::default();
        let out = self.fuse_call(
            FUSE_GETATTR,
            nodeid,
            as_bytes(&inp),
            std::mem::size_of::<FuseAttrOut>(),
        )?;
        if out.len() < std::mem::size_of::<FuseAttrOut>() {
            return Err(-5);
        }
        let ao: FuseAttrOut = read_pod(&out);
        Ok(ao.attr)
    }

    fn resolve_path(&self, win_path: &str) -> Result<(u64, FuseAttr), i32> {
        let parts: Vec<&str> = win_path
            .split(['\\', '/'])
            .filter(|s| !s.is_empty())
            .collect();
        let mut cur = FUSE_ROOT_ID;
        if parts.is_empty() {
            return Ok((cur, self.getattr(cur)?));
        }
        let mut last_attr = FuseAttr::default();
        for p in parts {
            let entry = self.lookup(cur, p)?;
            cur = entry.nodeid;
            last_attr = entry.attr;
        }
        Ok((cur, last_attr))
    }

    fn resolve_parent<'a>(&self, win_path: &'a str) -> Result<(u64, &'a str), i32> {
        let parts: Vec<&str> = win_path
            .split(['\\', '/'])
            .filter(|s| !s.is_empty())
            .collect();
        let Some((&leaf, parents)) = parts.split_last() else {
            return Err(-22);
        };
        let mut cur = FUSE_ROOT_ID;
        for p in parents {
            cur = self.lookup(cur, p)?.nodeid;
        }
        Ok((cur, leaf))
    }
}

fn as_bytes<T: Copy>(v: &T) -> &[u8] {
    // SAFETY: `T` is a `#[repr(C)]` POD FUSE struct with no padding invariants violated.
    unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), std::mem::size_of::<T>()) }
}

fn read_pod<T: Copy + Default>(buf: &[u8]) -> T {
    let mut v = T::default();
    let n = std::mem::size_of::<T>().min(buf.len());
    // SAFETY: copies `n <= size_of::<T>()` bytes into stack-allocated `#[repr(C)]` POD struct.
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), (&mut v as *mut T).cast::<u8>(), n);
    }
    v
}

fn fuse_err_to_ntstatus(err: i32) -> NTSTATUS {
    match -err {
        0 => STATUS_SUCCESS,
        1 | 13 => STATUS_ACCESS_DENIED,
        2 => STATUS_OBJECT_NAME_NOT_FOUND,
        17 => STATUS_OBJECT_NAME_COLLISION,
        20 => STATUS_NOT_A_DIRECTORY,
        21 => STATUS_FILE_IS_A_DIRECTORY,
        22 => STATUS_INVALID_PARAMETER,
        30 => STATUS_MEDIA_WRITE_PROTECTED,
        39 => STATUS_DIRECTORY_NOT_EMPTY,
        _ => STATUS_UNSUCCESSFUL,
    }
}

fn attr_is_dir(a: &FuseAttr) -> bool {
    (a.mode & S_IFMT) == S_IFDIR
}

fn ticks_to_filetime(ticks: i64) -> FILETIME {
    let u = ticks as u64;
    FILETIME {
        dwLowDateTime: u as u32,
        dwHighDateTime: (u >> 32) as u32,
    }
}

fn pcwstr_to_string(p: PCWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: valid NUL-terminated UTF-16 pointer passed by Dokan.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` UTF-16 code units.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

// ---- Dokan mount state & callbacks ----------------------------------------------------------

struct OpenHandle {
    nodeid: u64,
    fh: u64,
    is_dir: bool,
}

struct DokanMountCtx {
    client: ViofsClient,
    tag: String,
    read_only: bool,
    next_ctx: AtomicU64,
    handles: Mutex<HashMap<u64, OpenHandle>>,
    mounted_tx: Mutex<Option<mpsc::Sender<()>>>,
}

unsafe fn ctx_from_info(info: *mut DokanFileInfo) -> &'static DokanMountCtx {
    // SAFETY: `DokanOptions.global_context` stores a leaked `&'static DokanMountCtx`.
    unsafe { &*((*(*info).dokan_options).global_context as *const DokanMountCtx) }
}

unsafe extern "system" fn dk_zw_create_file(
    file_name: PCWSTR,
    _security_ctx: *mut c_void,
    _desired_access: u32,
    _file_attributes: u32,
    _share_access: u32,
    create_disposition: u32,
    create_options: u32,
    info: *mut DokanFileInfo,
) -> NTSTATUS {
    // SAFETY: `info` is provided by Dokan.
    let ctx = unsafe { ctx_from_info(info) };
    let path = pcwstr_to_string(file_name);
    let want_dir = (create_options & FILE_DIRECTORY_FILE) != 0;
    let want_non_dir = (create_options & FILE_NON_DIRECTORY_FILE) != 0;

    if (create_options & FILE_DELETE_ON_CLOSE) != 0 && ctx.read_only {
        return STATUS_MEDIA_WRITE_PROTECTED;
    }

    match ctx.client.resolve_path(&path) {
        Ok((nodeid, attr)) => {
            let is_dir = attr_is_dir(&attr);
            if want_dir && !is_dir {
                return STATUS_NOT_A_DIRECTORY;
            }
            if want_non_dir && is_dir {
                return STATUS_FILE_IS_A_DIRECTORY;
            }
            if create_disposition == FILE_CREATE {
                return STATUS_OBJECT_NAME_COLLISION;
            }
            if matches!(
                create_disposition,
                FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF
            ) {
                if ctx.read_only {
                    return STATUS_MEDIA_WRITE_PROTECTED;
                }
                if !is_dir {
                    let sa = FuseSetattrIn {
                        valid: FATTR_SIZE,
                        size: 0,
                        ..Default::default()
                    };
                    if let Err(e) = ctx.client.fuse_call(
                        FUSE_SETATTR,
                        nodeid,
                        as_bytes(&sa),
                        std::mem::size_of::<FuseAttrOut>(),
                    ) {
                        return fuse_err_to_ntstatus(e);
                    }
                }
            }
            let open_in = FuseOpenIn {
                flags: if ctx.read_only || is_dir {
                    O_RDONLY
                } else {
                    O_RDWR
                },
                unused: 0,
            };
            let op = if is_dir { FUSE_OPENDIR } else { FUSE_OPEN };
            let fh = match ctx.client.fuse_call(
                op,
                nodeid,
                as_bytes(&open_in),
                std::mem::size_of::<FuseOpenOut>(),
            ) {
                Ok(out) if out.len() >= std::mem::size_of::<FuseOpenOut>() => {
                    read_pod::<FuseOpenOut>(&out).fh
                }
                Ok(_) => 0,
                Err(e) if !is_dir && !ctx.read_only => {
                    // Retry read-only open when the underlying host file is read-only.
                    let ro_in = FuseOpenIn {
                        flags: O_RDONLY,
                        unused: 0,
                    };
                    match ctx.client.fuse_call(
                        FUSE_OPEN,
                        nodeid,
                        as_bytes(&ro_in),
                        std::mem::size_of::<FuseOpenOut>(),
                    ) {
                        Ok(out) if out.len() >= std::mem::size_of::<FuseOpenOut>() => {
                            read_pod::<FuseOpenOut>(&out).fh
                        }
                        _ => return fuse_err_to_ntstatus(e),
                    }
                }
                Err(e) => return fuse_err_to_ntstatus(e),
            };
            let cid = ctx.next_ctx.fetch_add(1, Ordering::Relaxed);
            ctx.handles
                .lock()
                .unwrap()
                .insert(cid, OpenHandle { nodeid, fh, is_dir });
            // SAFETY: writes handle context and directory flag into Dokan's `DokanFileInfo`.
            unsafe {
                (*info).context = cid;
                (*info).is_directory = u8::from(is_dir);
            }
            if matches!(
                create_disposition,
                FILE_OPEN_IF | FILE_OVERWRITE_IF | FILE_SUPERSEDE
            ) {
                STATUS_OBJECT_NAME_COLLISION
            } else {
                STATUS_SUCCESS
            }
        }
        Err(-2) => {
            if matches!(create_disposition, FILE_OPEN | FILE_OVERWRITE) {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
            if ctx.read_only {
                return STATUS_MEDIA_WRITE_PROTECTED;
            }
            let (parent, leaf) = match ctx.client.resolve_parent(&path) {
                Ok(p) => p,
                Err(e) => return fuse_err_to_ntstatus(e),
            };
            if want_dir {
                let mk = FuseMkdirIn {
                    mode: 0o755,
                    umask: 0,
                };
                let mut body = as_bytes(&mk).to_vec();
                body.extend_from_slice(leaf.as_bytes());
                body.push(0);
                let out = match ctx.client.fuse_call(
                    FUSE_MKDIR,
                    parent,
                    &body,
                    std::mem::size_of::<FuseEntryOut>(),
                ) {
                    Ok(o) => o,
                    Err(e) => return fuse_err_to_ntstatus(e),
                };
                let entry: FuseEntryOut = read_pod(&out);
                let cid = ctx.next_ctx.fetch_add(1, Ordering::Relaxed);
                ctx.handles.lock().unwrap().insert(
                    cid,
                    OpenHandle {
                        nodeid: entry.nodeid,
                        fh: 0,
                        is_dir: true,
                    },
                );
                // SAFETY: updates `DokanFileInfo` for newly created directory.
                unsafe {
                    (*info).context = cid;
                    (*info).is_directory = 1;
                }
                STATUS_SUCCESS
            } else {
                let cr = FuseCreateIn {
                    flags: O_RDWR,
                    mode: 0o100644,
                    umask: 0,
                    padding: 0,
                };
                let mut body = as_bytes(&cr).to_vec();
                body.extend_from_slice(leaf.as_bytes());
                body.push(0);
                let expected =
                    std::mem::size_of::<FuseEntryOut>() + std::mem::size_of::<FuseOpenOut>();
                let out = match ctx.client.fuse_call(FUSE_CREATE, parent, &body, expected) {
                    Ok(o) if o.len() >= expected => o,
                    Ok(_) => return STATUS_UNSUCCESSFUL,
                    Err(e) => return fuse_err_to_ntstatus(e),
                };
                let entry: FuseEntryOut = read_pod(&out);
                let open_out: FuseOpenOut = read_pod(&out[std::mem::size_of::<FuseEntryOut>()..]);
                let cid = ctx.next_ctx.fetch_add(1, Ordering::Relaxed);
                ctx.handles.lock().unwrap().insert(
                    cid,
                    OpenHandle {
                        nodeid: entry.nodeid,
                        fh: open_out.fh,
                        is_dir: false,
                    },
                );
                // SAFETY: updates `DokanFileInfo` for newly created file.
                unsafe {
                    (*info).context = cid;
                    (*info).is_directory = 0;
                }
                STATUS_SUCCESS
            }
        }
        Err(e) => fuse_err_to_ntstatus(e),
    }
}

unsafe extern "system" fn dk_cleanup(file_name: PCWSTR, info: *mut DokanFileInfo) {
    // SAFETY: reads DokanFileInfo fields.
    let ctx = unsafe { ctx_from_info(info) };
    // SAFETY: reads `delete_pending` and `is_directory`.
    let (delete_pending, is_dir) =
        unsafe { ((*info).delete_pending != 0, (*info).is_directory != 0) };
    if delete_pending && !ctx.read_only {
        let path = pcwstr_to_string(file_name);
        if let Ok((parent, leaf)) = ctx.client.resolve_parent(&path) {
            let mut body = leaf.as_bytes().to_vec();
            body.push(0);
            let op = if is_dir { FUSE_RMDIR } else { FUSE_UNLINK };
            let _ = ctx.client.fuse_call(op, parent, &body, 0);
        }
    }
}

unsafe extern "system" fn dk_close_file(_file_name: PCWSTR, info: *mut DokanFileInfo) {
    // SAFETY: reads context ID from `DokanFileInfo`.
    let ctx = unsafe { ctx_from_info(info) };
    // SAFETY: reads and clears `context`.
    let cid = unsafe {
        let c = (*info).context;
        (*info).context = 0;
        c
    };
    if let Some(h) = ctx.handles.lock().unwrap().remove(&cid)
        && h.fh != 0
    {
        let rel = FuseReleaseIn {
            fh: h.fh,
            flags: 0,
            release_flags: 0,
            lock_owner: 0,
        };
        let op = if h.is_dir {
            FUSE_RELEASEDIR
        } else {
            FUSE_RELEASE
        };
        let _ = ctx.client.fuse_call(op, h.nodeid, as_bytes(&rel), 0);
    }
}

unsafe extern "system" fn dk_read_file(
    _file_name: PCWSTR,
    buffer: *mut c_void,
    buffer_length: u32,
    read_length: *mut u32,
    offset: i64,
    info: *mut DokanFileInfo,
) -> NTSTATUS {
    // SAFETY: reads `DokanFileInfo`.
    let ctx = unsafe { ctx_from_info(info) };
    // SAFETY: reads `context`.
    let cid = unsafe { (*info).context };
    let (nodeid, fh) = {
        let guard = ctx.handles.lock().unwrap();
        let Some(h) = guard.get(&cid) else {
            return STATUS_INVALID_PARAMETER;
        };
        (h.nodeid, h.fh)
    };
    let mut done = 0usize;
    let total = buffer_length as usize;
    while done < total {
        let want = (total - done).min(64 * 1024) as u32;
        let ri = FuseReadIn {
            fh,
            offset: (offset as u64) + (done as u64),
            size: want,
            read_flags: 0,
            lock_owner: 0,
            flags: 0,
            padding: 0,
        };
        match ctx
            .client
            .fuse_call(FUSE_READ, nodeid, as_bytes(&ri), want as usize)
        {
            Ok(data) if data.is_empty() => break,
            Ok(data) => {
                let n = data.len().min(total - done);
                // SAFETY: copies read bytes into Dokan's output buffer within `buffer_length`.
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), buffer.cast::<u8>().add(done), n);
                }
                done += n;
                if n < want as usize {
                    break;
                }
            }
            Err(e) => return fuse_err_to_ntstatus(e),
        }
    }
    // SAFETY: writes total bytes read.
    unsafe {
        *read_length = done as u32;
    }
    STATUS_SUCCESS
}

unsafe extern "system" fn dk_write_file(
    _file_name: PCWSTR,
    buffer: *const c_void,
    number_of_bytes_to_write: u32,
    number_of_bytes_written: *mut u32,
    offset: i64,
    info: *mut DokanFileInfo,
) -> NTSTATUS {
    // SAFETY: reads `DokanFileInfo`.
    let ctx = unsafe { ctx_from_info(info) };
    if ctx.read_only {
        return STATUS_MEDIA_WRITE_PROTECTED;
    }
    // SAFETY: reads `context` and `write_to_end_of_file`.
    let (cid, append) = unsafe { ((*info).context, (*info).write_to_end_of_file != 0) };
    let (nodeid, fh) = {
        let guard = ctx.handles.lock().unwrap();
        let Some(h) = guard.get(&cid) else {
            return STATUS_INVALID_PARAMETER;
        };
        (h.nodeid, h.fh)
    };
    let mut cur_off = if append {
        ctx.client.getattr(nodeid).map_or(0, |a| a.size)
    } else {
        offset.max(0) as u64
    };
    // SAFETY: input slice of `number_of_bytes_to_write` bytes supplied by Dokan.
    let src = unsafe {
        std::slice::from_raw_parts(buffer.cast::<u8>(), number_of_bytes_to_write as usize)
    };
    let mut done = 0usize;
    while done < src.len() {
        let chunk = &src[done..(done + 64 * 1024).min(src.len())];
        let wi = FuseWriteIn {
            fh,
            offset: cur_off,
            size: chunk.len() as u32,
            write_flags: 0,
            lock_owner: 0,
            flags: 0,
            padding: 0,
        };
        let mut body = Vec::with_capacity(std::mem::size_of::<FuseWriteIn>() + chunk.len());
        body.extend_from_slice(as_bytes(&wi));
        body.extend_from_slice(chunk);
        match ctx.client.fuse_call(
            FUSE_WRITE,
            nodeid,
            &body,
            std::mem::size_of::<FuseWriteOut>(),
        ) {
            Ok(out) => {
                let wo: FuseWriteOut = read_pod(&out);
                let wrote = (wo.size as usize).min(chunk.len());
                done += wrote;
                cur_off += wrote as u64;
                if wrote == 0 {
                    break;
                }
            }
            Err(e) => return fuse_err_to_ntstatus(e),
        }
    }
    // SAFETY: writes byte count written.
    unsafe {
        *number_of_bytes_written = done as u32;
    }
    STATUS_SUCCESS
}

unsafe extern "system" fn dk_get_file_info(
    file_name: PCWSTR,
    buf: *mut BY_HANDLE_FILE_INFORMATION,
    info: *mut DokanFileInfo,
) -> NTSTATUS {
    // SAFETY: reads `DokanFileInfo`.
    let ctx = unsafe { ctx_from_info(info) };
    let path = pcwstr_to_string(file_name);
    let (nodeid, attr) = match ctx.client.resolve_path(&path) {
        Ok(x) => x,
        Err(e) => return fuse_err_to_ntstatus(e),
    };
    let is_dir = attr_is_dir(&attr);
    let mut attrs = if is_dir {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    if ctx.read_only {
        attrs |= FILE_ATTRIBUTE_READONLY;
    }
    let ft_m = ticks_to_filetime(unix_to_filetime(attr.mtime as i64, attr.mtimensec));
    let ft_a = ticks_to_filetime(unix_to_filetime(attr.atime as i64, attr.atimensec));
    let ft_c = ticks_to_filetime(unix_to_filetime(attr.ctime as i64, attr.ctimensec));
    // SAFETY: populates caller-provided `BY_HANDLE_FILE_INFORMATION`.
    unsafe {
        (*buf).dwFileAttributes = attrs;
        (*buf).ftCreationTime = ft_c;
        (*buf).ftLastAccessTime = ft_a;
        (*buf).ftLastWriteTime = ft_m;
        (*buf).dwVolumeSerialNumber = 0x05B8_D0CA;
        (*buf).nFileSizeHigh = (attr.size >> 32) as u32;
        (*buf).nFileSizeLow = attr.size as u32;
        (*buf).nNumberOfLinks = attr.nlink.max(1);
        (*buf).nFileIndexHigh = (nodeid >> 32) as u32;
        (*buf).nFileIndexLow = nodeid as u32;
    }
    STATUS_SUCCESS
}

unsafe extern "system" fn dk_find_files(
    file_name: PCWSTR,
    fill_find_data: PFillFindData,
    info: *mut DokanFileInfo,
) -> NTSTATUS {
    // SAFETY: reads `DokanFileInfo`.
    let ctx = unsafe { ctx_from_info(info) };
    let path = pcwstr_to_string(file_name);
    let (nodeid, _) = match ctx.client.resolve_path(&path) {
        Ok(x) => x,
        Err(e) => return fuse_err_to_ntstatus(e),
    };
    let open_in = FuseOpenIn {
        flags: O_RDONLY,
        unused: 0,
    };
    let fh = match ctx.client.fuse_call(
        FUSE_OPENDIR,
        nodeid,
        as_bytes(&open_in),
        std::mem::size_of::<FuseOpenOut>(),
    ) {
        Ok(out) if out.len() >= std::mem::size_of::<FuseOpenOut>() => {
            read_pod::<FuseOpenOut>(&out).fh
        }
        Ok(_) => 0,
        Err(e) => return fuse_err_to_ntstatus(e),
    };

    let mut cookie = 0u64;
    let mut status = STATUS_SUCCESS;
    loop {
        let ri = FuseReadIn {
            fh,
            offset: cookie,
            size: 64 * 1024,
            read_flags: 0,
            lock_owner: 0,
            flags: 0,
            padding: 0,
        };
        let out = match ctx
            .client
            .fuse_call(FUSE_READDIR, nodeid, as_bytes(&ri), 64 * 1024)
        {
            Ok(o) => o,
            Err(e) => {
                status = fuse_err_to_ntstatus(e);
                break;
            }
        };
        if out.is_empty() {
            break;
        }
        let mut pos = 0usize;
        let hdr_sz = std::mem::size_of::<FuseDirent>();
        while pos + hdr_sz <= out.len() {
            let de: FuseDirent = read_pod(&out[pos..]);
            let name_start = pos + hdr_sz;
            let name_end = name_start + de.namelen as usize;
            if name_end > out.len() {
                break;
            }
            cookie = de.off;
            let name = String::from_utf8_lossy(&out[name_start..name_end]);
            let padded = (hdr_sz + de.namelen as usize + 7) & !7;
            pos += padded;

            if name == "." || name == ".." {
                continue;
            }
            let attr = ctx.client.lookup(nodeid, &name).map(|e| e.attr).ok();
            // SAFETY: zeroed `WIN32_FIND_DATAW` is valid before populating fields.
            let mut fd: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
            let is_dir = attr.as_ref().is_some_and(attr_is_dir) || de.typ == 4;
            fd.dwFileAttributes = if is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
            if ctx.read_only {
                fd.dwFileAttributes |= FILE_ATTRIBUTE_READONLY;
            }
            if let Some(a) = attr {
                fd.nFileSizeHigh = (a.size >> 32) as u32;
                fd.nFileSizeLow = a.size as u32;
                let ft = ticks_to_filetime(unix_to_filetime(a.mtime as i64, a.mtimensec));
                fd.ftCreationTime = ft;
                fd.ftLastAccessTime = ft;
                fd.ftLastWriteTime = ft;
            }
            let name_w = wide(&name);
            let copy_len = name_w.len().min(fd.cFileName.len());
            fd.cFileName[..copy_len].copy_from_slice(&name_w[..copy_len]);
            // SAFETY: delivers one directory entry to Dokan.
            unsafe {
                fill_find_data(&fd, info);
            }
        }
    }

    if fh != 0 {
        let rel = FuseReleaseIn {
            fh,
            flags: 0,
            release_flags: 0,
            lock_owner: 0,
        };
        let _ = ctx
            .client
            .fuse_call(FUSE_RELEASEDIR, nodeid, as_bytes(&rel), 0);
    }
    status
}

unsafe extern "system" fn dk_delete_check(
    _file_name: PCWSTR,
    info: *mut DokanFileInfo,
) -> NTSTATUS {
    // SAFETY: reads `DokanFileInfo`.
    let ctx = unsafe { ctx_from_info(info) };
    if ctx.read_only {
        STATUS_MEDIA_WRITE_PROTECTED
    } else {
        STATUS_SUCCESS
    }
}

unsafe extern "system" fn dk_move_file(
    file_name: PCWSTR,
    new_file_name: PCWSTR,
    _replace: i32,
    info: *mut DokanFileInfo,
) -> NTSTATUS {
    // SAFETY: reads `DokanFileInfo`.
    let ctx = unsafe { ctx_from_info(info) };
    if ctx.read_only {
        return STATUS_MEDIA_WRITE_PROTECTED;
    }
    let old_path = pcwstr_to_string(file_name);
    let new_path = pcwstr_to_string(new_file_name);
    let (old_parent, old_leaf) = match ctx.client.resolve_parent(&old_path) {
        Ok(x) => x,
        Err(e) => return fuse_err_to_ntstatus(e),
    };
    let (new_parent, new_leaf) = match ctx.client.resolve_parent(&new_path) {
        Ok(x) => x,
        Err(e) => return fuse_err_to_ntstatus(e),
    };
    let ri = FuseRenameIn { newdir: new_parent };
    let mut body = as_bytes(&ri).to_vec();
    body.extend_from_slice(old_leaf.as_bytes());
    body.push(0);
    body.extend_from_slice(new_leaf.as_bytes());
    body.push(0);
    match ctx.client.fuse_call(FUSE_RENAME, old_parent, &body, 0) {
        Ok(_) => STATUS_SUCCESS,
        Err(e) => fuse_err_to_ntstatus(e),
    }
}

unsafe extern "system" fn dk_set_eof(
    file_name: PCWSTR,
    byte_offset: i64,
    info: *mut DokanFileInfo,
) -> NTSTATUS {
    // SAFETY: reads `DokanFileInfo`.
    let ctx = unsafe { ctx_from_info(info) };
    if ctx.read_only {
        return STATUS_MEDIA_WRITE_PROTECTED;
    }
    let path = pcwstr_to_string(file_name);
    let (nodeid, _) = match ctx.client.resolve_path(&path) {
        Ok(x) => x,
        Err(e) => return fuse_err_to_ntstatus(e),
    };
    let sa = FuseSetattrIn {
        valid: FATTR_SIZE,
        size: byte_offset.max(0) as u64,
        ..Default::default()
    };
    match ctx.client.fuse_call(
        FUSE_SETATTR,
        nodeid,
        as_bytes(&sa),
        std::mem::size_of::<FuseAttrOut>(),
    ) {
        Ok(_) => STATUS_SUCCESS,
        Err(e) => fuse_err_to_ntstatus(e),
    }
}

unsafe extern "system" fn dk_noop_ok(_file_name: PCWSTR, _info: *mut DokanFileInfo) -> NTSTATUS {
    STATUS_SUCCESS
}

unsafe extern "system" fn dk_set_attrs(
    _file_name: PCWSTR,
    _attrs: u32,
    info: *mut DokanFileInfo,
) -> NTSTATUS {
    // SAFETY: reads `DokanFileInfo`.
    let ctx = unsafe { ctx_from_info(info) };
    if ctx.read_only {
        STATUS_MEDIA_WRITE_PROTECTED
    } else {
        STATUS_SUCCESS
    }
}

unsafe extern "system" fn dk_set_time(
    _file_name: PCWSTR,
    _c: *const FILETIME,
    _a: *const FILETIME,
    _w: *const FILETIME,
    info: *mut DokanFileInfo,
) -> NTSTATUS {
    // SAFETY: reads `DokanFileInfo`.
    let ctx = unsafe { ctx_from_info(info) };
    if ctx.read_only {
        STATUS_MEDIA_WRITE_PROTECTED
    } else {
        STATUS_SUCCESS
    }
}

unsafe extern "system" fn dk_get_disk_free_space(
    free_avail: *mut u64,
    total_bytes: *mut u64,
    total_free: *mut u64,
    info: *mut DokanFileInfo,
) -> NTSTATUS {
    // SAFETY: reads `DokanFileInfo`.
    let ctx = unsafe { ctx_from_info(info) };
    let (avail, total, free) = match ctx.client.fuse_call(
        FUSE_STATFS,
        FUSE_ROOT_ID,
        &[],
        std::mem::size_of::<FuseKstatfs>(),
    ) {
        Ok(out) if out.len() >= std::mem::size_of::<FuseKstatfs>() => {
            let st: FuseKstatfs = read_pod(&out);
            let bs = u64::from(st.frsize.max(st.bsize).max(4096));
            (
                st.bavail.saturating_mul(bs),
                st.blocks.saturating_mul(bs),
                st.bfree.saturating_mul(bs),
            )
        }
        _ => (16 << 30, 64 << 30, 16 << 30),
    };
    // SAFETY: writes free/total byte counts to Dokan output pointers.
    unsafe {
        if !free_avail.is_null() {
            *free_avail = avail;
        }
        if !total_bytes.is_null() {
            *total_bytes = total;
        }
        if !total_free.is_null() {
            *total_free = free;
        }
    }
    STATUS_SUCCESS
}

unsafe extern "system" fn dk_get_vol_info(
    vol_name: PWSTR,
    vol_name_len: u32,
    serial: *mut u32,
    max_comp: *mut u32,
    fs_flags: *mut u32,
    fs_name: PWSTR,
    fs_name_len: u32,
    info: *mut DokanFileInfo,
) -> NTSTATUS {
    // SAFETY: reads `DokanFileInfo`.
    let ctx = unsafe { ctx_from_info(info) };
    let v = wide(&ctx.tag);
    let f = wide("virtiofs");
    // SAFETY: copies volume and filesystem names into caller buffers.
    unsafe {
        if !vol_name.is_null() && vol_name_len > 0 {
            let n = v.len().min(vol_name_len as usize);
            std::ptr::copy_nonoverlapping(v.as_ptr(), vol_name, n);
            *vol_name.add(n - 1) = 0;
        }
        if !fs_name.is_null() && fs_name_len > 0 {
            let n = f.len().min(fs_name_len as usize);
            std::ptr::copy_nonoverlapping(f.as_ptr(), fs_name, n);
            *fs_name.add(n - 1) = 0;
        }
        if !serial.is_null() {
            *serial = 0x05B8_D0CA;
        }
        if !max_comp.is_null() {
            *max_comp = 255;
        }
        if !fs_flags.is_null() {
            // FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK (+ FILE_READ_ONLY_VOLUME if RO)
            *fs_flags = 0x0000_0002 | 0x0000_0004 | if ctx.read_only { 0x0008_0000 } else { 0 };
        }
    }
    STATUS_SUCCESS
}

unsafe extern "system" fn dk_mounted(_mp: PCWSTR, info: *mut DokanFileInfo) -> NTSTATUS {
    // SAFETY: signals the mount readiness waiter once.
    let ctx = unsafe { ctx_from_info(info) };
    if let Some(tx) = ctx.mounted_tx.lock().unwrap().take() {
        let _ = tx.send(());
    }
    STATUS_SUCCESS
}

unsafe extern "system" fn dk_unmounted(_info: *mut DokanFileInfo) -> NTSTATUS {
    STATUS_SUCCESS
}

unsafe extern "system" fn dk_not_impl_sec(
    _f: PCWSTR,
    _si: *mut u32,
    _sd: *mut c_void,
    _bl: u32,
    _ln: *mut u32,
    _info: *mut DokanFileInfo,
) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}

unsafe extern "system" fn dk_not_impl_set_sec(
    _f: PCWSTR,
    _si: *mut u32,
    _sd: *mut c_void,
    _bl: u32,
    _info: *mut DokanFileInfo,
) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}

/// Mount a PCIe `virtio-fs` share (`viofs.sys`) via runtime-loaded `dokan2.dll`.
pub(crate) fn start_dokany_mount(
    tag: String,
    target: String,
    read_only: bool,
) -> io::Result<Arc<AtomicBool>> {
    let api = load_dokan_api().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Dokany 2 (dokan2.dll) is not installed in this guest",
        )
    })?;
    let client = ViofsClient::open(&tag)?;

    // Dokan requires directory mount points to exist and be empty.
    let target_path = Path::new(&target);
    if target_path.exists() {
        let _ = fs::remove_dir(target_path);
    }
    fs::create_dir_all(target_path)?;

    let (tx, rx) = mpsc::channel();
    let ctx = Box::leak(Box::new(DokanMountCtx {
        client,
        tag,
        read_only,
        next_ctx: AtomicU64::new(1),
        handles: Mutex::new(HashMap::new()),
        mounted_tx: Mutex::new(Some(tx)),
    }));
    let ctx_addr = (ctx as *const DokanMountCtx) as u64;
    let stop = Arc::new(AtomicBool::new(false));
    let target_clone = target.clone();

    thread::spawn(move || {
        let mp_w = wide(&target_clone);
        let mut opts = DokanOptions {
            version: DOKAN_VERSION_200,
            single_thread: 0,
            options: if read_only {
                DOKAN_OPTION_WRITE_PROTECT
            } else {
                0
            },
            global_context: ctx_addr,
            mount_point: mp_w.as_ptr(),
            unc_name: null(),
            timeout: 15_000,
            allocation_unit_size: 4096,
            sector_size: 4096,
            volume_security_descriptor_length: 0,
            volume_security_descriptor: [0u8; VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE],
        };
        let mut ops = DokanOperations {
            zw_create_file: Some(dk_zw_create_file),
            cleanup: Some(dk_cleanup),
            close_file: Some(dk_close_file),
            read_file: Some(dk_read_file),
            write_file: Some(dk_write_file),
            flush_file_buffers: Some(dk_noop_ok),
            get_file_information: Some(dk_get_file_info),
            find_files: Some(dk_find_files),
            find_files_with_pattern: None,
            set_file_attributes: Some(dk_set_attrs),
            set_file_time: Some(dk_set_time),
            delete_file: Some(dk_delete_check),
            delete_directory: Some(dk_delete_check),
            move_file: Some(dk_move_file),
            set_end_of_file: Some(dk_set_eof),
            set_allocation_size: Some(dk_set_eof),
            lock_file: None,
            unlock_file: None,
            get_disk_free_space: Some(dk_get_disk_free_space),
            get_volume_information: Some(dk_get_vol_info),
            mounted: Some(dk_mounted),
            unmounted: Some(dk_unmounted),
            get_file_security: Some(dk_not_impl_sec),
            set_file_security: Some(dk_not_impl_set_sec),
            find_streams: None,
        };
        // SAFETY: runs the Dokan filesystem dispatch loop until unmounted.
        let rc = unsafe { (api.main)(&mut opts, &mut ops) };
        if rc != 0 {
            eprintln!("osbx-agent dokany: DokanMain({target_clone}) exited with {rc}");
        }
    });

    rx.recv_timeout(Duration::from_secs(10)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("Dokany mount {target} did not become ready within 10s"),
        )
    })?;
    Ok(stop)
}
