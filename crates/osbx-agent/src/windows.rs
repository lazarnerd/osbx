//! Windows in-guest agent (`osbx-agent.exe`).
//!
//! Runs as a LocalSystem Windows Service (`osbx-agent`, or `--console` interactively) inside a
//! Windows guest VM and serves the exact `osbx-proto` protocol over Red Hat `virtio-win`'s
//! `viosock.sys` (`AF_VSOCK`) transport:
//! * `AGENT_PORT (1024)`: framed `EXEC` (pipes or ConPTY), `RESIZE`, `SIGNAL`, `POWEROFF`
//! * `TUNNEL_PORT (1025)`: raw host -> guest TCP port forwarding (RDP, HTTP, etc.)
//! * `EGRESS_PORT (3128)`: guest `127.0.0.1:3128` -> host policy proxy (no virtual NIC)
//! * `--install-ca <pem>`: installs the sandbox CA into `LocalMachine\Root` and wires WinHTTP,
//!   WinINET, and machine proxy environment variables.

#![allow(unsafe_code)]

use osbx_proto::{
    AGENT_PORT, CHUNK, EGRESS_PORT, ERROR, EXEC, EXIT, ExecRequest, GUEST_PROXY_ADDR, POWEROFF,
    RESIZE, SIGNAL, STDERR, STDIN, STDIN_EOF, STDOUT, TUNNEL_PORT, read_frame, write_frame,
};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::windows::ffi::OsStrExt;
use std::process::Command;
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, GetLastError, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LUID, SetHandleInformation,
};
use windows_sys::Win32::Networking::WinSock::{
    INVALID_SOCKET, SD_SEND, SOCK_STREAM, SOCKET, SOCKET_ERROR, WSADATA, WSAStartup, accept, bind,
    closesocket, connect, listen, recv, send, shutdown, socket,
};
use windows_sys::Win32::Security::Cryptography::{
    CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_LOCAL_MACHINE,
    CertAddEncodedCertificateToStore, CertCloseStore, CertOpenStore, X509_ASN_ENCODING,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    SECURITY_ATTRIBUTES, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadFile,
    WriteFile,
};
use windows_sys::Win32::System::Console::{
    COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_DWORD, REG_SZ, RegCloseKey,
    RegCreateKeyExW, RegSetValueExW,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};
use windows_sys::Win32::System::Shutdown::{
    InitiateSystemShutdownExW, SHTDN_REASON_FLAG_PLANNED, SHTDN_REASON_MAJOR_OTHER,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess, INFINITE,
    InitializeProcThreadAttributeList, OpenProcessToken, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

const HOST_CID: u32 = 2;
const VMADDR_CID_ANY: u32 = u32::MAX;
/// Red Hat `viosock.sys` IOCTL to query the dynamic `AF_VSOCK` address family:
/// `CTL_CODE(FILE_DEVICE_UNKNOWN (0x22), 0x800, METHOD_BUFFERED (0), FILE_ANY_ACCESS (0))`.
const IOCTL_VIOSOCK_GET_AF: u32 = 0x0022_2000;
const FALLBACK_AF_VSOCK: u16 = 40;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

static SERVICE_STATUS_H: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static AF_VSOCK_CACHE: OnceLock<u16> = OnceLock::new();

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

pub fn run() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--install-ca") {
        let Some(pem_path) = args.get(1) else {
            eprintln!("usage: osbx-agent --install-ca <ca.pem>");
            std::process::exit(2);
        };
        if let Err(e) = install_ca_and_proxy(pem_path) {
            eprintln!("osbx-agent --install-ca failed: {e}");
            std::process::exit(1);
        }
        return;
    }

    if args.first().map(String::as_str) == Some("--console") {
        run_agent_loop();
        return;
    }

    // Attempt to run as a Windows Service; fall back to console mode if launched interactively.
    let mut name = wide("osbx-agent");
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: `table` is properly NUL-terminated and `service_main` matches the SCM callback ABI.
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 {
        // SAFETY: `GetLastError` reads thread-local error code.
        let err = unsafe { GetLastError() };
        if err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
            run_agent_loop();
        } else {
            eprintln!("StartServiceCtrlDispatcherW failed: {err}");
            std::process::exit(1);
        }
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide("osbx-agent");
    // SAFETY: registers the SCM control handler for `osbx-agent`.
    let handle = unsafe { RegisterServiceCtrlHandlerW(name.as_ptr(), Some(service_ctrl)) };
    if handle.is_null() {
        return;
    }
    SERVICE_STATUS_H.store(handle as usize, std::sync::atomic::Ordering::SeqCst);
    report_service_state(handle, SERVICE_START_PENDING, 0);
    report_service_state(handle, SERVICE_RUNNING, 0);
    run_agent_loop();
    report_service_state(handle, SERVICE_STOPPED, 0);
}

unsafe extern "system" fn service_ctrl(control: u32) {
    if matches!(control, SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN) {
        let h = SERVICE_STATUS_H.load(std::sync::atomic::Ordering::SeqCst) as SERVICE_STATUS_HANDLE;
        if !h.is_null() {
            report_service_state(h, SERVICE_STOPPED, 0);
        }
        std::process::exit(0);
    }
}

fn report_service_state(handle: SERVICE_STATUS_HANDLE, state: u32, exit_code: u32) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    // SAFETY: `handle` is a valid SCM handle and `status` is initialized.
    unsafe {
        SetServiceStatus(handle, &status);
    }
}

fn run_agent_loop() {
    init_winsock();
    // Wait until `viosock.sys` is ready during early Windows boot.
    let af = wait_for_viosock();
    eprintln!("osbx-agent (windows): ready (AF_VSOCK={af})");
    let _ = configure_windows_proxy();

    thread::spawn(move || accept_loop(af, AGENT_PORT, handle_control));
    thread::spawn(move || accept_loop(af, TUNNEL_PORT, handle_tunnel));
    egress_listener(af);
}

fn init_winsock() {
    // SAFETY: `WSADATA` is plain old data; all-zeros is valid before `WSAStartup` fills it.
    let mut wsa: WSADATA = unsafe { std::mem::zeroed() };
    // SAFETY: `wsa` points to valid writable storage; version 2.2 requested.
    let _ = unsafe { WSAStartup(0x0202, &mut wsa) };
}

fn query_viosock_af() -> Option<u16> {
    let path = wide(r"\\.\Viosock");
    // SAFETY: opens the Red Hat `viosock.sys` control device to query the dynamic AF_VSOCK value.
    let h = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return None;
    }
    let mut af: u32 = 0;
    let mut returned: u32 = 0;
    // SAFETY: valid device handle and output buffer of 4 bytes.
    let ok = unsafe {
        DeviceIoControl(
            h,
            IOCTL_VIOSOCK_GET_AF,
            null(),
            0,
            (&mut af as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
            null_mut(),
        )
    };
    // SAFETY: closing our device handle.
    unsafe {
        CloseHandle(h);
    }
    (ok != 0 && returned >= 2 && af <= u32::from(u16::MAX)).then_some(af as u16)
}

fn wait_for_viosock() -> u16 {
    *AF_VSOCK_CACHE.get_or_init(|| {
        for _ in 0..60 {
            if let Some(af) = query_viosock_af() {
                return af;
            }
            // Fallback probe: try opening a socket with AF_VSOCK = 40 directly.
            // SAFETY: WinSock `socket` call with stream type.
            let s = unsafe { socket(i32::from(FALLBACK_AF_VSOCK), SOCK_STREAM, 0) };
            if s != INVALID_SOCKET {
                // SAFETY: closing probe socket.
                unsafe {
                    closesocket(s);
                }
                return FALLBACK_AF_VSOCK;
            }
            thread::sleep(Duration::from_millis(500));
        }
        FALLBACK_AF_VSOCK
    })
}

/// Ref-counted Windows WinSock vsock stream supporting full-duplex concurrent Read + Write.
#[derive(Clone)]
struct VsockConn(Arc<SocketGuard>);

struct SocketGuard(SOCKET);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        // SAFETY: last owner closes the underlying socket once.
        unsafe {
            closesocket(self.0);
        }
    }
}

impl VsockConn {
    fn shutdown_write(&self) {
        // SAFETY: valid open socket handle.
        unsafe {
            shutdown(self.0.0, SD_SEND);
        }
    }
}

impl Read for VsockConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len().min(i32::MAX as usize) as i32;
        // SAFETY: `buf` is valid writable memory of `len` bytes.
        let n = unsafe { recv(self.0.0, buf.as_mut_ptr(), len, 0) };
        if n == SOCKET_ERROR {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

impl Write for VsockConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len().min(i32::MAX as usize) as i32;
        // SAFETY: `buf` is valid readable memory of `len` bytes.
        let n = unsafe { send(self.0.0, buf.as_ptr(), len, 0) };
        if n == SOCKET_ERROR {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn vsock_listen(af: u16, port: u32) -> io::Result<SocketGuard> {
    // SAFETY: WinSock stream socket creation.
    let s = unsafe { socket(i32::from(af), SOCK_STREAM, 0) };
    if s == INVALID_SOCKET {
        return Err(io::Error::last_os_error());
    }
    let guard = SocketGuard(s);
    let addr = SockAddrVm {
        svm_family: af,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };
    // SAFETY: `addr` is properly sized `SockAddrVm`.
    if unsafe {
        bind(
            s,
            (&addr as *const SockAddrVm).cast(),
            std::mem::size_of::<SockAddrVm>() as i32,
        )
    } == SOCKET_ERROR
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: listening on bound socket.
    if unsafe { listen(s, 32) } == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    Ok(guard)
}

fn vsock_connect(af: u16, cid: u32, port: u32) -> io::Result<VsockConn> {
    // SAFETY: WinSock stream socket creation.
    let s = unsafe { socket(i32::from(af), SOCK_STREAM, 0) };
    if s == INVALID_SOCKET {
        return Err(io::Error::last_os_error());
    }
    let conn = VsockConn(Arc::new(SocketGuard(s)));
    let addr = SockAddrVm {
        svm_family: af,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: cid,
        svm_zero: [0; 4],
    };
    // SAFETY: `addr` is properly sized `SockAddrVm`.
    if unsafe {
        connect(
            s,
            (&addr as *const SockAddrVm).cast(),
            std::mem::size_of::<SockAddrVm>() as i32,
        )
    } == SOCKET_ERROR
    {
        return Err(io::Error::last_os_error());
    }
    Ok(conn)
}

fn accept_loop(af: u16, port: u32, handler: fn(VsockConn)) {
    let listener = loop {
        match vsock_listen(af, port) {
            Ok(l) => break l,
            Err(e) => {
                eprintln!("osbx-agent: vsock listen {port} failed: {e}; retrying");
                thread::sleep(Duration::from_secs(1));
            }
        }
    };
    loop {
        // SAFETY: accepting on valid listening socket.
        let client = unsafe { accept(listener.0, null_mut(), null_mut()) };
        if client == INVALID_SOCKET {
            thread::sleep(Duration::from_millis(50));
            continue;
        }
        let conn = VsockConn(Arc::new(SocketGuard(client)));
        thread::spawn(move || handler(conn));
    }
}

fn egress_listener(af: u16) {
    let listener = loop {
        match TcpListener::bind(GUEST_PROXY_ADDR) {
            Ok(l) => break l,
            Err(e) => {
                eprintln!("osbx-agent: bind {GUEST_PROXY_ADDR}: {e}");
                thread::sleep(Duration::from_secs(1));
            }
        }
    };
    for incoming in listener.incoming().flatten() {
        thread::spawn(move || {
            let Ok(vs) = vsock_connect(af, HOST_CID, EGRESS_PORT) else {
                return;
            };
            let _ = splice(incoming, vs);
        });
    }
}

fn handle_tunnel(vs: VsockConn) {
    let mut reader = BufReader::new(vs.clone());
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let target = line.trim();
    let Ok(mut tcp) = TcpStream::connect(target) else {
        return;
    };
    let buffered = reader.buffer().to_vec();
    if !buffered.is_empty() && tcp.write_all(&buffered).is_err() {
        return;
    }
    let _ = splice(tcp, vs);
}

fn splice(mut tcp: TcpStream, mut vs: VsockConn) -> io::Result<()> {
    let mut tcp_w = tcp.try_clone()?;
    let mut vs_r = vs.clone();
    let down = thread::spawn(move || {
        let _ = io::copy(&mut vs_r, &mut tcp_w);
        let _ = tcp_w.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut tcp, &mut vs);
    vs.shutdown_write();
    let _ = down.join();
    Ok(())
}

fn handle_control(mut conn: VsockConn) {
    let frame = match read_frame(&mut conn) {
        Ok(Some(f)) => f,
        _ => return,
    };
    match frame.0 {
        POWEROFF => {
            trigger_poweroff();
        }
        EXEC => {
            let req: ExecRequest = match serde_json::from_slice(&frame.1) {
                Ok(r) => r,
                Err(e) => {
                    let _ = write_frame(
                        &mut conn,
                        ERROR,
                        format!("bad exec request: {e}").as_bytes(),
                    );
                    return;
                }
            };
            if req.argv.is_empty() {
                let _ = write_frame(&mut conn, ERROR, b"empty argv");
                return;
            }
            let res = if req.tty {
                run_exec_conpty(conn.clone(), &req)
            } else {
                run_exec_piped(conn.clone(), &req)
            };
            if let Err(e) = res {
                let _ = write_frame(
                    &mut conn,
                    ERROR,
                    format!("cannot run {:?}: {e}", req.argv[0]).as_bytes(),
                );
            }
        }
        other => {
            let _ = write_frame(
                &mut conn,
                ERROR,
                format!("unexpected frame 0x{other:02x}").as_bytes(),
            );
        }
    }
}

/// Build a properly escaped Windows command line from `argv`.
fn build_cmdline(argv: &[String]) -> String {
    let mut out = String::new();
    for (i, arg) in argv.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let needs_quote = arg.is_empty() || arg.chars().any(|c| c == ' ' || c == '\t' || c == '"');
        if !needs_quote {
            out.push_str(arg);
            continue;
        }
        out.push('"');
        let mut backslashes = 0usize;
        for c in arg.chars() {
            if c == '\\' {
                backslashes += 1;
            } else if c == '"' {
                for _ in 0..backslashes * 2 + 1 {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            } else {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
        for _ in 0..backslashes * 2 {
            out.push('\\');
        }
        out.push('"');
    }
    out
}

/// Build a Windows UTF-16 `CREATE_UNICODE_ENVIRONMENT` block, merging the host system environment
/// with `overrides` (case-insensitive key replacement).
fn build_env_block(overrides: &BTreeMap<String, String>) -> Vec<u16> {
    let mut merged: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (k, v) in std::env::vars() {
        merged.insert(k.to_ascii_uppercase(), (k, v));
    }
    for (k, v) in overrides {
        merged.insert(k.to_ascii_uppercase(), (k.clone(), v.clone()));
    }
    let mut block = Vec::new();
    for (_, (k, v)) in merged {
        block.extend(OsStr::new(&k).encode_wide());
        block.push(b'=' as u16);
        block.extend(OsStr::new(&v).encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

struct OwnedHandle(HANDLE);
// SAFETY: Win32 kernel handles (pipes, processes, jobs) are valid across threads in this process.
unsafe impl Send for OwnedHandle {}
// SAFETY: Win32 kernel handles are synchronized by the OS kernel.
unsafe impl Sync for OwnedHandle {}
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: valid owned handle closed once on drop.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn create_pipe_pair(
    inherit_read: bool,
    inherit_write: bool,
) -> io::Result<(OwnedHandle, OwnedHandle)> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut r: HANDLE = null_mut();
    let mut w: HANDLE = null_mut();
    // SAFETY: `CreatePipe` initializes `r` and `w`.
    if unsafe { CreatePipe(&mut r, &mut w, &sa, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if !inherit_read {
        // SAFETY: clears inherit flag on our read handle.
        unsafe {
            SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);
        }
    }
    if !inherit_write {
        // SAFETY: clears inherit flag on our write handle.
        unsafe {
            SetHandleInformation(w, HANDLE_FLAG_INHERIT, 0);
        }
    }
    Ok((OwnedHandle(r), OwnedHandle(w)))
}

fn create_kill_on_close_job() -> Option<OwnedHandle> {
    // SAFETY: creates an unnamed Job Object.
    let job = unsafe { CreateJobObjectW(null(), null()) };
    if job.is_null() {
        return None;
    }
    // SAFETY: `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` is plain old data.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: configures kill-on-close so grandchildren are always reaped.
    let ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        // SAFETY: closes failed job handle.
        unsafe {
            CloseHandle(job);
        }
        return None;
    }
    Some(OwnedHandle(job))
}

fn pump_handle_to_frames(handle: OwnedHandle, frame_ty: u8, writer: Arc<Mutex<VsockConn>>) {
    let mut buf = vec![0u8; CHUNK];
    loop {
        let mut n: u32 = 0;
        // SAFETY: reads from valid pipe handle into `buf`.
        let ok = unsafe {
            ReadFile(
                handle.0,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut n,
                null_mut(),
            )
        };
        if ok == 0 || n == 0 {
            break;
        }
        let mut w = writer.lock().unwrap();
        if write_frame(&mut *w, frame_ty, &buf[..n as usize]).is_err() {
            break;
        }
    }
}

fn write_all_handle(handle: HANDLE, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        let mut written: u32 = 0;
        // SAFETY: writes valid slice to open pipe handle.
        let ok = unsafe {
            WriteFile(
                handle,
                data.as_ptr(),
                data.len().min(u32::MAX as usize) as u32,
                &mut written,
                null_mut(),
            )
        };
        if ok == 0 || written == 0 {
            return false;
        }
        data = &data[written as usize..];
    }
    true
}

fn run_exec_piped(conn: VsockConn, req: &ExecRequest) -> io::Result<()> {
    let (in_r, in_w) = create_pipe_pair(true, false)?;
    let (out_r, out_w) = create_pipe_pair(false, true)?;
    let (err_r, err_w) = create_pipe_pair(false, true)?;

    let mut cmd = wide(&build_cmdline(&req.argv));
    let mut env = build_env_block(&req.env);
    let cwd = req.cwd.as_deref().map(wide);

    // SAFETY: `STARTUPINFOW` is plain old data.
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_r.0;
    si.hStdOutput = out_w.0;
    si.hStdError = err_w.0;
    // SAFETY: `PROCESS_INFORMATION` is plain old data filled by `CreateProcessW`.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: spawns child process with explicit redirected std handles.
    let ok = unsafe {
        CreateProcessW(
            null(),
            cmd.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            env.as_mut_ptr().cast(),
            cwd.as_ref().map_or(null(), |w| w.as_ptr()),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(in_r);
    drop(out_w);
    drop(err_w);

    let proc_h = OwnedHandle(pi.hProcess);
    let _thread_h = OwnedHandle(pi.hThread);
    let job = create_kill_on_close_job().map(Arc::new);
    if let Some(j) = &job {
        // SAFETY: assigns child process to kill-on-close Job Object.
        unsafe {
            AssignProcessToJobObject(j.0, proc_h.0);
        }
    }

    let writer = Arc::new(Mutex::new(conn.clone()));
    let w_out = writer.clone();
    let t_out = thread::spawn(move || pump_handle_to_frames(out_r, STDOUT, w_out));
    let w_err = writer.clone();
    let t_err = thread::spawn(move || pump_handle_to_frames(err_r, STDERR, w_err));

    let mut reader = conn;
    let job_sig = job.clone();
    let proc_raw = proc_h.0 as usize;
    let t_in = thread::spawn(move || {
        let mut stdin_h = Some(in_w);
        while let Ok(Some((ty, payload))) = read_frame(&mut reader) {
            match ty {
                STDIN => {
                    if let Some(h) = &stdin_h
                        && !write_all_handle(h.0, &payload)
                    {
                        stdin_h = None;
                    }
                }
                STDIN_EOF => {
                    stdin_h = None;
                }
                SIGNAL => {
                    if let Some(j) = &job_sig {
                        // SAFETY: terminates job tree on host signal.
                        unsafe {
                            TerminateJobObject(j.0, 137);
                        }
                    } else {
                        // SAFETY: `proc_raw` is valid until `WaitForSingleObject` completes.
                        unsafe {
                            TerminateProcess(proc_raw as HANDLE, 137);
                        }
                    }
                }
                _ => {}
            }
        }
    });

    // SAFETY: waits for child exit.
    unsafe {
        WaitForSingleObject(proc_h.0, INFINITE);
    }
    let mut code: u32 = 1;
    // SAFETY: reads exit code of exited process.
    unsafe {
        GetExitCodeProcess(proc_h.0, &mut code);
    }
    let _ = t_out.join();
    let _ = t_err.join();
    drop(t_in);
    let _ = write_frame(
        &mut *writer.lock().unwrap(),
        EXIT,
        &(code as i32).to_le_bytes(),
    );
    Ok(())
}

fn run_exec_conpty(conn: VsockConn, req: &ExecRequest) -> io::Result<()> {
    let (in_r, in_w) = create_pipe_pair(false, false)?;
    let (out_r, out_w) = create_pipe_pair(false, false)?;
    let cols = if req.cols == 0 { 80 } else { req.cols } as i16;
    let rows = if req.rows == 0 { 24 } else { req.rows } as i16;

    let mut hpc: HPCON = 0;
    // SAFETY: creates a Windows ConPTY bound to our pipe handles.
    let hr =
        unsafe { CreatePseudoConsole(COORD { X: cols, Y: rows }, in_r.0, out_w.0, 0, &mut hpc) };
    if hr < 0 {
        return Err(io::Error::other(format!(
            "CreatePseudoConsole: 0x{:08x}",
            hr as u32
        )));
    }
    struct PtyGuard(HPCON);
    // SAFETY: `HPCON` is a process-wide opaque pseudo-console handle synchronized by Mutex.
    unsafe impl Send for PtyGuard {}
    // SAFETY: `HPCON` access is serialized by Mutex.
    unsafe impl Sync for PtyGuard {}
    impl PtyGuard {
        fn close(&mut self) {
            if self.0 != 0 {
                let h = self.0;
                self.0 = 0;
                // SAFETY: closes ConPTY handle exactly once.
                unsafe {
                    ClosePseudoConsole(h);
                }
            }
        }
    }
    impl Drop for PtyGuard {
        fn drop(&mut self) {
            self.close();
        }
    }
    let pty = Arc::new(Mutex::new(PtyGuard(hpc)));

    let mut attr_size: usize = 0;
    // SAFETY: queries required byte size for 1 attribute.
    unsafe {
        InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut attr_size);
    }
    let mut attr_buf = vec![0u8; attr_size.max(64)];
    let attr_list = attr_buf.as_mut_ptr().cast();
    // SAFETY: initializes attribute list in `attr_buf`.
    if unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    struct AttrGuard(*mut std::ffi::c_void);
    impl Drop for AttrGuard {
        fn drop(&mut self) {
            // SAFETY: frees initialized attribute list.
            unsafe {
                DeleteProcThreadAttributeList(self.0);
            }
        }
    }
    let _attr_guard = AttrGuard(attr_list);

    // SAFETY: attaches `hpc` to the attribute list.
    if unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
            hpc as *const std::ffi::c_void,
            std::mem::size_of::<HPCON>(),
            null_mut(),
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut cmd = wide(&build_cmdline(&req.argv));
    let mut env = build_env_block(&req.env);
    let cwd = req.cwd.as_deref().map(wide);
    // SAFETY: `STARTUPINFOEXW` is plain old data.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.lpAttributeList = attr_list;

    // SAFETY: `PROCESS_INFORMATION` is plain old data filled by `CreateProcessW`.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: spawns child attached to ConPTY via `EXTENDED_STARTUPINFO_PRESENT`.
    let ok = unsafe {
        CreateProcessW(
            null(),
            cmd.as_mut_ptr(),
            null(),
            null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            env.as_mut_ptr().cast(),
            cwd.as_ref().map_or(null(), |w| w.as_ptr()),
            &si.StartupInfo,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(in_r);
    drop(out_w);

    let proc_h = OwnedHandle(pi.hProcess);
    let _thread_h = OwnedHandle(pi.hThread);
    let job = create_kill_on_close_job().map(Arc::new);
    if let Some(j) = &job {
        // SAFETY: attaches ConPTY child to Job Object.
        unsafe {
            AssignProcessToJobObject(j.0, proc_h.0);
        }
    }

    let writer = Arc::new(Mutex::new(conn.clone()));
    let w_out = writer.clone();
    let t_out = thread::spawn(move || pump_handle_to_frames(out_r, STDOUT, w_out));

    let in_w = Arc::new(Mutex::new(Some(in_w)));
    let mut reader = conn;
    let in_w_thr = in_w.clone();
    let pty_ctrl = pty.clone();
    let job_sig = job.clone();
    let _t_in = thread::spawn(move || {
        while let Ok(Some((ty, payload))) = read_frame(&mut reader) {
            match ty {
                STDIN => {
                    let mut guard = in_w_thr.lock().unwrap();
                    if let Some(h) = guard.as_ref()
                        && !write_all_handle(h.0, &payload)
                    {
                        *guard = None;
                    }
                }
                STDIN_EOF => {
                    // Do NOT close the ConPTY input pipe on host stdin EOF: closing `in_w`
                    // terminates `conhost.exe` prematurely before non-interactive commands finish.
                }
                RESIZE if payload.len() == 4 => {
                    let r = u16::from_le_bytes([payload[0], payload[1]]) as i16;
                    let c = u16::from_le_bytes([payload[2], payload[3]]) as i16;
                    let guard = pty_ctrl.lock().unwrap();
                    if guard.0 != 0 {
                        // SAFETY: resizes active ConPTY.
                        unsafe {
                            ResizePseudoConsole(
                                guard.0,
                                COORD {
                                    X: c.max(1),
                                    Y: r.max(1),
                                },
                            );
                        }
                    }
                }
                SIGNAL => {
                    if let Some(j) = &job_sig {
                        // SAFETY: terminates job tree on signal.
                        unsafe {
                            TerminateJobObject(j.0, 137);
                        }
                    }
                }
                _ => {}
            }
        }
    });

    // SAFETY: waits for ConPTY child process exit.
    unsafe {
        WaitForSingleObject(proc_h.0, INFINITE);
    }
    let mut code: u32 = 1;
    // SAFETY: fetches child exit code.
    unsafe {
        GetExitCodeProcess(proc_h.0, &mut code);
    }
    // Close ConPTY explicitly (even though `_t_in` still holds an Arc clone) so `out_r` reaches
    // EOF promptly instead of blocking `t_out.join()`.
    *in_w.lock().unwrap() = None;
    pty.lock().unwrap().close();
    let _ = t_out.join();
    let _ = write_frame(
        &mut *writer.lock().unwrap(),
        EXIT,
        &(code as i32).to_le_bytes(),
    );
    Ok(())
}

/// Install a PEM-encoded CA certificate into `LocalMachine\Root` and configure WinHTTP, WinINET,
/// and machine proxy environment variables.
fn install_ca_and_proxy(pem_path: &str) -> io::Result<()> {
    let pem = std::fs::read_to_string(pem_path)?;
    let der = decode_pem_cert(&pem)?;
    let store_name = wide("ROOT");
    // SAFETY: opens the LocalMachine Root certificate store.
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE,
            store_name.as_ptr().cast(),
        )
    };
    if store.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: adds DER-encoded X.509 certificate into LocalMachine\Root.
    let ok = unsafe {
        CertAddEncodedCertificateToStore(
            store,
            X509_ASN_ENCODING,
            der.as_ptr(),
            der.len() as u32,
            CERT_STORE_ADD_REPLACE_EXISTING,
            null_mut(),
        )
    };
    // SAFETY: closes cert store handle.
    unsafe {
        CertCloseStore(store, 0);
    }
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    configure_windows_proxy()?;
    set_machine_env("NODE_EXTRA_CA_CERTS", pem_path)?;
    set_machine_env("SSL_CERT_FILE", pem_path)?;
    set_machine_env("REQUESTS_CA_BUNDLE", pem_path)?;
    set_machine_env("CARGO_HTTP_CAINFO", pem_path)?;
    Ok(())
}

fn configure_windows_proxy() -> io::Result<()> {
    // 1. WinHTTP (PowerShell Invoke-WebRequest, .NET HttpClient, winget, services)
    let _ = Command::new("netsh")
        .args(["winhttp", "set", "proxy", GUEST_PROXY_ADDR, "<local>"])
        .status();
    // 2. WinINET (Chromium/Edge, PowerShell 5.1/.NET WebRequest, Visual Studio Installer, NuGet)
    // Set both HKCU and machine-wide HKLM (`ProxySettingsPerUser = 0`) so SYSTEM services and
    // interactive users inherit 127.0.0.1:3128 automatically.
    let _ = set_reg_dword(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
        "ProxySettingsPerUser",
        0,
    );
    for root in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        let _ = set_reg_dword(
            root,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyEnable",
            1,
        );
        let _ = set_reg_sz(
            root,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyServer",
            GUEST_PROXY_ADDR,
        );
        let _ = set_reg_sz(
            root,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyOverride",
            "<local>",
        );
    }
    // 3. Machine environment variables
    let proxy_url = format!("http://{GUEST_PROXY_ADDR}");
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        let _ = set_machine_env(k, &proxy_url);
    }
    let _ = set_machine_env("NO_PROXY", "localhost,127.0.0.1");
    // 4. .NET Framework machine.config `<system.net><defaultProxy>` so PowerShell 5.1 and
    //    .NET services running under LocalSystem also route through 127.0.0.1:3128 automatically.
    let net_snippet = format!(
        "  <system.net>\r\n    <defaultProxy enabled=\"true\">\r\n      <proxy proxyaddress=\"http://{GUEST_PROXY_ADDR}\" bypassonlocal=\"true\" usesystemdefault=\"false\" />\r\n    </defaultProxy>\r\n  </system.net>\r\n"
    );
    for cfg_path in [
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config",
        r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\machine.config",
    ] {
        if let Ok(content) = std::fs::read_to_string(cfg_path)
            && !content.contains(GUEST_PROXY_ADDR)
            && let Some(pos) = content.rfind("</configuration>")
        {
            let mut updated = String::with_capacity(content.len() + net_snippet.len());
            updated.push_str(&content[..pos]);
            updated.push_str(&net_snippet);
            updated.push_str(&content[pos..]);
            let _ = std::fs::write(cfg_path, updated);
        }
    }
    Ok(())
}

fn set_machine_env(name: &str, value: &str) -> io::Result<()> {
    set_reg_sz(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        name,
        value,
    )
}

fn set_reg_sz(root: HKEY, subkey: &str, name: &str, value: &str) -> io::Result<()> {
    let sub = wide(subkey);
    let mut hkey: HKEY = null_mut();
    // SAFETY: opens or creates registry key.
    let rc = unsafe {
        RegCreateKeyExW(
            root,
            sub.as_ptr(),
            0,
            null(),
            0,
            KEY_SET_VALUE,
            null(),
            &mut hkey,
            null_mut(),
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let n = wide(name);
    let v = wide(value);
    // SAFETY: writes NUL-terminated UTF-16 REG_SZ value.
    let rc2 = unsafe {
        RegSetValueExW(
            hkey,
            n.as_ptr(),
            0,
            REG_SZ,
            v.as_ptr().cast(),
            (v.len() * 2) as u32,
        )
    };
    // SAFETY: closes registry key handle.
    unsafe {
        RegCloseKey(hkey);
    }
    if rc2 != 0 {
        return Err(io::Error::from_raw_os_error(rc2 as i32));
    }
    Ok(())
}

fn set_reg_dword(root: HKEY, subkey: &str, name: &str, value: u32) -> io::Result<()> {
    let sub = wide(subkey);
    let mut hkey: HKEY = null_mut();
    // SAFETY: opens or creates registry key.
    let rc = unsafe {
        RegCreateKeyExW(
            root,
            sub.as_ptr(),
            0,
            null(),
            0,
            KEY_SET_VALUE,
            null(),
            &mut hkey,
            null_mut(),
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let n = wide(name);
    // SAFETY: writes 4-byte REG_DWORD value.
    let rc2 = unsafe {
        RegSetValueExW(
            hkey,
            n.as_ptr(),
            0,
            REG_DWORD,
            (&value as *const u32).cast(),
            4,
        )
    };
    // SAFETY: closes registry key handle.
    unsafe {
        RegCloseKey(hkey);
    }
    if rc2 != 0 {
        return Err(io::Error::from_raw_os_error(rc2 as i32));
    }
    Ok(())
}

fn decode_pem_cert(pem: &str) -> io::Result<Vec<u8>> {
    let mut b64 = String::new();
    let mut inside = false;
    for line in pem.lines() {
        let t = line.trim();
        if t == "-----BEGIN CERTIFICATE-----" {
            inside = true;
            continue;
        }
        if t == "-----END CERTIFICATE-----" {
            break;
        }
        if inside {
            b64.push_str(t);
        }
    }
    if b64.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no PEM CERTIFICATE block found",
        ));
    }
    let val = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(b64.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for b in b64.bytes() {
        if b == b'=' {
            break;
        }
        let Some(v) = val(b) else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid base64"));
        };
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

fn trigger_poweroff() {
    let mut token: HANDLE = null_mut();
    // SAFETY: opens current process token to enable SeShutdownPrivilege.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    } != 0
    {
        let priv_name = wide("SeShutdownPrivilege");
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        // SAFETY: looks up SeShutdownPrivilege LUID.
        if unsafe { LookupPrivilegeValueW(null(), priv_name.as_ptr(), &mut luid) } != 0 {
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            // SAFETY: enables shutdown privilege on our token.
            unsafe {
                AdjustTokenPrivileges(token, 0, &tp, 0, null_mut(), null_mut());
            }
        }
        // SAFETY: closes token handle.
        unsafe {
            CloseHandle(token);
        }
    }
    // SAFETY: initiates clean Windows shutdown -> ACPI S5 poweroff.
    unsafe {
        InitiateSystemShutdownExW(
            null(),
            null(),
            0,
            1, // force apps closed
            0, // poweroff (not reboot)
            SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_FLAG_PLANNED,
        );
    }
}
