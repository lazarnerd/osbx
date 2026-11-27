//! Host OS differences, in one place: the supervisor's control socket (`AF_UNIX` on both
//! Unix and Windows), terminal raw mode and size, detaching the supervisor, private files.

use std::io;
use std::path::Path;
use std::process::Command;

#[cfg(unix)]
pub use std::os::unix::net::{UnixListener as LocalListener, UnixStream as LocalStream};
#[cfg(windows)]
pub use uds_windows::{UnixListener as LocalListener, UnixStream as LocalStream};

/// Is standard stream `fd` (0 stdin, 1 stdout, 2 stderr) a terminal?
pub fn is_tty(fd: i32) -> bool {
    use std::io::IsTerminal;
    match fd {
        0 => io::stdin().is_terminal(),
        1 => io::stdout().is_terminal(),
        2 => io::stderr().is_terminal(),
        _ => false,
    }
}

/// Current size (rows, cols) of the terminal on stdout, if any.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn term_size() -> Option<(u16, u16)> {
    // SAFETY: winsize is plain data; TIOCGWINSZ writes into the valid pointer we pass.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: as above; descriptor 1 is stdout.
    let rc = unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &raw mut ws) };
    (rc == 0 && ws.ws_row > 0).then_some((ws.ws_row, ws.ws_col))
}

/// Current size (rows, cols) of the console window, if stdout is a console.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn term_size() -> Option<(u16, u16)> {
    use windows_sys::Win32::System::Console::{
        CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo, GetStdHandle, STD_OUTPUT_HANDLE,
    };
    // SAFETY: plain-data struct filled by the call; the handle comes from GetStdHandle.
    unsafe {
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut info) == 0 {
            return None;
        }
        let w = info.srWindow;
        let rows = (w.Bottom - w.Top + 1).max(1) as u16;
        let cols = (w.Right - w.Left + 1).max(1) as u16;
        Some((rows, cols))
    }
}

/// Puts the terminal in raw mode for the lifetime of the guard.
#[cfg(unix)]
pub struct RawMode(libc::termios);

#[cfg(unix)]
impl RawMode {
    /// Enter raw mode (None if stdin is not a terminal).
    #[allow(unsafe_code)]
    pub fn enter() -> Option<RawMode> {
        // SAFETY: termios is plain data; tcgetattr fills it from a valid descriptor.
        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: valid descriptor (0 = stdin) and pointer.
        if unsafe { libc::tcgetattr(0, &raw mut orig) } != 0 {
            return None;
        }
        let mut raw = orig;
        // SAFETY: cfmakeraw only edits the struct we own; tcsetattr applies it to stdin.
        unsafe {
            libc::cfmakeraw(&raw mut raw);
            libc::tcsetattr(0, libc::TCSANOW, &raw const raw);
        }
        Some(RawMode(orig))
    }
}

#[cfg(unix)]
impl Drop for RawMode {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: restores the attributes saved in `enter` on the same descriptor.
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &raw const self.0);
        }
    }
}

/// Puts the console in raw VT mode for the lifetime of the guard: keys (including Ctrl-C) go to
/// the sandbox as VT sequences, and output escape sequences are interpreted.
#[cfg(windows)]
pub struct RawMode {
    input: u32,
    output: u32,
}

#[cfg(windows)]
impl RawMode {
    /// Enter raw mode (None if stdin is not a console).
    #[allow(unsafe_code)]
    pub fn enter() -> Option<RawMode> {
        use windows_sys::Win32::System::Console::*;
        // SAFETY: console mode calls on the process's standard handles with valid out-pointers.
        unsafe {
            let (hin, hout) = (
                GetStdHandle(STD_INPUT_HANDLE),
                GetStdHandle(STD_OUTPUT_HANDLE),
            );
            let (mut input, mut output) = (0u32, 0u32);
            if GetConsoleMode(hin, &mut input) == 0 {
                return None;
            }
            GetConsoleMode(hout, &mut output);
            let raw_in = (input
                & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
                | ENABLE_VIRTUAL_TERMINAL_INPUT;
            SetConsoleMode(hin, raw_in);
            SetConsoleMode(
                hout,
                output | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN,
            );
            Some(RawMode { input, output })
        }
    }
}

#[cfg(windows)]
impl Drop for RawMode {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        use windows_sys::Win32::System::Console::*;
        // SAFETY: restores the modes saved in `enter` on the same standard handles.
        unsafe {
            SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), self.input);
            SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), self.output);
        }
    }
}

/// Detach a child (the supervisor) from this terminal: Ctrl-C here must not stop it, and it
/// outlives this process.
pub fn detach(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
        // Children are created with handle inheritance on (that is how their own stdio is
        // passed), which would also leak *our* standard handles into the long-lived child: a
        // pipe reading our output would then never see end-of-file. Our handles stay usable;
        // children that need them get duplicates from `Stdio::inherit`.
        no_inherit_std_handles();
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn no_inherit_std_handles() {
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: changes only the inheritance flag of this process's own standard handles.
        unsafe {
            let h = GetStdHandle(which);
            if !h.is_null() {
                SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

/// Write a file only this user can read (0600 on Unix; on Windows the per-user profile
/// directory the state lives in is already private).
pub fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(data)
}

/// Create a directory (and parents) only this user can enter.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}
