//! The osbx guest agent. Runs inside the microVM (as PID 1's child or on its own) and serves:
//! * exec over vsock port 1024 (framed, see `osbx-proto`),
//! * TCP tunnels into the guest on vsock port 1025 (to publish guest ports),
//! * proxy egress: a TCP listener on 127.0.0.1:3128 whose connections are piped to the host,
//!   where the policy proxy serves them.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("osbx-agent only runs inside a Linux guest");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use osbx_proto::{
        AGENT_PORT, CHUNK, EGRESS_PORT, ERROR, EXEC, EXIT, ExecRequest, GUEST_PROXY_BIND,
        GUEST_SSH_AUTH_SOCK, POWEROFF, RESIZE, SIGNAL, SSH_AGENT_PORT, STDERR, STDIN, STDIN_EOF,
        STDOUT, TUNNEL_PORT, read_frame, write_frame,
    };
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{self, BufReader, Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, LazyLock, Mutex, mpsc};
    use std::thread;
    use std::time::Duration;

    const HOST_CID: u32 = 2;
    const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

    /// Exit statuses of children, handed out by the single reaper. As PID 1 the agent inherits
    /// every orphan, so one thread owns `waitpid(-1)`; command handlers collect their own child's
    /// status from here instead of calling `wait` (which would race the reaper).
    #[derive(Default)]
    struct Table {
        waiters: HashMap<i32, mpsc::Sender<i32>>,
        reaped: HashMap<i32, i32>,
    }
    static CHILDREN: LazyLock<Mutex<Table>> = LazyLock::new(Mutex::default);

    #[allow(unsafe_code)]
    fn reaper() {
        loop {
            let mut status = 0i32;
            // SAFETY: waitpid(2) with a valid pointer to a local status word.
            let pid = unsafe { libc::waitpid(-1, &raw mut status, 0) };
            if pid <= 0 {
                thread::sleep(Duration::from_millis(50)); // ECHILD: nothing to reap yet
                continue;
            }
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            };
            let mut t = CHILDREN.lock().unwrap();
            match t.waiters.remove(&pid) {
                Some(tx) => {
                    let _ = tx.send(code);
                }
                None => {
                    if t.reaped.len() > 4096 {
                        t.reaped.clear(); // orphans nobody asked about
                    }
                    t.reaped.insert(pid, code);
                }
            }
        }
    }

    fn wait_child(pid: i32) -> i32 {
        let rx = {
            let mut t = CHILDREN.lock().unwrap();
            if let Some(code) = t.reaped.remove(&pid) {
                return code;
            }
            let (tx, rx) = mpsc::channel();
            t.waiters.insert(pid, tx);
            rx
        };
        rx.recv().unwrap_or(255)
    }

    /// Apply `/etc/hostname` (the kernel does not do it; init systems normally do).
    #[allow(unsafe_code)]
    fn set_hostname() {
        let Ok(name) = std::fs::read_to_string("/etc/hostname") else {
            return;
        };
        let name = name.trim();
        if name.is_empty() {
            return;
        }
        // SAFETY: sethostname(2) reads `name.len()` bytes from a valid, live buffer.
        unsafe {
            libc::sethostname(name.as_ptr().cast(), name.len());
        }
    }

    pub fn run() {
        eprintln!("osbx-agent: starting");
        set_hostname();
        thread::spawn(reaper);
        thread::spawn(|| accept_loop(AGENT_PORT, handle_control));
        thread::spawn(|| accept_loop(TUNNEL_PORT, handle_tunnel));
        thread::spawn(egress_listener);
        if std::fs::read_to_string("/proc/cmdline")
            .unwrap_or_default()
            .split_whitespace()
            .any(|a| a == "osbx.ssh_agent=1")
        {
            thread::spawn(ssh_agent_listener);
        }
        loop {
            thread::sleep(Duration::from_secs(3600));
        }
    }

    // ---- vsock plumbing -------------------------------------------------------------------

    #[allow(unsafe_code)]
    fn vsock_socket() -> io::Result<OwnedFd> {
        // SAFETY: plain socket(2) call with constant arguments.
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by socket(2) and is owned by nobody else.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    #[allow(unsafe_code)]
    fn sockaddr(cid: u32, port: u32) -> libc::sockaddr_vm {
        // SAFETY: sockaddr_vm is plain old data for which all-zero is a valid value.
        let mut a: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        a.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        a.svm_cid = cid;
        a.svm_port = port;
        a
    }

    #[allow(unsafe_code)]
    fn vsock_listen(port: u32) -> io::Result<OwnedFd> {
        let fd = vsock_socket()?;
        let addr = sockaddr(libc::VMADDR_CID_ANY, port);
        // SAFETY: `addr` is a valid sockaddr_vm and its size is passed correctly; `fd` is open.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast(),
                size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a bound stream socket.
        if unsafe { libc::listen(fd.as_raw_fd(), 128) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    #[allow(unsafe_code)]
    fn vsock_accept(listener: &OwnedFd) -> io::Result<File> {
        // SAFETY: accept4(2) with null address pointers is valid; the listener fd is open.
        let fd = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor returned by accept4 and owned by nobody else.
        Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    #[allow(unsafe_code)]
    fn vsock_connect(cid: u32, port: u32) -> io::Result<File> {
        let fd = vsock_socket()?;
        let addr = sockaddr(cid, port);
        // SAFETY: `addr` is a valid sockaddr_vm and its size is passed correctly; `fd` is open.
        let rc = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&raw const addr).cast(),
                size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(File::from(fd))
    }

    #[allow(unsafe_code)]
    fn shutdown_write(f: &File) {
        // SAFETY: shutdown(2) on an open socket descriptor; the result is deliberately ignored.
        unsafe {
            libc::shutdown(f.as_raw_fd(), libc::SHUT_WR);
        }
    }

    fn accept_loop(port: u32, handler: fn(File)) {
        let listener = loop {
            match vsock_listen(port) {
                Ok(l) => break l,
                Err(e) => {
                    // the vsock driver may not be loaded yet
                    eprintln!("osbx-agent: vsock listen {port}: {e}; retrying");
                    thread::sleep(Duration::from_millis(500));
                }
            }
        };
        eprintln!("osbx-agent: listening on vsock port {port}");
        loop {
            match vsock_accept(&listener) {
                Ok(conn) => {
                    thread::spawn(move || handler(conn));
                }
                Err(e) => {
                    eprintln!("osbx-agent: accept on {port}: {e}");
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    /// Pipe bytes both ways between a vsock stream and a TCP stream until both sides finish.
    fn bridge(vs: File, tcp: TcpStream) {
        let (Ok(vs2), Ok(tcp2)) = (vs.try_clone(), tcp.try_clone()) else {
            return;
        };
        let up = thread::spawn(move || {
            let (mut from, mut to) = (vs, tcp2);
            let _ = io::copy(&mut from, &mut to);
            let _ = to.shutdown(Shutdown::Write);
        });
        let (mut from, mut to) = (tcp, vs2);
        let _ = io::copy(&mut from, &mut to);
        shutdown_write(&to);
        let _ = up.join();
    }

    // ---- tunnel service -------------------------------------------------------------------

    fn handle_tunnel(conn: File) {
        // first line: "host:port\n"; read byte-wise so no payload is swallowed by a buffer
        let mut line = Vec::new();
        let mut one = [0u8; 1];
        let mut c = &conn;
        while line.len() < 256 {
            match c.read(&mut one) {
                Ok(1) if one[0] == b'\n' => break,
                Ok(1) => line.push(one[0]),
                _ => return,
            }
        }
        let Ok(target) = String::from_utf8(line) else {
            return;
        };
        match TcpStream::connect(target.trim()) {
            Ok(tcp) => bridge(conn, tcp),
            Err(e) => eprintln!("osbx-agent: tunnel to {target}: {e}"),
        }
    }

    /// Pipe bytes both ways between a vsock stream and a Unix socket until both sides finish.
    fn bridge_unix(vs: File, unix: UnixStream) {
        let (Ok(vs2), Ok(unix2)) = (vs.try_clone(), unix.try_clone()) else {
            return;
        };
        let up = thread::spawn(move || {
            let (mut from, mut to) = (vs, unix2);
            let _ = io::copy(&mut from, &mut to);
            let _ = to.shutdown(Shutdown::Write);
        });
        let (mut from, mut to) = (unix, vs2);
        let _ = io::copy(&mut from, &mut to);
        shutdown_write(&to);
        let _ = up.join();
    }

    // ---- ssh-agent: guest-local Unix socket -> host -------------------------------------------

    fn ssh_agent_listener() {
        let path = std::path::Path::new(GUEST_SSH_AUTH_SOCK);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
        }
        let _ = std::fs::remove_file(path);
        let listener = match UnixListener::bind(path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("osbx-agent: bind {GUEST_SSH_AUTH_SOCK}: {e}");
                return;
            }
        };
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
        eprintln!("osbx-agent: ssh-agent on {GUEST_SSH_AUTH_SOCK}");
        for conn in listener.incoming().flatten() {
            thread::spawn(move || match vsock_connect(HOST_CID, SSH_AGENT_PORT) {
                Ok(vs) => bridge_unix(vs, conn),
                Err(e) => eprintln!("osbx-agent: host ssh-agent unreachable: {e}"),
            });
        }
    }

    // ---- egress: guest-local proxy address -> host --------------------------------------------

    fn egress_listener() {
        let listener = loop {
            match TcpListener::bind(GUEST_PROXY_BIND) {
                Ok(l) => break l,
                Err(e) => {
                    eprintln!("osbx-agent: bind {GUEST_PROXY_BIND}: {e}; retrying");
                    thread::sleep(Duration::from_millis(500));
                }
            }
        };
        eprintln!("osbx-agent: egress proxy on {GUEST_PROXY_BIND}");
        for tcp in listener.incoming().flatten() {
            thread::spawn(move || match vsock_connect(HOST_CID, EGRESS_PORT) {
                Ok(vs) => bridge(vs, tcp),
                Err(e) => eprintln!("osbx-agent: host proxy unreachable: {e}"),
            });
        }
    }

    // ---- control service ------------------------------------------------------------------

    fn send(out: &Mutex<File>, ty: u8, payload: &[u8]) -> io::Result<()> {
        write_frame(&mut *out.lock().unwrap(), ty, payload)
    }

    fn handle_control(conn: File) {
        let Ok(reader_file) = conn.try_clone() else {
            return;
        };
        let mut reader = BufReader::new(reader_file);
        let out = Arc::new(Mutex::new(conn));
        let req: ExecRequest = match read_frame(&mut reader) {
            Ok(Some((EXEC, payload))) => match serde_json::from_slice(&payload) {
                Ok(r) => r,
                Err(e) => {
                    let _ = send(&out, ERROR, format!("bad exec request: {e}").as_bytes());
                    return;
                }
            },
            Ok(Some((POWEROFF, _))) => {
                poweroff();
                return;
            }
            _ => return,
        };
        if req.argv.is_empty() {
            let _ = send(&out, ERROR, b"empty argv");
            return;
        }
        let mut env = req.env.clone();
        env.entry("PATH".into())
            .or_insert_with(|| DEFAULT_PATH.into());
        let account = match req.user.as_deref().map(lookup_user) {
            None => None,
            Some(Ok(a)) => Some(a),
            Some(Err(e)) => {
                let _ = send(&out, ERROR, e.as_bytes());
                return;
            }
        };
        if let Some(a) = &account {
            env.entry("HOME".into()).or_insert_with(|| a.home.clone());
            env.entry("USER".into()).or_insert_with(|| a.name.clone());
            env.entry("LOGNAME".into())
                .or_insert_with(|| a.name.clone());
        }
        if req.tty {
            env.entry("TERM".into())
                .or_insert_with(|| "xterm-256color".into());
        }
        let cwd = req
            .cwd
            .clone()
            .or_else(|| account.as_ref().map(|a| a.home.clone()))
            .unwrap_or_else(|| "/".into());
        let mut cmd = Command::new(&req.argv[0]);
        cmd.args(&req.argv[1..])
            .env_clear()
            .envs(&env)
            .current_dir(&cwd);
        let drop_to = account.as_ref().map(|a| (a.uid, a.gid, a.groups.clone()));
        // With a TTY, the child gets the pty slave on all three descriptors and becomes the session
        // leader with it as controlling terminal; the master side is our single output stream.
        let pty = if req.tty {
            match open_pty(req.rows, req.cols) {
                Ok(p) => Some(p),
                Err(e) => {
                    let _ = send(
                        &out,
                        ERROR,
                        format!("cannot allocate a terminal: {e}").as_bytes(),
                    );
                    return;
                }
            }
        } else {
            None
        };
        match &pty {
            Some((_, slave)) => {
                let (Ok(a), Ok(b), Ok(c)) =
                    (slave.try_clone(), slave.try_clone(), slave.try_clone())
                else {
                    return;
                };
                cmd.stdin(Stdio::from(a))
                    .stdout(Stdio::from(b))
                    .stderr(Stdio::from(c));
                make_session_leader(&mut cmd);
            }
            None => {
                cmd.stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
            }
        }
        if let Some((uid, gid, groups)) = drop_to {
            drop_privileges(&mut cmd, uid, gid, groups);
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = send(
                    &out,
                    ERROR,
                    format!("cannot run {}: {e}", req.argv[0]).as_bytes(),
                );
                return;
            }
        };
        // `cmd` still holds its copies of the pty slave; the master only reports end-of-output once
        // every slave descriptor is closed, so drop them now or a TTY session never ends.
        drop(cmd);
        let pid = child.id() as i32;
        let pump = |mut src: Box<dyn Read + Send>, ty: u8, out: Arc<Mutex<File>>| {
            thread::spawn(move || {
                let mut buf = vec![0u8; CHUNK];
                // a pty master reports EIO once the last slave holder exits: that is the end of output
                while let Ok(n) = src.read(&mut buf) {
                    if n == 0 || send(&out, ty, &buf[..n]).is_err() {
                        break;
                    }
                }
            })
        };
        let (mut stdin, t_out, t_err, master): (Option<Box<dyn Write + Send>>, _, _, Option<File>) =
            match pty {
                Some((master, slave)) => {
                    drop(slave); // only the child holds it now, so EOF/EIO arrives when the child is done
                    let (Ok(r), Ok(w)) = (master.try_clone(), master.try_clone()) else {
                        return;
                    };
                    (
                        Some(Box::new(w)),
                        pump(Box::new(r), STDOUT, out.clone()),
                        None,
                        Some(master),
                    )
                }
                None => (
                    child
                        .stdin
                        .take()
                        .map(|s| Box::new(s) as Box<dyn Write + Send>),
                    pump(Box::new(child.stdout.take().unwrap()), STDOUT, out.clone()),
                    Some(pump(
                        Box::new(child.stderr.take().unwrap()),
                        STDERR,
                        out.clone(),
                    )),
                    None,
                ),
            };
        let tty = req.tty;
        // host -> command: stdin data, EOF, signals, resizes; a closed connection kills the command
        thread::spawn(move || {
            loop {
                match read_frame(&mut reader) {
                    Ok(Some((STDIN, d))) => {
                        if let Some(s) = stdin.as_mut()
                            && s.write_all(&d).is_err()
                        {
                            stdin = None;
                        }
                    }
                    Ok(Some((STDIN_EOF, _))) => {
                        if !tty {
                            stdin = None; // a terminal has no EOF; the session ends when the child exits
                        }
                    }
                    Ok(Some((SIGNAL, d))) if d.len() == 4 => {
                        kill(pid, i32::from_le_bytes(d.try_into().unwrap()))
                    }
                    Ok(Some((RESIZE, d))) if d.len() == 4 => {
                        if let Some(m) = &master {
                            set_winsize(
                                m,
                                u16::from_le_bytes([d[0], d[1]]),
                                u16::from_le_bytes([d[2], d[3]]),
                            );
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => {
                        kill(pid, libc::SIGKILL);
                        break;
                    }
                }
            }
        });
        let code = wait_child(pid);
        drop(child);
        let _ = t_out.join();
        if let Some(t) = t_err {
            let _ = t.join();
        }
        let _ = send(&out, EXIT, &code.to_le_bytes());
        shutdown_write(&out.lock().unwrap());
    }

    struct Account {
        name: String,
        uid: u32,
        gid: u32,
        home: String,
        groups: Vec<u32>,
    }

    /// Resolve a user name or numeric uid from /etc/passwd (+ supplementary groups from /etc/group).
    fn lookup_user(user: &str) -> Result<Account, String> {
        let passwd = std::fs::read_to_string("/etc/passwd")
            .map_err(|e| format!("cannot read /etc/passwd: {e}"))?;
        let entry = passwd
            .lines()
            .map(|l| l.split(':').collect::<Vec<_>>())
            .find(|f| f.len() >= 7 && (f[0] == user || f[2] == user))
            .ok_or_else(|| format!("no such user in the guest: {user}"))?;
        let (uid, gid) = (
            entry[2].parse().map_err(|_| "bad uid")?,
            entry[3].parse().map_err(|_| "bad gid")?,
        );
        let name = entry[0].to_owned();
        let mut groups = vec![gid];
        if let Ok(g) = std::fs::read_to_string("/etc/group") {
            for f in g
                .lines()
                .map(|l| l.split(':').collect::<Vec<_>>())
                .filter(|f| f.len() >= 4)
            {
                if f[3].split(',').any(|m| m == name)
                    && let Ok(id) = f[2].parse()
                {
                    groups.push(id);
                }
            }
        }
        Ok(Account {
            name,
            uid,
            gid,
            home: entry[5].to_owned(),
            groups,
        })
    }

    /// Become `uid`/`gid` with supplementary `groups` in the child. Done here rather than with
    /// `Command::uid`, because std applies uid/gid before `pre_exec` hooks run, and setgroups(2)
    /// must happen while still root.
    #[allow(unsafe_code)]
    fn drop_privileges(cmd: &mut Command, uid: u32, gid: u32, groups: Vec<u32>) {
        use std::os::unix::process::CommandExt;
        // SAFETY: setgroups/setgid/setuid are async-signal-safe; `groups` was fully built before
        // fork and is not modified afterwards.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    #[allow(unsafe_code)]
    fn make_session_leader(cmd: &mut Command) {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid(2) and ioctl(TIOCSCTTY) are async-signal-safe; descriptor 0 is the pty slave
        // installed by Command before this hook runs.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    #[allow(unsafe_code)]
    fn open_pty(rows: u16, cols: u16) -> io::Result<(File, File)> {
        let (mut master, mut slave) = (-1, -1);
        let ws = libc::winsize {
            ws_row: if rows == 0 { 24 } else { rows },
            ws_col: if cols == 0 { 80 } else { cols },
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: openpty(3) writes two descriptors into the provided ints; the name and termios
        // pointers may be null and the winsize pointer refers to a live local.
        let rc = unsafe {
            libc::openpty(
                &raw mut master,
                &raw mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                &raw const ws,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both descriptors were just returned by openpty and are owned by nobody else.
        let (m, s) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        Ok((File::from(m), File::from(s)))
    }

    #[allow(unsafe_code)]
    fn set_winsize(master: &File, rows: u16, cols: u16) {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCSWINSZ reads a winsize struct from a valid pointer; the descriptor is open.
        unsafe {
            libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &raw const ws);
        }
    }

    #[allow(unsafe_code)]
    fn kill(pid: i32, sig: i32) {
        // SAFETY: kill(2) with a pid of a child this process spawned; failure is harmless.
        unsafe {
            libc::kill(pid, sig);
        }
    }

    #[allow(unsafe_code)]
    fn poweroff() {
        // SAFETY: sync(2) takes no arguments; reboot(2) with RESTART asks the kernel to reset the
        // machine, which the host VMM treats as a clean shutdown (reboot=k).
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_RESTART);
        }
    }
}
