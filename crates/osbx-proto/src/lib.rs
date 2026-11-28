//! Wire protocol between the host and the guest agent.
//!
//! A *control* connection (vsock port [`AGENT_PORT`]) carries one command: the host sends an
//! `EXEC` frame, optional `STDIN`/`STDIN_EOF`/`SIGNAL` frames, and the agent answers with
//! `STDOUT`/`STDERR` frames and a final `EXIT`. Frames are `type:u8, len:u32 (LE), payload`.
//!
//! Two raw (unframed) byte tunnels complement it:
//! * guest port [`TUNNEL_PORT`]: the host sends one line `host:port\n`, the agent connects to that
//!   TCP address *inside the guest* and pipes bytes both ways (used to publish guest ports);
//! * host port [`EGRESS_PORT`]: the agent listens on [`GUEST_PROXY_ADDR`] inside the guest and
//!   pipes every accepted connection to the host, where the policy proxy serves it.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};

/// Guest vsock port of the control service.
pub const AGENT_PORT: u32 = 1024;
/// Guest vsock port of the tunnel service.
pub const TUNNEL_PORT: u32 = 1025;
/// Host vsock port the guest's forwarded SSH agent connections are delivered to.
pub const SSH_AGENT_PORT: u32 = 1026;
/// Host vsock port serving host directory RPC + watch events for Windows `sync`/`projfs` shares.
pub const FILE_SYNC_PORT: u32 = 1027;
/// Host vsock port the guest's egress is delivered to.
pub const EGRESS_PORT: u32 = 3128;
/// Where processes inside a Linux guest find the forwarded SSH agent socket (`ssh-agent@1`).
pub const GUEST_SSH_AUTH_SOCK: &str = "/run/osbx/ssh-agent.sock";
/// Where processes inside a Windows guest find the forwarded SSH agent named pipe (`ssh-agent@1`).
pub const GUEST_WINDOWS_SSH_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
/// Where processes inside the guest find the proxy.
pub const GUEST_PROXY_ADDR: &str = "127.0.0.1:3128";
/// Where the agent listens for egress: every guest interface. The guest has no NIC, so this only
/// adds internal bridges, which is how containers inside the sandbox (Docker) reach the proxy.
pub const GUEST_PROXY_BIND: &str = "0.0.0.0:3128";
/// Largest frame accepted.
pub const MAX_FRAME: usize = 16 << 20;
/// Largest data chunk sent in one frame.
pub const CHUNK: usize = 32 << 10;

/// Host -> agent: run a command.
pub const EXEC: u8 = 0x01;
/// Host -> agent: bytes for the command's stdin.
pub const STDIN: u8 = 0x02;
/// Host -> agent: close the command's stdin.
pub const STDIN_EOF: u8 = 0x03;
/// Host -> agent: send a signal (payload: i32 LE) to the command.
pub const SIGNAL: u8 = 0x04;
/// Host -> agent: sync disks and power the guest off.
pub const POWEROFF: u8 = 0x05;
/// Host -> agent: terminal size changed (payload: rows u16 LE, cols u16 LE). TTY commands only.
pub const RESIZE: u8 = 0x06;
/// Host -> agent: install sandbox CA PEM and configure proxy in-process (payload: UTF-8 PEM).
pub const SETUP_CA: u8 = 0x07;
/// Host -> agent: mount a host share inside the guest (payload: JSON [`MountRequest`]).
pub const MOUNT: u8 = 0x08;
/// Host -> agent: extract a tar stream into a guest path (payload: JSON [`CpRequest`], followed by `STDIN` frames + `STDIN_EOF`).
pub const CP_PUT: u8 = 0x09;
/// Host -> agent: stream a guest path as a tar archive (payload: JSON [`CpRequest`]; replies with `STDOUT` frames + `OK`).
pub const CP_GET: u8 = 0x0A;
/// Agent -> host: command stdout bytes.
pub const STDOUT: u8 = 0x10;
/// Agent -> host: command stderr bytes.
pub const STDERR: u8 = 0x11;
/// Agent -> host: command finished (payload: i32 LE exit status; 128+n if killed by signal n).
pub const EXIT: u8 = 0x12;
/// Agent -> host: the request failed (payload: UTF-8 message).
pub const ERROR: u8 = 0x13;
/// Agent -> host: control command (`SETUP_CA`, `MOUNT`, `CP_PUT`, `CP_GET`) succeeded (optional UTF-8 payload).
pub const OK: u8 = 0x14;

/// File-sync vsock RPC request frame (`FILE_SYNC_PORT`, payload: JSON [`FileSyncReq`]).
pub const FS_REQ: u8 = 0x20;
/// File-sync vsock RPC response frame (`FILE_SYNC_PORT`, payload: JSON [`FileSyncResp`]).
pub const FS_RESP: u8 = 0x21;
/// File-sync raw file data chunk (`FILE_SYNC_PORT`, payload: raw bytes).
pub const FS_DATA: u8 = 0x22;
/// File-sync watch event (`FILE_SYNC_PORT`, payload: JSON [`FileSyncEvent`]).
pub const FS_EVENT: u8 = 0x23;

/// What to run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRequest {
    /// Program and arguments (no shell parsing).
    pub argv: Vec<String>,
    /// Environment (replaces the agent's; PATH gets a default if absent).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Working directory (default: the user's home if `user` is set, else `/`).
    #[serde(default)]
    pub cwd: Option<String>,
    /// Run as this user (name or numeric uid from the guest's /etc/passwd); default root.
    #[serde(default)]
    pub user: Option<String>,
    /// Allocate a pseudo-terminal (stdout and stderr are merged, as on a real terminal).
    #[serde(default)]
    pub tty: bool,
    /// Initial terminal size when `tty` is set.
    #[serde(default)]
    pub rows: u16,
    /// Initial terminal size when `tty` is set.
    #[serde(default)]
    pub cols: u16,
    /// Launch in the interactive desktop session (`winsta0\default`, Windows guests only).
    #[serde(default)]
    pub gui: bool,
}

/// Request sent in a [`MOUNT`] control frame asking the guest agent to mount one host share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountRequest {
    /// Share identifier (matching `virtio-fs` tag and `FILE_SYNC_PORT` tag).
    pub tag: String,
    /// Guest target path (e.g. `C:\workspace` or `C:\mnt\data`).
    pub target: String,
    /// Enforce read-only access inside the guest (host also enforces `EROFS`).
    #[serde(default)]
    pub read_only: bool,
    /// Requested backend (`auto`, `sync`, `projfs`, `dokany`, `winfsp`, `virtiofs-native`).
    #[serde(default = "default_auto")]
    pub backend: String,
}

fn default_auto() -> String {
    "auto".into()
}

/// Request sent in a [`CP_PUT`] or [`CP_GET`] control frame for native agent-side file copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpRequest {
    /// Target directory (for `CP_PUT`) or source file/directory path (for `CP_GET`) in the guest.
    pub path: String,
    /// Optional new leaf name when copying a single item under a different name (`CP_PUT`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rename: Option<String>,
}

/// Metadata for a single file or directory exposed over [`FILE_SYNC_PORT`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// File or directory name (not a full path).
    pub name: String,
    /// True if directory, false if regular file.
    pub is_dir: bool,
    /// Byte length (0 for directories).
    pub size: u64,
    /// Last-modified UNIX timestamp seconds.
    pub mtime_secs: i64,
    /// Last-modified sub-second nanoseconds.
    pub mtime_nanos: u32,
    /// True if read-only on the host or share.
    #[serde(default)]
    pub read_only: bool,
}

/// RPC request sent by the guest agent to the host over [`FILE_SYNC_PORT`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FileSyncReq {
    /// List immediate children of `path` (empty string for share root).
    ListDir {
        /// Share tag.
        tag: String,
        /// Forward-slash relative path inside the share.
        path: String,
    },
    /// Fetch metadata for `path`.
    Stat {
        /// Share tag.
        tag: String,
        /// Forward-slash relative path inside the share.
        path: String,
    },
    /// Read up to `len` bytes starting at `offset` (response followed by one [`FS_DATA`] frame).
    ReadFile {
        /// Share tag.
        tag: String,
        /// Forward-slash relative path inside the share.
        path: String,
        /// Byte offset.
        offset: u64,
        /// Maximum bytes to read.
        len: u32,
    },
    /// Write bytes (supplied in the immediately following [`FS_DATA`] frame) at `offset`.
    WriteFile {
        /// Share tag.
        tag: String,
        /// Forward-slash relative path inside the share.
        path: String,
        /// Byte offset.
        offset: u64,
        /// Truncate the file to `offset + data.len()` if true.
        #[serde(default)]
        truncate: bool,
    },
    /// Create directory (and any missing parents).
    Mkdir {
        /// Share tag.
        tag: String,
        /// Forward-slash relative path inside the share.
        path: String,
    },
    /// Remove a file or directory.
    Remove {
        /// Share tag.
        tag: String,
        /// Forward-slash relative path inside the share.
        path: String,
        /// Remove directories recursively when true.
        #[serde(default)]
        recursive: bool,
    },
    /// Rename/move within the same share.
    Rename {
        /// Share tag.
        tag: String,
        /// Source relative path.
        from: String,
        /// Destination relative path.
        to: String,
    },
    /// Subscribe to host-side file change notifications (keeps stream open for [`FS_EVENT`] frames).
    Watch {
        /// Share tag.
        tag: String,
    },
}

/// RPC response returned by the host over [`FILE_SYNC_PORT`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FileSyncResp {
    /// Success with no body.
    Ok,
    /// Directory listing result.
    Entries {
        /// Immediate child entries.
        entries: Vec<FileEntry>,
    },
    /// Metadata result.
    Meta {
        /// Entry metadata.
        entry: FileEntry,
    },
    /// Precedes one [`FS_DATA`] frame carrying `len` bytes.
    Data {
        /// Exact byte count in the immediately following [`FS_DATA`] frame.
        len: u32,
    },
    /// Path does not exist.
    NotFound,
    /// Mutation rejected because share is read-only (`EROFS`).
    ReadOnly,
    /// Path invalid or attempted escape outside share root.
    InvalidPath {
        /// Reason.
        message: String,
    },
    /// General I/O error.
    Error {
        /// Error description.
        message: String,
    },
}

/// Change event streamed by the host to a subscribed [`FileSyncReq::Watch`] guest client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSyncEvent {
    /// Forward-slash relative path inside the share.
    pub path: String,
    /// True if the path was removed; false if created or modified.
    pub removed: bool,
    /// True if directory (best-effort; false when removed).
    #[serde(default)]
    pub is_dir: bool,
}

/// Encode a [`RESIZE`] payload.
pub fn resize_payload(rows: u16, cols: u16) -> [u8; 4] {
    let mut b = [0u8; 4];
    b[..2].copy_from_slice(&rows.to_le_bytes());
    b[2..].copy_from_slice(&cols.to_le_bytes());
    b
}

/// Write one frame.
pub fn write_frame(w: &mut impl Write, ty: u8, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    let mut head = [0u8; 5];
    head[0] = ty;
    head[1..].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    w.write_all(&head)?;
    w.write_all(payload)?;
    w.flush()
}

/// Read one frame; `Ok(None)` on a clean end of stream.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 5];
    match r.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(head[1..].try_into().unwrap()) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some((head[0], payload)))
}

/// Outcome of a remote command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    /// Exit status (128+n when killed by signal n).
    pub code: i32,
}

/// Run `req` over an established control connection and stream its output.
///
/// `reader` and `writer` are the two halves of the connection. `stdin` is sent from a helper
/// thread so a command that produces a lot of output before consuming its input cannot deadlock.
pub fn run_exec<R, W>(
    mut reader: R,
    mut writer: W,
    req: &ExecRequest,
    stdin: Option<Box<dyn Read + Send>>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<ExecResult>
where
    R: Read,
    W: Write + Send + 'static,
{
    write_frame(
        &mut writer,
        EXEC,
        &serde_json::to_vec(req).map_err(io::Error::other)?,
    )?;
    let sender = std::thread::spawn(move || -> io::Result<()> {
        if let Some(mut input) = stdin {
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = input.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                write_frame(&mut writer, STDIN, &buf[..n])?;
            }
        }
        write_frame(&mut writer, STDIN_EOF, &[])
    });
    let result = loop {
        match read_frame(&mut reader)? {
            Some((STDOUT, d)) => stdout.write_all(&d)?,
            Some((STDERR, d)) => stderr.write_all(&d)?,
            Some((EXIT, d)) if d.len() == 4 => {
                break Ok(ExecResult {
                    code: i32::from_le_bytes(d.try_into().unwrap()),
                });
            }
            Some((ERROR, d)) => {
                break Err(io::Error::other(String::from_utf8_lossy(&d).into_owned()));
            }
            Some(_) => {}
            None => {
                break Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "agent closed the connection before the command finished",
                ));
            }
        }
    };
    // The command is done; a stdin sender blocked on a full pipe is released by the connection closing.
    drop(sender);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frames_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, STDOUT, b"hello").unwrap();
        write_frame(&mut buf, EXIT, &7i32.to_le_bytes()).unwrap();
        let mut r = Cursor::new(buf);
        assert_eq!(
            read_frame(&mut r).unwrap(),
            Some((STDOUT, b"hello".to_vec()))
        );
        assert_eq!(
            read_frame(&mut r).unwrap(),
            Some((EXIT, 7i32.to_le_bytes().to_vec()))
        );
        assert_eq!(read_frame(&mut r).unwrap(), None);
    }

    #[test]
    fn oversized_and_truncated_frames_are_errors() {
        let mut head = vec![STDOUT];
        head.extend_from_slice(&((MAX_FRAME as u32) + 1).to_le_bytes());
        assert!(read_frame(&mut Cursor::new(head)).is_err());
        let mut short = vec![STDOUT];
        short.extend_from_slice(&10u32.to_le_bytes());
        short.extend_from_slice(b"abc");
        assert!(read_frame(&mut Cursor::new(short)).is_err());
        assert!(write_frame(&mut Vec::new(), STDOUT, &vec![0u8; MAX_FRAME + 1]).is_err());
    }

    #[test]
    fn exec_request_json_defaults() {
        let r: ExecRequest = serde_json::from_str(r#"{"argv":["ls"]}"#).unwrap();
        assert_eq!(r.argv, ["ls"]);
        assert!(r.env.is_empty() && r.cwd.is_none());
    }
}
