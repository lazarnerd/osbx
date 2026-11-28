//! Protocol-level integration tests for `osbx_sandbox::file_sync::FileSyncServer`.
//!
//! Drives the real framed `FILE_SYNC_PORT` RPC & `Watch` event server over loopback TCP sockets
//! with concurrent read-write and read-only shares, verifying directory listing, stat, partial
//! reads/writes, truncate, mkdir, rename, recursive remove, live watch notifications, read-only
//! (`EROFS`) enforcement, and root-jail / symlink-escape rejection.

use osbx_proto::{
    FS_DATA, FS_EVENT, FS_REQ, FS_RESP, FileSyncEvent, FileSyncReq, FileSyncResp, read_frame,
    write_frame,
};
use osbx_sandbox::file_sync::{FileSyncServer, FileSyncShare};
use std::io;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "osbx-filesync-it-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn spawn_client(srv: &FileSyncServer) -> TcpStream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let srv = srv.clone();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        srv.serve(stream);
    });
    let client = TcpStream::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client
}

fn rpc(stream: &mut TcpStream, req: &FileSyncReq, data: Option<&[u8]>) -> io::Result<FileSyncResp> {
    let payload = serde_json::to_vec(req).unwrap();
    write_frame(stream, FS_REQ, &payload)?;
    if let Some(bytes) = data {
        write_frame(stream, FS_DATA, bytes)?;
    }
    match read_frame(stream)? {
        Some((FS_RESP, buf)) => Ok(serde_json::from_slice(&buf).unwrap()),
        other => panic!("expected FS_RESP, got {other:?}"),
    }
}

#[test]
fn file_sync_server_multi_share_crud_ro_security_and_watch() {
    let root = TestRoot::new("full");
    let rw_dir = root.0.join("rw");
    let ro_dir = root.0.join("ro");
    let outside = root.0.join("outside.txt");
    std::fs::create_dir_all(rw_dir.join("sub")).unwrap();
    std::fs::create_dir_all(&ro_dir).unwrap();
    std::fs::write(rw_dir.join("hello.txt"), b"initial-rw-content").unwrap();
    std::fs::write(rw_dir.join("sub/nested.txt"), b"nested").unwrap();
    std::fs::write(ro_dir.join("readme.txt"), b"immutable-ro-content").unwrap();
    std::fs::write(&outside, b"host-secret").unwrap();

    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, rw_dir.join("escape_link")).unwrap();

    let closed = Arc::new(AtomicBool::new(false));
    let srv = FileSyncServer::new(
        vec![
            FileSyncShare {
                tag: "workspace".into(),
                host_dir: rw_dir.clone(),
                read_only: false,
            },
            FileSyncShare {
                tag: "ro_data".into(),
                host_dir: ro_dir.clone(),
                read_only: true,
            },
        ],
        closed.clone(),
    );

    let mut c = spawn_client(&srv);

    // 1. ListDir + Stat on RW share
    match rpc(
        &mut c,
        &FileSyncReq::ListDir {
            tag: "workspace".into(),
            path: String::new(),
        },
        None,
    )
    .unwrap()
    {
        FileSyncResp::Entries { entries } => {
            let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            assert!(names.contains(&"hello.txt"), "{names:?}");
            assert!(names.contains(&"sub"), "{names:?}");
            assert!(
                !names.contains(&"escape_link"),
                "symlinks must not be exposed: {names:?}"
            );
        }
        other => panic!("unexpected list_dir resp: {other:?}"),
    }

    match rpc(
        &mut c,
        &FileSyncReq::Stat {
            tag: "workspace".into(),
            path: "hello.txt".into(),
        },
        None,
    )
    .unwrap()
    {
        FileSyncResp::Meta { entry } => {
            assert_eq!(entry.name, "hello.txt");
            assert!(!entry.is_dir);
            assert_eq!(entry.size, 18);
            assert!(!entry.read_only);
        }
        other => panic!("unexpected stat resp: {other:?}"),
    }

    // 2. Partial offset ReadFile
    match rpc(
        &mut c,
        &FileSyncReq::ReadFile {
            tag: "workspace".into(),
            path: "hello.txt".into(),
            offset: 8,
            len: 2,
        },
        None,
    )
    .unwrap()
    {
        FileSyncResp::Data { len } => {
            assert_eq!(len, 2);
            let (ty, data) = read_frame(&mut c).unwrap().unwrap();
            assert_eq!(ty, FS_DATA);
            assert_eq!(data, b"rw");
        }
        other => panic!("unexpected read resp: {other:?}"),
    }

    // 3. WriteFile (create nested parent, partial write, truncate), Mkdir, Rename, Remove
    assert_eq!(
        rpc(
            &mut c,
            &FileSyncReq::WriteFile {
                tag: "workspace".into(),
                path: "deep/new.txt".into(),
                offset: 0,
                truncate: true,
            },
            Some(b"hello world!"),
        )
        .unwrap(),
        FileSyncResp::Ok
    );
    assert_eq!(
        std::fs::read(rw_dir.join("deep/new.txt")).unwrap(),
        b"hello world!"
    );

    assert_eq!(
        rpc(
            &mut c,
            &FileSyncReq::WriteFile {
                tag: "workspace".into(),
                path: "deep/new.txt".into(),
                offset: 6,
                truncate: true,
            },
            Some(b"osbx"),
        )
        .unwrap(),
        FileSyncResp::Ok
    );
    assert_eq!(
        std::fs::read(rw_dir.join("deep/new.txt")).unwrap(),
        b"hello osbx"
    );

    assert_eq!(
        rpc(
            &mut c,
            &FileSyncReq::Mkdir {
                tag: "workspace".into(),
                path: "created/dir".into(),
            },
            None,
        )
        .unwrap(),
        FileSyncResp::Ok
    );
    assert!(rw_dir.join("created/dir").is_dir());

    assert_eq!(
        rpc(
            &mut c,
            &FileSyncReq::Rename {
                tag: "workspace".into(),
                from: "deep/new.txt".into(),
                to: "created/dir/moved.txt".into(),
            },
            None,
        )
        .unwrap(),
        FileSyncResp::Ok
    );
    assert!(!rw_dir.join("deep/new.txt").exists());
    assert_eq!(
        std::fs::read(rw_dir.join("created/dir/moved.txt")).unwrap(),
        b"hello osbx"
    );

    assert_eq!(
        rpc(
            &mut c,
            &FileSyncReq::Remove {
                tag: "workspace".into(),
                path: "created".into(),
                recursive: true,
            },
            None,
        )
        .unwrap(),
        FileSyncResp::Ok
    );
    assert!(!rw_dir.join("created").exists());

    // 4. Read-only share enforces EROFS on every mutating operation while allowing reads
    match rpc(
        &mut c,
        &FileSyncReq::ReadFile {
            tag: "ro_data".into(),
            path: "readme.txt".into(),
            offset: 0,
            len: 64,
        },
        None,
    )
    .unwrap()
    {
        FileSyncResp::Data { len } => {
            assert_eq!(len, 20);
            let (ty, data) = read_frame(&mut c).unwrap().unwrap();
            assert_eq!(ty, FS_DATA);
            assert_eq!(data, b"immutable-ro-content");
        }
        other => panic!("unexpected ro read resp: {other:?}"),
    }

    assert_eq!(
        rpc(
            &mut c,
            &FileSyncReq::WriteFile {
                tag: "ro_data".into(),
                path: "readme.txt".into(),
                offset: 0,
                truncate: true,
            },
            Some(b"pwned"),
        )
        .unwrap(),
        FileSyncResp::ReadOnly
    );
    assert_eq!(
        rpc(
            &mut c,
            &FileSyncReq::Mkdir {
                tag: "ro_data".into(),
                path: "nope".into(),
            },
            None,
        )
        .unwrap(),
        FileSyncResp::ReadOnly
    );
    assert_eq!(
        rpc(
            &mut c,
            &FileSyncReq::Remove {
                tag: "ro_data".into(),
                path: "readme.txt".into(),
                recursive: false,
            },
            None,
        )
        .unwrap(),
        FileSyncResp::ReadOnly
    );
    assert_eq!(
        rpc(
            &mut c,
            &FileSyncReq::Rename {
                tag: "ro_data".into(),
                from: "readme.txt".into(),
                to: "other.txt".into(),
            },
            None,
        )
        .unwrap(),
        FileSyncResp::ReadOnly
    );
    assert_eq!(
        std::fs::read(ro_dir.join("readme.txt")).unwrap(),
        b"immutable-ro-content"
    );

    // 5. Path traversal, drive prefixes, leading-slash jailing, and symlink escape rejection
    for bad in [
        "../outside.txt",
        "sub/../../outside.txt",
        r"C:\Windows\System32",
    ] {
        assert!(
            matches!(
                rpc(
                    &mut c,
                    &FileSyncReq::Stat {
                        tag: "workspace".into(),
                        path: bad.into(),
                    },
                    None,
                )
                .unwrap(),
                FileSyncResp::InvalidPath { .. }
            ),
            "path {bad:?} must be rejected"
        );
    }
    assert_eq!(
        rpc(
            &mut c,
            &FileSyncReq::Stat {
                tag: "workspace".into(),
                path: "/etc/passwd".into(),
            },
            None,
        )
        .unwrap(),
        FileSyncResp::NotFound,
        "leading-slash paths must be jailed inside share root, never reading host /etc/passwd"
    );
    #[cfg(unix)]
    assert!(
        matches!(
            rpc(
                &mut c,
                &FileSyncReq::ReadFile {
                    tag: "workspace".into(),
                    path: "escape_link".into(),
                    offset: 0,
                    len: 64,
                },
                None,
            )
            .unwrap(),
            FileSyncResp::InvalidPath { .. }
        ),
        "symlink escaping share root must be rejected"
    );

    // 6. Live Watch event stream detects host create, modify, and remove
    let mut watcher = spawn_client(&srv);
    assert_eq!(
        rpc(
            &mut watcher,
            &FileSyncReq::Watch {
                tag: "workspace".into(),
            },
            None,
        )
        .unwrap(),
        FileSyncResp::Ok
    );

    std::fs::write(rw_dir.join("watched.txt"), b"v1").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_create = false;
    while Instant::now() < deadline {
        if let Ok(Some((FS_EVENT, payload))) = read_frame(&mut watcher) {
            let ev: FileSyncEvent = serde_json::from_slice(&payload).unwrap();
            if ev.path == "watched.txt" && !ev.removed {
                saw_create = true;
                break;
            }
        }
    }
    assert!(
        saw_create,
        "watch did not emit create event for watched.txt"
    );

    std::fs::remove_file(rw_dir.join("watched.txt")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_remove = false;
    while Instant::now() < deadline {
        if let Ok(Some((FS_EVENT, payload))) = read_frame(&mut watcher) {
            let ev: FileSyncEvent = serde_json::from_slice(&payload).unwrap();
            if ev.path == "watched.txt" && ev.removed {
                saw_remove = true;
                break;
            }
        }
    }
    assert!(
        saw_remove,
        "watch did not emit remove event for watched.txt"
    );

    closed.store(true, Ordering::SeqCst);
}
