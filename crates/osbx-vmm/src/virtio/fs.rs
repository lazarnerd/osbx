//! virtio-fs: share a host directory with the guest (FUSE over virtio).
//!
//! The FUSE protocol and the passthrough file system come from `fuse-backend-rs`; this file is
//! the virtio glue. Files the guest creates are owned by the user running the VMM on the host,
//! which is what a shared workspace wants.

use super::{
    Activation, GuestMem, INT_USED_RING, Interrupt, SharedQueue, VIRTIO_F_VERSION_1, VirtioDevice,
};
use fuse_backend_rs::api::server::Server;
use fuse_backend_rs::passthrough::{CachePolicy, Config, PassthroughFs};
use fuse_backend_rs::transport::{Reader, VirtioFsWriter};
use std::io;
use std::path::Path;
use std::sync::Arc;
use virtio_queue::{QueueOwnedT, QueueT};

/// Longest mount tag the spec allows.
pub const MAX_TAG: usize = 36;

/// A virtio-fs device exporting one host directory.
pub struct Fs {
    tag: [u8; MAX_TAG],
    server: Arc<Server<Arc<PassthroughFs>>>,
    active: Option<(GuestMem, Vec<SharedQueue>, Interrupt)>,
}

impl Fs {
    /// Export `host_dir` under mount tag `tag`.
    pub fn new(tag: &str, host_dir: &Path) -> io::Result<Self> {
        if tag.is_empty() || tag.len() > MAX_TAG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tag must be 1..=36 bytes",
            ));
        }
        let root = std::fs::canonicalize(host_dir)?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a directory", root.display()),
            ));
        }
        let cfg = Config {
            root_dir: root.to_string_lossy().into_owned(),
            do_import: true,
            cache_policy: CachePolicy::Auto,
            xattr: false,
            ..Config::default()
        };
        let fs = PassthroughFs::new(cfg)?;
        fs.import()?;
        let mut t = [0u8; MAX_TAG];
        t[..tag.len()].copy_from_slice(tag.as_bytes());
        Ok(Self {
            tag: t,
            server: Arc::new(Server::new(Arc::new(fs))),
            active: None,
        })
    }
}

impl VirtioDevice for Fs {
    fn device_type(&self) -> u32 {
        26
    }
    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }
    fn queue_max_sizes(&self) -> Vec<u16> {
        vec![128, 128] // hiprio, one request queue
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut cfg = [0u8; MAX_TAG + 4];
        cfg[..MAX_TAG].copy_from_slice(&self.tag);
        cfg[MAX_TAG..].copy_from_slice(&1u32.to_le_bytes()); // num_request_queues
        for (i, b) in data.iter_mut().enumerate() {
            *b = cfg.get(offset as usize + i).copied().unwrap_or(0);
        }
    }
    fn activate(&mut self, a: Activation) {
        self.active = Some((a.mem, a.queues, a.irq));
    }
    fn queue_notify(&mut self, queue: u32) {
        let Some((mem, queues, irq)) = self.active.clone() else {
            return;
        };
        let Some(queue) = queues.get(queue as usize) else {
            return;
        };
        let mut q = queue.lock().unwrap();
        let mut signal = false;
        while let Ok(iter) = q.iter(&mem) {
            let chains: Vec<_> = iter.collect();
            if chains.is_empty() {
                if q.enable_notification(&mem).unwrap_or(false) {
                    continue;
                }
                break;
            }
            for chain in chains {
                let head = chain.head_index();
                let used = match (
                    Reader::from_descriptor_chain(&mem, chain.clone()),
                    VirtioFsWriter::new(&mem, chain),
                ) {
                    (Ok(r), Ok(w)) => self
                        .server
                        .handle_message(r, w.into(), None, None)
                        .unwrap_or(0),
                    _ => 0,
                };
                if q.add_used(&mem, head, used as u32).is_ok() {
                    signal = true;
                }
            }
        }
        if signal && q.needs_notification(&mem).unwrap_or(true) {
            drop(q);
            irq.signal(INT_USED_RING);
        }
    }
}
