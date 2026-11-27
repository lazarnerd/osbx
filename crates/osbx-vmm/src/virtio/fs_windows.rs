//! virtio-fs on hosts without the Linux passthrough file system: the virtio glue around osbx's
//! own FUSE server ([`crate::fuse`]).

use super::{
    Activation, GuestMem, INT_USED_RING, Interrupt, SharedQueue, VIRTIO_F_VERSION_1, VirtioDevice,
};
use crate::fuse::Server;
use std::io::{self, Read, Write};
use std::path::Path;
use virtio_queue::{QueueOwnedT, QueueT};

/// Longest mount tag the spec allows.
pub const MAX_TAG: usize = 36;

/// A virtio-fs device exporting one host directory.
pub struct Fs {
    tag: [u8; MAX_TAG],
    server: Server,
    active: Option<(GuestMem, Vec<SharedQueue>, Interrupt)>,
}

impl Fs {
    /// Export `host_dir` under mount tag `tag`. When `read_only` is true, every mutating FUSE
    /// request is rejected on the host with `EROFS`.
    pub fn new(tag: &str, host_dir: &Path, read_only: bool) -> io::Result<Self> {
        if tag.is_empty() || tag.len() > MAX_TAG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tag must be 1..=36 bytes",
            ));
        }
        let mut t = [0u8; MAX_TAG];
        t[..tag.len()].copy_from_slice(tag.as_bytes());
        Ok(Self {
            tag: t,
            server: Server::new(host_dir, read_only)?,
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
                let mut used = 0u32;
                if let (Ok(mut rd), Ok(mut wr)) = (chain.clone().reader(&mem), chain.writer(&mem)) {
                    let mut req = vec![0u8; rd.available_bytes()];
                    if rd.read_exact(&mut req).is_ok()
                        && let Some(reply) = self.server.handle(&req)
                    {
                        let n = reply.len().min(wr.available_bytes());
                        if wr.write_all(&reply[..n]).is_ok() {
                            used = n as u32;
                        }
                    }
                }
                if q.add_used(&mem, head, used).is_ok() {
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
