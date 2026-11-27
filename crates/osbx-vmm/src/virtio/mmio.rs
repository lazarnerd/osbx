//! The virtio-MMIO transport (register layout from the virtio 1.x specification, §4.2.2).

use super::{Activation, GuestMem, Interrupt, SharedQueue, VIRTIO_F_VERSION_1, VirtioDevice};
use crate::irq::Irq;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use virtio_queue::{Queue, QueueT};

/// Size of one device's register window.
pub const MMIO_SIZE: u64 = 0x1000;
const MAGIC: u32 = 0x7472_6976; // "virt"
const VENDOR: u32 = 0x4f53_4258; // "OSBX"

const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_FAILED: u32 = 0x80;

/// One device plus its MMIO register state.
pub struct MmioTransport {
    dev: Box<dyn VirtioDevice>,
    mem: GuestMem,
    queues: Vec<SharedQueue>,
    irq_status: Arc<AtomicU32>,
    irq: Interrupt,
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: u64,
    queue_sel: u32,
    status: u32,
    activated: bool,
}

impl MmioTransport {
    /// Wrap `dev`; `irq` is the device's interrupt line.
    pub fn new(dev: Box<dyn VirtioDevice>, mem: GuestMem, irq: Irq) -> Self {
        let queues = dev
            .queue_max_sizes()
            .into_iter()
            .map(|n| {
                Arc::new(Mutex::new(
                    Queue::new(n).expect("queue size is a power of two"),
                ))
            })
            .collect();
        let irq_status = Arc::new(AtomicU32::new(0));
        let irq = Interrupt::new(irq_status.clone(), irq);
        Self {
            dev,
            mem,
            queues,
            irq_status,
            irq,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: 0,
            queue_sel: 0,
            status: 0,
            activated: false,
        }
    }

    fn selected(&self) -> Option<&SharedQueue> {
        self.queues.get(self.queue_sel as usize)
    }

    /// Handle a guest read at `offset` within the window.
    pub fn read(&self, offset: u64, data: &mut [u8]) {
        if offset >= 0x100 {
            self.dev.read_config(offset - 0x100, data);
            return;
        }
        let v: u32 = match offset {
            0x000 => MAGIC,
            0x004 => 2,
            0x008 => self.dev.device_type(),
            0x00c => VENDOR,
            0x010 => {
                let f = self.dev.features() | VIRTIO_F_VERSION_1;
                if self.device_features_sel == 0 {
                    f as u32
                } else if self.device_features_sel == 1 {
                    (f >> 32) as u32
                } else {
                    0
                }
            }
            0x034 => self
                .selected()
                .map_or(0, |q| u32::from(q.lock().unwrap().max_size())),
            0x044 => self
                .selected()
                .map_or(0, |q| u32::from(q.lock().unwrap().ready())),
            0x060 => self.irq_status.load(Ordering::SeqCst),
            0x070 => self.status,
            // Shared memory regions (SHMLen/SHMBase): none. The spec says a missing region reads
            // as all ones; 0 would mean "a region of length 0" and makes e.g. virtiofs fail to probe.
            0x0b0 | 0x0b4 | 0x0b8 | 0x0bc => 0xffff_ffff,
            0x0fc => 0,
            _ => 0,
        };
        let bytes = v.to_le_bytes();
        let n = data.len().min(4);
        data[..n].copy_from_slice(&bytes[..n]);
    }

    /// Handle a guest write at `offset` within the window.
    pub fn write(&mut self, offset: u64, data: &[u8]) {
        if offset >= 0x100 {
            self.dev.write_config(offset - 0x100, data);
            return;
        }
        let mut b = [0u8; 4];
        let n = data.len().min(4);
        b[..n].copy_from_slice(&data[..n]);
        let v = u32::from_le_bytes(b);
        match offset {
            0x014 => self.device_features_sel = v,
            0x020 => {
                let shift = if self.driver_features_sel == 0 { 0 } else { 32 };
                if self.driver_features_sel <= 1 {
                    let mask = 0xffff_ffffu64 << shift;
                    self.driver_features = (self.driver_features & !mask) | (u64::from(v) << shift);
                }
            }
            0x024 => self.driver_features_sel = v,
            0x030 => self.queue_sel = v,
            0x038 => {
                if let Some(q) = self.selected() {
                    q.lock().unwrap().set_size(v as u16);
                }
            }
            0x044 => {
                if let Some(q) = self.selected() {
                    q.lock().unwrap().set_ready(v == 1);
                }
            }
            0x050 => self.dev.queue_notify(v),
            0x064 => {
                self.irq_status.fetch_and(!v, Ordering::SeqCst);
            }
            0x070 => self.set_status(v),
            0x080 => self.with_queue(|q| q.set_desc_table_address(Some(v), None)),
            0x084 => self.with_queue(|q| q.set_desc_table_address(None, Some(v))),
            0x090 => self.with_queue(|q| q.set_avail_ring_address(Some(v), None)),
            0x094 => self.with_queue(|q| q.set_avail_ring_address(None, Some(v))),
            0x0a0 => self.with_queue(|q| q.set_used_ring_address(Some(v), None)),
            0x0a4 => self.with_queue(|q| q.set_used_ring_address(None, Some(v))),
            _ => {}
        }
    }

    fn with_queue(&self, f: impl FnOnce(&mut Queue)) {
        if let Some(q) = self.selected() {
            f(&mut q.lock().unwrap());
        }
    }

    fn set_status(&mut self, v: u32) {
        if v == 0 {
            self.reset();
            return;
        }
        // The driver may only set bits, and FEATURES_OK only if it accepts our feature set.
        let mut v = v;
        if v & STATUS_FEATURES_OK != 0 && self.status & STATUS_FEATURES_OK == 0 {
            let offered = self.dev.features() | VIRTIO_F_VERSION_1;
            if self.driver_features & !offered != 0
                || self.driver_features & VIRTIO_F_VERSION_1 == 0
            {
                v &= !STATUS_FEATURES_OK; // refused: the driver will see the bit cleared
            }
        }
        self.status = v;
        let all = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK;
        if v & all == all && v & STATUS_FAILED == 0 && !self.activated {
            self.activated = true;
            self.dev.activate(Activation {
                mem: self.mem.clone(),
                queues: self.queues.clone(),
                irq: self.irq.clone(),
            });
        }
    }

    fn reset(&mut self) {
        self.status = 0;
        self.activated = false;
        self.driver_features = 0;
        self.irq_status.store(0, Ordering::SeqCst);
        for q in &self.queues {
            q.lock().unwrap().reset();
        }
        self.dev.reset();
    }
}
