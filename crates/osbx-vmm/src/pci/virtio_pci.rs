//! Modern Virtio 1.0 PCIe transport (`virtio-pci`, Virtio 1.0 §4.1.4) with MSI-X and INTx.
//!
//! Wraps any existing [`VirtioDevice`] (`Block`, `VirtioScsi`, `Vsock`, `Fs`) so OVMF UEFI and
//! Windows `virtio-win` drivers (`viostor.sys`, `vioscsi.sys`, `viosock.sys`, `viofs.sys`) can
//! bind natively over PCIe.

use crate::irq::Irq;
use crate::pci::{BarSet, BarSpec, MsiRouter, PciDevice};
use crate::virtio::{
    Activation, GuestMem, INT_CONFIG, INT_USED_RING, Interrupt, InterruptSink, SharedQueue,
    VIRTIO_F_VERSION_1, VirtioDevice,
};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use virtio_queue::{Queue, QueueT};

/// Size of BAR0 (`COMMON_CFG` + `ISR_CFG` + `DEVICE_CFG` + `NOTIFY_CFG`).
pub const VIRTIO_BAR0_SIZE: u64 = 0x4000;
/// Size of BAR2 (MSI-X Table + PBA).
pub const VIRTIO_BAR2_SIZE: u64 = 0x2000;

const MSIX_NO_VECTOR: u16 = 0xffff;
const MAX_MSIX_VECTORS: usize = 8;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 0x80;

#[derive(Clone, Copy, Default)]
struct MsixEntry {
    addr: u64,
    data: u32,
    vector_ctrl: u32,
    route_handle: Option<u32>,
    pending: bool,
}

struct MsixState {
    enabled: AtomicBool,
    function_masked: AtomicBool,
    entries: Mutex<Vec<MsixEntry>>,
    config_vector: Mutex<u16>,
    queue_vectors: Mutex<Vec<u16>>,
    router: Arc<dyn MsiRouter>,
    intx_status: Arc<AtomicU8>,
    intx_line: Irq,
}

impl MsixState {
    fn signal_vector(&self, vec_idx: u16, isr_bit: u8) {
        if self.enabled.load(Ordering::SeqCst) {
            if vec_idx == MSIX_NO_VECTOR {
                return;
            }
            let mut entries = self.entries.lock().unwrap();
            let Some(e) = entries.get_mut(vec_idx as usize) else {
                return;
            };
            if self.function_masked.load(Ordering::SeqCst) || e.vector_ctrl & 1 != 0 {
                e.pending = true;
                return;
            }
            e.pending = false;
            if let Some(h) = e.route_handle {
                self.router.trigger(h);
            }
        } else {
            self.intx_status.fetch_or(isr_bit, Ordering::SeqCst);
            self.intx_line.pulse();
        }
    }

    fn deliver_pending(&self) {
        if !self.enabled.load(Ordering::SeqCst) || self.function_masked.load(Ordering::SeqCst) {
            return;
        }
        let mut entries = self.entries.lock().unwrap();
        for e in entries.iter_mut() {
            if e.pending
                && e.vector_ctrl & 1 == 0
                && let Some(h) = e.route_handle
            {
                e.pending = false;
                self.router.trigger(h);
            }
        }
    }
}

impl InterruptSink for MsixState {
    fn signal_config(&self) {
        let v = *self.config_vector.lock().unwrap();
        self.signal_vector(v, INT_CONFIG as u8);
    }

    fn signal_queue(&self, queue: u16) {
        let v = self
            .queue_vectors
            .lock()
            .unwrap()
            .get(queue as usize)
            .copied()
            .unwrap_or(MSIX_NO_VECTOR);
        self.signal_vector(v, INT_USED_RING as u8);
    }
}

/// Modern Virtio 1.0 PCIe device wrapping a [`VirtioDevice`].
pub struct VirtioPciTransport {
    dev: Box<dyn VirtioDevice>,
    mem: GuestMem,
    queues: Vec<SharedQueue>,
    cfg: [u8; 256],
    bars: BarSet,
    msix: Arc<MsixState>,
    irq: Interrupt,
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: u64,
    queue_sel: u16,
    status: u8,
    activated: bool,
}

impl VirtioPciTransport {
    /// Wrap `dev` as a modern Virtio 1.0 PCIe device at pre-allocated BAR addresses `bar0` and
    /// `bar2`.
    pub fn new(
        dev: Box<dyn VirtioDevice>,
        mem: GuestMem,
        bar0: u64,
        bar2: u64,
        intx_gsi: u8,
        intx_line: Irq,
        msi_router: Arc<dyn MsiRouter>,
    ) -> Self {
        let queue_sizes = dev.queue_max_sizes();
        let num_queues = queue_sizes.len();
        let queues: Vec<SharedQueue> = queue_sizes
            .into_iter()
            .map(|n| {
                Arc::new(Mutex::new(
                    Queue::new(n).expect("queue size is a power of two"),
                ))
            })
            .collect();

        let msix_vectors = (num_queues + 1).clamp(2, MAX_MSIX_VECTORS);
        let mut entries = Vec::with_capacity(msix_vectors);
        for _ in 0..msix_vectors {
            entries.push(MsixEntry {
                vector_ctrl: 1, // masked by default per PCI spec
                ..Default::default()
            });
        }
        let intx_status = Arc::new(AtomicU8::new(0));
        let msix = Arc::new(MsixState {
            enabled: AtomicBool::new(false),
            function_masked: AtomicBool::new(false),
            entries: Mutex::new(entries),
            config_vector: Mutex::new(MSIX_NO_VECTOR),
            queue_vectors: Mutex::new(vec![MSIX_NO_VECTOR; num_queues]),
            router: msi_router,
            intx_status,
            intx_line,
        });
        let irq = Interrupt::from_sink(msix.clone());

        let dev_type = dev.device_type();
        let pci_dev_id = 0x1040u16 + dev_type as u16;
        let class_code: u32 = match dev_type {
            2 | 8 => 0x0100_0001, // Mass Storage / SCSI, rev 1
            19 => 0x0280_0001,    // Other Network, rev 1
            26 => 0x0180_0001,    // Other Mass Storage, rev 1
            _ => 0x00ff_0001,
        };

        let mut cfg = [0u8; 256];
        cfg[0x00..0x02].copy_from_slice(&0x1af4u16.to_le_bytes()); // Vendor: Red Hat / Virtio
        cfg[0x02..0x04].copy_from_slice(&pci_dev_id.to_le_bytes());
        cfg[0x06..0x08].copy_from_slice(&0x0010u16.to_le_bytes()); // Status: Capabilities List
        cfg[0x08..0x0c].copy_from_slice(&class_code.to_le_bytes());
        cfg[0x2c..0x2e].copy_from_slice(&0x1af4u16.to_le_bytes()); // Subsystem Vendor
        // Virtio 1.0 §4.1.2.1: non-transitional devices MUST use Subsystem ID >= 0x40 (QEMU uses 0x1100).
        cfg[0x2e..0x30].copy_from_slice(&0x1100u16.to_le_bytes());
        cfg[0x34] = 0x40; // Capabilities pointer
        cfg[0x3c] = intx_gsi;
        cfg[0x3d] = 0x01; // INTA#

        // Virtio PCI capabilities (BAR0):
        // 0x40: COMMON_CFG (type 1, offset 0x0000, len 0x1000)
        write_virtio_cap(&mut cfg, 0x40, 0x50, 1, 0, 0x0000, 0x1000);
        // 0x50: ISR_CFG (type 3, offset 0x1000, len 0x1000)
        write_virtio_cap(&mut cfg, 0x50, 0x60, 3, 0, 0x1000, 0x1000);
        // 0x60: DEVICE_CFG (type 4, offset 0x2000, len 0x1000)
        write_virtio_cap(&mut cfg, 0x60, 0x70, 4, 0, 0x2000, 0x1000);
        // 0x70: NOTIFY_CFG (type 2, offset 0x3000, len 0x1000, multiplier = 4)
        write_virtio_cap(&mut cfg, 0x70, 0x84, 2, 0, 0x3000, 0x1000);
        cfg[0x72] = 20; // cap_len = 20 for notify cap
        cfg[0x80..0x84].copy_from_slice(&4u32.to_le_bytes()); // notify_off_multiplier = 4

        // 0x84: MSI-X capability (ID 0x11, BAR2 table at 0x0000, PBA at 0x1000)
        cfg[0x84] = 0x11;
        cfg[0x85] = 0x00; // end of capability list
        let msg_ctrl = (msix_vectors as u16 - 1) & 0x07ff;
        cfg[0x86..0x88].copy_from_slice(&msg_ctrl.to_le_bytes());
        cfg[0x88..0x8c].copy_from_slice(&0x0000_0002u32.to_le_bytes()); // Table: BAR2, offset 0
        cfg[0x8c..0x90].copy_from_slice(&0x0000_1002u32.to_le_bytes()); // PBA: BAR2, offset 0x1000

        let bars = BarSet::new(
            vec![
                BarSpec {
                    index: 0,
                    size: VIRTIO_BAR0_SIZE,
                    is_64bit: false,
                    prefetchable: false,
                    direct_mapped: false,
                },
                BarSpec {
                    index: 2,
                    size: VIRTIO_BAR2_SIZE,
                    is_64bit: false,
                    prefetchable: false,
                    direct_mapped: false,
                },
            ],
            &[(0, bar0), (2, bar2)],
        );

        Self {
            dev,
            mem,
            queues,
            cfg,
            bars,
            msix,
            irq,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: 0,
            queue_sel: 0,
            status: 0,
            activated: false,
        }
    }

    fn selected_queue(&self) -> Option<&SharedQueue> {
        self.queues.get(self.queue_sel as usize)
    }

    fn set_status(&mut self, mut v: u8) {
        if v == 0 {
            self.reset();
            return;
        }
        if v & STATUS_FEATURES_OK != 0 && self.status & STATUS_FEATURES_OK == 0 {
            let offered = self.dev.features() | VIRTIO_F_VERSION_1;
            if self.driver_features & !offered != 0
                || self.driver_features & VIRTIO_F_VERSION_1 == 0
            {
                v &= !STATUS_FEATURES_OK;
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
        self.msix.intx_status.store(0, Ordering::SeqCst);
        *self.msix.config_vector.lock().unwrap() = MSIX_NO_VECTOR;
        self.msix.queue_vectors.lock().unwrap().fill(MSIX_NO_VECTOR);
        for q in &self.queues {
            q.lock().unwrap().reset();
        }
        self.dev.reset();
    }

    fn read_common_cfg(&self, offset: u64, data: &mut [u8]) {
        // Build the 56-byte virtio_pci_common_cfg snapshot so any 1/2/4/8-byte read works cleanly.
        let mut reg = [0u8; 56];
        let offered = self.dev.features() | VIRTIO_F_VERSION_1;
        let dev_feat = match self.device_features_sel {
            0 => offered as u32,
            1 => (offered >> 32) as u32,
            _ => 0,
        };
        let drv_feat = match self.driver_features_sel {
            0 => self.driver_features as u32,
            1 => (self.driver_features >> 32) as u32,
            _ => 0,
        };
        reg[0x00..0x04].copy_from_slice(&self.device_features_sel.to_le_bytes());
        reg[0x04..0x08].copy_from_slice(&dev_feat.to_le_bytes());
        reg[0x08..0x0c].copy_from_slice(&self.driver_features_sel.to_le_bytes());
        reg[0x0c..0x10].copy_from_slice(&drv_feat.to_le_bytes());
        reg[0x10..0x12].copy_from_slice(&self.msix.config_vector.lock().unwrap().to_le_bytes());
        reg[0x12..0x14].copy_from_slice(&(self.queues.len() as u16).to_le_bytes());
        reg[0x14] = self.status;
        reg[0x15] = 0; // config_generation
        reg[0x16..0x18].copy_from_slice(&self.queue_sel.to_le_bytes());
        if let Some(q_arc) = self.selected_queue() {
            let q = q_arc.lock().unwrap();
            let q_size = if q.size() == 0 {
                q.max_size()
            } else {
                q.size()
            };
            reg[0x18..0x1a].copy_from_slice(&q_size.to_le_bytes());
            let q_vec = self
                .msix
                .queue_vectors
                .lock()
                .unwrap()
                .get(self.queue_sel as usize)
                .copied()
                .unwrap_or(MSIX_NO_VECTOR);
            reg[0x1a..0x1c].copy_from_slice(&q_vec.to_le_bytes());
            reg[0x1c..0x1e].copy_from_slice(&u16::from(q.ready()).to_le_bytes());
            reg[0x1e..0x20].copy_from_slice(&self.queue_sel.to_le_bytes());
            reg[0x20..0x28].copy_from_slice(&q.desc_table().to_le_bytes());
            reg[0x28..0x30].copy_from_slice(&q.avail_ring().to_le_bytes());
            reg[0x30..0x38].copy_from_slice(&q.used_ring().to_le_bytes());
        } else {
            reg[0x1a..0x1c].copy_from_slice(&MSIX_NO_VECTOR.to_le_bytes());
        }

        for (i, b) in data.iter_mut().enumerate() {
            *b = reg.get(offset as usize + i).copied().unwrap_or(0);
        }
    }

    fn write_common_cfg(&mut self, offset: u64, data: &[u8]) {
        // Split 64-bit queue address writes into two 32-bit writes.
        if data.len() == 8 && matches!(offset, 0x20 | 0x28 | 0x30) {
            self.write_common_cfg(offset, &data[0..4]);
            self.write_common_cfg(offset + 4, &data[4..8]);
            return;
        }
        let u16_val = || {
            let mut b = [0u8; 2];
            let n = data.len().min(2);
            b[..n].copy_from_slice(&data[..n]);
            u16::from_le_bytes(b)
        };
        let u32_val = || {
            let mut b = [0u8; 4];
            let n = data.len().min(4);
            b[..n].copy_from_slice(&data[..n]);
            u32::from_le_bytes(b)
        };
        match offset {
            0x00 => self.device_features_sel = u32_val(),
            0x08 => self.driver_features_sel = u32_val(),
            0x0c => {
                let v = u32_val();
                if self.driver_features_sel <= 1 {
                    let shift = if self.driver_features_sel == 0 { 0 } else { 32 };
                    let mask = 0xffff_ffffu64 << shift;
                    self.driver_features = (self.driver_features & !mask) | (u64::from(v) << shift);
                }
            }
            0x10 => {
                let v = u16_val();
                let n = self.msix.entries.lock().unwrap().len() as u16;
                *self.msix.config_vector.lock().unwrap() = if v < n { v } else { MSIX_NO_VECTOR };
            }
            0x14 => {
                if let Some(&b) = data.first() {
                    self.set_status(b);
                }
            }
            0x16 => self.queue_sel = u16_val(),
            0x18 => {
                let v = u16_val();
                if let Some(q) = self.selected_queue() {
                    q.lock().unwrap().set_size(v);
                }
            }
            0x1a => {
                let v = u16_val();
                let n = self.msix.entries.lock().unwrap().len() as u16;
                if let Some(slot) = self
                    .msix
                    .queue_vectors
                    .lock()
                    .unwrap()
                    .get_mut(self.queue_sel as usize)
                {
                    *slot = if v < n { v } else { MSIX_NO_VECTOR };
                }
            }
            0x1c => {
                let v = u16_val();
                if let Some(q) = self.selected_queue() {
                    q.lock().unwrap().set_ready(v != 0);
                }
            }
            0x20 => self.with_queue(|q| q.set_desc_table_address(Some(u32_val()), None)),
            0x24 => self.with_queue(|q| q.set_desc_table_address(None, Some(u32_val()))),
            0x28 => self.with_queue(|q| q.set_avail_ring_address(Some(u32_val()), None)),
            0x2c => self.with_queue(|q| q.set_avail_ring_address(None, Some(u32_val()))),
            0x30 => self.with_queue(|q| q.set_used_ring_address(Some(u32_val()), None)),
            0x34 => self.with_queue(|q| q.set_used_ring_address(None, Some(u32_val()))),
            _ => {}
        }
    }

    fn with_queue(&self, f: impl FnOnce(&mut Queue)) {
        if let Some(q) = self.selected_queue() {
            f(&mut q.lock().unwrap());
        }
    }

    fn read_msix_table(&self, offset: u64, data: &mut [u8]) {
        if offset >= 0x1000 {
            let pba_off = (offset - 0x1000) as usize;
            let entries = self.msix.entries.lock().unwrap();
            let mut pba = 0u64;
            for (i, e) in entries.iter().enumerate() {
                if e.pending && i < 64 {
                    pba |= 1u64 << i;
                }
            }
            let raw = pba.to_le_bytes();
            for (i, b) in data.iter_mut().enumerate() {
                *b = raw.get(pba_off + i).copied().unwrap_or(0);
            }
            return;
        }
        let idx = (offset / 16) as usize;
        let field = (offset % 16) as usize;
        let entries = self.msix.entries.lock().unwrap();
        let Some(e) = entries.get(idx) else {
            data.fill(0);
            return;
        };
        let mut raw = [0u8; 16];
        raw[0..8].copy_from_slice(&e.addr.to_le_bytes());
        raw[8..12].copy_from_slice(&e.data.to_le_bytes());
        raw[12..16].copy_from_slice(&e.vector_ctrl.to_le_bytes());
        for (i, b) in data.iter_mut().enumerate() {
            *b = raw.get(field + i).copied().unwrap_or(0);
        }
    }

    fn write_msix_table(&mut self, offset: u64, data: &[u8]) {
        if offset >= 0x1000 || data.len() < 4 {
            return;
        }
        if data.len() == 8 && offset.is_multiple_of(16) {
            self.write_msix_table(offset, &data[0..4]);
            self.write_msix_table(offset + 4, &data[4..8]);
            return;
        }
        let idx = (offset / 16) as usize;
        let field = (offset % 16) as usize;
        let val = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let mut entries = self.msix.entries.lock().unwrap();
        let Some(e) = entries.get_mut(idx) else {
            return;
        };
        match field {
            0 => e.addr = (e.addr & !0xffff_ffff) | u64::from(val),
            4 => e.addr = (e.addr & 0xffff_ffff) | (u64::from(val) << 32),
            8 => e.data = val,
            12 => e.vector_ctrl = val,
            _ => return,
        }
        if e.addr != 0 {
            let handle = match e.route_handle {
                Some(h) => Some(h),
                None => self.msix.router.allocate().ok(),
            };
            if let Some(h) = handle {
                e.route_handle = Some(h);
                let _ = self.msix.router.configure(h, e.addr, e.data);
                if e.pending
                    && e.vector_ctrl & 1 == 0
                    && self.msix.enabled.load(Ordering::SeqCst)
                    && !self.msix.function_masked.load(Ordering::SeqCst)
                {
                    e.pending = false;
                    self.msix.router.trigger(h);
                }
            }
        }
    }
}

impl PciDevice for VirtioPciTransport {
    fn config_read(&self, offset: usize, data: &mut [u8]) {
        if (0x10..0x28).contains(&offset) {
            let reg_idx = (offset - 0x10) / 4;
            let byte_off = (offset - 0x10) % 4;
            let v = self.bars.read_u32(reg_idx).to_le_bytes();
            for (i, b) in data.iter_mut().enumerate() {
                *b = v.get(byte_off + i).copied().unwrap_or(0);
            }
            return;
        }
        for (i, b) in data.iter_mut().enumerate() {
            *b = self.cfg.get(offset + i).copied().unwrap_or(0);
        }
    }

    fn config_write(&mut self, offset: usize, data: &[u8]) {
        if (0x10..0x28).contains(&offset) && data.len() == 4 && offset.is_multiple_of(4) {
            let reg_idx = (offset - 0x10) / 4;
            let val = u32::from_le_bytes(data.try_into().unwrap());
            self.bars.write_u32(reg_idx, val);
            return;
        }
        for (i, &b) in data.iter().enumerate() {
            let idx = offset + i;
            match idx {
                0x04..=0x05 | 0x0c..=0x0d | 0x3c => self.cfg[idx] = b,
                0x87 => {
                    // Upper byte of MSI-X Message Control: bit 7 = Enable, bit 6 = Function Mask.
                    self.cfg[idx] = (self.cfg[idx] & 0x3f) | (b & 0xc0);
                    self.msix.enabled.store(b & 0x80 != 0, Ordering::SeqCst);
                    self.msix
                        .function_masked
                        .store(b & 0x40 != 0, Ordering::SeqCst);
                    self.msix.deliver_pending();
                }
                _ => {}
            }
        }
    }

    fn active_bars(&self) -> Vec<(usize, u64, u64)> {
        let cmd = u16::from_le_bytes([self.cfg[0x04], self.cfg[0x05]]);
        if cmd & 0x02 == 0 {
            return Vec::new();
        }
        self.bars.active_mmio()
    }

    fn bar_read(&self, bar_index: usize, offset: u64, data: &mut [u8]) {
        match bar_index {
            0 => match offset {
                0x0000..0x1000 => self.read_common_cfg(offset, data),
                0x1000..0x2000 => {
                    let v = self.msix.intx_status.swap(0, Ordering::SeqCst);
                    data.fill(0);
                    if let Some(first) = data.first_mut() {
                        *first = v;
                    }
                }
                0x2000..0x3000 => self.dev.read_config(offset - 0x2000, data),
                _ => data.fill(0),
            },
            2 => self.read_msix_table(offset, data),
            _ => data.fill(0xff),
        }
    }

    fn bar_write(&mut self, bar_index: usize, offset: u64, data: &[u8]) {
        match bar_index {
            0 => match offset {
                0x0000..0x1000 => self.write_common_cfg(offset, data),
                0x2000..0x3000 => self.dev.write_config(offset - 0x2000, data),
                0x3000..0x4000 => {
                    let q = if data.len() >= 2 {
                        u32::from(u16::from_le_bytes([data[0], data[1]]))
                    } else {
                        ((offset - 0x3000) / 4) as u32
                    };
                    self.dev.queue_notify(q);
                }
                _ => {}
            },
            2 => self.write_msix_table(offset, data),
            _ => {}
        }
    }
}

fn write_virtio_cap(
    cfg: &mut [u8; 256],
    pos: usize,
    next: u8,
    cfg_type: u8,
    bar: u8,
    offset: u32,
    length: u32,
) {
    cfg[pos] = 0x09; // PCI_CAP_ID_VNDR
    cfg[pos + 1] = next;
    cfg[pos + 2] = 16;
    cfg[pos + 3] = cfg_type;
    cfg[pos + 4] = bar;
    cfg[pos + 8..pos + 12].copy_from_slice(&offset.to_le_bytes());
    cfg[pos + 12..pos + 16].copy_from_slice(&length.to_le_bytes());
}
