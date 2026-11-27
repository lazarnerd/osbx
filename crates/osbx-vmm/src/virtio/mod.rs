//! virtio-MMIO devices (virtio 1.x, modern layout).
//!
//! The guest finds them from `virtio_mmio.device=<size>@<base>:<irq>` kernel arguments, so no
//! ACPI, device tree or PCI is needed. Queues are processed synchronously on the vCPU thread
//! when the guest kicks them; devices that receive data asynchronously (vsock) keep a clone of
//! their queues and signal the guest through [`Interrupt`].

pub mod blk;
#[cfg(target_os = "linux")]
pub mod fs;
#[cfg(windows)]
#[path = "fs_windows.rs"]
pub mod fs;
pub mod mmio;
pub mod scsi;
pub mod vsock;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use virtio_queue::Queue;
use vm_memory::GuestMemoryMmap;

use crate::irq::Irq;

/// `VIRTIO_F_VERSION_1`: the device is a virtio 1.x (non-legacy) device.
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
/// Interrupt-status bit: a used buffer notification.
pub const INT_USED_RING: u32 = 1;
/// Interrupt-status bit: the device configuration changed.
pub const INT_CONFIG: u32 = 2;

/// Guest memory handle shared with devices.
pub type GuestMem = GuestMemoryMmap<()>;
/// A queue shared between the transport and a device.
pub type SharedQueue = Arc<Mutex<Queue>>;

/// Transport-specific interrupt delivery (MMIO single line or PCI INTx / per-queue MSI-X).
pub trait InterruptSink: Send + Sync {
    /// Deliver a configuration-change interrupt.
    fn signal_config(&self);
    /// Deliver a used-buffer interrupt for `queue`.
    fn signal_queue(&self, queue: u16);
}

struct MmioInterruptSink {
    status: Arc<AtomicU32>,
    line: Irq,
}

impl InterruptSink for MmioInterruptSink {
    fn signal_config(&self) {
        self.status.fetch_or(INT_CONFIG, Ordering::SeqCst);
        self.line.pulse();
    }
    fn signal_queue(&self, _queue: u16) {
        self.status.fetch_or(INT_USED_RING, Ordering::SeqCst);
        self.line.pulse();
    }
}

/// Raises a device's interrupt (MMIO line, PCI INTx, or PCI MSI-X vector).
#[derive(Clone)]
pub struct Interrupt {
    sink: Arc<dyn InterruptSink>,
}

impl Interrupt {
    pub(crate) fn new(status: Arc<AtomicU32>, line: Irq) -> Self {
        Self {
            sink: Arc::new(MmioInterruptSink { status, line }),
        }
    }

    /// Wrap a transport-provided [`InterruptSink`] (e.g., `virtio-pci` MSI-X/INTx).
    pub fn from_sink(sink: Arc<dyn InterruptSink>) -> Self {
        Self { sink }
    }

    /// Signal a used-buffer notification on `queue`.
    pub fn signal_queue(&self, queue: u16) {
        self.sink.signal_queue(queue);
    }

    /// Set `bit` in the interrupt status register and pulse the line (queue 0 for `INT_USED_RING`).
    pub fn signal(&self, bit: u32) {
        if bit & INT_CONFIG != 0 {
            self.sink.signal_config();
        }
        if bit & INT_USED_RING != 0 {
            self.sink.signal_queue(0);
        }
    }
}

/// Everything a device needs once the driver has finished initialization.
pub struct Activation {
    /// Guest memory.
    pub mem: GuestMem,
    /// The device's queues, configured by the driver.
    pub queues: Vec<SharedQueue>,
    /// Interrupt line.
    pub irq: Interrupt,
}

/// A virtio device behind an MMIO transport.
pub trait VirtioDevice: Send {
    /// virtio device id (2 = block, 19 = vsock, ...).
    fn device_type(&self) -> u32;
    /// Offered feature bits (must include [`VIRTIO_F_VERSION_1`]).
    fn features(&self) -> u64;
    /// Maximum size of each queue.
    fn queue_max_sizes(&self) -> Vec<u16>;
    /// Read device-specific configuration space.
    fn read_config(&self, offset: u64, data: &mut [u8]);
    /// Write device-specific configuration space.
    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}
    /// The driver set DRIVER_OK.
    fn activate(&mut self, activation: Activation);
    /// The driver kicked `queue`.
    fn queue_notify(&mut self, queue: u32);
    /// The driver reset the device.
    fn reset(&mut self) {}
}
