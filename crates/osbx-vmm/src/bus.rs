//! A tiny MMIO bus: routes guest accesses to virtio transports by address.

use crate::virtio::mmio::{MMIO_SIZE, MmioTransport};
use std::sync::{Arc, Mutex};

/// Base address of the first virtio-MMIO window (above RAM, below the 32-bit MMIO hole).
pub const MMIO_BASE: u64 = 0xd000_0000;
/// Interrupt lines handed to virtio devices: IOAPIC pins not used by the PIT (0), keyboard (1),
/// cascade (2), serial ports (3, 4), RTC (8) or FPU (13). Guests always get an MP table routing
/// all 24 IOAPIC pins, so lines above 15 work too.
pub const DEVICE_IRQS: [u32; 17] = [
    5, 6, 7, 9, 10, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
];

/// Devices by base address.
#[derive(Default, Clone)]
pub struct MmioBus {
    devices: Vec<(u64, Arc<Mutex<MmioTransport>>)>,
}

impl MmioBus {
    /// Address of device slot `i`.
    pub fn slot_base(i: usize) -> u64 {
        MMIO_BASE + i as u64 * MMIO_SIZE
    }
    /// Add a device at slot `i`.
    pub fn add(&mut self, slot: usize, dev: Arc<Mutex<MmioTransport>>) {
        self.devices.push((Self::slot_base(slot), dev));
    }
    fn find(&self, addr: u64) -> Option<(&Arc<Mutex<MmioTransport>>, u64)> {
        self.devices
            .iter()
            .find(|(b, _)| addr >= *b && addr < *b + MMIO_SIZE)
            .map(|(b, d)| (d, addr - b))
    }
    /// Guest read; returns false if no device claims the address.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> bool {
        match self.find(addr) {
            Some((d, off)) => {
                d.lock().unwrap().read(off, data);
                true
            }
            None => false,
        }
    }
    /// Guest write; returns false if no device claims the address.
    pub fn write(&self, addr: u64, data: &[u8]) -> bool {
        match self.find(addr) {
            Some((d, off)) => {
                d.lock().unwrap().write(off, data);
                true
            }
            None => false,
        }
    }
}
