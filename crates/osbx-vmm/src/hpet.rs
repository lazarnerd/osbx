//! Minimal 64-bit High Precision Event Timer (HPET) MMIO device at `0xFED0_0000`.
//!
//! Provides a monotonic 100 MHz (10 ns period) 64-bit main counter so OVMF, Linux, and Windows
//! kernels can calibrate timers cleanly alongside the ACPI PM timer and Hyper-V Reference TSC.

use std::sync::Mutex;
use std::time::Instant;

/// Standard x86 HPET MMIO base address (advertised in ACPI `HPET` table).
pub const HPET_BASE: u64 = 0xfed0_0000;
/// HPET MMIO window size.
pub const HPET_SIZE: u64 = 0x1000;
/// Event Timer Block ID matching `GCAP_ID` lower 32 bits (Intel `0x8086`, 64-bit, 3 timers, rev 1).
pub const HPET_BLOCK_ID: u32 = 0x8086_a201;
/// Counter tick period in femtoseconds: 10 ns = 10_000_000 fs (100 MHz).
const PERIOD_FS: u64 = 10_000_000;

struct Inner {
    gen_conf: u64,
    counter_base: u64,
    enabled_at: Instant,
    timer_cfg: [u64; 3],
    timer_cmp: [u64; 3],
}

/// Emulated HPET MMIO device.
pub struct Hpet {
    inner: Mutex<Inner>,
}

impl Default for Hpet {
    fn default() -> Self {
        Self::new()
    }
}

impl Hpet {
    /// Create a stopped HPET with counter = 0.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                gen_conf: 0,
                counter_base: 0,
                enabled_at: Instant::now(),
                timer_cfg: [0x0000_0030; 3], // 64-bit capable, periodic capable
                timer_cmp: [u64::MAX; 3],
            }),
        }
    }

    fn current_counter(inner: &Inner) -> u64 {
        if inner.gen_conf & 1 == 0 {
            inner.counter_base
        } else {
            let ticks = (inner.enabled_at.elapsed().as_nanos() / 10) as u64;
            inner.counter_base.wrapping_add(ticks)
        }
    }

    /// Handle a guest MMIO read at `offset` within `HPET_BASE..HPET_BASE + HPET_SIZE`.
    pub fn read(&self, offset: u64, data: &mut [u8]) {
        let inner = self.inner.lock().unwrap();
        let aligned = offset & !7;
        let shift = ((offset & 7) * 8) as u32;
        let reg_val: u64 = match aligned {
            0x000 => (PERIOD_FS << 32) | u64::from(HPET_BLOCK_ID),
            0x010 => inner.gen_conf,
            0x020 => 0, // GINTR_STA
            0x0f0 => Self::current_counter(&inner),
            0x100 => inner.timer_cfg[0],
            0x108 => inner.timer_cmp[0],
            0x120 => inner.timer_cfg[1],
            0x128 => inner.timer_cmp[1],
            0x140 => inner.timer_cfg[2],
            0x148 => inner.timer_cmp[2],
            _ => 0,
        };
        let bytes = (reg_val >> shift).to_le_bytes();
        let n = data.len().min(8);
        data[..n].copy_from_slice(&bytes[..n]);
    }

    /// Handle a guest MMIO write at `offset` within `HPET_BASE..HPET_BASE + HPET_SIZE`.
    pub fn write(&self, offset: u64, data: &[u8]) {
        let mut inner = self.inner.lock().unwrap();
        let aligned = offset & !7;
        let shift = ((offset & 7) * 8) as u32;
        let mut raw = [0u8; 8];
        let n = data.len().min(8);
        raw[..n].copy_from_slice(&data[..n]);
        let val = u64::from_le_bytes(raw);
        let mask = if n == 8 {
            u64::MAX
        } else {
            ((1u64 << (n * 8)) - 1) << shift
        };
        let merge = |old: u64| (old & !mask) | ((val << shift) & mask);

        match aligned {
            0x010 => {
                let was_enabled = inner.gen_conf & 1 != 0;
                let now_val = merge(inner.gen_conf) & 0x3;
                let now_enabled = now_val & 1 != 0;
                if was_enabled && !now_enabled {
                    inner.counter_base = Self::current_counter(&inner);
                } else if !was_enabled && now_enabled {
                    inner.enabled_at = Instant::now();
                }
                inner.gen_conf = now_val;
            }
            0x0f0 => {
                let cur = Self::current_counter(&inner);
                inner.counter_base = merge(cur);
                inner.enabled_at = Instant::now();
            }
            0x100 => inner.timer_cfg[0] = merge(inner.timer_cfg[0]),
            0x108 => inner.timer_cmp[0] = merge(inner.timer_cmp[0]),
            0x120 => inner.timer_cfg[1] = merge(inner.timer_cfg[1]),
            0x128 => inner.timer_cmp[1] = merge(inner.timer_cmp[1]),
            0x140 => inner.timer_cfg[2] = merge(inner.timer_cfg[2]),
            0x148 => inner.timer_cmp[2] = merge(inner.timer_cmp[2]),
            _ => {}
        }
    }
}
