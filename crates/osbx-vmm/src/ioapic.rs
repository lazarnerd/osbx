//! A userspace 82093AA-style IOAPIC (24 pins) for backends without an in-kernel one (Windows
//! Hypervisor Platform emulates only the local APIC).
//!
//! Every line osbx raises is a pulse (edge). Guests are told (MP table, ISA bus, conforming)
//! that all pins are edge-triggered, active-high, so remote-IRR/level semantics are not needed.
//! A pulse on a masked pin is remembered and delivered when the pin is unmasked, so a device
//! interrupt is never lost while the guest reprograms a route.

use std::sync::Mutex;

/// Number of redirection entries.
pub const PINS: usize = 24;
/// Size of the register window.
pub const IOAPIC_SIZE: u64 = 0x1000;

/// An interrupt message for the local APICs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message {
    /// Vector.
    pub vector: u8,
    /// Delivery mode (0 fixed, 1 lowest priority, 2 SMI, 4 NMI, 5 INIT, 7 ExtINT).
    pub delivery: u8,
    /// Logical (true) or physical destination mode.
    pub logical: bool,
    /// Destination APIC id (physical) or logical mask.
    pub dest: u8,
}

struct State {
    select: u8,
    id: u32,
    redir: [u64; PINS],
    pending: u32,
}

/// The IOAPIC; `deliver` sends a message to the local APICs.
pub struct IoApic {
    state: Mutex<State>,
    deliver: Box<dyn Fn(Message) + Send + Sync>,
}

const MASKED: u64 = 1 << 16;

impl IoApic {
    /// A reset IOAPIC (all pins masked) with APIC id `id`.
    pub fn new(id: u8, deliver: impl Fn(Message) + Send + Sync + 'static) -> Self {
        Self {
            state: Mutex::new(State {
                select: 0,
                id: u32::from(id) << 24,
                redir: [MASKED; PINS],
                pending: 0,
            }),
            deliver: Box::new(deliver),
        }
    }

    fn message(entry: u64) -> Message {
        Message {
            vector: entry as u8,
            delivery: ((entry >> 8) & 7) as u8,
            logical: entry & (1 << 11) != 0,
            dest: (entry >> 56) as u8,
        }
    }

    /// Pulse input `pin`.
    pub fn pulse(&self, pin: usize) {
        if pin >= PINS {
            return;
        }
        let msg = {
            let mut s = self.state.lock().unwrap();
            let e = s.redir[pin];
            if e & MASKED != 0 {
                s.pending |= 1 << pin;
                return;
            }
            Self::message(e)
        };
        (self.deliver)(msg);
    }

    /// Guest read at `offset` within the window.
    pub fn read(&self, offset: u64, data: &mut [u8]) {
        let s = self.state.lock().unwrap();
        let v: u32 = match offset {
            0x00 => u32::from(s.select),
            0x10 => match s.select {
                0x00 => s.id,
                0x01 => ((PINS as u32 - 1) << 16) | 0x11, // max redirection entry, version
                0x02 => s.id,                             // arbitration id
                r @ 0x10..=0x3f => {
                    let e = s.redir[usize::from((r - 0x10) / 2)];
                    if r % 2 == 0 {
                        e as u32
                    } else {
                        (e >> 32) as u32
                    }
                }
                _ => 0,
            },
            _ => 0,
        };
        let b = v.to_le_bytes();
        let n = data.len().min(4);
        data[..n].copy_from_slice(&b[..n]);
    }

    /// Guest write at `offset` within the window.
    pub fn write(&self, offset: u64, data: &[u8]) {
        let mut b = [0u8; 4];
        let n = data.len().min(4);
        b[..n].copy_from_slice(&data[..n]);
        let v = u32::from_le_bytes(b);
        let mut deliver = None;
        {
            let mut s = self.state.lock().unwrap();
            match offset {
                0x00 => s.select = v as u8,
                0x10 => match s.select {
                    0x00 => s.id = v & 0x0f00_0000,
                    r @ 0x10..=0x3f => {
                        let pin = usize::from((r - 0x10) / 2);
                        let e = &mut s.redir[pin];
                        // delivery status (12) and remote IRR (14) are read-only
                        let ro = (1u64 << 12) | (1 << 14);
                        *e = if r % 2 == 0 {
                            (*e & (0xffff_ffff_0000_0000 | ro)) | (u64::from(v) & !ro)
                        } else {
                            (*e & 0xffff_ffff) | (u64::from(v) << 32)
                        };
                        let e = *e;
                        if e & MASKED == 0 && s.pending & (1 << pin) != 0 {
                            s.pending &= !(1 << pin);
                            deliver = Some(Self::message(e));
                        }
                    }
                    _ => {}
                },
                _ => {} // 0x40: EOI register (version 0x20+); nothing to clear for edge pins
            }
        }
        if let Some(m) = deliver {
            (self.deliver)(m);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn wr(io: &IoApic, reg: u8, v: u32) {
        io.write(0, &[reg]);
        io.write(0x10, &v.to_le_bytes());
    }
    fn rd(io: &IoApic, reg: u8) -> u32 {
        io.write(0, &[reg]);
        let mut b = [0u8; 4];
        io.read(0x10, &mut b);
        u32::from_le_bytes(b)
    }

    #[test]
    fn routes_unmasked_pins_and_keeps_masked_pulses() {
        let got = Arc::new(Mutex::new(Vec::new()));
        let g = got.clone();
        let io = IoApic::new(4, move |m| g.lock().unwrap().push(m));
        assert_eq!(rd(&io, 1), 0x0017_0011);
        assert_eq!(rd(&io, 0) >> 24, 4);
        io.pulse(5); // masked at reset: remembered
        assert!(got.lock().unwrap().is_empty());
        wr(&io, 0x10 + 2 * 5 + 1, 2 << 24); // destination APIC 2
        wr(&io, 0x10 + 2 * 5, 0x31); // vector 0x31, fixed, physical, unmasked
        assert_eq!(
            got.lock().unwrap().as_slice(),
            &[Message {
                vector: 0x31,
                delivery: 0,
                logical: false,
                dest: 2
            }]
        );
        io.pulse(5);
        assert_eq!(got.lock().unwrap().len(), 2);
        assert_eq!(rd(&io, 0x10 + 2 * 5), 0x31);
        io.pulse(99); // out of range: ignored
    }
}
