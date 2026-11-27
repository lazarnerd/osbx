//! Port and MMIO dispatch shared by every hypervisor backend: the COM1 UART, reset ports,
//! virtio-MMIO devices and (for backends without in-kernel ones) the IOAPIC and legacy stubs.

use crate::boot::ExitReason;
use crate::bus::MmioBus;
use crate::ioapic::{IOAPIC_SIZE, IoApic};
use crate::irq::Irq;
use crate::mptable::IOAPIC_ADDR;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use vm_superio::{Serial, Trigger};

/// COM1 base port.
pub const COM1: u16 = 0x3f8;
/// COM1 interrupt line.
pub const COM1_IRQ: u32 = 4;

/// Raises COM1's interrupt.
pub struct UartIrq(pub Irq);
impl Trigger for UartIrq {
    type E = io::Error;
    fn trigger(&self) -> io::Result<()> {
        self.0.pulse();
        Ok(())
    }
}

/// Serial output sink: capture, optionally echo.
pub struct Sink {
    /// Everything written so far.
    pub captured: Arc<Mutex<Vec<u8>>>,
    /// Copy to stdout too.
    pub echo: bool,
}
impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.captured.lock().unwrap().extend_from_slice(buf);
        if self.echo {
            let mut out = io::stdout().lock();
            out.write_all(buf)?;
            out.flush()?;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The emulated 16550.
pub type Uart = Serial<UartIrq, vm_superio::serial::NoEvents, Sink>;

/// Everything a vCPU exit may touch.
pub struct Devices {
    /// COM1.
    pub uart: Arc<Mutex<Uart>>,
    /// virtio-MMIO devices.
    pub bus: MmioBus,
    /// Userspace IOAPIC, when the backend has no in-kernel one.
    pub ioapic: Option<Arc<IoApic>>,
    /// CMOS real-time clock (ports 0x70/0x71).
    pub rtc: Rtc,
}

/// A read-only MC146818-style CMOS clock reporting the host's UTC time, so the guest boots with
/// the right wall-clock time on backends without a paravirtual clock (WHP). Writes to the time
/// registers are ignored; CMOS RAM reads as zero.
#[derive(Default)]
pub struct Rtc {
    index: Mutex<u8>,
}

/// Days since 1970-01-01 -> (year, month, day) in the proleptic Gregorian calendar.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

impl Rtc {
    fn write(&self, port: u16, v: u8) {
        if port == 0x70 {
            *self.index.lock().unwrap() = v & 0x7f; // bit 7 is the NMI mask
        }
    }

    fn read(&self, port: u16) -> u8 {
        if port == 0x70 {
            return 0xff;
        }
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()) as i64;
        let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
        let (y, mo, d) = civil_from_days(days);
        let bcd = |x: u32| (((x / 10) << 4) | (x % 10)) as u8;
        match *self.index.lock().unwrap() {
            0x00 => bcd((rem % 60) as u32),
            0x02 => bcd((rem / 60 % 60) as u32),
            0x04 => bcd((rem / 3600) as u32),
            0x06 => bcd(((days + 4).rem_euclid(7) + 1) as u32), // 1 = Sunday
            0x07 => bcd(d),
            0x08 => bcd(mo),
            0x09 => bcd((y % 100) as u32),
            0x32 => bcd((y / 100) as u32), // century
            0x0a => 0x26,                  // 32.768 kHz base, no update in progress
            0x0b => 0x02,                  // 24-hour mode, BCD, no interrupts
            0x0c => 0x00,
            0x0d => 0x80, // valid RAM and time
            _ => 0,
        }
    }
}

impl Devices {
    /// Guest `out`; returns an exit reason if the guest asked to reset.
    pub fn io_out(&self, port: u16, data: &[u8]) -> Option<ExitReason> {
        match port {
            p if (COM1..COM1 + 8).contains(&p) => {
                let _ = self.uart.lock().unwrap().write((p - COM1) as u8, data[0]);
            }
            // keyboard-controller reset, PCI reset control register
            0x64 if data.first() == Some(&0xfe) => return Some(ExitReason::GuestReset),
            0xcf9 if data.first().is_some_and(|b| b & 0x04 != 0) => {
                return Some(ExitReason::GuestReset);
            }
            0x70 | 0x71 => self.rtc.write(port, data[0]),
            _ => {}
        }
        None
    }

    /// Guest `in`.
    pub fn io_in(&self, port: u16, data: &mut [u8]) {
        match port {
            p if (COM1..COM1 + 8).contains(&p) => {
                data[0] = self.uart.lock().unwrap().read((p - COM1) as u8)
            }
            0x60 | 0x64 => data.fill(0), // i8042 present but idle
            0x70 | 0x71 => data[0] = self.rtc.read(port),
            // No 8259 PIC behind a userspace IOAPIC: its mask registers do not read back 0xff, so
            // the guest's probe concludes there is none and routes everything through the IOAPIC.
            0x21 | 0xa1 if self.ioapic.is_some() => data.fill(0),
            _ => data.fill(0xff), // nothing there
        }
    }

    /// Guest MMIO read.
    pub fn mmio_read(&self, addr: u64, data: &mut [u8]) {
        if let Some(io) = self.ioapic(addr) {
            io.read(addr - u64::from(IOAPIC_ADDR), data);
        } else if !self.bus.read(addr, data) {
            data.fill(0xff);
        }
    }

    /// Guest MMIO write.
    pub fn mmio_write(&self, addr: u64, data: &[u8]) {
        if let Some(io) = self.ioapic(addr) {
            io.write(addr - u64::from(IOAPIC_ADDR), data);
        } else {
            self.bus.write(addr, data);
        }
    }

    fn ioapic(&self, addr: u64) -> Option<&IoApic> {
        let base = u64::from(IOAPIC_ADDR);
        self.ioapic
            .as_deref()
            .filter(|_| (base..base + IOAPIC_SIZE).contains(&addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(20_513), (2026, 3, 1)); // after a non-leap February
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }

    #[test]
    fn rtc_reads_bcd_utc() {
        let rtc = Rtc::default();
        rtc.write(0x70, 0x0d);
        assert_eq!(rtc.read(0x71), 0x80);
        rtc.write(0x70, 0x32);
        assert_eq!(rtc.read(0x71), 0x20); // 20xx
        rtc.write(0x70, 0x08);
        let m = rtc.read(0x71);
        assert!((0x01..=0x12).contains(&m) && m & 0x0f <= 9);
    }
}
