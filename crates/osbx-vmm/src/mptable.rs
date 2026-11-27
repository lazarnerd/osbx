//! Intel MultiProcessor Specification 1.4 tables, so the guest kernel (booted with `acpi=off`)
//! discovers every vCPU, the IOAPIC and the ISA interrupt routing.

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

/// Where the tables go: the start of the 1 KiB "EBDA" area below 640 KiB, which the e820 map
/// leaves out of usable RAM.
pub const MPTABLE_START: u64 = 0x9fc00;
/// Local APIC address.
pub const APIC_ADDR: u32 = 0xfee0_0000;
/// IOAPIC address.
pub const IOAPIC_ADDR: u32 = 0xfec0_0000;
/// Most vCPUs that fit in the 1 KiB area with all other entries.
pub const MAX_CPUS: u8 = 32;
const IOAPIC_PINS: u8 = 24;

fn checksum(b: &[u8]) -> u8 {
    0u8.wrapping_sub(b.iter().fold(0u8, |a, x| a.wrapping_add(*x)))
}

/// Build the tables for `cpus` vCPUs (APIC ids 0..cpus, the IOAPIC gets id `cpus`).
pub fn build(cpus: u8) -> Vec<u8> {
    assert!((1..=MAX_CPUS).contains(&cpus), "1..=32 vCPUs");
    let ioapic_id = cpus;
    let mut entries: Vec<u8> = Vec::new();
    let mut count: u16 = 0;
    for id in 0..cpus {
        // processor: type, apic id, apic version, flags (EN | BP for the boot CPU), signature, features
        let flags = 1 | if id == 0 { 2 } else { 0 };
        entries.extend_from_slice(&[0, id, 0x14, flags]);
        entries.extend_from_slice(&0x0600u32.to_le_bytes()); // family 6
        entries.extend_from_slice(&0x0201u32.to_le_bytes()); // FPU | APIC
        entries.extend_from_slice(&[0u8; 8]);
        count += 1;
    }
    // bus 0: ISA
    entries.extend_from_slice(&[1, 0]);
    entries.extend_from_slice(b"ISA   ");
    count += 1;
    // IOAPIC: type, id, version, flags (enabled), address
    entries.extend_from_slice(&[2, ioapic_id, 0x11, 1]);
    entries.extend_from_slice(&IOAPIC_ADDR.to_le_bytes());
    count += 1;
    // I/O interrupts: ISA irq n -> IOAPIC pin n (conforming polarity/trigger)
    for pin in 0..IOAPIC_PINS {
        entries.extend_from_slice(&[3, 0, 0, 0, 0, pin, ioapic_id, pin]);
        count += 1;
    }
    // local interrupts: ExtINT -> LINT0, NMI -> LINT1, on every local APIC (0xff)
    entries.extend_from_slice(&[4, 3, 0, 0, 0, 0, 0xff, 0]);
    entries.extend_from_slice(&[4, 1, 0, 0, 0, 0, 0xff, 1]);
    count += 2;

    // configuration table header (44 bytes)
    let base_len = (44 + entries.len()) as u16;
    let mut table = Vec::with_capacity(base_len as usize);
    table.extend_from_slice(b"PCMP");
    table.extend_from_slice(&base_len.to_le_bytes());
    table.push(4); // spec revision 1.4
    table.push(0); // checksum, filled below
    table.extend_from_slice(b"OSBX    ");
    table.extend_from_slice(b"MICROVM     ");
    table.extend_from_slice(&0u32.to_le_bytes()); // OEM table pointer
    table.extend_from_slice(&0u16.to_le_bytes()); // OEM table size
    table.extend_from_slice(&count.to_le_bytes());
    table.extend_from_slice(&APIC_ADDR.to_le_bytes());
    table.extend_from_slice(&0u16.to_le_bytes()); // extended table length
    table.push(0); // extended checksum
    table.push(0); // reserved
    table.extend_from_slice(&entries);
    table[7] = checksum(&table);

    // floating pointer (16 bytes) right before the table
    let table_addr = (MPTABLE_START + 16) as u32;
    let mut fp = Vec::with_capacity(16);
    fp.extend_from_slice(b"_MP_");
    fp.extend_from_slice(&table_addr.to_le_bytes());
    fp.push(1); // length in 16-byte units
    fp.push(4); // spec revision
    fp.push(0); // checksum
    fp.extend_from_slice(&[0u8; 5]); // features: none (configuration table present)
    fp[10] = checksum(&fp);

    let mut out = fp;
    out.extend_from_slice(&table);
    out
}

/// Write the tables into guest memory.
pub fn write(mem: &GuestMemoryMmap<()>, cpus: u8) -> Result<(), String> {
    let bytes = build(cpus);
    if bytes.len() > 1024 {
        return Err("MP table larger than the EBDA area".into());
    }
    mem.write_slice(&bytes, GuestAddress(MPTABLE_START))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sum(b: &[u8]) -> u8 {
        b.iter().fold(0u8, |a, x| a.wrapping_add(*x))
    }

    #[test]
    fn checksums_and_layout() {
        for cpus in [1u8, 2, 4, 32] {
            let t = build(cpus);
            assert!(t.len() <= 1024, "{cpus} cpus: {} bytes", t.len());
            assert_eq!(&t[..4], b"_MP_");
            assert_eq!(sum(&t[..16]), 0, "floating pointer checksum");
            let table = &t[16..];
            assert_eq!(&table[..4], b"PCMP");
            let len = u16::from_le_bytes([table[4], table[5]]) as usize;
            assert_eq!(len, table.len());
            assert_eq!(sum(table), 0, "configuration table checksum");
            let count = u16::from_le_bytes([table[34], table[35]]);
            assert_eq!(count, u16::from(cpus) + 1 + 1 + 24 + 2);
            // first processor entry is the enabled boot processor
            assert_eq!(&table[44..48], &[0, 0, 0x14, 3]);
        }
    }

    #[test]
    #[should_panic(expected = "1..=32 vCPUs")]
    fn too_many_cpus() {
        build(33);
    }
}
