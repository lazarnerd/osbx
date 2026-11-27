//! ACPI 2.0 table generator + QEMU `fw_cfg` table-loader (`etc/acpi/rsdp`, `etc/acpi/tables`,
//! `etc/table-loader`) for Q35 PCIe UEFI guests (Linux & Windows).
//!
//! Tables generated:
//! - `RSDP` (v2) -> `XSDT`
//! - `FADT` (v5) -> `FACS` + `DSDT` (ICH9 PM base `0x0600`, SCI IRQ 9, reset `0xCF9`)
//! - `MADT` (Local APICs for `0..cpus`, IOAPIC `0xFEC0_0000`, ISOs for IRQ 0->2 and SCI IRQ 9)
//! - `MCFG` (PCIe ECAM at `0xB000_0000`, buses `0..=15`)
//! - `HPET` (`0xFED0_0000`)
//! - `DSDT` (AML: `\_S5`, `\_SB.PCI0` with `_CRS` + `_PRT`, COM1 `PNP0501`, RTC `PNP0B00`, Power
//!   Button `PNP0C0C`)

use crate::hpet::{HPET_BASE, HPET_BLOCK_ID};
use crate::mptable::{APIC_ADDR, IOAPIC_ADDR};
use crate::pci::{PCI_MMIO32_BASE, PCI_MMIO32_END, PCIE_ECAM_BASE};
use crate::tpm::{TPM_CRB_BASE, TPM_CRB_CTRL_AREA, TPM_CRB_SIZE};

/// ICH9 ACPI PM I/O base advertised in FADT.
pub const ACPI_PM_BASE: u16 = 0x0600;
const ACPI_SCI_IRQ: u16 = 9;

const RSDP_FILE: &str = "etc/acpi/rsdp";
const TABLES_FILE: &str = "etc/acpi/tables";

const CMD_ALLOCATE: u32 = 1;
const CMD_ADD_POINTER: u32 = 2;
const CMD_ADD_CHECKSUM: u32 = 3;
const ZONE_HIGH: u8 = 1;
const ZONE_FSEG: u8 = 2;

/// Built ACPI blobs ready to register in `fw_cfg`.
pub struct AcpiBlobs {
    /// `etc/acpi/rsdp`
    pub rsdp: Vec<u8>,
    /// `etc/acpi/tables`
    pub tables: Vec<u8>,
    /// `etc/table-loader`
    pub loader: Vec<u8>,
}

/// Build ACPI 2.0 tables and the `etc/table-loader` bytecode script for `cpus` vCPUs, optional
/// 64-bit PCI MMIO window `[pci_mmio64_base, pci_mmio64_end)`, and optional CRB vTPM 2.0 table.
pub fn build(cpus: u8, pci_mmio64: Option<(u64, u64)>, with_tpm: bool) -> AcpiBlobs {
    let mut tables = Vec::new();
    let mut loader = Vec::new();

    push_allocate(&mut loader, TABLES_FILE, 64, ZONE_HIGH);
    push_allocate(&mut loader, RSDP_FILE, 16, ZONE_FSEG);

    // 1. FACS (64 bytes, 64-byte aligned)
    align_vec(&mut tables, 64);
    let facs_off = tables.len();
    let mut facs = [0u8; 64];
    facs[0..4].copy_from_slice(b"FACS");
    facs[4..8].copy_from_slice(&64u32.to_le_bytes());
    tables.extend_from_slice(&facs);

    // 2. DSDT
    align_vec(&mut tables, 8);
    let dsdt_off = tables.len();
    let dsdt = build_dsdt(pci_mmio64, with_tpm);
    tables.extend_from_slice(&dsdt);
    push_checksum(&mut loader, TABLES_FILE, dsdt_off + 9, dsdt_off, dsdt.len());

    // 3. FADT (rev 5, 268 bytes)
    align_vec(&mut tables, 8);
    let fadt_off = tables.len();
    let fadt = build_fadt(facs_off as u32, dsdt_off as u32);
    tables.extend_from_slice(&fadt);
    // Patch FACS and DSDT pointers (both 32-bit and 64-bit X_* fields).
    push_pointer(&mut loader, TABLES_FILE, TABLES_FILE, fadt_off + 36, 4);
    push_pointer(&mut loader, TABLES_FILE, TABLES_FILE, fadt_off + 40, 4);
    push_pointer(&mut loader, TABLES_FILE, TABLES_FILE, fadt_off + 132, 8);
    push_pointer(&mut loader, TABLES_FILE, TABLES_FILE, fadt_off + 140, 8);
    push_checksum(&mut loader, TABLES_FILE, fadt_off + 9, fadt_off, fadt.len());

    // 4. MADT
    align_vec(&mut tables, 8);
    let madt_off = tables.len();
    let madt = build_madt(cpus);
    tables.extend_from_slice(&madt);
    push_checksum(&mut loader, TABLES_FILE, madt_off + 9, madt_off, madt.len());

    // 5. MCFG
    align_vec(&mut tables, 8);
    let mcfg_off = tables.len();
    let mcfg = build_mcfg();
    tables.extend_from_slice(&mcfg);
    push_checksum(&mut loader, TABLES_FILE, mcfg_off + 9, mcfg_off, mcfg.len());

    // 6. HPET
    align_vec(&mut tables, 8);
    let hpet_off = tables.len();
    let hpet = build_hpet();
    tables.extend_from_slice(&hpet);
    push_checksum(&mut loader, TABLES_FILE, hpet_off + 9, hpet_off, hpet.len());

    // 6b. Optional TPM2 (CRB Start Method 7)
    let mut entries = vec![
        fadt_off as u64,
        madt_off as u64,
        mcfg_off as u64,
        hpet_off as u64,
    ];
    if with_tpm {
        align_vec(&mut tables, 8);
        let tpm2_off = tables.len();
        let tpm2 = build_tpm2();
        tables.extend_from_slice(&tpm2);
        push_checksum(&mut loader, TABLES_FILE, tpm2_off + 9, tpm2_off, tpm2.len());
        entries.push(tpm2_off as u64);
    }

    // 7. XSDT pointing to FADT, MADT, MCFG, HPET (and optional TPM2)
    align_vec(&mut tables, 8);
    let xsdt_off = tables.len();
    let xsdt_len = 36 + entries.len() * 8;
    let mut xsdt = make_header(*b"XSDT", xsdt_len as u32, 1);
    for (i, &off) in entries.iter().enumerate() {
        xsdt.extend_from_slice(&off.to_le_bytes());
        push_pointer(
            &mut loader,
            TABLES_FILE,
            TABLES_FILE,
            xsdt_off + 36 + i * 8,
            8,
        );
    }
    tables.extend_from_slice(&xsdt);
    push_checksum(&mut loader, TABLES_FILE, xsdt_off + 9, xsdt_off, xsdt.len());

    // 8. RSDP v2 pointing to XSDT
    let mut rsdp = [0u8; 36];
    rsdp[0..8].copy_from_slice(b"RSD PTR ");
    rsdp[9..15].copy_from_slice(b"OSBX  ");
    rsdp[15] = 2; // ACPI 2.0+
    rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
    rsdp[24..32].copy_from_slice(&(xsdt_off as u64).to_le_bytes());
    push_pointer(&mut loader, RSDP_FILE, TABLES_FILE, 24, 8);
    push_checksum(&mut loader, RSDP_FILE, 8, 0, 20);
    push_checksum(&mut loader, RSDP_FILE, 32, 0, 36);

    AcpiBlobs {
        rsdp: rsdp.to_vec(),
        tables,
        loader,
    }
}

fn align_vec(v: &mut Vec<u8>, align: usize) {
    while !v.len().is_multiple_of(align) {
        v.push(0);
    }
}

fn make_header(sig: [u8; 4], length: u32, revision: u8) -> Vec<u8> {
    let mut h = vec![0u8; 36];
    h[0..4].copy_from_slice(&sig);
    h[4..8].copy_from_slice(&length.to_le_bytes());
    h[8] = revision;
    h[10..16].copy_from_slice(b"OSBX  ");
    h[16..24].copy_from_slice(b"OSBXQ35 ");
    h[24..28].copy_from_slice(&1u32.to_le_bytes());
    h[28..32].copy_from_slice(b"OSBX");
    h[32..36].copy_from_slice(&1u32.to_le_bytes());
    h
}

fn write_gas_io(buf: &mut [u8], bit_width: u8, addr: u64) {
    buf[0] = 1; // System I/O
    buf[1] = bit_width;
    buf[2] = 0; // bit offset
    buf[3] = match bit_width {
        8 => 1,
        16 => 2,
        32 => 3,
        _ => 0,
    };
    buf[4..12].copy_from_slice(&addr.to_le_bytes());
}

fn build_fadt(facs_off: u32, dsdt_off: u32) -> Vec<u8> {
    let mut f = make_header(*b"FACP", 268, 5);
    f.resize(268, 0);
    f[36..40].copy_from_slice(&facs_off.to_le_bytes());
    f[40..44].copy_from_slice(&dsdt_off.to_le_bytes());
    f[45] = 1; // Preferred PM profile: Desktop
    f[46..48].copy_from_slice(&ACPI_SCI_IRQ.to_le_bytes());
    let pm = u32::from(ACPI_PM_BASE);
    f[56..60].copy_from_slice(&pm.to_le_bytes()); // PM1a_EVT_BLK
    f[64..68].copy_from_slice(&(pm + 4).to_le_bytes()); // PM1a_CNT_BLK
    f[76..80].copy_from_slice(&(pm + 8).to_le_bytes()); // PM_TMR_BLK
    f[88] = 4; // PM1_EVT_LEN
    f[89] = 2; // PM1_CNT_LEN
    f[91] = 4; // PM_TMR_LEN
    f[108] = 0x32; // CENTURY register in CMOS
    // IAPC_BOOT_ARCH: LEGACY_DEVICES (bit 0) | 8042=0 | VGA=1 (bit 2=0 means VGA present)
    f[109..111].copy_from_slice(&0x0001u16.to_le_bytes());
    // Flags: WBINVD(0) | PROC_C1(2) | PWR_BUTTON(4=0 -> fixed? set 4=1 control method button)
    // | SLP_BUTTON(5) | FIX_RTC(6=0) | RTC_S4(7) | RESET_REG_SUP(10) | USE_PLATFORM_CLOCK(15)
    let flags: u32 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 5) | (1 << 7) | (1 << 10) | (1 << 15);
    f[112..116].copy_from_slice(&flags.to_le_bytes());
    write_gas_io(&mut f[116..128], 8, 0x0cf9); // RESET_REG
    f[128] = 0x06; // RESET_VALUE (system reset)
    f[131] = 0; // FADT minor version
    f[132..140].copy_from_slice(&u64::from(facs_off).to_le_bytes()); // X_FIRMWARE_CTRL
    f[140..148].copy_from_slice(&u64::from(dsdt_off).to_le_bytes()); // X_DSDT
    write_gas_io(&mut f[148..160], 32, u64::from(ACPI_PM_BASE)); // X_PM1a_EVT_BLK
    write_gas_io(&mut f[172..184], 16, u64::from(ACPI_PM_BASE + 4)); // X_PM1a_CNT_BLK
    write_gas_io(&mut f[208..220], 32, u64::from(ACPI_PM_BASE + 8)); // X_PM_TMR_BLK
    f
}

fn build_madt(cpus: u8) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&APIC_ADDR.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes()); // PCAT_COMPAT (8259 present)

    // Processor Local APIC entries (type 0, len 8)
    for id in 0..cpus {
        body.extend_from_slice(&[0, 8, id, id, 1, 0, 0, 0]);
    }
    // IOAPIC (type 1, len 12)
    body.push(1);
    body.push(12);
    body.push(0); // IOAPIC ID
    body.push(0);
    body.extend_from_slice(&IOAPIC_ADDR.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // GSI base 0

    // Interrupt Source Override: ISA IRQ 0 -> GSI 2 (bus 0, src 0, gsi 2, flags 0)
    body.extend_from_slice(&[2, 10, 0, 0, 2, 0, 0, 0, 0, 0]);
    // Interrupt Source Override: SCI IRQ 9 -> GSI 9 (active high, level triggered: 0x000d)
    body.extend_from_slice(&[2, 10, 0, 9, 9, 0, 0, 0, 0x0d, 0x00]);

    let mut hdr = make_header(*b"APIC", (36 + body.len()) as u32, 3);
    hdr.extend_from_slice(&body);
    hdr
}

fn build_mcfg() -> Vec<u8> {
    let mut body = vec![0u8; 8]; // reserved
    body.extend_from_slice(&PCIE_ECAM_BASE.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // PCI segment group 0
    body.push(0); // start bus
    body.push(15); // end bus
    body.extend_from_slice(&0u32.to_le_bytes()); // reserved

    let mut hdr = make_header(*b"MCFG", (36 + body.len()) as u32, 1);
    hdr.extend_from_slice(&body);
    hdr
}

fn build_hpet() -> Vec<u8> {
    let mut body = Vec::with_capacity(20);
    body.extend_from_slice(&HPET_BLOCK_ID.to_le_bytes());
    let mut gas = [0u8; 12];
    gas[0] = 0; // System Memory
    gas[1] = 64;
    gas[4..12].copy_from_slice(&HPET_BASE.to_le_bytes());
    body.extend_from_slice(&gas);
    body.push(0); // HPET number
    body.extend_from_slice(&128u16.to_le_bytes()); // min clock tick
    body.push(0); // page protection

    let mut hdr = make_header(*b"HPET", (36 + body.len()) as u32, 1);
    hdr.extend_from_slice(&body);
    hdr
}

fn build_tpm2() -> Vec<u8> {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&0u16.to_le_bytes()); // PlatformClass = Client (0)
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    body.extend_from_slice(&TPM_CRB_CTRL_AREA.to_le_bytes()); // ControlAreaAddress = 0xFED4_0040
    body.extend_from_slice(&7u32.to_le_bytes()); // StartMethod = 7 (CRB)

    let mut hdr = make_header(*b"TPM2", (36 + body.len()) as u32, 4);
    hdr.extend_from_slice(&body);
    hdr
}

fn aml_string(s: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(2 + s.len());
    b.push(0x0d); // StringPrefix
    b.extend_from_slice(s.as_bytes());
    b.push(0);
    b
}

// --- Minimal AML builder for DSDT ---

fn aml_pkg_len(body_len: usize) -> Vec<u8> {
    // Package length includes the length bytes themselves.
    let len1 = body_len + 1;
    if len1 < 64 {
        return vec![len1 as u8];
    }
    let len2 = body_len + 2;
    if len2 < (1 << 12) {
        return vec![0x40 | (len2 & 0x0f) as u8, (len2 >> 4) as u8];
    }
    let len3 = body_len + 3;
    vec![
        0x80 | (len3 & 0x0f) as u8,
        ((len3 >> 4) & 0xff) as u8,
        ((len3 >> 12) & 0xff) as u8,
    ]
}

fn aml_int(v: u64) -> Vec<u8> {
    match v {
        0 => vec![0x00],
        1 => vec![0x01],
        2..=0xff => vec![0x0a, v as u8],
        0x100..=0xffff => {
            let mut b = vec![0x0b];
            b.extend_from_slice(&(v as u16).to_le_bytes());
            b
        }
        0x1_0000..=0xffff_ffff => {
            let mut b = vec![0x0c];
            b.extend_from_slice(&(v as u32).to_le_bytes());
            b
        }
        _ => {
            let mut b = vec![0x0e];
            b.extend_from_slice(&v.to_le_bytes());
            b
        }
    }
}

fn aml_name(name: &[u8; 4], val: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(5 + val.len());
    b.push(0x08); // NameOp
    b.extend_from_slice(name);
    b.extend_from_slice(val);
    b
}

fn aml_package(items: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![items.len() as u8];
    for it in items {
        body.extend_from_slice(it);
    }
    let mut b = vec![0x12]; // PackageOp
    b.extend_from_slice(&aml_pkg_len(body.len()));
    b.extend_from_slice(&body);
    b
}

fn aml_buffer(bytes: &[u8]) -> Vec<u8> {
    let mut body = aml_int(bytes.len() as u64);
    body.extend_from_slice(bytes);
    let mut b = vec![0x11]; // BufferOp
    b.extend_from_slice(&aml_pkg_len(body.len()));
    b.extend_from_slice(&body);
    b
}

fn aml_device(name: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(4 + body.len());
    inner.extend_from_slice(name);
    inner.extend_from_slice(body);
    let mut b = vec![0x5b, 0x82]; // ExtOp DeviceOp
    b.extend_from_slice(&aml_pkg_len(inner.len()));
    b.extend_from_slice(&inner);
    b
}

fn aml_scope(name: &[u8], body: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(name.len() + body.len());
    inner.extend_from_slice(name);
    inner.extend_from_slice(body);
    let mut b = vec![0x10]; // ScopeOp
    b.extend_from_slice(&aml_pkg_len(inner.len()));
    b.extend_from_slice(&inner);
    b
}

/// Encode an EISA PNP ID string (e.g. `"PNP0A08"`) as a 32-bit ACPI compressed ID.
fn eisa_id(s: &str) -> u32 {
    let b = s.as_bytes();
    let c0 = u32::from(b[0] - 0x40);
    let c1 = u32::from(b[1] - 0x40);
    let c2 = u32::from(b[2] - 0x40);
    let hex = u32::from_str_radix(&s[3..7], 16).unwrap();
    let v = (c0 << 26) | (c1 << 21) | (c2 << 16) | hex;
    v.swap_bytes()
}

/// Build the DSDT AML payload.
fn build_dsdt(pci_mmio64: Option<(u64, u64)>, with_tpm: bool) -> Vec<u8> {
    let mut aml = Vec::new();

    // Name(\_S5, Package(4) { 0, 0, 0, 0 })
    aml.extend_from_slice(&aml_name(
        b"_S5_",
        &aml_package(&[aml_int(0), aml_int(0), aml_int(0), aml_int(0)]),
    ));

    // Scope(\_SB) { PCI0, COM1, RTC0, PWRB }
    let mut sb = Vec::new();

    // PCI0: PCIe Root Bridge
    let mut pci0 = Vec::new();
    pci0.extend_from_slice(&aml_name(b"_HID", &aml_int(u64::from(eisa_id("PNP0A08")))));
    pci0.extend_from_slice(&aml_name(b"_CID", &aml_int(u64::from(eisa_id("PNP0A03")))));
    pci0.extend_from_slice(&aml_name(b"_SEG", &aml_int(0)));
    pci0.extend_from_slice(&aml_name(b"_BBN", &aml_int(0)));
    pci0.extend_from_slice(&aml_name(b"_ADR", &aml_int(0)));

    // _CRS resource descriptors for PCI0
    let mut crs = Vec::new();
    // WordBusNumber (bus 0..=15)
    crs.extend_from_slice(&[
        0x88, 0x0d, 0x00, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x10,
        0x00,
    ]);
    // WordIO (0x0000..=0x0CF7)
    crs.extend_from_slice(&[
        0x88, 0x0d, 0x00, 0x01, 0x0c, 0x03, 0x00, 0x00, 0x00, 0x00, 0xf7, 0x0c, 0x00, 0x00, 0xf8,
        0x0c,
    ]);
    // WordIO (0x0D00..=0xFFFF)
    crs.extend_from_slice(&[
        0x88, 0x0d, 0x00, 0x01, 0x0c, 0x03, 0x00, 0x00, 0x00, 0x0d, 0xff, 0xff, 0x00, 0x00, 0x00,
        0xf3,
    ]);
    // DWordMemory (32-bit PCI MMIO: PCI_MMIO32_BASE..PCI_MMIO32_END)
    let m32_min = PCI_MMIO32_BASE as u32;
    let m32_max = (PCI_MMIO32_END - 1) as u32;
    let m32_len = (PCI_MMIO32_END - PCI_MMIO32_BASE) as u32;
    crs.extend_from_slice(&[0x87, 0x17, 0x00, 0x00, 0x0c, 0x01]);
    crs.extend_from_slice(&0u32.to_le_bytes()); // gran
    crs.extend_from_slice(&m32_min.to_le_bytes());
    crs.extend_from_slice(&m32_max.to_le_bytes());
    crs.extend_from_slice(&0u32.to_le_bytes()); // trans
    crs.extend_from_slice(&m32_len.to_le_bytes());
    // Optional QWordMemory (64-bit PCI MMIO)
    if let Some((m64_base, m64_end)) = pci_mmio64
        && m64_end > m64_base
    {
        let m64_max = m64_end - 1;
        let m64_len = m64_end - m64_base;
        crs.extend_from_slice(&[0x8a, 0x2b, 0x00, 0x00, 0x0c, 0x01]);
        crs.extend_from_slice(&0u64.to_le_bytes());
        crs.extend_from_slice(&m64_base.to_le_bytes());
        crs.extend_from_slice(&m64_max.to_le_bytes());
        crs.extend_from_slice(&0u64.to_le_bytes());
        crs.extend_from_slice(&m64_len.to_le_bytes());
    }
    // EndTag
    crs.extend_from_slice(&[0x79, 0x00]);
    pci0.extend_from_slice(&aml_name(b"_CRS", &aml_buffer(&crs)));

    // _PRT: static GSI routing for PCI devices 1..=15 and 31 (ICH9 AHCI at 00:1f.2)
    let mut prt_entries = Vec::new();
    for dev in (1u64..=15).chain(std::iter::once(31u64)) {
        let gsi = 16 + ((dev - 1) % 4);
        prt_entries.push(aml_package(&[
            aml_int((dev << 16) | 0xffff),
            aml_int(0), // INTA#
            aml_int(0), // hardwired GSI
            aml_int(gsi),
        ]));
    }
    pci0.extend_from_slice(&aml_name(b"_PRT", &aml_package(&prt_entries)));

    // COM1 serial port inside PCI0 (PNP0501, 0x3F8..0x3FF, IRQ 4)
    let mut com1 = Vec::new();
    com1.extend_from_slice(&aml_name(b"_HID", &aml_int(u64::from(eisa_id("PNP0501")))));
    com1.extend_from_slice(&aml_name(b"_UID", &aml_int(1)));
    com1.extend_from_slice(&aml_name(b"_STA", &aml_int(0x0f)));
    let com1_crs = [
        0x47, 0x01, 0xf8, 0x03, 0xf8, 0x03, 0x01, 0x08, // IO 0x3f8 len 8
        0x22, 0x10, 0x00, // IRQ 4
        0x79, 0x00, // EndTag
    ];
    com1.extend_from_slice(&aml_name(b"_CRS", &aml_buffer(&com1_crs)));
    pci0.extend_from_slice(&aml_device(b"COM1", &com1));

    // CMOS RTC inside PCI0 (PNP0B00, 0x70..0x71, IRQ 8)
    let mut rtc = Vec::new();
    rtc.extend_from_slice(&aml_name(b"_HID", &aml_int(u64::from(eisa_id("PNP0B00")))));
    let rtc_crs = [
        0x47, 0x01, 0x70, 0x00, 0x70, 0x00, 0x01, 0x02, // IO 0x70 len 2
        0x22, 0x00, 0x01, // IRQ 8
        0x79, 0x00,
    ];
    rtc.extend_from_slice(&aml_name(b"_CRS", &aml_buffer(&rtc_crs)));
    pci0.extend_from_slice(&aml_device(b"RTC0", &rtc));

    sb.extend_from_slice(&aml_device(b"PCI0", &pci0));

    // Power Button (PNP0C0C)
    let pwrb = aml_name(b"_HID", &aml_int(u64::from(eisa_id("PNP0C0C"))));
    sb.extend_from_slice(&aml_device(b"PWRB", &pwrb));

    // Optional TPM 2.0 CRB Device (MSFT0101 at 0xFED4_0000 len 0x5000)
    if with_tpm {
        let mut tpm = Vec::new();
        tpm.extend_from_slice(&aml_name(b"_HID", &aml_string("MSFT0101")));
        tpm.extend_from_slice(&aml_name(b"_UID", &aml_int(1)));
        tpm.extend_from_slice(&aml_name(b"_STA", &aml_int(0x0f)));
        let mut tpm_crs = vec![0x86, 0x09, 0x00, 0x01]; // Memory32Fixed, ReadWrite
        tpm_crs.extend_from_slice(&(TPM_CRB_BASE as u32).to_le_bytes());
        tpm_crs.extend_from_slice(&(TPM_CRB_SIZE as u32).to_le_bytes());
        tpm_crs.extend_from_slice(&[0x79, 0x00]); // EndTag
        tpm.extend_from_slice(&aml_name(b"_CRS", &aml_buffer(&tpm_crs)));
        sb.extend_from_slice(&aml_device(b"TPM0", &tpm));
    }

    aml.extend_from_slice(&aml_scope(b"\\_SB_", &sb));

    let mut hdr = make_header(*b"DSDT", (36 + aml.len()) as u32, 2);
    hdr.extend_from_slice(&aml);
    hdr
}

fn push_allocate(loader: &mut Vec<u8>, file: &str, align: u32, zone: u8) {
    let mut cmd = [0u8; 128];
    cmd[0..4].copy_from_slice(&CMD_ALLOCATE.to_le_bytes());
    write_cstr(&mut cmd[4..60], file);
    cmd[60..64].copy_from_slice(&align.to_le_bytes());
    cmd[64] = zone;
    loader.extend_from_slice(&cmd);
}

fn push_pointer(loader: &mut Vec<u8>, dest: &str, src: &str, offset: usize, size: u8) {
    let mut cmd = [0u8; 128];
    cmd[0..4].copy_from_slice(&CMD_ADD_POINTER.to_le_bytes());
    write_cstr(&mut cmd[4..60], dest);
    write_cstr(&mut cmd[60..116], src);
    cmd[116..120].copy_from_slice(&(offset as u32).to_le_bytes());
    cmd[120] = size;
    loader.extend_from_slice(&cmd);
}

fn push_checksum(loader: &mut Vec<u8>, file: &str, result_off: usize, start: usize, len: usize) {
    let mut cmd = [0u8; 128];
    cmd[0..4].copy_from_slice(&CMD_ADD_CHECKSUM.to_le_bytes());
    write_cstr(&mut cmd[4..60], file);
    cmd[60..64].copy_from_slice(&(result_off as u32).to_le_bytes());
    cmd[64..68].copy_from_slice(&(start as u32).to_le_bytes());
    cmd[68..72].copy_from_slice(&(len as u32).to_le_bytes());
    loader.extend_from_slice(&cmd);
}

fn write_cstr(dst: &mut [u8], s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&b[..n]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acpi_blobs_build_and_align() {
        let blobs = build(4, Some((0x2_0000_0000, 0x3_0000_0000)), false);
        assert_eq!(blobs.rsdp.len(), 36);
        assert_eq!(&blobs.rsdp[0..8], b"RSD PTR ");
        assert!(blobs.loader.len().is_multiple_of(128));
        assert!(blobs.tables.len() > 400);

        let blobs_tpm = build(4, None, true);
        assert!(blobs_tpm.tables.windows(4).any(|w| w == b"TPM2"));
        assert!(blobs_tpm.tables.windows(8).any(|w| w == b"MSFT0101"));
    }
}
