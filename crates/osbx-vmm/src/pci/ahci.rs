//! Minimal ICH9 AHCI 1.3 SATA/ATAPI controller (`8086:2922`, PCI `00:1f.2`) for ISO CD-ROMs.
//!
//! Exposes read-only ISO9660 images as ATAPI CD-ROM drives so both OVMF (`SataControllerDxe` +
//! `AtaAtapiPassThruDxe`) and Windows WinPE (`storahci.sys` + `cdrom.sys`) discover the Windows
//! install ISO, `virtio-win.iso`, and `autounattend.xml` seed ISO using inbox drivers before
//! `viostor.sys` / `viosock.sys` are installed.

use crate::irq::Irq;
use crate::pci::{BarSet, BarSpec, MsiRouter, PciDevice};
use crate::virtio::GuestMem;
use crate::virtio::scsi::{CdromTarget, SCSI_STATUS_GOOD};
use std::io;
use std::path::Path;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress};

/// Size of AHCI BAR5 (`ABAR`) MMIO window (4 KiB, covers HBA + up to 6 ports).
pub const AHCI_BAR5_SIZE: u64 = 0x1000;
const MAX_PORTS: usize = 6;
const ATAPI_SIG: u32 = 0xeb14_0101;
const SSTS_ACTIVE: u32 = 0x0000_0133; // DET=3 (present+phy), SPD=3 (Gen3), IPM=1 (active)
const STATUS_READY: u8 = 0x50; // DRDY | DSC
const STATUS_ERR: u8 = 0x51; // DRDY | DSC | ERR
const MSI_CAP_OFF: usize = 0x80;

struct AhciPort {
    target: CdromTarget,
    clb: u64,
    fb: u64,
    is: u32,
    ie: u32,
    cmd: u32,
    tfd: u32,
    sig: u32,
    ssts: u32,
    sctl: u32,
    serr: u32,
    ci: u32,
    last_sense: Option<[u8; 18]>,
}

impl AhciPort {
    fn new(target: CdromTarget) -> Self {
        Self {
            target,
            clb: 0,
            fb: 0,
            is: 0,
            ie: 0,
            cmd: 0x0100_0006, // ATAPI | POD | SUD
            tfd: u32::from(STATUS_READY),
            sig: ATAPI_SIG,
            ssts: SSTS_ACTIVE,
            sctl: 0,
            serr: 0,
            ci: 0,
            last_sense: None,
        }
    }

    fn reset(&mut self) {
        self.is = 0;
        self.ie = 0;
        self.cmd = 0x0100_0006;
        self.tfd = u32::from(STATUS_READY);
        self.sig = ATAPI_SIG;
        self.ssts = SSTS_ACTIVE;
        self.sctl = 0;
        self.serr = 0;
        self.ci = 0;
        self.last_sense = None;
    }

    fn write_d2h_fis(
        &self,
        mem: &GuestMem,
        status: u8,
        err: u8,
        lba: [u8; 3],
        sector_cnt: u8,
        irq: bool,
    ) {
        if self.cmd & 0x10 == 0 || self.fb == 0 {
            return;
        }
        let mut fis = [0u8; 20];
        fis[0] = 0x34; // Register D2H FIS
        fis[1] = if irq { 0x40 } else { 0x00 };
        fis[2] = status;
        fis[3] = err;
        fis[4] = lba[0];
        fis[5] = lba[1];
        fis[6] = lba[2];
        fis[7] = 0xa0;
        fis[12] = sector_cnt;
        let _ = mem.write_slice(&fis, GuestAddress(self.fb + 0x40));
    }

    fn write_pio_fis(&self, mem: &GuestMem, status: u8, e_status: u8, transfer_count: u16) {
        if self.cmd & 0x10 == 0 || self.fb == 0 {
            return;
        }
        let mut fis = [0u8; 20];
        fis[0] = 0x5f; // PIO Setup FIS
        fis[1] = 0x60; // D=1 (device->host) | I=1 (interrupt)
        fis[2] = status;
        fis[3] = 0;
        fis[15] = e_status;
        fis[16..18].copy_from_slice(&transfer_count.to_le_bytes());
        let _ = mem.write_slice(&fis, GuestAddress(self.fb + 0x20));
    }
}

/// ICH9 AHCI 1.3 PCI controller (`8086:2922`) exposing read-only ATAPI CD-ROM ports.
pub struct AhciController {
    cfg: [u8; 256],
    bars: BarSet,
    mem: GuestMem,
    intx: Irq,
    msi_router: Arc<dyn MsiRouter>,
    msi_handle: Option<u32>,
    ghc: u32,
    ports: Vec<AhciPort>,
}

impl AhciController {
    /// Open one or more ISO files as AHCI ATAPI CD-ROM ports `0..paths.len()`.
    pub fn open(
        paths: &[impl AsRef<Path>],
        mem: GuestMem,
        bar5: u64,
        irq_line: u8,
        intx: Irq,
        msi_router: Arc<dyn MsiRouter>,
    ) -> io::Result<Self> {
        if paths.len() > MAX_PORTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("AHCI supports at most {MAX_PORTS} CD-ROM ports"),
            ));
        }
        let mut ports = Vec::with_capacity(paths.len());
        for p in paths {
            ports.push(AhciPort::new(CdromTarget::open(p.as_ref())?));
        }

        let mut cfg = [0u8; 256];
        cfg[0x00..0x02].copy_from_slice(&0x8086u16.to_le_bytes()); // Intel
        cfg[0x02..0x04].copy_from_slice(&0x2922u16.to_le_bytes()); // ICH9 AHCI
        cfg[0x06..0x08].copy_from_slice(&0x0010u16.to_le_bytes()); // Capabilities list
        cfg[0x08..0x0c].copy_from_slice(&0x0106_0102u32.to_le_bytes()); // Mass storage, SATA, AHCI 1.0, rev 2
        cfg[0x2c..0x2e].copy_from_slice(&0x1af4u16.to_le_bytes());
        cfg[0x2e..0x30].copy_from_slice(&0x1100u16.to_le_bytes());
        cfg[0x34] = MSI_CAP_OFF as u8;
        cfg[0x3c] = irq_line;
        cfg[0x3d] = 1; // INTA#
        // PCI MSI capability (64-bit address capable, 1 vector) at 0x80:
        cfg[MSI_CAP_OFF] = 0x05; // MSI Cap ID
        cfg[MSI_CAP_OFF + 1] = 0x00; // Next = none
        cfg[MSI_CAP_OFF + 2..MSI_CAP_OFF + 4].copy_from_slice(&0x0080u16.to_le_bytes()); // 64-bit capable

        let bars = BarSet::new(
            vec![BarSpec {
                index: 5,
                size: AHCI_BAR5_SIZE,
                is_64bit: false,
                prefetchable: false,
                direct_mapped: false,
            }],
            &[(5, bar5)],
        );

        let msi_handle = msi_router.allocate().ok();
        Ok(Self {
            cfg,
            bars,
            mem,
            intx,
            msi_router,
            msi_handle,
            ghc: 1 << 31, // AE=1
            ports,
        })
    }

    fn hba_cap(&self) -> u32 {
        let np = (self.ports.len().max(1) - 1) as u32;
        np | (31 << 8) // NCS = 32 slots
            | (1 << 18) // SAM = AHCI only
            | (3 << 20) // ISS = Gen3 6 Gbps
            | (1 << 24) // SCLO = Command List Override
            | (1 << 31) // S64A = 64-bit addressing
    }

    fn hba_is(&self) -> u32 {
        let mut bits = 0u32;
        for (i, p) in self.ports.iter().enumerate() {
            if (p.is & p.ie) != 0 {
                bits |= 1u32 << i;
            }
        }
        bits
    }

    fn raise_irq_if_needed(&self) {
        if (self.ghc & 0x02) == 0 || self.hba_is() == 0 {
            return;
        }
        let msi_ctl = u16::from_le_bytes([self.cfg[MSI_CAP_OFF + 2], self.cfg[MSI_CAP_OFF + 3]]);
        if msi_ctl & 0x01 != 0
            && let Some(h) = self.msi_handle
        {
            self.msi_router.trigger(h);
        } else {
            self.intx.pulse();
        }
    }

    fn sync_msi(&self) {
        let msi_ctl = u16::from_le_bytes([self.cfg[MSI_CAP_OFF + 2], self.cfg[MSI_CAP_OFF + 3]]);
        if msi_ctl & 0x01 == 0 {
            return;
        }
        let Some(h) = self.msi_handle else {
            return;
        };
        let addr_lo = u32::from_le_bytes(
            self.cfg[MSI_CAP_OFF + 4..MSI_CAP_OFF + 8]
                .try_into()
                .unwrap(),
        );
        let addr_hi = u32::from_le_bytes(
            self.cfg[MSI_CAP_OFF + 8..MSI_CAP_OFF + 12]
                .try_into()
                .unwrap(),
        );
        let data = u32::from(u16::from_le_bytes([
            self.cfg[MSI_CAP_OFF + 12],
            self.cfg[MSI_CAP_OFF + 13],
        ]));
        let addr = (u64::from(addr_hi) << 32) | u64::from(addr_lo);
        let _ = self.msi_router.configure(h, addr, data);
    }

    fn process_port(&mut self, idx: usize) {
        let mem = self.mem.clone();
        let Some(port) = self.ports.get_mut(idx) else {
            return;
        };
        if port.cmd & 0x01 == 0 || port.clb == 0 {
            return;
        }
        let mut raised = false;
        for slot in 0..32u32 {
            if port.ci & (1u32 << slot) == 0 {
                continue;
            }
            port.ci &= !(1u32 << slot);
            let hdr_addr = port.clb + u64::from(slot) * 32;
            let mut hdr = [0u8; 32];
            if mem.read_slice(&mut hdr, GuestAddress(hdr_addr)).is_err() {
                continue;
            }
            let dw0 = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
            let prdtl = (dw0 >> 16) as usize;
            let ctba_lo = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) & !0x7f;
            let ctba_hi = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
            let ctba = (u64::from(ctba_hi) << 32) | u64::from(ctba_lo);

            let mut cfis = [0u8; 64];
            if mem.read_slice(&mut cfis, GuestAddress(ctba)).is_err() {
                continue;
            }
            if cfis[0] != 0x27 {
                continue;
            }
            // Control FIS (C=0): handle Soft Reset (SRST = bit 2 of cfis[15])
            if cfis[1] & 0x80 == 0 {
                if cfis[15] & 0x04 != 0 {
                    port.tfd = 0x80; // BSY
                } else {
                    port.sig = ATAPI_SIG;
                    port.tfd = u32::from(STATUS_READY);
                    port.last_sense = None;
                    port.write_d2h_fis(&mem, STATUS_READY, 0x01, [0x01, 0x14, 0xeb], 0x01, false);
                }
                continue;
            }

            let prdt_cap = prdt_total_bytes(&mem, ctba, prdtl);
            let ata_cmd = cfis[2];
            match ata_cmd {
                0xec => {
                    // IDENTIFY DEVICE: abort with ATAPI signature per ATA/ATAPI spec.
                    port.sig = ATAPI_SIG;
                    port.tfd = u32::from(STATUS_ERR) | (0x04 << 8);
                    port.write_d2h_fis(&mem, STATUS_ERR, 0x04, [0x01, 0x14, 0xeb], 0x01, true);
                    port.is |= 0x01; // DHRS
                    raised = true;
                }
                0xa1 => {
                    // IDENTIFY PACKET DEVICE (512 bytes)
                    let id = build_atapi_identify(idx);
                    let written = write_prdt(&mem, ctba, prdtl, &id);
                    let _ = mem.write_slice(&written.to_le_bytes(), GuestAddress(hdr_addr + 4));
                    port.tfd = u32::from(STATUS_READY);
                    port.write_pio_fis(&mem, 0x58, STATUS_READY, written as u16);
                    port.write_d2h_fis(&mem, STATUS_READY, 0, [0x01, 0x14, 0xeb], 0x01, true);
                    port.is |= 0x03; // DHRS | PSS
                    raised = true;
                }
                0xa0 => {
                    // PACKET: read 16-byte SCSI CDB at ctba + 0x40
                    let mut cdb = [0u8; 16];
                    if mem.read_slice(&mut cdb, GuestAddress(ctba + 0x40)).is_err() {
                        continue;
                    }
                    let saved = if cdb[0] == 0x03 {
                        port.last_sense.take()
                    } else {
                        None
                    };
                    let res = port.target.execute_cdb(idx, &cdb, prdt_cap, saved);
                    if res.status == SCSI_STATUS_GOOD {
                        let written = if !res.data_out.is_empty() {
                            write_prdt(&mem, ctba, prdtl, &res.data_out)
                        } else {
                            0
                        };
                        let _ = mem.write_slice(&written.to_le_bytes(), GuestAddress(hdr_addr + 4));
                        port.tfd = u32::from(STATUS_READY);
                        port.write_d2h_fis(&mem, STATUS_READY, 0, [0, 0, 0], 0x03, true);
                        port.is |= 0x01; // DHRS
                    } else {
                        port.last_sense = res.sense;
                        let sense_key = res.sense.map_or(0x05, |s| s[2] & 0x0f);
                        let err = sense_key << 4;
                        let _ = mem.write_slice(&0u32.to_le_bytes(), GuestAddress(hdr_addr + 4));
                        port.tfd = u32::from(STATUS_ERR) | (u32::from(err) << 8);
                        port.write_d2h_fis(&mem, STATUS_ERR, err, [0, 0, 0], 0x03, true);
                        port.is |= 0x01 | (1 << 30); // DHRS | TFES
                    }
                    raised = true;
                }
                0x00 | 0x08 | 0xe0 | 0xe1 | 0xe5 | 0xe7 | 0xea | 0xef => {
                    // NOP, DEVICE RESET, STANDBY/IDLE/CHECK POWER, FLUSH CACHE, SET FEATURES
                    let _ = mem.write_slice(&0u32.to_le_bytes(), GuestAddress(hdr_addr + 4));
                    port.tfd = u32::from(STATUS_READY);
                    let sc = if ata_cmd == 0xe5 { 0xff } else { 0x01 };
                    port.write_d2h_fis(&mem, STATUS_READY, 0, [0x01, 0x14, 0xeb], sc, true);
                    port.is |= 0x01;
                    raised = true;
                }
                _ => {
                    // Unsupported ATA command -> ABRT
                    let _ = mem.write_slice(&0u32.to_le_bytes(), GuestAddress(hdr_addr + 4));
                    port.tfd = u32::from(STATUS_ERR) | (0x04 << 8);
                    port.write_d2h_fis(&mem, STATUS_ERR, 0x04, [0, 0, 0], 0, true);
                    port.is |= 0x01 | (1 << 30);
                    raised = true;
                }
            }
        }
        if raised {
            self.raise_irq_if_needed();
        }
    }

    fn read_reg32(&self, off: u64) -> u32 {
        match off {
            0x00 => self.hba_cap(),
            0x04 => self.ghc,
            0x08 => self.hba_is(),
            0x0c => (1u32 << self.ports.len()).saturating_sub(1),
            0x10 => 0x0001_0300, // AHCI 1.3
            0x24 => 0,           // CAP2
            o if o >= 0x100 => {
                let port_idx = ((o - 0x100) / 0x80) as usize;
                let reg = (o - 0x100) % 0x80;
                let Some(p) = self.ports.get(port_idx) else {
                    return 0;
                };
                match reg {
                    0x00 => p.clb as u32,
                    0x04 => (p.clb >> 32) as u32,
                    0x08 => p.fb as u32,
                    0x0c => (p.fb >> 32) as u32,
                    0x10 => p.is,
                    0x14 => p.ie,
                    0x18 => {
                        let mut v = p.cmd & !((1 << 14) | (1 << 15) | (1 << 3));
                        if p.cmd & (1 << 4) != 0 {
                            v |= 1 << 14; // FR mirrors FRE
                        }
                        if p.cmd & (1 << 0) != 0 {
                            v |= 1 << 15; // CR mirrors ST
                        }
                        v
                    }
                    0x20 => p.tfd,
                    0x24 => p.sig,
                    0x28 => p.ssts,
                    0x2c => p.sctl,
                    0x30 => p.serr,
                    0x34 => 0,
                    0x38 => p.ci,
                    _ => 0,
                }
            }
            _ => 0,
        }
    }

    fn write_reg32(&mut self, off: u64, val: u32) {
        match off {
            0x04 => {
                if val & 1 != 0 {
                    // HBA Reset
                    self.ghc = 1 << 31;
                    for p in &mut self.ports {
                        p.reset();
                    }
                } else {
                    self.ghc = (val & 0x02) | (1 << 31);
                    self.raise_irq_if_needed();
                }
            }
            0x08 => {
                // AHCI 1.3 §10.7.2.2 (Single MSI mode): if any port still has an unserviced
                // interrupt pending after software clears PxIS and writes IS, re-assert MSI.
                let _ = val;
                self.raise_irq_if_needed();
            }
            o if o >= 0x100 => {
                let port_idx = ((o - 0x100) / 0x80) as usize;
                let reg = (o - 0x100) % 0x80;
                if port_idx >= self.ports.len() {
                    return;
                }
                match reg {
                    0x00 => {
                        let p = &mut self.ports[port_idx];
                        p.clb = (p.clb & !0xffff_ffff) | u64::from(val & !0x3ff);
                    }
                    0x04 => {
                        let p = &mut self.ports[port_idx];
                        p.clb = (p.clb & 0xffff_ffff) | (u64::from(val) << 32);
                    }
                    0x08 => {
                        let p = &mut self.ports[port_idx];
                        p.fb = (p.fb & !0xffff_ffff) | u64::from(val & !0xff);
                    }
                    0x0c => {
                        let p = &mut self.ports[port_idx];
                        p.fb = (p.fb & 0xffff_ffff) | (u64::from(val) << 32);
                    }
                    0x10 => {
                        self.ports[port_idx].is &= !val;
                    }
                    0x14 => {
                        self.ports[port_idx].ie = val;
                        self.raise_irq_if_needed();
                    }
                    0x18 => {
                        let prev_fre = self.ports[port_idx].cmd & 0x10 != 0;
                        let prev_st = self.ports[port_idx].cmd & 0x01 != 0;
                        let p = &mut self.ports[port_idx];
                        // Keep writable bits (ST, SUD, POD, FRE, ATAPI); CLO clears BSY/DRQ.
                        if val & (1 << 3) != 0 {
                            p.tfd &= !0x88;
                        }
                        p.cmd = (val & 0x0100_0017) | (1 << 24);
                        if prev_st && (p.cmd & 0x01 == 0) {
                            p.ci = 0;
                        }
                        if !prev_fre && (p.cmd & 0x10 != 0) {
                            p.write_d2h_fis(
                                &self.mem,
                                STATUS_READY,
                                0x01,
                                [0x01, 0x14, 0xeb],
                                0x01,
                                false,
                            );
                        }
                        if !prev_st && (p.cmd & 0x01 != 0) && p.ci != 0 {
                            self.process_port(port_idx);
                        }
                    }
                    0x2c => {
                        let prev_det = self.ports[port_idx].sctl & 0x0f;
                        let new_det = val & 0x0f;
                        let p = &mut self.ports[port_idx];
                        p.sctl = val;
                        if new_det == 1 {
                            p.ssts = 0;
                            p.tfd = 0x7f;
                        } else if prev_det == 1 && new_det == 0 {
                            // COMRESET complete: link back up, ATAPI signature ready.
                            p.ssts = SSTS_ACTIVE;
                            p.sig = ATAPI_SIG;
                            p.tfd = u32::from(STATUS_READY);
                            p.serr |= (1 << 16) | (1 << 26); // DIAG_N | DIAG_X
                            p.last_sense = None;
                            p.write_d2h_fis(
                                &self.mem,
                                STATUS_READY,
                                0x01,
                                [0x01, 0x14, 0xeb],
                                0x01,
                                false,
                            );
                        }
                    }
                    0x30 => {
                        self.ports[port_idx].serr &= !val;
                    }
                    0x38 => {
                        self.ports[port_idx].ci |= val;
                        self.process_port(port_idx);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

impl PciDevice for AhciController {
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
        let mut msi_touched = false;
        for (i, &b) in data.iter().enumerate() {
            let idx = offset + i;
            if matches!(idx, 0x04..=0x05 | 0x0c..=0x0d | 0x3c) {
                self.cfg[idx] = b;
            } else if idx == MSI_CAP_OFF + 2 {
                // Only bit 0 (MSI Enable) is writable in low byte of Message Control (1 vector).
                self.cfg[idx] = (self.cfg[idx] & !0x01) | (b & 0x01);
                msi_touched = true;
            } else if (MSI_CAP_OFF + 4..MSI_CAP_OFF + 14).contains(&idx) {
                self.cfg[idx] = b;
                msi_touched = true;
            }
        }
        if msi_touched {
            self.sync_msi();
        }
    }

    fn active_bars(&self) -> Vec<(usize, u64, u64)> {
        let cmd = u16::from_le_bytes([self.cfg[0x04], self.cfg[0x05]]);
        if cmd & 0x02 == 0 {
            return Vec::new();
        }
        self.bars.active_mmio()
    }

    fn bar_read(&self, bar: usize, offset: u64, data: &mut [u8]) {
        if bar != 5 {
            data.fill(0xff);
            return;
        }
        let aligned = offset & !3;
        let shift = (offset & 3) as usize;
        let v = self.read_reg32(aligned).to_le_bytes();
        for (i, b) in data.iter_mut().enumerate() {
            *b = v.get(shift + i).copied().unwrap_or(0);
        }
    }

    fn bar_write(&mut self, bar: usize, offset: u64, data: &[u8]) {
        if bar != 5 || data.is_empty() {
            return;
        }
        let aligned = offset & !3;
        let shift = (offset & 3) as usize;
        let mut bytes = if data.len() == 4 && shift == 0 {
            [0u8; 4]
        } else {
            self.read_reg32(aligned).to_le_bytes()
        };
        for (i, &b) in data.iter().enumerate() {
            if shift + i < 4 {
                bytes[shift + i] = b;
            }
        }
        self.write_reg32(aligned, u32::from_le_bytes(bytes));
    }
}

fn prdt_total_bytes(mem: &GuestMem, ctba: u64, prdtl: usize) -> usize {
    let mut total = 0usize;
    for i in 0..prdtl {
        let mut entry = [0u8; 16];
        if mem
            .read_slice(&mut entry, GuestAddress(ctba + 0x80 + (i as u64) * 16))
            .is_err()
        {
            break;
        }
        let dbc =
            ((u32::from_le_bytes(entry[12..16].try_into().unwrap()) & 0x003f_ffff) + 1) as usize;
        total = total.saturating_add(dbc);
    }
    total
}

fn write_prdt(mem: &GuestMem, ctba: u64, prdtl: usize, src: &[u8]) -> u32 {
    let mut off = 0usize;
    for i in 0..prdtl {
        if off >= src.len() {
            break;
        }
        let mut entry = [0u8; 16];
        if mem
            .read_slice(&mut entry, GuestAddress(ctba + 0x80 + (i as u64) * 16))
            .is_err()
        {
            break;
        }
        let lo = u32::from_le_bytes(entry[0..4].try_into().unwrap());
        let hi = u32::from_le_bytes(entry[4..8].try_into().unwrap());
        let dba = (u64::from(hi) << 32) | u64::from(lo & !1);
        let dbc =
            ((u32::from_le_bytes(entry[12..16].try_into().unwrap()) & 0x003f_ffff) + 1) as usize;
        let take = dbc.min(src.len() - off);
        if mem
            .write_slice(&src[off..off + take], GuestAddress(dba))
            .is_err()
        {
            break;
        }
        off += take;
    }
    off as u32
}

fn build_atapi_identify(port_idx: usize) -> [u8; 512] {
    let mut words = [0u16; 256];
    words[0] = 0x85c0; // ATAPI, CD-ROM (5), removable, 12-byte packet
    put_ata_str(&mut words[10..20], &format!("OSBXCD{port_idx:02}"));
    put_ata_str(&mut words[23..27], "1.0");
    put_ata_str(&mut words[27..47], "OSBX AHCI CD-ROM");
    words[49] = 0x0300; // DMA + LBA
    words[53] = 0x0007; // words 54-58, 64-70, 88 valid
    words[63] = 0x0407; // MDMA2 selected
    words[64] = 0x0003; // PIO3/4
    words[76] = 0x000e; // SATA Gen1/2/3
    words[80] = 0x01f0; // ATA/ATAPI-4..8
    words[82] = 0x0214; // PACKET, DEVICE RESET, NOP
    words[83] = 0x4000;
    words[85] = 0x0214;
    words[88] = 0x203f; // UDMA5 selected
    words[93] = 0x6001;
    let mut out = [0u8; 512];
    for (i, w) in words.iter().enumerate() {
        out[i * 2..i * 2 + 2].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn put_ata_str(dst: &mut [u16], s: &str) {
    let bytes = s.as_bytes();
    for (i, slot) in dst.iter_mut().enumerate() {
        let hi = bytes.get(i * 2).copied().unwrap_or(b' ');
        let lo = bytes.get(i * 2 + 1).copied().unwrap_or(b' ');
        *slot = (u16::from(hi) << 8) | u16::from(lo);
    }
}
