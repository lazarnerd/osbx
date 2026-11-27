//! Minimal read-only virtio-scsi CD-ROM controller (Virtio 1.0 §5.6).
//!
//! Exposes one or more read-only ISO9660 images as 2048-byte-block SCSI CD-ROM targets
//! (LUN 0 on targets `0..targets.len()`). Used to boot and run unattended Windows ISO
//! installations (Windows install ISO + `virtio-win` driver ISO + `autounattend.xml` seed ISO).

use super::{Activation, GuestMem, Interrupt, SharedQueue, VIRTIO_F_VERSION_1, VirtioDevice};
use crate::virtio::blk::read_exact_at;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use virtio_queue::{QueueOwnedT, QueueT};

pub(crate) const CDROM_BLOCK: u64 = 2048;
const REQ_HDR_LEN: usize = 51;
const RESP_HDR_LEN: usize = 108;

const VIRTIO_SCSI_S_OK: u8 = 0;
const VIRTIO_SCSI_S_BAD_TARGET: u8 = 3;

pub(crate) const SCSI_STATUS_GOOD: u8 = 0x00;
pub(crate) const SCSI_STATUS_CHECK_CONDITION: u8 = 0x02;

/// Outcome of executing a single SCSI CD-ROM CDB.
pub(crate) struct ScsiResult {
    pub data_out: Vec<u8>,
    pub status: u8,
    pub sense: Option<[u8; 18]>,
}

/// Read-only ISO9660 CD-ROM backing image shared by `VirtioScsi` and AHCI ATAPI.
pub(crate) struct CdromTarget {
    file: File,
    len: u64,
    blocks: u64,
}

impl CdromTarget {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        let blocks = len.div_ceil(CDROM_BLOCK).max(1);
        Ok(Self { file, len, blocks })
    }

    fn read_blocks(&self, lba: u64, count: u32, out: &mut [u8]) -> io::Result<()> {
        let byte_off = lba.saturating_mul(CDROM_BLOCK);
        let want = (u64::from(count) * CDROM_BLOCK).min(out.len() as u64) as usize;
        if byte_off >= self.len {
            out[..want].fill(0);
            return Ok(());
        }
        let avail = (self.len - byte_off).min(want as u64) as usize;
        read_exact_at(&self.file, &mut out[..avail], byte_off)?;
        if avail < want {
            out[avail..want].fill(0);
        }
        Ok(())
    }

    /// Execute a SCSI CDB (12 or 16 bytes) against this read-only CD-ROM image.
    pub(crate) fn execute_cdb(
        &self,
        target_id: usize,
        cdb: &[u8],
        data_cap: usize,
        saved_sense: Option<[u8; 18]>,
    ) -> ScsiResult {
        let mut data_out: Vec<u8> = Vec::new();
        let mut scsi_status = SCSI_STATUS_GOOD;
        let mut sense: Option<[u8; 18]> = None;

        let c = |idx: usize| cdb.get(idx).copied().unwrap_or(0);
        match c(0) {
            0x00 | 0x1e | 0x1b => {
                // TEST UNIT READY, PREVENT ALLOW MEDIUM REMOVAL, START STOP UNIT
            }
            0x03 => {
                // REQUEST SENSE: return saved sense if present, otherwise NO SENSE.
                let alloc = usize::from(c(4)).min(data_cap);
                let s = saved_sense.unwrap_or_else(|| {
                    let mut s = [0u8; 18];
                    s[0] = 0x70;
                    s[7] = 10;
                    s
                });
                data_out.extend_from_slice(&s[..alloc.min(s.len())]);
            }
            0x12 => {
                // INQUIRY
                let evpd = c(1) & 1 != 0;
                let page = c(2);
                let alloc = usize::from(u16::from_be_bytes([c(3), c(4)])).min(data_cap);
                if !evpd {
                    let mut inq = [0u8; 36];
                    inq[0] = 0x05; // CD/DVD-ROM peripheral device type
                    inq[1] = 0x80; // removable medium
                    inq[2] = 0x05; // SPC-3
                    inq[3] = 0x02; // response data format = 2
                    inq[4] = 31; // additional length
                    inq[8..16].copy_from_slice(b"OSBX    ");
                    inq[16..32].copy_from_slice(b"CD-ROM          ");
                    inq[32..36].copy_from_slice(b"1.0 ");
                    data_out.extend_from_slice(&inq[..alloc.min(inq.len())]);
                } else {
                    match page {
                        0x00 => {
                            let p = [0x05, 0x00, 0x00, 0x03, 0x00, 0x80, 0x83];
                            data_out.extend_from_slice(&p[..alloc.min(p.len())]);
                        }
                        0x80 => {
                            let serial = format!("OSBXCD{target_id:02}");
                            let mut p = vec![0x05, 0x80, 0x00, serial.len() as u8];
                            p.extend_from_slice(serial.as_bytes());
                            data_out.extend_from_slice(&p[..alloc.min(p.len())]);
                        }
                        0x83 => {
                            let id = format!("osbx-cdrom-{target_id}");
                            let desc_len = id.len() as u8;
                            let mut p = vec![
                                0x05,
                                0x83,
                                0x00,
                                desc_len + 4,
                                0x02, // ASCII
                                0x01, // T10 vendor id
                                0x00,
                                desc_len,
                            ];
                            p.extend_from_slice(id.as_bytes());
                            data_out.extend_from_slice(&p[..alloc.min(p.len())]);
                        }
                        _ => {
                            scsi_status = SCSI_STATUS_CHECK_CONDITION;
                            sense = Some(sense_illegal(0x24, 0x00));
                        }
                    }
                }
            }
            0xa0 => {
                // REPORT LUNS: 1 LUN (LUN 0)
                let alloc = u32::from_be_bytes([c(6), c(7), c(8), c(9)]) as usize;
                let mut buf = [0u8; 16];
                buf[0..4].copy_from_slice(&8u32.to_be_bytes());
                let take = alloc.min(data_cap).min(buf.len());
                data_out.extend_from_slice(&buf[..take]);
            }
            0x25 => {
                // READ CAPACITY (10)
                let last_lba = self.blocks.saturating_sub(1).min(u64::from(u32::MAX)) as u32;
                let mut cap = [0u8; 8];
                cap[0..4].copy_from_slice(&last_lba.to_be_bytes());
                cap[4..8].copy_from_slice(&(CDROM_BLOCK as u32).to_be_bytes());
                data_out.extend_from_slice(&cap[..data_cap.min(cap.len())]);
            }
            0x9e if (c(1) & 0x1f) == 0x10 => {
                // READ CAPACITY (16)
                let alloc = u32::from_be_bytes([c(10), c(11), c(12), c(13)]) as usize;
                let last_lba = self.blocks.saturating_sub(1);
                let mut cap = [0u8; 32];
                cap[0..8].copy_from_slice(&last_lba.to_be_bytes());
                cap[8..12].copy_from_slice(&(CDROM_BLOCK as u32).to_be_bytes());
                let take = alloc.min(data_cap).min(cap.len());
                data_out.extend_from_slice(&cap[..take]);
            }
            0x28 => {
                // READ (10)
                let lba = u64::from(u32::from_be_bytes([c(2), c(3), c(4), c(5)]));
                let count = u32::from(u16::from_be_bytes([c(7), c(8)]));
                read_into(
                    self,
                    lba,
                    count,
                    data_cap,
                    &mut data_out,
                    &mut scsi_status,
                    &mut sense,
                );
            }
            0xa8 => {
                // READ (12)
                let lba = u64::from(u32::from_be_bytes([c(2), c(3), c(4), c(5)]));
                let count = u32::from_be_bytes([c(6), c(7), c(8), c(9)]);
                read_into(
                    self,
                    lba,
                    count,
                    data_cap,
                    &mut data_out,
                    &mut scsi_status,
                    &mut sense,
                );
            }
            0x88 => {
                // READ (16)
                let lba = u64::from_be_bytes([c(2), c(3), c(4), c(5), c(6), c(7), c(8), c(9)]);
                let count = u32::from_be_bytes([c(10), c(11), c(12), c(13)]);
                read_into(
                    self,
                    lba,
                    count,
                    data_cap,
                    &mut data_out,
                    &mut scsi_status,
                    &mut sense,
                );
            }
            0x1a => {
                // MODE SENSE (6): minimal write-protected header
                let alloc = usize::from(c(4)).min(data_cap);
                let hdr = [3u8, 0x00, 0x80, 0x00];
                data_out.extend_from_slice(&hdr[..alloc.min(hdr.len())]);
            }
            0x5a => {
                // MODE SENSE (10): include page 0x2A (CD/DVD capabilities) when requested
                let page = c(2) & 0x3f;
                let alloc = usize::from(u16::from_be_bytes([c(7), c(8)])).min(data_cap);
                let mut buf = vec![0u8, 6, 0x70, 0x80, 0, 0, 0, 0];
                if page == 0x2a || page == 0x3f {
                    let mut p2a = [0u8; 28];
                    p2a[0] = 0x2a;
                    p2a[1] = 26;
                    p2a[2] = 0x3f; // CD-R/RW/DVD-ROM read
                    p2a[4] = 0x71;
                    p2a[5] = 0x60;
                    p2a[6] = 0x29; // tray loading mechanism
                    p2a[8..10].copy_from_slice(&0x02c2u16.to_be_bytes());
                    p2a[12..14].copy_from_slice(&0x0200u16.to_be_bytes());
                    p2a[14..16].copy_from_slice(&0x02c2u16.to_be_bytes());
                    buf.extend_from_slice(&p2a);
                    let len = (buf.len() - 2) as u16;
                    buf[0..2].copy_from_slice(&len.to_be_bytes());
                }
                data_out.extend_from_slice(&buf[..alloc.min(buf.len())]);
            }
            0x43 => {
                // READ TOC: single data track 1 + lead-out 0xAA
                let msf = c(1) & 0x02 != 0;
                let format = c(2) & 0x0f;
                let alloc = usize::from(u16::from_be_bytes([c(7), c(8)])).min(data_cap);
                if format == 1 {
                    // Session info
                    let mut toc = [0u8; 12];
                    toc[0..2].copy_from_slice(&10u16.to_be_bytes());
                    toc[2] = 1;
                    toc[3] = 1;
                    toc[5] = 0x14;
                    toc[6] = 0x01;
                    if msf {
                        toc[8..12].copy_from_slice(&[0, 0, 2, 0]);
                    }
                    data_out.extend_from_slice(&toc[..alloc.min(toc.len())]);
                } else {
                    let mut toc = [0u8; 20];
                    toc[0..2].copy_from_slice(&18u16.to_be_bytes());
                    toc[2] = 1; // first track
                    toc[3] = 1; // last track
                    // Track 1 descriptor
                    toc[5] = 0x14; // data track
                    toc[6] = 0x01;
                    if msf {
                        toc[8..12].copy_from_slice(&[0, 0, 2, 0]);
                    }
                    // Lead-out descriptor
                    toc[13] = 0x14;
                    toc[14] = 0xaa;
                    let end_lba = self.blocks.min(u64::from(u32::MAX)) as u32;
                    if msf {
                        let f = end_lba.saturating_add(150);
                        toc[16..20].copy_from_slice(&[
                            0,
                            (f / (60 * 75)).min(99) as u8,
                            ((f / 75) % 60) as u8,
                            (f % 75) as u8,
                        ]);
                    } else {
                        toc[16..20].copy_from_slice(&end_lba.to_be_bytes());
                    }
                    data_out.extend_from_slice(&toc[..alloc.min(toc.len())]);
                }
            }
            0x46 => {
                // GET CONFIGURATION: DVD-ROM profile (0x0010) + basic features
                let alloc = usize::from(u16::from_be_bytes([c(7), c(8)])).min(data_cap);
                let mut buf = vec![0u8; 8];
                buf[6..8].copy_from_slice(&0x0010u16.to_be_bytes()); // current profile = DVD-ROM
                // Feature 0x0000: Profile List (DVD-ROM active)
                buf.extend_from_slice(&[0x00, 0x00, 0x03, 0x04, 0x00, 0x10, 0x01, 0x00]);
                // Feature 0x0001: Core
                buf.extend_from_slice(&[0x00, 0x01, 0x03, 0x04, 0x00, 0x00, 0x00, 0x02]);
                // Feature 0x0003: Removable Medium
                buf.extend_from_slice(&[0x00, 0x03, 0x03, 0x04, 0x29, 0x00, 0x00, 0x00]);
                // Feature 0x0010: Random Readable
                buf.extend_from_slice(&[
                    0x00, 0x10, 0x01, 0x08, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00,
                ]);
                let data_len = (buf.len() - 4) as u32;
                buf[0..4].copy_from_slice(&data_len.to_be_bytes());
                data_out.extend_from_slice(&buf[..alloc.min(buf.len())]);
            }
            0x4a => {
                // GET EVENT STATUS NOTIFICATION: media present
                let alloc = usize::from(u16::from_be_bytes([c(7), c(8)])).min(data_cap);
                let buf = [0u8, 6, 0x04, 0x10, 0x00, 0x02, 0x00, 0x00];
                data_out.extend_from_slice(&buf[..alloc.min(buf.len())]);
            }
            0x51 => {
                // READ DISC INFORMATION: finalized single-session ROM disc
                let alloc = usize::from(u16::from_be_bytes([c(7), c(8)])).min(data_cap);
                let mut buf = [0u8; 34];
                buf[0..2].copy_from_slice(&32u16.to_be_bytes());
                buf[2] = 0x0e; // complete disc, complete last session
                buf[3] = 1; // first track
                buf[4] = 1; // sessions LSB
                buf[5] = 1; // first track in last session LSB
                buf[6] = 1; // last track in last session LSB
                data_out.extend_from_slice(&buf[..alloc.min(buf.len())]);
            }
            0x52 => {
                // READ TRACK INFORMATION: track 1 covers all sectors
                let alloc = usize::from(u16::from_be_bytes([c(7), c(8)])).min(data_cap);
                let mut buf = [0u8; 36];
                buf[0..2].copy_from_slice(&34u16.to_be_bytes());
                buf[2] = 1; // track number
                buf[3] = 1; // session number
                buf[5] = 0x04; // data track
                buf[6] = 0x01; // mode 1
                let blocks = self.blocks.min(u64::from(u32::MAX)) as u32;
                buf[24..28].copy_from_slice(&blocks.to_be_bytes());
                data_out.extend_from_slice(&buf[..alloc.min(buf.len())]);
            }
            0xbd => {
                // MECHANISM STATUS: tray closed, slot 0
                let alloc = usize::from(u16::from_be_bytes([c(8), c(9)])).min(data_cap);
                let buf = [0u8; 8];
                data_out.extend_from_slice(&buf[..alloc.min(buf.len())]);
            }
            _ => {
                scsi_status = SCSI_STATUS_CHECK_CONDITION;
                sense = Some(sense_illegal(0x20, 0x00));
            }
        }

        ScsiResult {
            data_out,
            status: scsi_status,
            sense,
        }
    }
}

/// Read-only virtio-scsi controller serving ISO CD-ROM targets.
pub struct VirtioScsi {
    targets: Vec<CdromTarget>,
    active: Option<(GuestMem, Vec<SharedQueue>, Interrupt)>,
}

impl VirtioScsi {
    /// Open one or more ISO files as SCSI CD-ROM targets `0..paths.len()`.
    pub fn open(paths: &[impl AsRef<Path>]) -> io::Result<Self> {
        let mut targets = Vec::with_capacity(paths.len());
        for p in paths {
            targets.push(CdromTarget::open(p.as_ref())?);
        }
        Ok(Self {
            targets,
            active: None,
        })
    }
}

impl VirtioDevice for VirtioScsi {
    fn device_type(&self) -> u32 {
        8
    }

    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }

    fn queue_max_sizes(&self) -> Vec<u16> {
        // Queue 0: control, Queue 1: event, Queue 2: request
        vec![64, 64, 128]
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // struct virtio_scsi_config (36 bytes):
        //   0..4:   num_queues = 1
        //   4..8:   seg_max = 128
        //   8..12:  max_sectors = 0xffff
        //  12..16:  cmd_per_lun = 128
        //  16..20:  event_info_size = 0
        //  20..24:  sense_size = 96
        //  24..28:  cdb_size = 32
        //  28..30:  max_channel = 0
        //  30..32:  max_target = targets.len().max(1) - 1 (or 7)
        //  32..36:  max_lun = 1
        let mut cfg = [0u8; 36];
        cfg[0..4].copy_from_slice(&1u32.to_le_bytes());
        cfg[4..8].copy_from_slice(&128u32.to_le_bytes());
        cfg[8..12].copy_from_slice(&0xffffu32.to_le_bytes());
        cfg[12..16].copy_from_slice(&128u32.to_le_bytes());
        cfg[20..24].copy_from_slice(&96u32.to_le_bytes());
        cfg[24..28].copy_from_slice(&32u32.to_le_bytes());
        let max_target = (self.targets.len().max(1) - 1) as u16;
        cfg[30..32].copy_from_slice(&max_target.to_le_bytes());
        cfg[32..36].copy_from_slice(&1u32.to_le_bytes());
        for (i, b) in data.iter_mut().enumerate() {
            *b = cfg.get(offset as usize + i).copied().unwrap_or(0);
        }
    }

    fn activate(&mut self, a: Activation) {
        self.active = Some((a.mem, a.queues, a.irq));
    }

    fn queue_notify(&mut self, queue: u32) {
        let Some((mem, queues, irq)) = self.active.clone() else {
            return;
        };
        let Some(q_arc) = queues.get(queue as usize) else {
            return;
        };
        if queue != 2 {
            // Drain control/event queues with trivial success if ever kicked.
            let mut q = q_arc.lock().unwrap();
            let mut signal = false;
            while let Ok(iter) = q.iter(&mem) {
                let chains: Vec<_> = iter.collect();
                if chains.is_empty() {
                    if q.enable_notification(&mem).unwrap_or(false) {
                        continue;
                    }
                    break;
                }
                for chain in chains {
                    let head = chain.head_index();
                    if q.add_used(&mem, head, 0).is_ok() {
                        signal = true;
                    }
                }
            }
            if signal && q.needs_notification(&mem).unwrap_or(true) {
                drop(q);
                irq.signal_queue(queue as u16);
            }
            return;
        }

        let mut q = q_arc.lock().unwrap();
        let mut signal = false;
        while let Ok(iter) = q.iter(&mem) {
            let chains: Vec<_> = iter.collect();
            if chains.is_empty() {
                if q.enable_notification(&mem).unwrap_or(false) {
                    continue;
                }
                break;
            }
            for chain in chains {
                let head = chain.head_index();
                let used = self.handle_req(&mem, chain);
                if q.add_used(&mem, head, used).is_ok() {
                    signal = true;
                }
            }
        }
        if signal && q.needs_notification(&mem).unwrap_or(true) {
            drop(q);
            irq.signal_queue(2);
        }
    }

    fn reset(&mut self) {
        self.active = None;
    }
}

impl VirtioScsi {
    fn handle_req(&self, mem: &GuestMem, chain: virtio_queue::DescriptorChain<&GuestMem>) -> u32 {
        let (Ok(mut rd), Ok(mut wr)) = (chain.clone().reader(mem), chain.writer(mem)) else {
            return 0;
        };
        let mut req = [0u8; REQ_HDR_LEN];
        if rd.read_exact(&mut req).is_err() {
            return 0;
        }
        let target_id = req[1] as usize;
        let lun = (u16::from(req[2] & 0x3f) << 8) | u16::from(req[3]);
        let cdb = &req[19..51];

        let mut resp = [0u8; RESP_HDR_LEN];
        let Some(target) = self
            .targets
            .get(target_id)
            .filter(|_| req[0] == 1 && lun == 0)
        else {
            resp[11] = VIRTIO_SCSI_S_BAD_TARGET;
            let _ = wr.write_all(&resp);
            return RESP_HDR_LEN as u32;
        };

        let data_cap = wr.available_bytes().saturating_sub(RESP_HDR_LEN);
        let res = target.execute_cdb(target_id, cdb, data_cap, None);

        resp[10] = res.status;
        resp[11] = VIRTIO_SCSI_S_OK;
        if let Some(s) = res.sense {
            resp[0..4].copy_from_slice(&(s.len() as u32).to_le_bytes());
            resp[12..12 + s.len()].copy_from_slice(&s);
        }
        let mut written = 0u32;
        if wr.write_all(&resp).is_ok() {
            written += RESP_HDR_LEN as u32;
            if !res.data_out.is_empty() && wr.write_all(&res.data_out).is_ok() {
                written += res.data_out.len() as u32;
            }
        }
        written
    }
}

fn read_into(
    target: &CdromTarget,
    lba: u64,
    count: u32,
    data_cap: usize,
    data_out: &mut Vec<u8>,
    scsi_status: &mut u8,
    sense: &mut Option<[u8; 18]>,
) {
    let want = (u64::from(count) * CDROM_BLOCK).min(data_cap as u64) as usize;
    if want == 0 {
        return;
    }
    data_out.resize(want, 0);
    if target.read_blocks(lba, count, data_out).is_err() {
        data_out.clear();
        *scsi_status = SCSI_STATUS_CHECK_CONDITION;
        *sense = Some(sense_illegal(0x21, 0x00)); // LBA out of range
    }
}

fn sense_illegal(asc: u8, ascq: u8) -> [u8; 18] {
    let mut s = [0u8; 18];
    s[0] = 0x70; // current errors
    s[2] = 0x05; // ILLEGAL REQUEST
    s[7] = 10;
    s[12] = asc;
    s[13] = ascq;
    s
}
