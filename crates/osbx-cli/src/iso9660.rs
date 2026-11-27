//! Pure-Rust ISO9660 (ECMA-119) + Joliet Level 3 image writer.
//!
//! Produces a flat read-only CD-ROM image suitable for mounting inside Windows (CDFS) and Linux
//! without relying on external `xorriso` or `genisoimage` binaries.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

const SECTOR: usize = 2048;

/// A single file to place in the root directory of the generated ISO9660 + Joliet image.
pub struct IsoFile {
    /// File name as seen by Joliet readers (Windows CDFS preserves exact case and extensions).
    pub name: String,
    /// Raw file bytes.
    pub data: Vec<u8>,
}

/// Write a valid ECMA-119 ISO9660 + Joliet Level 3 image containing `files` in its root directory.
pub fn write_iso(path: &Path, volume_id: &str, files: &[IsoFile]) -> io::Result<()> {
    let bytes = build_iso_bytes(volume_id, files)?;
    let mut f = File::create(path)?;
    f.write_all(&bytes)?;
    f.flush()
}

/// Build an ISO9660 + Joliet Level 3 image in memory.
pub fn build_iso_bytes(volume_id: &str, files: &[IsoFile]) -> io::Result<Vec<u8>> {
    struct Entry<'a> {
        pvd_name: Vec<u8>,
        joliet_name: Vec<u8>,
        data: &'a [u8],
        lba: u32,
        sectors: u32,
    }

    let mut entries: Vec<Entry<'_>> = Vec::with_capacity(files.len());
    let mut seen_pvd = std::collections::HashSet::new();
    for (idx, f) in files.iter().enumerate() {
        if f.name.is_empty() || f.name.contains('/') || f.name.contains('\\') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid ISO9660 filename: {:?}", f.name),
            ));
        }
        if f.data.len() > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("ISO9660 file {:?} exceeds 4 GiB limit", f.name),
            ));
        }
        let mut base = sanitize_iso_name(&f.name);
        if !seen_pvd.insert(base.clone()) {
            base = format!("FILE_{idx:04}");
        }
        let pvd_name = format!("{base};1").into_bytes();
        let joliet_name = encode_utf16be(&format!("{};1", f.name));
        let sectors = f.data.len().div_ceil(SECTOR) as u32;
        entries.push(Entry {
            pvd_name,
            joliet_name,
            data: &f.data,
            lba: 0,
            sectors,
        });
    }

    // Primary directory entries sorted by ISO9660 identifier; Joliet sorted by UTF-16BE identifier.
    let mut pvd_order: Vec<usize> = (0..entries.len()).collect();
    pvd_order.sort_by(|&a, &b| entries[a].pvd_name.cmp(&entries[b].pvd_name));
    let mut joliet_order: Vec<usize> = (0..entries.len()).collect();
    joliet_order.sort_by(|&a, &b| entries[a].joliet_name.cmp(&entries[b].joliet_name));

    // Fixed sector layout:
    //  0..16: System Area (zeroes)
    //  16:    Primary Volume Descriptor (PVD)
    //  17:    Supplementary Volume Descriptor (Joliet SVD)
    //  18:    Volume Descriptor Set Terminator
    //  19:    PVD Type L Path Table
    //  20:    PVD Type M Path Table
    //  21:    Joliet Type L Path Table
    //  22:    Joliet Type M Path Table
    //  23..:  PVD Root Directory, then Joliet Root Directory, then file extents.
    let pvd_l_path_lba: u32 = 19;
    let pvd_m_path_lba: u32 = 20;
    let joliet_l_path_lba: u32 = 21;
    let joliet_m_path_lba: u32 = 22;
    let pvd_root_lba: u32 = 23;

    // Pre-size both root directories with placeholder LBAs so we know their exact sector counts.
    let pvd_root_sectors = count_dir_sectors(&pvd_order, |i| &entries[i].pvd_name);
    let joliet_root_lba = pvd_root_lba + pvd_root_sectors;
    let joliet_root_sectors = count_dir_sectors(&joliet_order, |i| &entries[i].joliet_name);

    let mut next_lba = joliet_root_lba + joliet_root_sectors;
    for e in &mut entries {
        e.lba = if e.data.is_empty() {
            joliet_root_lba
        } else {
            let lba = next_lba;
            next_lba += e.sectors;
            lba
        };
    }
    let total_sectors = next_lba;

    let pvd_root_bytes = build_root_dir(
        pvd_root_lba,
        pvd_root_sectors * SECTOR as u32,
        &pvd_order,
        |i| {
            (
                &entries[i].pvd_name,
                entries[i].lba,
                entries[i].data.len() as u32,
            )
        },
    );
    let joliet_root_bytes = build_root_dir(
        joliet_root_lba,
        joliet_root_sectors * SECTOR as u32,
        &joliet_order,
        |i| {
            (
                &entries[i].joliet_name,
                entries[i].lba,
                entries[i].data.len() as u32,
            )
        },
    );
    debug_assert_eq!(pvd_root_bytes.len(), pvd_root_sectors as usize * SECTOR);
    debug_assert_eq!(
        joliet_root_bytes.len(),
        joliet_root_sectors as usize * SECTOR
    );

    let mut out = vec![0u8; total_sectors as usize * SECTOR];

    // Sector 16: Primary Volume Descriptor
    let pvd = &mut out[16 * SECTOR..17 * SECTOR];
    write_volume_descriptor(
        pvd,
        1,
        &pad_ascii(&sanitize_iso_name(volume_id), 32),
        None,
        total_sectors,
        pvd_l_path_lba,
        pvd_m_path_lba,
        pvd_root_lba,
        pvd_root_bytes.len() as u32,
    );

    // Sector 17: Supplementary Volume Descriptor (Joliet UCS-2 Level 3: %/E)
    let svd = &mut out[17 * SECTOR..18 * SECTOR];
    write_volume_descriptor(
        svd,
        2,
        &pad_utf16be(volume_id, 32),
        Some([0x25, 0x2F, 0x45]),
        total_sectors,
        joliet_l_path_lba,
        joliet_m_path_lba,
        joliet_root_lba,
        joliet_root_bytes.len() as u32,
    );

    // Sector 18: Volume Descriptor Set Terminator
    let term = &mut out[18 * SECTOR..19 * SECTOR];
    term[0] = 255;
    term[1..6].copy_from_slice(b"CD001");
    term[6] = 1;

    // Sectors 19..22: Path tables (single root entry: 10 bytes each)
    write_path_table_le(&mut out[19 * SECTOR..20 * SECTOR], pvd_root_lba);
    write_path_table_be(&mut out[20 * SECTOR..21 * SECTOR], pvd_root_lba);
    write_path_table_le(&mut out[21 * SECTOR..22 * SECTOR], joliet_root_lba);
    write_path_table_be(&mut out[22 * SECTOR..23 * SECTOR], joliet_root_lba);

    // Root directories
    let pvd_off = pvd_root_lba as usize * SECTOR;
    out[pvd_off..pvd_off + pvd_root_bytes.len()].copy_from_slice(&pvd_root_bytes);
    let joliet_off = joliet_root_lba as usize * SECTOR;
    out[joliet_off..joliet_off + joliet_root_bytes.len()].copy_from_slice(&joliet_root_bytes);

    // File extents
    for e in &entries {
        if !e.data.is_empty() {
            let off = e.lba as usize * SECTOR;
            out[off..off + e.data.len()].copy_from_slice(e.data);
        }
    }

    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn write_volume_descriptor(
    sec: &mut [u8],
    vd_type: u8,
    vol_id_32: &[u8],
    escape_seq: Option<[u8; 3]>,
    total_sectors: u32,
    l_path_lba: u32,
    m_path_lba: u32,
    root_lba: u32,
    root_len: u32,
) {
    sec[0] = vd_type;
    sec[1..6].copy_from_slice(b"CD001");
    sec[6] = 1; // Version
    // System identifier (8..40): spaces (or UTF-16BE spaces for Joliet)
    if let Some(esc) = escape_seq {
        for chunk in sec[8..40].as_chunks_mut::<2>().0 {
            chunk.copy_from_slice(&[0x00, b' ']);
        }
        sec[88..91].copy_from_slice(&esc);
    } else {
        sec[8..40].fill(b' ');
    }
    sec[40..72].copy_from_slice(&vol_id_32[..32]);
    put_both32(&mut sec[80..88], total_sectors);
    put_both16(&mut sec[120..124], 1); // Volume Set Size
    put_both16(&mut sec[124..128], 1); // Volume Sequence Number
    put_both16(&mut sec[128..132], SECTOR as u16); // Logical Block Size
    put_both32(&mut sec[132..140], 10); // Path Table Size (single root entry)
    sec[140..144].copy_from_slice(&l_path_lba.to_le_bytes());
    sec[148..152].copy_from_slice(&m_path_lba.to_be_bytes());
    // Root directory record at offset 156 (34 bytes)
    let root_rec = make_dir_record(&[0x00], root_lba, root_len, 0x02);
    debug_assert_eq!(root_rec.len(), 34);
    sec[156..190].copy_from_slice(&root_rec);
    // Space-padded identifier fields (190..813)
    if escape_seq.is_some() {
        for chunk in sec[190..812].as_chunks_mut::<2>().0 {
            chunk.copy_from_slice(&[0x00, b' ']);
        }
    } else {
        sec[190..813].fill(b' ');
    }
    // Volume Creation / Modification Date & Time (ASCII YYYYMMDDHHMMSScc + tz byte)
    sec[813..829].copy_from_slice(b"2025010100000000");
    sec[830..846].copy_from_slice(b"2025010100000000");
    sec[847..863].copy_from_slice(b"0000000000000000");
    sec[864..880].copy_from_slice(b"0000000000000000");
    sec[881] = 1; // File Structure Version
}

fn write_path_table_le(sec: &mut [u8], root_lba: u32) {
    sec[0] = 1; // Directory Identifier Length
    sec[1] = 0; // Extended Attribute Record Length
    sec[2..6].copy_from_slice(&root_lba.to_le_bytes());
    sec[6..8].copy_from_slice(&1u16.to_le_bytes()); // Parent Directory Number (root = 1)
    sec[8] = 0; // Root identifier
    sec[9] = 0; // Pad byte
}

fn write_path_table_be(sec: &mut [u8], root_lba: u32) {
    sec[0] = 1;
    sec[1] = 0;
    sec[2..6].copy_from_slice(&root_lba.to_be_bytes());
    sec[6..8].copy_from_slice(&1u16.to_be_bytes());
    sec[8] = 0;
    sec[9] = 0;
}

fn dir_record_len(id_len: usize) -> usize {
    let raw = 33 + id_len;
    raw + (raw & 1)
}

fn make_dir_record(id: &[u8], lba: u32, len: u32, flags: u8) -> Vec<u8> {
    let rec_len = dir_record_len(id.len());
    let mut rec = vec![0u8; rec_len];
    rec[0] = rec_len as u8;
    rec[1] = 0; // Extended Attribute Record Length
    put_both32(&mut rec[2..10], lba);
    put_both32(&mut rec[10..18], len);
    // Recording Date and Time (years since 1900, month, day, hour, min, sec, tz)
    rec[18..25].copy_from_slice(&[125, 1, 1, 0, 0, 0, 0]);
    rec[25] = flags;
    put_both16(&mut rec[28..32], 1); // Volume Sequence Number
    rec[32] = id.len() as u8;
    rec[33..33 + id.len()].copy_from_slice(id);
    rec
}

fn count_dir_sectors<'a>(order: &[usize], name_fn: impl Fn(usize) -> &'a [u8]) -> u32 {
    let mut pos = 34 + 34; // '.' and '..'
    let mut sectors = 1u32;
    for &idx in order {
        let len = dir_record_len(name_fn(idx).len());
        if pos + len > SECTOR {
            sectors += 1;
            pos = 0;
        }
        pos += len;
    }
    sectors
}

fn build_root_dir<'a>(
    root_lba: u32,
    root_byte_len: u32,
    order: &[usize],
    item_fn: impl Fn(usize) -> (&'a [u8], u32, u32),
) -> Vec<u8> {
    let mut buf = Vec::new();
    let dot = make_dir_record(&[0x00], root_lba, root_byte_len, 0x02);
    let dotdot = make_dir_record(&[0x01], root_lba, root_byte_len, 0x02);
    buf.extend_from_slice(&dot);
    buf.extend_from_slice(&dotdot);
    for &idx in order {
        let (id, lba, size) = item_fn(idx);
        let rec = make_dir_record(id, lba, size, 0x00);
        let in_sec = buf.len() % SECTOR;
        if in_sec + rec.len() > SECTOR {
            buf.resize(buf.len() + (SECTOR - in_sec), 0);
        }
        buf.extend_from_slice(&rec);
    }
    let rem = buf.len() % SECTOR;
    if rem != 0 {
        buf.resize(buf.len() + (SECTOR - rem), 0);
    }
    buf
}

fn put_both16(dst: &mut [u8], v: u16) {
    dst[0..2].copy_from_slice(&v.to_le_bytes());
    dst[2..4].copy_from_slice(&v.to_be_bytes());
}

fn put_both32(dst: &mut [u8], v: u32) {
    dst[0..4].copy_from_slice(&v.to_le_bytes());
    dst[4..8].copy_from_slice(&v.to_be_bytes());
}

fn sanitize_iso_name(name: &str) -> String {
    let mut s = String::new();
    for ch in name.chars() {
        let up = ch.to_ascii_uppercase();
        if up.is_ascii_alphanumeric() || up == '_' || up == '.' {
            s.push(up);
        } else {
            s.push('_');
        }
        if s.len() >= 30 {
            break;
        }
    }
    if s.is_empty() { "OSBX".into() } else { s }
}

fn pad_ascii(s: &str, width: usize) -> Vec<u8> {
    let mut out = vec![b' '; width];
    let bytes = s.as_bytes();
    let n = bytes.len().min(width);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

fn encode_utf16be(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_be_bytes());
    }
    out
}

fn pad_utf16be(s: &str, byte_width: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(byte_width);
    for u in s.encode_utf16().take(byte_width / 2) {
        out.extend_from_slice(&u.to_be_bytes());
    }
    while out.len() + 2 <= byte_width {
        out.extend_from_slice(&[0x00, b' ']);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_valid_iso9660_joliet_image() {
        let files = vec![
            IsoFile {
                name: "autounattend.xml".into(),
                data: b"<unattend/>".to_vec(),
            },
            IsoFile {
                name: "setup_osbx.cmd".into(),
                data: b"@echo off\r\n".to_vec(),
            },
            IsoFile {
                name: "osbx-agent.exe".into(),
                data: vec![0x4d, 0x5a, 0x90, 0x00],
            },
        ];
        let img = build_iso_bytes("OSBX_SEED", &files).unwrap();
        assert_eq!(img.len() % SECTOR, 0);

        // Verify Primary Volume Descriptor (sector 16)
        let pvd = &img[16 * SECTOR..17 * SECTOR];
        assert_eq!(pvd[0], 1);
        assert_eq!(&pvd[1..6], b"CD001");
        assert_eq!(&pvd[40..49], b"OSBX_SEED");
        let vol_sectors = u32::from_le_bytes(pvd[80..84].try_into().unwrap());
        assert_eq!(vol_sectors as usize * SECTOR, img.len());

        // Verify Joliet Supplementary Volume Descriptor (sector 17)
        let svd = &img[17 * SECTOR..18 * SECTOR];
        assert_eq!(svd[0], 2);
        assert_eq!(&svd[1..6], b"CD001");
        assert_eq!(&svd[88..91], &[0x25, 0x2F, 0x45]);

        // Verify Terminator (sector 18)
        let term = &img[18 * SECTOR..19 * SECTOR];
        assert_eq!(term[0], 255);
        assert_eq!(&term[1..6], b"CD001");

        // Parse Joliet root directory and verify all 3 filenames & payloads match verbatim!
        let joliet_root_lba =
            u32::from_le_bytes(svd[156 + 2..156 + 6].try_into().unwrap()) as usize;
        let joliet_root_len =
            u32::from_le_bytes(svd[156 + 10..156 + 14].try_into().unwrap()) as usize;
        let dir = &img[joliet_root_lba * SECTOR..joliet_root_lba * SECTOR + joliet_root_len];
        let mut found = std::collections::BTreeMap::new();
        let mut pos = 0usize;
        while pos < dir.len() {
            let rec_len = dir[pos] as usize;
            if rec_len == 0 {
                pos = ((pos / SECTOR) + 1) * SECTOR;
                continue;
            }
            let flags = dir[pos + 25];
            let id_len = dir[pos + 32] as usize;
            if flags & 0x02 == 0 {
                let raw_id = &dir[pos + 33..pos + 33 + id_len];
                let u16s: Vec<u16> = raw_id
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                let name = String::from_utf16(&u16s).unwrap();
                let lba = u32::from_le_bytes(dir[pos + 2..pos + 6].try_into().unwrap()) as usize;
                let size = u32::from_le_bytes(dir[pos + 10..pos + 14].try_into().unwrap()) as usize;
                let data = img[lba * SECTOR..lba * SECTOR + size].to_vec();
                found.insert(name, data);
            }
            pos += rec_len;
        }
        assert_eq!(found.get("autounattend.xml;1").unwrap(), b"<unattend/>");
        assert_eq!(found.get("setup_osbx.cmd;1").unwrap(), b"@echo off\r\n");
        assert_eq!(
            found.get("osbx-agent.exe;1").unwrap(),
            &vec![0x4d, 0x5a, 0x90, 0x00]
        );
    }
}
