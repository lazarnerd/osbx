//! Emulated TCG PC Client CRB (Command Response Buffer) vTPM 2.0 MMIO device (`0xFED4_0000`).
//!
//! Implements the TCG PTP CRB register interface (Locality 0, 4 KiB window; 5 localities reserved
//! at `0xFED4_0000..0xFED4_5000`) and an in-process TPM 2.0 command processor sufficient for OVMF,
//! Windows `tpm.sys` / `Get-Tpm`, and Windows 11 TPM 2.0 platform checks, with persistent state
//! saved to a per-sandbox file (`tpm.state`).

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Standard TCG PC Client TPM CRB MMIO base address.
pub const TPM_CRB_BASE: u64 = 0xFED4_0000;
/// Total MMIO size covering Localities 0..4 (20 KiB, standard DSDT `_CRS`).
pub const TPM_CRB_SIZE: u64 = 0x5000;
/// Control Area address advertised in the ACPI `TPM2` table (`TPM_CRB_BASE + 0x40`).
pub const TPM_CRB_CTRL_AREA: u64 = TPM_CRB_BASE + 0x40;

const CRB_DATA_OFFSET: usize = 0x80;
const CRB_DATA_SIZE: usize = 0x1000 - CRB_DATA_OFFSET; // 3968 bytes

// CRB register offsets within Locality 0
const REG_LOC_STATE: usize = 0x00;
const REG_LOC_CTRL: usize = 0x08;
const REG_LOC_STS: usize = 0x0C;
const REG_INTF_ID_LO: usize = 0x30;
const REG_INTF_ID_HI: usize = 0x34;
const REG_CTRL_EXT_LO: usize = 0x38;
const REG_CTRL_EXT_HI: usize = 0x3C;
const REG_CTRL_REQ: usize = 0x40;
const REG_CTRL_STS: usize = 0x44;
const REG_CTRL_CANCEL: usize = 0x48;
const REG_CTRL_START: usize = 0x4C;
const REG_INT_ENABLE: usize = 0x50;
const REG_INT_STS: usize = 0x54;
const REG_CTRL_CMD_SIZE: usize = 0x58;
const REG_CTRL_CMD_LADDR: usize = 0x5C;
const REG_CTRL_CMD_HADDR: usize = 0x60;
const REG_CTRL_RSP_SIZE: usize = 0x64;
const REG_CTRL_RSP_LADDR: usize = 0x68;
const REG_CTRL_RSP_HADDR: usize = 0x6C;

// TPM 2.0 tags & return codes
const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_RC_SUCCESS: u32 = 0x0000;
const TPM_RC_SIZE: u32 = 0x0095;
const TPM_RC_INITIALIZE: u32 = 0x0100;
const TPM_RC_COMMAND_CODE: u32 = 0x0143;
const TPM_RC_HANDLE_1: u32 = 0x018B; // TPM_RC_H + TPM_RC_1 + TPM_RC_HANDLE

// TPM 2.0 command codes
const TPM2_CC_HIERARCHY_CONTROL: u32 = 0x0000_0121;
const TPM2_CC_CLEAR: u32 = 0x0000_0126;
const TPM2_CC_CLEAR_CONTROL: u32 = 0x0000_0127;
const TPM2_CC_INCREMENTAL_SELF_TEST: u32 = 0x0000_0142;
const TPM2_CC_SELF_TEST: u32 = 0x0000_0143;
const TPM2_CC_STARTUP: u32 = 0x0000_0144;
const TPM2_CC_SHUTDOWN: u32 = 0x0000_0145;
const TPM2_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const TPM2_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
const TPM2_CC_READ_PUBLIC: u32 = 0x0000_0173;
const TPM2_CC_GET_CAPABILITY: u32 = 0x0000_017A;
const TPM2_CC_GET_RANDOM: u32 = 0x0000_017B;
const TPM2_CC_GET_TEST_RESULT: u32 = 0x0000_017C;
const TPM2_CC_PCR_READ: u32 = 0x0000_017E;
const TPM2_CC_READ_CLOCK: u32 = 0x0000_0181;
const TPM2_CC_PCR_EXTEND: u32 = 0x0000_0182;

// TPM 2.0 capabilities
const TPM_CAP_ALGS: u32 = 0;
const TPM_CAP_HANDLES: u32 = 1;
const TPM_CAP_COMMANDS: u32 = 2;
const TPM_CAP_PCRS: u32 = 5;
const TPM_CAP_TPM_PROPERTIES: u32 = 6;

// TPM 2.0 algorithms
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_SHA1: u16 = 0x0004;
const TPM_ALG_HMAC: u16 = 0x0005;
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_XOR: u16 = 0x000A;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_NULL: u16 = 0x0010;

/// Emulated CRB vTPM 2.0 device with persistent state file.
pub struct Tpm2Crb {
    state_path: Option<PathBuf>,
    loc_assigned: bool,
    idle: bool,
    int_enable: u32,
    int_sts: u32,
    started: bool,
    reset_count: u32,
    restart_count: u32,
    pcr_update_counter: u32,
    pcrs_sha256: [[u8; 32]; 24],
    boot_instant: Instant,
    rng_counter: u64,
    data_buf: Vec<u8>,
    debug: bool,
}

impl Tpm2Crb {
    /// Create a CRB vTPM 2.0 device, loading persistent counters from `state_path` if present.
    pub fn open(state_path: Option<&Path>) -> Self {
        let mut reset_count = 1u32;
        if let Some(p) = state_path
            && let Ok(bytes) = std::fs::read(p)
            && bytes.len() >= 8
            && &bytes[0..4] == b"OTPM"
        {
            reset_count = u32::from_le_bytes(bytes[4..8].try_into().unwrap()).saturating_add(1);
        }
        let dev = Self {
            state_path: state_path.map(Path::to_path_buf),
            loc_assigned: false,
            idle: false,
            int_enable: 0,
            int_sts: 0,
            started: false,
            reset_count,
            restart_count: 0,
            pcr_update_counter: 0,
            pcrs_sha256: [[0u8; 32]; 24],
            boot_instant: Instant::now(),
            rng_counter: 1,
            data_buf: vec![0u8; CRB_DATA_SIZE],
            debug: std::env::var_os("OSBX_TPM_DEBUG").is_some(),
        };
        dev.save_state();
        dev
    }

    fn save_state(&self) {
        let Some(p) = &self.state_path else {
            return;
        };
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(b"OTPM");
        buf.extend_from_slice(&self.reset_count.to_le_bytes());
        let _ = std::fs::write(p, buf);
    }

    /// Handle an MMIO read at `offset` relative to [`TPM_CRB_BASE`].
    pub fn read(&self, offset: u64, data: &mut [u8]) {
        let off = offset as usize;
        if off >= 0x1000 {
            data.fill(0xff);
            return;
        }
        if off >= CRB_DATA_OFFSET {
            let start = off - CRB_DATA_OFFSET;
            for (i, dst) in data.iter_mut().enumerate() {
                *dst = self.data_buf.get(start + i).copied().unwrap_or(0);
            }
            return;
        }
        // Serve aligned 32-bit control registers (supporting 1/2/4/8-byte slices).
        let mut cur = off;
        let mut i = 0;
        while i < data.len() {
            let reg_off = cur & !3;
            let byte_in_reg = cur & 3;
            let val = self.read_reg32(reg_off).to_le_bytes();
            let take = (4 - byte_in_reg).min(data.len() - i);
            data[i..i + take].copy_from_slice(&val[byte_in_reg..byte_in_reg + take]);
            cur += take;
            i += take;
        }
    }

    /// Handle an MMIO write at `offset` relative to [`TPM_CRB_BASE`].
    pub fn write(&mut self, offset: u64, data: &[u8]) {
        let off = offset as usize;
        if off >= 0x1000 {
            return;
        }
        if off >= CRB_DATA_OFFSET {
            let start = off - CRB_DATA_OFFSET;
            for (i, &src) in data.iter().enumerate() {
                if let Some(dst) = self.data_buf.get_mut(start + i) {
                    *dst = src;
                }
            }
            return;
        }
        let val = match data.len() {
            1 => u32::from(data[0]),
            2 => u32::from(u16::from_le_bytes([data[0], data[1]])),
            4.. => u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            _ => return,
        };
        match off & !3 {
            REG_LOC_CTRL => {
                if val & 0x01 != 0 {
                    self.loc_assigned = true;
                }
                if val & 0x02 != 0 {
                    self.loc_assigned = false;
                }
            }
            REG_CTRL_REQ => {
                if val & 0x01 != 0 {
                    self.idle = false;
                } else if val & 0x02 != 0 {
                    self.idle = true;
                }
            }
            REG_CTRL_START => {
                if val & 0x01 != 0 {
                    self.execute_command();
                }
            }
            REG_INT_ENABLE => {
                self.int_enable = val;
            }
            REG_INT_STS => {
                self.int_sts &= !val;
            }
            _ => {}
        }
    }

    fn read_reg32(&self, reg_off: usize) -> u32 {
        match reg_off {
            REG_LOC_STATE => {
                // bit 7 = tpmRegValidSts (1), bit 1 = locAssigned, bit 0 = tpmEstablished (1)
                0x81 | if self.loc_assigned { 0x02 } else { 0 }
            }
            REG_LOC_STS => u32::from(self.loc_assigned),
            // InterfaceType=1 (CRB), Version=1, CapCRBIdleBypass=1, DataXfer=64-bit, CapCRB=1, Selector=CRB
            REG_INTF_ID_LO => 0x0002_5A11,
            REG_INTF_ID_HI | REG_CTRL_EXT_LO | REG_CTRL_EXT_HI => 0,
            REG_CTRL_REQ | REG_CTRL_CANCEL | REG_CTRL_START => 0,
            REG_CTRL_STS => {
                if self.idle {
                    0x02
                } else {
                    0x00
                }
            }
            REG_INT_ENABLE => self.int_enable,
            REG_INT_STS => self.int_sts,
            REG_CTRL_CMD_SIZE | REG_CTRL_RSP_SIZE => CRB_DATA_SIZE as u32,
            REG_CTRL_CMD_LADDR | REG_CTRL_RSP_LADDR => {
                (TPM_CRB_BASE + CRB_DATA_OFFSET as u64) as u32
            }
            REG_CTRL_CMD_HADDR | REG_CTRL_RSP_HADDR => 0,
            _ => 0,
        }
    }

    fn execute_command(&mut self) {
        if self.data_buf.len() < 10 {
            self.write_response(TPM_ST_NO_SESSIONS, TPM_RC_SIZE, &[]);
            return;
        }
        let tag = u16::from_be_bytes(self.data_buf[0..2].try_into().unwrap());
        let cmd_size = u32::from_be_bytes(self.data_buf[2..6].try_into().unwrap()) as usize;
        let cmd_code = u32::from_be_bytes(self.data_buf[6..10].try_into().unwrap());
        if cmd_size < 10 || cmd_size > self.data_buf.len() {
            self.write_response(TPM_ST_NO_SESSIONS, TPM_RC_SIZE, &[]);
            return;
        }
        let body = self.data_buf[10..cmd_size].to_vec();
        let (rc, payload) = match cmd_code {
            TPM2_CC_STARTUP => {
                if self.started {
                    (TPM_RC_INITIALIZE, Vec::new())
                } else {
                    self.started = true;
                    (TPM_RC_SUCCESS, Vec::new())
                }
            }
            TPM2_CC_SHUTDOWN => {
                self.save_state();
                (TPM_RC_SUCCESS, Vec::new())
            }
            TPM2_CC_SELF_TEST => (TPM_RC_SUCCESS, Vec::new()),
            TPM2_CC_INCREMENTAL_SELF_TEST => (TPM_RC_SUCCESS, 0u32.to_be_bytes().to_vec()),
            TPM2_CC_GET_TEST_RESULT => {
                let mut out = Vec::with_capacity(6);
                out.extend_from_slice(&0u16.to_be_bytes()); // outData.size = 0
                out.extend_from_slice(&TPM_RC_SUCCESS.to_be_bytes());
                (TPM_RC_SUCCESS, out)
            }
            TPM2_CC_GET_CAPABILITY => self.handle_get_capability(&body),
            TPM2_CC_GET_RANDOM => self.handle_get_random(&body),
            TPM2_CC_PCR_READ => self.handle_pcr_read(&body),
            TPM2_CC_PCR_EXTEND => self.handle_pcr_extend(&body),
            TPM2_CC_READ_CLOCK => self.handle_read_clock(),
            TPM2_CC_CLEAR => {
                self.pcrs_sha256 = [[0u8; 32]; 24];
                self.pcr_update_counter = self.pcr_update_counter.wrapping_add(1);
                (TPM_RC_SUCCESS, Vec::new())
            }
            TPM2_CC_CLEAR_CONTROL | TPM2_CC_HIERARCHY_CONTROL | TPM2_CC_FLUSH_CONTEXT => {
                (TPM_RC_SUCCESS, Vec::new())
            }
            TPM2_CC_NV_READ_PUBLIC | TPM2_CC_READ_PUBLIC => (TPM_RC_HANDLE_1, Vec::new()),
            _ => (TPM_RC_COMMAND_CODE, Vec::new()),
        };
        let out_len = self.write_response(tag, rc, &payload);
        if self.debug {
            let extra = if cmd_code == TPM2_CC_GET_CAPABILITY && body.len() >= 12 {
                format!(
                    " cap={} prop=0x{:x} cnt={}",
                    u32::from_be_bytes(body[0..4].try_into().unwrap()),
                    u32::from_be_bytes(body[4..8].try_into().unwrap()),
                    u32::from_be_bytes(body[8..12].try_into().unwrap()),
                )
            } else {
                String::new()
            };
            eprintln!(
                "[tpm] tag=0x{tag:04x} cc=0x{cmd_code:04x}{extra} in={cmd_size} -> rc=0x{rc:04x} out={out_len}",
            );
        }
    }

    fn write_response(&mut self, req_tag: u16, rc: u32, payload: &[u8]) -> usize {
        if rc == TPM_RC_SUCCESS && req_tag == TPM_ST_SESSIONS {
            // TPM 2.0 Part 3: successful session response carries `parameterSize (u32 BE)` +
            // parameters + minimal PWAP `TPMS_AUTH_RESPONSE` (nonce=0, attrs=continue(1), hmac=0).
            const PWAP_RESP: [u8; 5] = [0x00, 0x00, 0x01, 0x00, 0x00];
            let param_len = payload.len().min(self.data_buf.len().saturating_sub(19));
            let total = 10 + 4 + param_len + PWAP_RESP.len();
            self.data_buf[0..2].copy_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
            self.data_buf[2..6].copy_from_slice(&(total as u32).to_be_bytes());
            self.data_buf[6..10].copy_from_slice(&rc.to_be_bytes());
            self.data_buf[10..14].copy_from_slice(&(param_len as u32).to_be_bytes());
            self.data_buf[14..14 + param_len].copy_from_slice(&payload[..param_len]);
            self.data_buf[14 + param_len..total].copy_from_slice(&PWAP_RESP);
            return total;
        }
        let total = (10 + payload.len()).min(self.data_buf.len());
        self.data_buf[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        self.data_buf[2..6].copy_from_slice(&(total as u32).to_be_bytes());
        self.data_buf[6..10].copy_from_slice(&rc.to_be_bytes());
        let copy_len = total - 10;
        self.data_buf[10..10 + copy_len].copy_from_slice(&payload[..copy_len]);
        total
    }

    fn handle_get_capability(&self, body: &[u8]) -> (u32, Vec<u8>) {
        if body.len() < 12 {
            return (TPM_RC_SIZE, Vec::new());
        }
        let cap = u32::from_be_bytes(body[0..4].try_into().unwrap());
        let prop = u32::from_be_bytes(body[4..8].try_into().unwrap());
        let count = u32::from_be_bytes(body[8..12].try_into().unwrap()) as usize;

        let mut out = Vec::new();
        match cap {
            TPM_CAP_TPM_PROPERTIES => {
                let fixed_props: &[(u32, u32)] = &[
                    (0x100, 0x322E_3000),               // PT_FAMILY_INDICATOR ("2.0\0")
                    (0x101, 0),                         // PT_LEVEL
                    (0x102, 159),                       // PT_REVISION (1.59)
                    (0x103, 1),                         // PT_DAY_OF_YEAR
                    (0x104, 2025),                      // PT_YEAR
                    (0x105, 0x4F53_4258),               // PT_MANUFACTURER ("OSBX")
                    (0x106, 0x4F53_4258),               // PT_VENDOR_STRING_1 ("OSBX")
                    (0x107, 0x2076_5450),               // PT_VENDOR_STRING_2 (" vTP")
                    (0x108, 0x4D20_322E),               // PT_VENDOR_STRING_3 ("M 2.")
                    (0x109, 0x3000_0000),               // PT_VENDOR_STRING_4 ("0\0\0\0")
                    (0x10A, 1),                         // PT_VENDOR_TPM_TYPE
                    (0x10B, 0x0002_0000),               // PT_FIRMWARE_VERSION_1
                    (0x10C, 0x0001_0000),               // PT_FIRMWARE_VERSION_2
                    (0x10D, CRB_DATA_SIZE as u32),      // PT_INPUT_BUFFER
                    (0x10E, 3),                         // PT_HR_TRANSIENT_MIN
                    (0x10F, 7),                         // PT_HR_PERSISTENT_MIN
                    (0x110, 3),                         // PT_HR_LOADED_MIN
                    (0x111, 64),                        // PT_ACTIVE_SESSIONS_MAX
                    (0x112, 24),                        // PT_PCR_COUNT
                    (0x113, 3),                         // PT_PCR_SELECT_MIN
                    (0x114, 0xFFFF),                    // PT_CONTEXT_GAP_MAX
                    (0x116, 64),                        // PT_NV_COUNTERS_MAX
                    (0x117, 2048),                      // PT_NV_INDEX_MAX
                    (0x118, 0),                         // PT_MEMORY
                    (0x119, 0x0040_0000),               // PT_CLOCK_UPDATE
                    (0x11A, u32::from(TPM_ALG_SHA256)), // PT_CONTEXT_HASH
                    (0x11B, u32::from(TPM_ALG_AES)),    // PT_CONTEXT_SYM
                    (0x11C, 128),                       // PT_CONTEXT_SYM_SIZE
                    (0x11D, 255),                       // PT_ORDERLY_COUNT
                    (0x11E, CRB_DATA_SIZE as u32),      // PT_MAX_COMMAND_SIZE
                    (0x11F, CRB_DATA_SIZE as u32),      // PT_MAX_RESPONSE_SIZE
                    (0x120, 32),                        // PT_MAX_DIGEST
                    (0x121, 1024),                      // PT_MAX_OBJECT_CONTEXT
                    (0x122, 1024),                      // PT_MAX_SESSION_CONTEXT
                    (0x123, 1),                         // PT_PS_FAMILY_INDICATOR
                    (0x124, 0),                         // PT_PS_LEVEL
                    (0x125, 0x0104),                    // PT_PS_REVISION
                    (0x126, 1),                         // PT_PS_DAY_OF_YEAR
                    (0x127, 2025),                      // PT_PS_YEAR
                    (0x128, 128),                       // PT_SPLIT_MAX
                    (0x129, 16),                        // PT_TOTAL_COMMANDS
                    (0x12A, 16),                        // PT_LIBRARY_COMMANDS
                    (0x12B, 0),                         // PT_VENDOR_COMMANDS
                    (0x12C, 2048),                      // PT_NV_BUFFER_MAX
                    (0x12D, 0),                         // PT_MODES
                    (0x12E, 1024),                      // PT_MAX_CAP_BUFFER
                ];
                let var_props: &[(u32, u32)] = &[
                    (0x200, 0),           // PT_PERMANENT
                    (0x201, 0x8000_0007), // PT_STARTUP_CLEAR (phEnable|shEnable|ehEnable|orderly)
                    (0x202, 0),           // PT_HR_NV_INDEX
                    (0x203, 0),           // PT_HR_LOADED
                    (0x204, 3),           // PT_HR_LOADED_AVAIL
                    (0x205, 0),           // PT_HR_ACTIVE
                    (0x206, 64),          // PT_HR_ACTIVE_AVAIL
                    (0x207, 3),           // PT_HR_TRANSIENT_AVAIL
                    (0x208, 0),           // PT_HR_PERSISTENT
                    (0x209, 7),           // PT_HR_PERSISTENT_AVAIL
                    (0x20A, 0),           // PT_NV_COUNTERS
                    (0x20B, 64),          // PT_NV_COUNTERS_AVAIL
                    (0x20C, 0),           // PT_ALGORITHM_SET
                    (0x20D, 0),           // PT_LOADED_CURVES
                    (0x20E, 0),           // PT_LOCKOUT_COUNTER
                    (0x20F, 32),          // PT_MAX_AUTH_FAIL
                    (0x210, 1000),        // PT_LOCKOUT_INTERVAL
                    (0x211, 1000),        // PT_LOCKOUT_RECOVERY
                    (0x212, 0),           // PT_NV_WRITE_RECOVERY
                    (0x213, 0),           // PT_AUDIT_COUNTER_0
                    (0x214, 0),           // PT_AUDIT_COUNTER_1
                ];
                // TCG TPM 2.0 Part 3 §30.2: only return properties within the requested group.
                let group = if prop < 0x200 { fixed_props } else { var_props };
                let matching: Vec<(u32, u32)> =
                    group.iter().copied().filter(|(k, _)| *k >= prop).collect();
                let take = matching.len().min(count);
                let more = u8::from(matching.len() > take);
                out.push(more);
                out.extend_from_slice(&cap.to_be_bytes());
                out.extend_from_slice(&(take as u32).to_be_bytes());
                for (k, v) in &matching[..take] {
                    out.extend_from_slice(&k.to_be_bytes());
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            TPM_CAP_PCRS => {
                out.push(0); // moreData = NO
                out.extend_from_slice(&cap.to_be_bytes());
                out.extend_from_slice(&1u32.to_be_bytes()); // 1 bank: SHA-256
                out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
                out.push(3); // sizeofSelect
                out.extend_from_slice(&[0xff, 0xff, 0xff]); // PCRs 0..23
            }
            TPM_CAP_ALGS => {
                let algs: &[(u16, u32)] = &[
                    (TPM_ALG_RSA, 0x0000_0001),
                    (TPM_ALG_SHA1, 0x0000_0004),
                    (TPM_ALG_HMAC, 0x0000_0005),
                    (TPM_ALG_AES, 0x0000_0002),
                    (TPM_ALG_XOR, 0x0000_0006),
                    (TPM_ALG_SHA256, 0x0000_0004),
                    (TPM_ALG_NULL, 0x0000_0000),
                ];
                let matching: Vec<(u16, u32)> = algs
                    .iter()
                    .copied()
                    .filter(|(a, _)| u32::from(*a) >= prop)
                    .collect();
                let take = matching.len().min(count);
                out.push(u8::from(matching.len() > take));
                out.extend_from_slice(&cap.to_be_bytes());
                out.extend_from_slice(&(take as u32).to_be_bytes());
                for (a, attr) in &matching[..take] {
                    out.extend_from_slice(&a.to_be_bytes());
                    out.extend_from_slice(&attr.to_be_bytes());
                }
            }
            TPM_CAP_COMMANDS => {
                let cmds: &[u32] = &[
                    TPM2_CC_HIERARCHY_CONTROL,
                    TPM2_CC_CLEAR,
                    TPM2_CC_CLEAR_CONTROL,
                    TPM2_CC_INCREMENTAL_SELF_TEST,
                    TPM2_CC_SELF_TEST,
                    TPM2_CC_STARTUP,
                    TPM2_CC_SHUTDOWN,
                    TPM2_CC_FLUSH_CONTEXT,
                    TPM2_CC_NV_READ_PUBLIC,
                    TPM2_CC_READ_PUBLIC,
                    TPM2_CC_GET_CAPABILITY,
                    TPM2_CC_GET_RANDOM,
                    TPM2_CC_GET_TEST_RESULT,
                    TPM2_CC_PCR_READ,
                    TPM2_CC_READ_CLOCK,
                    TPM2_CC_PCR_EXTEND,
                ];
                let matching: Vec<u32> = cmds.iter().copied().filter(|c| *c >= prop).collect();
                let take = matching.len().min(count);
                out.push(u8::from(matching.len() > take));
                out.extend_from_slice(&cap.to_be_bytes());
                out.extend_from_slice(&(take as u32).to_be_bytes());
                for c in &matching[..take] {
                    out.extend_from_slice(&c.to_be_bytes());
                }
            }
            TPM_CAP_HANDLES => {
                out.push(0);
                out.extend_from_slice(&cap.to_be_bytes());
                out.extend_from_slice(&0u32.to_be_bytes());
            }
            _ => {
                out.push(0);
                out.extend_from_slice(&cap.to_be_bytes());
                out.extend_from_slice(&0u32.to_be_bytes());
            }
        }
        (TPM_RC_SUCCESS, out)
    }

    fn handle_get_random(&mut self, body: &[u8]) -> (u32, Vec<u8>) {
        if body.len() < 2 {
            return (TPM_RC_SIZE, Vec::new());
        }
        let want = (u16::from_be_bytes([body[0], body[1]]) as usize).min(64);
        let mut bytes = Vec::with_capacity(want);
        while bytes.len() < want {
            let mut h = RandomState::new().build_hasher();
            self.rng_counter = self.rng_counter.wrapping_add(1);
            h.write_u64(self.rng_counter);
            h.write_u128(self.boot_instant.elapsed().as_nanos());
            bytes.extend_from_slice(&h.finish().to_le_bytes());
        }
        bytes.truncate(want);
        let mut out = Vec::with_capacity(2 + bytes.len());
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&bytes);
        (TPM_RC_SUCCESS, out)
    }

    fn handle_pcr_read(&self, body: &[u8]) -> (u32, Vec<u8>) {
        if body.len() < 4 {
            return (TPM_RC_SIZE, Vec::new());
        }
        let sel_count = u32::from_be_bytes(body[0..4].try_into().unwrap()) as usize;
        let mut pos = 4usize;
        let mut selected: Vec<usize> = Vec::new();
        let mut out_sel_bits = [0u8; 3];
        for _ in 0..sel_count {
            if pos + 3 > body.len() {
                break;
            }
            let alg = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let sz = body[pos + 2] as usize;
            pos += 3;
            if pos + sz > body.len() {
                break;
            }
            if alg == TPM_ALG_SHA256 {
                for pcr in 0..24 {
                    let byte_i = pcr / 8;
                    let bit_i = pcr % 8;
                    if byte_i < sz && (body[pos + byte_i] & (1 << bit_i)) != 0 && selected.len() < 8
                    {
                        selected.push(pcr);
                        out_sel_bits[byte_i] |= 1 << bit_i;
                    }
                }
            }
            pos += sz;
        }
        let mut out = Vec::new();
        out.extend_from_slice(&self.pcr_update_counter.to_be_bytes());
        // pcrSelectionOut (1 bank)
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.push(3);
        out.extend_from_slice(&out_sel_bits);
        // pcrValues (TPML_DIGEST)
        out.extend_from_slice(&(selected.len() as u32).to_be_bytes());
        for pcr in selected {
            out.extend_from_slice(&32u16.to_be_bytes());
            out.extend_from_slice(&self.pcrs_sha256[pcr]);
        }
        (TPM_RC_SUCCESS, out)
    }

    fn handle_pcr_extend(&mut self, body: &[u8]) -> (u32, Vec<u8>) {
        if body.len() < 4 {
            return (TPM_RC_SIZE, Vec::new());
        }
        let pcr = u32::from_be_bytes(body[0..4].try_into().unwrap()) as usize;
        if pcr < 24 {
            // Mix existing PCR value with the incoming digest bytes deterministically.
            let mut h = RandomState::new().build_hasher();
            h.write(&self.pcrs_sha256[pcr]);
            h.write(&body[4..]);
            let mix = h.finish().to_le_bytes();
            for (i, b) in self.pcrs_sha256[pcr].iter_mut().enumerate() {
                *b ^= mix[i % 8];
            }
            self.pcr_update_counter = self.pcr_update_counter.wrapping_add(1);
        }
        (TPM_RC_SUCCESS, Vec::new())
    }

    fn handle_read_clock(&self) -> (u32, Vec<u8>) {
        let ms = self.boot_instant.elapsed().as_millis() as u64;
        let mut out = Vec::with_capacity(25);
        out.extend_from_slice(&ms.to_be_bytes()); // time
        out.extend_from_slice(&ms.to_be_bytes()); // clockInfo.clock
        out.extend_from_slice(&self.reset_count.to_be_bytes());
        out.extend_from_slice(&self.restart_count.to_be_bytes());
        out.push(1); // safe = YES
        (TPM_RC_SUCCESS, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send_cmd(tpm: &mut Tpm2Crb, code: u32, body: &[u8]) -> (u32, Vec<u8>) {
        let len = (10 + body.len()) as u32;
        let mut cmd = Vec::with_capacity(len as usize);
        cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&len.to_be_bytes());
        cmd.extend_from_slice(&code.to_be_bytes());
        cmd.extend_from_slice(body);
        tpm.write(CRB_DATA_OFFSET as u64, &cmd);
        tpm.write(REG_CTRL_START as u64, &1u32.to_le_bytes());

        let mut hdr = [0u8; 10];
        tpm.read(CRB_DATA_OFFSET as u64, &mut hdr);
        let rsp_len = u32::from_be_bytes(hdr[2..6].try_into().unwrap()) as usize;
        let rc = u32::from_be_bytes(hdr[6..10].try_into().unwrap());
        let mut payload = vec![0u8; rsp_len.saturating_sub(10)];
        if !payload.is_empty() {
            tpm.read((CRB_DATA_OFFSET + 10) as u64, &mut payload);
        }
        (rc, payload)
    }

    #[test]
    fn crb_tpm2_startup_and_get_capability() {
        let mut tpm = Tpm2Crb::open(None);
        // Request Locality 0
        tpm.write(REG_LOC_CTRL as u64, &1u32.to_le_bytes());
        let mut loc_state = [0u8; 4];
        tpm.read(REG_LOC_STATE as u64, &mut loc_state);
        assert_eq!(u32::from_le_bytes(loc_state) & 0x83, 0x83);

        // TPM2_Startup(TPM_SU_CLEAR = 0x0000)
        let (rc, _) = send_cmd(&mut tpm, TPM2_CC_STARTUP, &0u16.to_be_bytes());
        assert_eq!(rc, TPM_RC_SUCCESS);

        // TPM2_SelfTest(fullTest = 1)
        let (rc, _) = send_cmd(&mut tpm, TPM2_CC_SELF_TEST, &[1]);
        assert_eq!(rc, TPM_RC_SUCCESS);

        // TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, PT_FAMILY_INDICATOR = 0x100, count = 4)
        let mut cap_req = Vec::new();
        cap_req.extend_from_slice(&TPM_CAP_TPM_PROPERTIES.to_be_bytes());
        cap_req.extend_from_slice(&0x100u32.to_be_bytes());
        cap_req.extend_from_slice(&4u32.to_be_bytes());
        let (rc, rsp) = send_cmd(&mut tpm, TPM2_CC_GET_CAPABILITY, &cap_req);
        assert_eq!(rc, TPM_RC_SUCCESS);
        // moreData=1, cap=6, count=4, first property = (0x100, "2.0\0")
        assert_eq!(rsp[0], 1);
        assert_eq!(u32::from_be_bytes(rsp[5..9].try_into().unwrap()), 4);
        assert_eq!(u32::from_be_bytes(rsp[9..13].try_into().unwrap()), 0x100);
        assert_eq!(&rsp[13..17], b"2.0\0");

        // TPM2_GetRandom(16)
        let (rc, rnd) = send_cmd(&mut tpm, TPM2_CC_GET_RANDOM, &16u16.to_be_bytes());
        assert_eq!(rc, TPM_RC_SUCCESS);
        assert_eq!(u16::from_be_bytes([rnd[0], rnd[1]]), 16);
        assert_eq!(rnd.len(), 18);
    }
}
