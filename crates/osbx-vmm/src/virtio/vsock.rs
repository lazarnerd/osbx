//! virtio-vsock, implemented in userspace.
//!
//! The guest sees a standard vsock device (CID 3); the host side is a plain Rust API:
//! [`VsockHost::listen`] accepts guest-initiated connections and [`VsockHost::connect`]
//! opens host-initiated ones. Streams are blocking `Read + Write`. Because it is not tied to
//! the Linux `vhost-vsock` kernel module, the same device works on any hypervisor backend.
//!
//! Flow control follows the virtio spec: each side advertises `buf_alloc` and `fwd_cnt`, and a
//! sender never has more than `buf_alloc` unconsumed bytes in flight.

use super::{
    Activation, GuestMem, INT_USED_RING, Interrupt, SharedQueue, VIRTIO_F_VERSION_1, VirtioDevice,
};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use virtio_queue::{QueueOwnedT, QueueT};

const HDR: usize = 44;
const OP_REQUEST: u16 = 1;
const OP_RESPONSE: u16 = 2;
const OP_RST: u16 = 3;
const OP_SHUTDOWN: u16 = 4;
const OP_RW: u16 = 5;
const OP_CREDIT_UPDATE: u16 = 6;
const OP_CREDIT_REQUEST: u16 = 7;
const TYPE_STREAM: u16 = 1;
/// The host's CID.
pub const HOST_CID: u64 = 2;
/// Receive buffer we advertise per connection.
const BUF_ALLOC: u32 = 256 * 1024;
/// Most bytes a host writer may queue before blocking.
const TX_LIMIT: usize = 1 << 20;

#[derive(Clone, Copy, Default, Debug)]
struct Hdr {
    src_cid: u64,
    dst_cid: u64,
    src_port: u32,
    dst_port: u32,
    len: u32,
    ty: u16,
    op: u16,
    flags: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
}

impl Hdr {
    fn parse(b: &[u8; HDR]) -> Self {
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let u16_at = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap());
        Self {
            src_cid: u64_at(0),
            dst_cid: u64_at(8),
            src_port: u32_at(16),
            dst_port: u32_at(20),
            len: u32_at(24),
            ty: u16_at(28),
            op: u16_at(30),
            flags: u32_at(32),
            buf_alloc: u32_at(36),
            fwd_cnt: u32_at(40),
        }
    }
    fn to_bytes(self) -> [u8; HDR] {
        let mut b = [0u8; HDR];
        b[0..8].copy_from_slice(&self.src_cid.to_le_bytes());
        b[8..16].copy_from_slice(&self.dst_cid.to_le_bytes());
        b[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        b[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        b[24..28].copy_from_slice(&self.len.to_le_bytes());
        b[28..30].copy_from_slice(&self.ty.to_le_bytes());
        b[30..32].copy_from_slice(&self.op.to_le_bytes());
        b[32..36].copy_from_slice(&self.flags.to_le_bytes());
        b[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        b[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        b
    }
}

/// (guest port, host port)
type Key = (u32, u32);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum State {
    Connecting,
    Established,
}

struct Conn {
    state: State,
    rx: VecDeque<u8>,
    rx_eof: bool,
    reset: bool,
    tx: VecDeque<u8>,
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
    tx_cnt: u32,
    fwd_cnt: u32,
    last_reported: u32,
}

impl Conn {
    fn new(state: State) -> Self {
        Self {
            state,
            rx: VecDeque::new(),
            rx_eof: false,
            reset: false,
            tx: VecDeque::new(),
            peer_buf_alloc: 0,
            peer_fwd_cnt: 0,
            tx_cnt: 0,
            fwd_cnt: 0,
            last_reported: 0,
        }
    }
    fn credit(&self) -> usize {
        let in_flight = self.tx_cnt.wrapping_sub(self.peer_fwd_cnt);
        self.peer_buf_alloc.saturating_sub(in_flight) as usize
    }
}

struct Active {
    mem: GuestMem,
    rx: SharedQueue,
    tx: SharedQueue,
    irq: Interrupt,
}

#[derive(Default)]
struct Inner {
    active: Option<Active>,
    conns: HashMap<Key, Conn>,
    listeners: HashMap<u32, Sender<VsockStream>>,
    ctrl: VecDeque<Hdr>,
    pending_accepts: Vec<(Sender<VsockStream>, Key)>,
    next_host_port: u32,
    guest_cid: u64,
}

struct Shared {
    inner: Mutex<Inner>,
    cv: Condvar,
}

/// The virtio device half (hand to the transport).
pub struct VsockDevice {
    shared: Arc<Shared>,
}

/// The host half: listen for and open connections.
#[derive(Clone)]
pub struct VsockHost {
    shared: Arc<Shared>,
}

/// Create a vsock device for a guest with `guest_cid` and its host handle.
pub fn vsock(guest_cid: u64) -> (VsockDevice, VsockHost) {
    let inner = Inner {
        next_host_port: 4096,
        guest_cid,
        ..Inner::default()
    };
    let shared = Arc::new(Shared {
        inner: Mutex::new(inner),
        cv: Condvar::new(),
    });
    (
        VsockDevice {
            shared: shared.clone(),
        },
        VsockHost { shared },
    )
}

impl VsockHost {
    /// Accept guest-initiated connections to host `port`. Streams arrive on the receiver.
    pub fn listen(&self, port: u32) -> Receiver<VsockStream> {
        let (tx, rx) = mpsc::channel();
        self.shared.inner.lock().unwrap().listeners.insert(port, tx);
        rx
    }

    /// Open a connection to the guest's `port`.
    pub fn connect(&self, port: u32, timeout: Duration) -> io::Result<VsockStream> {
        let mut g = self.shared.inner.lock().unwrap();
        let host_port = g.next_host_port;
        g.next_host_port += 1;
        let key = (port, host_port);
        g.conns.insert(key, Conn::new(State::Connecting));
        let hdr = ctrl_hdr(&g, key, OP_REQUEST, 0);
        g.ctrl.push_back(hdr);
        pump(&mut g);
        let deadline = Instant::now() + timeout;
        loop {
            match g.conns.get(&key) {
                Some(c) if c.reset => {
                    g.conns.remove(&key);
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "guest refused the vsock connection",
                    ));
                }
                Some(c) if c.state == State::Established => break,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection vanished",
                    ));
                }
                _ => {}
            }
            let now = Instant::now();
            if now >= deadline {
                g.conns.remove(&key);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "vsock connect timed out (is the guest agent running?)",
                ));
            }
            g = self.shared.cv.wait_timeout(g, deadline - now).unwrap().0;
        }
        drop(g);
        Ok(VsockStream::new(self.shared.clone(), key))
    }

    /// True once the guest driver has initialized the device.
    pub fn is_active(&self) -> bool {
        self.shared.inner.lock().unwrap().active.is_some()
    }
}

/// Shared by every clone of a stream; the last one dropped closes the connection.
struct Handle {
    shared: Arc<Shared>,
    key: Key,
}

/// A connected vsock stream (blocking). Clone it with [`VsockStream::try_clone`] to read and
/// write from different threads; the connection closes when the last clone is dropped.
pub struct VsockStream {
    h: Arc<Handle>,
}

impl VsockStream {
    fn new(shared: Arc<Shared>, key: Key) -> Self {
        Self {
            h: Arc::new(Handle { shared, key }),
        }
    }

    /// The guest-side port of this connection.
    pub fn guest_port(&self) -> u32 {
        self.h.key.0
    }

    /// A second handle to the same connection.
    pub fn try_clone(&self) -> VsockStream {
        VsockStream { h: self.h.clone() }
    }

    /// Send everything queued, then tell the guest we will send no more (it reads EOF).
    pub fn shutdown_write(&self) {
        let sh = &self.h.shared;
        let g = wait_drained(
            sh,
            sh.inner.lock().unwrap(),
            self.h.key,
            Duration::from_secs(5),
        );
        let mut g = g;
        if g.conns.get(&self.h.key).is_some_and(|c| !c.reset) {
            let mut hdr = ctrl_hdr(&g, self.h.key, OP_SHUTDOWN, 0);
            hdr.flags = 2;
            g.ctrl.push_back(hdr);
            pump(&mut g);
        }
    }
}

/// Wait (bounded) until the connection's queued output has been handed to the guest.
fn wait_drained<'a>(
    shared: &'a Shared,
    mut g: MutexGuard<'a, Inner>,
    key: Key,
    timeout: Duration,
) -> MutexGuard<'a, Inner> {
    let deadline = Instant::now() + timeout;
    loop {
        if g.conns.get(&key).is_none_or(|c| c.tx.is_empty() || c.reset) {
            return g;
        }
        let now = Instant::now();
        if now >= deadline {
            return g;
        }
        g = shared.cv.wait_timeout(g, deadline - now).unwrap().0;
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        let mut g = wait_drained(
            &self.shared,
            self.shared.inner.lock().unwrap(),
            self.key,
            Duration::from_secs(5),
        );
        if let Some(c) = g.conns.remove(&self.key)
            && !c.reset
        {
            let mut hdr = ctrl_hdr(&g, self.key, OP_SHUTDOWN, 0);
            hdr.flags = 3;
            g.ctrl.push_back(hdr);
            pump(&mut g);
        }
        self.shared.cv.notify_all();
    }
}

impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let (sh, key) = (&self.h.shared, self.h.key);
        let mut g = sh.inner.lock().unwrap();
        loop {
            let Some(c) = g.conns.get_mut(&key) else {
                return Ok(0);
            };
            if !c.rx.is_empty() {
                let n = buf.len().min(c.rx.len());
                for (i, b) in c.rx.drain(..n).enumerate() {
                    buf[i] = b;
                }
                c.fwd_cnt = c.fwd_cnt.wrapping_add(n as u32);
                if c.fwd_cnt.wrapping_sub(c.last_reported) >= BUF_ALLOC / 4 {
                    c.last_reported = c.fwd_cnt;
                    let hdr = ctrl_hdr(&g, key, OP_CREDIT_UPDATE, 0);
                    g.ctrl.push_back(hdr);
                    pump(&mut g);
                }
                return Ok(n);
            }
            if c.rx_eof || c.reset {
                return Ok(0);
            }
            g = sh.cv.wait(g).unwrap();
        }
    }
}

impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (sh, key) = (&self.h.shared, self.h.key);
        let mut g = sh.inner.lock().unwrap();
        loop {
            let Some(c) = g.conns.get_mut(&key) else {
                return Err(io::ErrorKind::BrokenPipe.into());
            };
            if c.reset {
                return Err(io::ErrorKind::ConnectionReset.into());
            }
            if c.tx.len() < TX_LIMIT {
                let n = buf.len().min(TX_LIMIT - c.tx.len());
                c.tx.extend(&buf[..n]);
                pump(&mut g);
                return Ok(n);
            }
            g = sh.cv.wait(g).unwrap();
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        let (sh, key) = (&self.h.shared, self.h.key);
        let g = wait_drained(sh, sh.inner.lock().unwrap(), key, Duration::from_secs(30));
        match g.conns.get(&key) {
            None => Ok(()),
            Some(c) if c.reset => Err(io::ErrorKind::ConnectionReset.into()),
            Some(c) if c.tx.is_empty() => Ok(()),
            Some(_) => Err(io::ErrorKind::TimedOut.into()),
        }
    }
}

fn ctrl_hdr(g: &Inner, key: Key, op: u16, len: u32) -> Hdr {
    let fwd = g.conns.get(&key).map_or(0, |c| c.fwd_cnt);
    Hdr {
        src_cid: HOST_CID,
        dst_cid: g.guest_cid,
        src_port: key.1,
        dst_port: key.0,
        len,
        ty: TYPE_STREAM,
        op,
        flags: 0,
        buf_alloc: BUF_ALLOC,
        fwd_cnt: fwd,
    }
}

/// A reply for a packet that matches no connection.
fn rst_for(g: &Inner, h: &Hdr) -> Hdr {
    Hdr {
        src_cid: HOST_CID,
        dst_cid: g.guest_cid,
        src_port: h.dst_port,
        dst_port: h.src_port,
        len: 0,
        ty: TYPE_STREAM,
        op: OP_RST,
        flags: 0,
        buf_alloc: BUF_ALLOC,
        fwd_cnt: 0,
    }
}

/// Move queued control packets and connection data into the guest's receive queue.
fn pump(g: &mut Inner) {
    let Some(act) = g.active.as_ref() else { return };
    let (mem, rxq, irq) = (act.mem.clone(), act.rx.clone(), act.irq.clone());
    let mut used_any = false;
    {
        let mut q = rxq.lock().unwrap();
        loop {
            // what to send next: a control packet, else data for a connection with credit
            let ctrl = g.ctrl.front().copied();
            let data_key = if ctrl.is_none() {
                g.conns
                    .iter()
                    .find(|(_, c)| {
                        c.state == State::Established
                            && !c.tx.is_empty()
                            && c.credit() > 0
                            && !c.reset
                    })
                    .map(|(k, _)| *k)
            } else {
                None
            };
            if ctrl.is_none() && data_key.is_none() {
                break;
            }
            let Some(chain) = q.pop_descriptor_chain(&mem) else {
                break;
            };
            let head = chain.head_index();
            let Ok(mut wr) = chain.writer(&mem) else {
                let _ = q.add_used(&mem, head, 0);
                continue;
            };
            let room = wr.available_bytes();
            if room < HDR {
                let _ = q.add_used(&mem, head, 0);
                used_any = true;
                continue;
            }
            let (hdr, payload): (Hdr, Vec<u8>) = if let Some(h) = ctrl {
                g.ctrl.pop_front();
                (h, Vec::new())
            } else {
                let key = data_key.unwrap();
                let n = {
                    let c = &g.conns[&key];
                    (room - HDR).min(c.credit()).min(c.tx.len())
                };
                let payload: Vec<u8> = g.conns.get_mut(&key).unwrap().tx.drain(..n).collect();
                g.conns.get_mut(&key).unwrap().tx_cnt = g.conns[&key].tx_cnt.wrapping_add(n as u32);
                let mut h = ctrl_hdr(g, key, OP_RW, n as u32);
                h.fwd_cnt = g.conns[&key].fwd_cnt;
                (h, payload)
            };
            let ok = wr.write_all(&hdr.to_bytes()).is_ok() && wr.write_all(&payload).is_ok();
            let _ = q.add_used(
                &mem,
                head,
                if ok { (HDR + payload.len()) as u32 } else { 0 },
            );
            used_any = true;
        }
        if used_any && !q.needs_notification(&mem).unwrap_or(true) {
            used_any = false;
        }
    }
    if used_any {
        irq.signal(INT_USED_RING);
    }
}

/// Handle one packet from the guest.
fn handle_packet(g: &mut Inner, h: Hdr, payload: &[u8]) {
    if h.ty != TYPE_STREAM || h.dst_cid != HOST_CID {
        g.ctrl.push_back(rst_for(g, &h));
        return;
    }
    let key = (h.src_port, h.dst_port);
    match h.op {
        OP_REQUEST => {
            let Some(listener) = g.listeners.get(&h.dst_port).cloned() else {
                g.ctrl.push_back(rst_for(g, &h));
                return;
            };
            let mut c = Conn::new(State::Established);
            c.peer_buf_alloc = h.buf_alloc;
            c.peer_fwd_cnt = h.fwd_cnt;
            g.conns.insert(key, c);
            let resp = ctrl_hdr(g, key, OP_RESPONSE, 0);
            g.ctrl.push_back(resp);
            // the stream needs the shared state; recover it from the listener-owning side
            // (the Arc is attached by `deliver` in the device, which owns the shared handle)
            g.pending_accepts.push((listener, key));
        }
        _ => {
            let Some(c) = g.conns.get_mut(&key) else {
                if h.op != OP_RST {
                    g.ctrl.push_back(rst_for(g, &h));
                }
                return;
            };
            c.peer_buf_alloc = h.buf_alloc;
            c.peer_fwd_cnt = h.fwd_cnt;
            match h.op {
                OP_RESPONSE => c.state = State::Established,
                OP_RST => {
                    c.reset = true;
                    c.rx_eof = true;
                }
                OP_SHUTDOWN => {
                    if h.flags & 2 != 0 {
                        c.rx_eof = true;
                    }
                    if h.flags & 3 == 3 {
                        let rst = rst_for(g, &h);
                        g.conns.get_mut(&key).unwrap().reset = true;
                        g.ctrl.push_back(rst);
                    }
                }
                OP_RW => c.rx.extend(payload),
                OP_CREDIT_REQUEST => {
                    let upd = ctrl_hdr(g, key, OP_CREDIT_UPDATE, 0);
                    g.ctrl.push_back(upd);
                }
                _ => {}
            }
        }
    }
}

impl VirtioDevice for VsockDevice {
    fn device_type(&self) -> u32 {
        19
    }
    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }
    fn queue_max_sizes(&self) -> Vec<u16> {
        vec![256, 256, 64] // rx, tx, event
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let cid = self.shared.inner.lock().unwrap().guest_cid.to_le_bytes();
        for (i, b) in data.iter_mut().enumerate() {
            *b = cid.get(offset as usize + i).copied().unwrap_or(0);
        }
    }
    fn activate(&mut self, a: Activation) {
        let mut g = self.shared.inner.lock().unwrap();
        g.active = Some(Active {
            mem: a.mem,
            rx: a.queues[0].clone(),
            tx: a.queues[1].clone(),
            irq: a.irq,
        });
        pump(&mut g);
        drop(g);
        self.shared.cv.notify_all();
    }
    fn queue_notify(&mut self, queue: u32) {
        let mut g = self.shared.inner.lock().unwrap();
        if queue == 1 {
            self.process_tx(&mut g);
        }
        pump(&mut g);
        drop(g);
        self.shared.cv.notify_all();
    }
    fn reset(&mut self) {
        let mut g = self.shared.inner.lock().unwrap();
        g.active = None;
        g.ctrl.clear();
        for c in g.conns.values_mut() {
            c.reset = true;
            c.rx_eof = true;
        }
        drop(g);
        self.shared.cv.notify_all();
    }
}

impl VsockDevice {
    fn process_tx(&self, g: &mut Inner) {
        let Some(act) = g.active.as_ref() else { return };
        let (mem, txq, irq) = (act.mem.clone(), act.tx.clone(), act.irq.clone());
        let mut packets = Vec::new();
        let mut signal = false;
        {
            let mut q = txq.lock().unwrap();
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
                    if let Ok(mut rd) = chain.reader(&mem) {
                        let mut raw = [0u8; HDR];
                        if rd.read_exact(&mut raw).is_ok() {
                            let h = Hdr::parse(&raw);
                            let mut payload = vec![0u8; (h.len as usize).min(rd.available_bytes())];
                            if rd.read_exact(&mut payload).is_ok() {
                                packets.push((h, payload));
                            }
                        }
                    }
                    let _ = q.add_used(&mem, head, 0);
                    signal = true;
                }
            }
            if signal && !q.needs_notification(&mem).unwrap_or(true) {
                signal = false;
            }
        }
        for (h, payload) in packets {
            handle_packet(g, h, &payload);
        }
        // hand newly accepted connections to their listeners
        for (listener, key) in std::mem::take(&mut g.pending_accepts) {
            let _ = listener.send(VsockStream::new(self.shared.clone(), key));
        }
        if signal {
            irq.signal(INT_USED_RING);
        }
    }
}
