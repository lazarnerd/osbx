//! virtio-fs: share a host directory with the guest (FUSE over virtio).
//!
//! The FUSE protocol and the passthrough file system come from `fuse-backend-rs`; this file is
//! the virtio glue. Files the guest creates are owned by the user running the VMM on the host,
//! which is what a shared workspace wants.

use super::{Activation, GuestMem, Interrupt, SharedQueue, VIRTIO_F_VERSION_1, VirtioDevice};
use fuse_backend_rs::abi::fuse_abi::{
    CreateIn, FsOptions, OpenOptions, SetattrValid, stat64, statvfs64,
};
use fuse_backend_rs::abi::virtio_fs::RemovemappingOne;
use fuse_backend_rs::api::filesystem::{
    Context, DirEntry, Entry, FileSystem, GetxattrReply, ListxattrReply, ZeroCopyReader,
    ZeroCopyWriter,
};
use fuse_backend_rs::api::server::Server;
use fuse_backend_rs::passthrough::{CachePolicy, Config, PassthroughFs};
use fuse_backend_rs::transport::{FsCacheReqHandler, Reader, VirtioFsWriter};
use std::ffi::CStr;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use virtio_queue::{QueueOwnedT, QueueT};

/// Longest mount tag the spec allows.
pub const MAX_TAG: usize = 36;

fn erofs() -> io::Error {
    io::Error::from_raw_os_error(libc::EROFS)
}

/// Passthrough file system wrapper that optionally enforces read-only semantics on the host side
/// (`EROFS` for every mutating FUSE operation, even if guest root remounts the share read-write).
struct ShareFs {
    inner: Arc<PassthroughFs>,
    read_only: bool,
}

impl ShareFs {
    fn check_writable(&self) -> io::Result<()> {
        if self.read_only { Err(erofs()) } else { Ok(()) }
    }
}

impl FileSystem for ShareFs {
    type Inode = <PassthroughFs as FileSystem>::Inode;
    type Handle = <PassthroughFs as FileSystem>::Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        let mut opts = self.inner.init(capable)?;
        if self.read_only {
            opts.remove(FsOptions::WRITEBACK_CACHE);
        }
        Ok(opts)
    }
    fn destroy(&self) {
        self.inner.destroy();
    }
    fn lookup(&self, ctx: &Context, parent: Self::Inode, name: &CStr) -> io::Result<Entry> {
        self.inner.lookup(ctx, parent, name)
    }
    fn forget(&self, ctx: &Context, inode: Self::Inode, count: u64) {
        self.inner.forget(ctx, inode, count);
    }
    fn batch_forget(&self, ctx: &Context, requests: Vec<(Self::Inode, u64)>) {
        self.inner.batch_forget(ctx, requests);
    }
    fn getattr(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        handle: Option<Self::Handle>,
    ) -> io::Result<(stat64, Duration)> {
        self.inner.getattr(ctx, inode, handle)
    }
    fn setattr(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        attr: stat64,
        handle: Option<Self::Handle>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        self.check_writable()?;
        self.inner.setattr(ctx, inode, attr, handle, valid)
    }
    fn readlink(&self, ctx: &Context, inode: Self::Inode) -> io::Result<Vec<u8>> {
        self.inner.readlink(ctx, inode)
    }
    fn symlink(
        &self,
        ctx: &Context,
        linkname: &CStr,
        parent: Self::Inode,
        name: &CStr,
    ) -> io::Result<Entry> {
        self.check_writable()?;
        self.inner.symlink(ctx, linkname, parent, name)
    }
    fn mknod(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        self.check_writable()?;
        self.inner.mknod(ctx, inode, name, mode, rdev, umask)
    }
    fn mkdir(
        &self,
        ctx: &Context,
        parent: Self::Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        self.check_writable()?;
        self.inner.mkdir(ctx, parent, name, mode, umask)
    }
    fn unlink(&self, ctx: &Context, parent: Self::Inode, name: &CStr) -> io::Result<()> {
        self.check_writable()?;
        self.inner.unlink(ctx, parent, name)
    }
    fn rmdir(&self, ctx: &Context, parent: Self::Inode, name: &CStr) -> io::Result<()> {
        self.check_writable()?;
        self.inner.rmdir(ctx, parent, name)
    }
    fn rename(
        &self,
        ctx: &Context,
        olddir: Self::Inode,
        oldname: &CStr,
        newdir: Self::Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        self.check_writable()?;
        self.inner
            .rename(ctx, olddir, oldname, newdir, newname, flags)
    }
    fn link(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        newparent: Self::Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        self.check_writable()?;
        self.inner.link(ctx, inode, newparent, newname)
    }
    fn open(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        flags: u32,
        fuse_flags: u32,
    ) -> io::Result<(Option<Self::Handle>, OpenOptions, Option<u32>)> {
        if self.read_only {
            let acc = flags & (libc::O_ACCMODE as u32);
            let write_bits = (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as u32;
            if acc == libc::O_WRONLY as u32
                || acc == libc::O_RDWR as u32
                || (flags & write_bits) != 0
            {
                return Err(erofs());
            }
        }
        self.inner.open(ctx, inode, flags, fuse_flags)
    }
    fn create(
        &self,
        ctx: &Context,
        parent: Self::Inode,
        name: &CStr,
        args: CreateIn,
    ) -> io::Result<(Entry, Option<Self::Handle>, OpenOptions, Option<u32>)> {
        self.check_writable()?;
        self.inner.create(ctx, parent, name, args)
    }
    fn read(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        handle: Self::Handle,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        self.inner
            .read(ctx, inode, handle, w, size, offset, lock_owner, flags)
    }
    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        handle: Self::Handle,
        r: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        flags: u32,
        fuse_flags: u32,
    ) -> io::Result<usize> {
        self.check_writable()?;
        self.inner.write(
            ctx,
            inode,
            handle,
            r,
            size,
            offset,
            lock_owner,
            delayed_write,
            flags,
            fuse_flags,
        )
    }
    fn flush(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        handle: Self::Handle,
        lock_owner: u64,
    ) -> io::Result<()> {
        self.inner.flush(ctx, inode, handle, lock_owner)
    }
    fn fsync(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        datasync: bool,
        handle: Self::Handle,
    ) -> io::Result<()> {
        self.check_writable()?;
        self.inner.fsync(ctx, inode, datasync, handle)
    }
    fn fallocate(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        handle: Self::Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        self.check_writable()?;
        self.inner
            .fallocate(ctx, inode, handle, mode, offset, length)
    }
    #[allow(clippy::too_many_arguments)]
    fn release(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        flags: u32,
        handle: Self::Handle,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.inner
            .release(ctx, inode, flags, handle, flush, flock_release, lock_owner)
    }
    fn statfs(&self, ctx: &Context, inode: Self::Inode) -> io::Result<statvfs64> {
        self.inner.statfs(ctx, inode)
    }
    fn setxattr(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        self.check_writable()?;
        self.inner.setxattr(ctx, inode, name, value, flags)
    }
    fn getxattr(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        self.inner.getxattr(ctx, inode, name, size)
    }
    fn listxattr(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        size: u32,
    ) -> io::Result<ListxattrReply> {
        self.inner.listxattr(ctx, inode, size)
    }
    fn removexattr(&self, ctx: &Context, inode: Self::Inode, name: &CStr) -> io::Result<()> {
        self.check_writable()?;
        self.inner.removexattr(ctx, inode, name)
    }
    fn opendir(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        flags: u32,
    ) -> io::Result<(Option<Self::Handle>, OpenOptions)> {
        self.inner.opendir(ctx, inode, flags)
    }
    fn readdir(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        handle: Self::Handle,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry) -> io::Result<usize>,
    ) -> io::Result<()> {
        self.inner
            .readdir(ctx, inode, handle, size, offset, add_entry)
    }
    fn readdirplus(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        handle: Self::Handle,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry, Entry) -> io::Result<usize>,
    ) -> io::Result<()> {
        self.inner
            .readdirplus(ctx, inode, handle, size, offset, add_entry)
    }
    fn fsyncdir(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        datasync: bool,
        handle: Self::Handle,
    ) -> io::Result<()> {
        self.check_writable()?;
        self.inner.fsyncdir(ctx, inode, datasync, handle)
    }
    fn releasedir(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        flags: u32,
        handle: Self::Handle,
    ) -> io::Result<()> {
        self.inner.releasedir(ctx, inode, flags, handle)
    }
    #[allow(clippy::too_many_arguments)]
    fn setupmapping(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        handle: Self::Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        vu_req: &mut dyn FsCacheReqHandler,
    ) -> io::Result<()> {
        if self.read_only && (flags & 2) != 0 {
            return Err(erofs());
        }
        self.inner
            .setupmapping(ctx, inode, handle, foffset, len, flags, moffset, vu_req)
    }
    fn removemapping(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        requests: Vec<RemovemappingOne>,
        vu_req: &mut dyn FsCacheReqHandler,
    ) -> io::Result<()> {
        self.inner.removemapping(ctx, inode, requests, vu_req)
    }
    fn access(&self, ctx: &Context, inode: Self::Inode, mask: u32) -> io::Result<()> {
        if self.read_only && (mask & libc::W_OK as u32) != 0 {
            return Err(erofs());
        }
        self.inner.access(ctx, inode, mask)
    }
    fn lseek(
        &self,
        ctx: &Context,
        inode: Self::Inode,
        handle: Self::Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        self.inner.lseek(ctx, inode, handle, offset, whence)
    }
}

/// A virtio-fs device exporting one host directory.
pub struct Fs {
    tag: [u8; MAX_TAG],
    server: Arc<Server<ShareFs>>,
    active: Option<(GuestMem, Vec<SharedQueue>, Interrupt)>,
}

impl Fs {
    /// Export `host_dir` under mount tag `tag`. When `read_only` is true, every mutating FUSE
    /// request is rejected on the host with `EROFS`.
    pub fn new(tag: &str, host_dir: &Path, read_only: bool) -> io::Result<Self> {
        if tag.is_empty() || tag.len() > MAX_TAG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tag must be 1..=36 bytes",
            ));
        }
        let root = std::fs::canonicalize(host_dir)?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a directory", root.display()),
            ));
        }
        let cfg = Config {
            root_dir: root.to_string_lossy().into_owned(),
            do_import: true,
            cache_policy: CachePolicy::Auto,
            xattr: false,
            ..Config::default()
        };
        let fs = PassthroughFs::new(cfg)?;
        fs.import()?;
        let mut t = [0u8; MAX_TAG];
        t[..tag.len()].copy_from_slice(tag.as_bytes());
        Ok(Self {
            tag: t,
            server: Arc::new(Server::new(ShareFs {
                inner: Arc::new(fs),
                read_only,
            })),
            active: None,
        })
    }
}

impl VirtioDevice for Fs {
    fn device_type(&self) -> u32 {
        26
    }
    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }
    fn queue_max_sizes(&self) -> Vec<u16> {
        vec![128, 128] // hiprio, one request queue
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut cfg = [0u8; MAX_TAG + 4];
        cfg[..MAX_TAG].copy_from_slice(&self.tag);
        cfg[MAX_TAG..].copy_from_slice(&1u32.to_le_bytes()); // num_request_queues
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
                let used = match (
                    Reader::from_descriptor_chain(&mem, chain.clone()),
                    VirtioFsWriter::new(&mem, chain),
                ) {
                    (Ok(r), Ok(w)) => self
                        .server
                        .handle_message(r, w.into(), None, None)
                        .unwrap_or(0),
                    _ => 0,
                };
                if q.add_used(&mem, head, used as u32).is_ok() {
                    signal = true;
                }
            }
        }
        if signal && q.needs_notification(&mem).unwrap_or(true) {
            drop(q);
            irq.signal_queue(queue as u16);
        }
    }
}
