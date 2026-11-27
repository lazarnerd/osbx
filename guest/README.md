# Guest assets and booting

`guest/build-assets.sh [--force] [--with-osbx]` builds what osbx boots into `guest/assets/` (git-ignored):
Ubuntu's kernel (verified via apt), a busybox initramfs with `guest/init` as PID 1, and the kernel modules the
guest loads on demand (KVM + vhost-vsock, vsock transport, virtiofs). `--with-osbx` also builds the static
guest agent (`osbx-agent`) and probe (`osbx-probe`); both are copied into `guest/assets/` for root filesystems.
**Check its exit status**: a failed musl build aborts the script.

```bash
./guest/build-assets.sh --with-osbx
cargo build -p osbx-cli
osbx=target/debug/osbx
$osbx vmm probe --run-guest --require-nested                  # can this host grant kvm@1?
$osbx vmm boot --kernel guest/assets/vmlinuz --initrd guest/assets/initramfs.cpio.gz            # self-test, then exits
$osbx vmm boot --kernel guest/assets/vmlinuz --initrd guest/assets/initramfs.cpio.gz --interactive   # busybox shell
$osbx vmm boot ... --append "osbx.mode=kvm"                   # load KVM in the guest, run the probe + a nested VM
```

Guest modes (`osbx.mode=` on the kernel command line): `agent` (what sandboxes use: loads vsock, mounts
`root=` and `osbx.share=TAG:PATH[:ro]` shares, loads KVM if `osbx.kvm=1`, then runs the agent), `test`
(default), `kvm`, `blk`, `shell`.
A guest `reboot -f` ends the run (exit 0); a crash, timeout or error exits 1.

## What the VMM provides today
x86_64 on Linux/KVM and Windows/WHP. Up to 32 vCPUs and 64 GiB RAM, direct 64-bit kernel entry (no firmware), MP table,
in-kernel irqchip + PIT (KVM) or WHP xAPIC + userspace IOAPIC/RTC (Windows), a 16550 UART (console + stdin), virtio-MMIO block, filesystem (virtio-fs) and vsock
devices. No NIC by design (egress goes through the host proxy over vsock); no ACPI/PCI (the default command
line turns those probes off). See `docs/STATUS.md`.
