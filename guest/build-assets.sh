#!/usr/bin/env bash
# Build the guest assets osbx boots: a kernel and an initramfs.
#
#   guest/build-assets.sh [--force] [--with-osbx] [--offline]
#
#   --with-osbx   also build static (musl) `osbx-agent` and `osbx-probe` binaries: the agent goes
#                 into the initramfs and into guest/assets/ (for root filesystems), the probe lets a
#                 guest check that it can run KVM itself (osbx.mode=kvm)
#   --offline     no downloads: keep the kernel, modules and busybox of the existing
#                 guest/assets/initramfs.cpio.gz and only re-install init, e2fsprogs and (with
#                 --with-osbx) the osbx binaries. For hosts without access to the Ubuntu archive.
#
# Output (git-ignored): guest/assets/vmlinuz, guest/assets/initramfs.cpio.gz, guest/assets/modules/
#
# Sources: the Ubuntu kernel image and modules plus a static busybox, fetched with
# `apt-get download` (no root needed; apt verifies them against the archive signatures).
# The kernel has the 8250 serial console, initrd support, devtmpfs and virtio (PCI, MMIO,
# block, net, console) built in; KVM, vhost-vsock and virtio-fs are modules (needed later
# for KVM inside the guest). Downloaded archives are untrusted data: they are unpacked into
# their own fresh directories and nothing from them is executed here except by the guest.
# e2fsprogs (mke2fs, e2fsck, resize2fs) and their libraries come from this build host.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OUT="$HERE/assets"
FORCE=0 WITH_OSBX=0 OFFLINE=0
for a in "$@"; do
  case "$a" in
    --force) FORCE=1 ;;
    --with-osbx) WITH_OSBX=1 ;;
    --offline) OFFLINE=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
if [ -f "$OUT/vmlinuz" ] && [ -f "$OUT/initramfs.cpio.gz" ] && [ "$FORCE" = 0 ] && [ "$WITH_OSBX" = 0 ] && [ "$OFFLINE" = 0 ]; then
  echo "assets already built in $OUT (use --force to rebuild)"; exit 0
fi

need="cpio gzip ldd mke2fs e2fsck resize2fs"
[ "$OFFLINE" = 1 ] || need="$need apt-get dpkg-deb zstd depmod modprobe"
for t in $need; do command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; done
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT" "$WORK/dl"
R="$WORK/root"

if [ "$OFFLINE" = 1 ]; then
  [ -f "$OUT/initramfs.cpio.gz" ] && [ -f "$OUT/vmlinuz" ] || { echo "--offline needs existing guest/assets (vmlinuz, initramfs.cpio.gz)" >&2; exit 1; }
  KVER=$(cat "$OUT/kernel-version" 2>/dev/null || echo unknown)
  echo "==> offline: reusing kernel $KVER, modules and busybox from guest/assets"
  mkdir -p "$R"
  ( cd "$R" && gzip -dc "$OUT/initramfs.cpio.gz" | cpio -id --quiet )
  rm -rf "$R/sbin" "$R/lib/x86_64-linux-gnu" "$R/lib64"
  install -m 0755 "$HERE/init" "$R/init"
else
  KPKG=$(apt-cache depends linux-image-virtual 2>/dev/null | awk '/Depends: linux-image-[0-9]/{print $2; exit}')
  [ -n "$KPKG" ] || { echo "cannot resolve the linux-image package (apt cache empty? run: sudo apt-get update)" >&2; exit 1; }
  KVER=${KPKG#linux-image-}
  echo "==> downloading $KPKG, linux-modules-$KVER, busybox-static"
  ( cd "$WORK/dl" && apt-get download "$KPKG" "linux-modules-$KVER" busybox-static >/dev/null )

  mkdir -p "$WORK/kernel" "$WORK/mods" "$WORK/bb"
  dpkg-deb -x "$WORK/dl/$KPKG"_*.deb "$WORK/kernel"
  dpkg-deb -x "$WORK/dl/linux-modules-$KVER"_*.deb "$WORK/mods"
  dpkg-deb -x "$WORK/dl"/busybox-static_*.deb "$WORK/bb"

  install -m 0644 "$WORK/kernel/boot/vmlinuz-$KVER" "$OUT/vmlinuz"
  install -m 0644 "$WORK/mods/boot/config-$KVER" "$OUT/kernel-config"
  rm -rf "$OUT/modules" && mkdir -p "$OUT/modules" && cp -a "$WORK/mods/lib/modules/$KVER" "$OUT/modules/"
  echo "$KVER" > "$OUT/kernel-version"

  echo "==> building initramfs"
  mkdir -p "$R"/{bin,proc,sys,dev,tmp,etc,root}
  BB="$WORK/bb/usr/bin/busybox"; [ -x "$BB" ] || BB="$WORK/bb/bin/busybox"
  install -m 0755 "$BB" "$R/bin/busybox"
  for applet in $("$BB" --list); do [ "$applet" = busybox ] || ln -sf busybox "$R/bin/$applet"; done
  install -m 0755 "$HERE/init" "$R/init"

  # Kernel modules the guest loads on demand, decompressed (busybox insmod cannot read .zst), each
  # with its dependency-ordered load list. `modules.dep` is not shipped in the package, so generate it.
  depmod -b "$WORK/mods" "$KVER"
  mkdir -p "$R/lib/modules"
  emit_modules() {  # emit_modules <list-file> <module>...   (one modprobe call per module)
    list="$R/etc/$1"; shift; : > "$list"
    for mod in "$@"; do
      for path in $(modprobe -d "$WORK/mods" -S "$KVER" --show-depends "$mod" | awk '$1=="insmod"{print $2}'); do
        name=$(basename "$path"); name=${name%.zst}
        grep -qx "/lib/modules/$name" "$list" && continue
        [ -f "$R/lib/modules/$name" ] || zstd -q -d -c "$path" > "$R/lib/modules/$name"
        echo "/lib/modules/$name" >> "$list"
      done
    done
  }
  emit_modules kvm-modules kvm_intel vhost_vsock
  emit_modules vsock-modules vmw_vsock_virtio_transport
  emit_modules fs-modules virtiofs
  # Docker inside the sandbox (dockerd@1): overlay storage, bridge networking, iptables/nftables NAT
  emit_modules docker-modules overlay bridge veth br_netfilter xt_MASQUERADE xt_addrtype xt_conntrack iptable_nat iptable_filter nft_compat nft_chain_nat
  echo "modules: kvm=$(wc -l < "$R/etc/kvm-modules") vsock=$(wc -l < "$R/etc/vsock-modules") fs=$(wc -l < "$R/etc/fs-modules") docker=$(wc -l < "$R/etc/docker-modules")"
fi

# e2fsprogs, for root filesystems built and grown inside the guest (the osbx image builder boots
# this initramfs with a blank disk; sandboxes grow their root online at boot). Copied from this
# build host together with the shared libraries and loader they need.
mkdir -p "$R/sbin"
for tool in mke2fs e2fsck resize2fs; do
  p=$(command -v "$tool")
  install -m 0755 "$p" "$R/sbin/$tool"
  for lib in $(ldd "$p" | awk '$2 == "=>" && $3 ~ /^\// {print $3} $1 ~ /^\// {print $1}'); do
    [ -f "$R$lib" ] && continue
    mkdir -p "$R$(dirname "$lib")"
    cp -L "$lib" "$R$lib"
  done
done
cp /etc/mke2fs.conf "$R/etc/mke2fs.conf"
echo "e2fsprogs: $(ls "$R/sbin" | tr '\n' ' ')($(du -sh "$R/lib/x86_64-linux-gnu" 2>/dev/null | cut -f1) of libraries)"

if [ "$WITH_OSBX" = 1 ]; then
  echo "==> building static osbx-agent and osbx-probe (x86_64-unknown-linux-musl)"
  [ "$OFFLINE" = 1 ] && export CARGO_NET_OFFLINE=true
  command -v rustup >/dev/null && { rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true; }
  TD=${CARGO_TARGET_DIR:-$HERE/../target}
  ( cd "$HERE/.." && cargo build -q --release -p osbx-agent -p osbx-vmm --bin osbx-agent --bin osbx-probe --target x86_64-unknown-linux-musl )
  install -m 0755 "$TD/x86_64-unknown-linux-musl/release/osbx-probe" "$R/bin/osbx-probe"
  install -m 0755 "$TD/x86_64-unknown-linux-musl/release/osbx-agent" "$R/bin/osbx-agent"
  install -m 0755 "$TD/x86_64-unknown-linux-musl/release/osbx-agent" "$OUT/osbx-agent"  # for rootfs images
  install -m 0755 "$TD/x86_64-unknown-linux-musl/release/osbx-probe" "$OUT/osbx-probe"  # ditto
  echo "osbx-probe $(ls -lh "$R/bin/osbx-probe" | awk '{print $5}'), osbx-agent $(ls -lh "$R/bin/osbx-agent" | awk '{print $5}') in initramfs"
fi
( cd "$R" && find . | cpio -o -H newc --quiet --owner 0:0 | gzip -9 > "$OUT/initramfs.cpio.gz" )
echo "built: $(ls -lh "$OUT/vmlinuz" | awk '{print $5}') kernel, $(ls -lh "$OUT/initramfs.cpio.gz" | awk '{print $5}') initramfs ($KVER)"
