#!/usr/bin/env bash
# Build (and optionally install) a Debian/Ubuntu .deb package for osbx.
#
#   scripts/build-deb.sh [OPTIONS]
#
#   --install            Install or upgrade the built .deb via `sudo apt install` (or `sudo dpkg -i`).
#   --skip-build         Reuse existing target/release/osbx instead of running `cargo build --release`.
#   --rebuild-assets     Also rebuild guest assets via `guest/build-assets.sh --offline --with-osbx`.
#   --assets-dir DIR     Guest assets directory (default: <repo>/guest/assets).
#   --output DIR         Output directory for the .deb package (default: <repo>/dist/deb).
#   --arch ARCH          Debian architecture (default: `dpkg --print-architecture`, e.g. amd64).
#
# Outputs in <output>:
#   osbx_<version>_<arch>.deb    Installable Debian package (`/usr/bin/osbx` + `/usr/share/osbx/guest`)
#   osbx.deb                     Copy of the latest package
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/.." && pwd)
OUT="$REPO_ROOT/dist/deb"
ASSETS="$REPO_ROOT/guest/assets"
INSTALL=0
SKIP_BUILD=0
REBUILD_ASSETS=0
DEB_ARCH=""

while [ $# -gt 0 ]; do
  case "$1" in
    --install)        INSTALL=1 ;;
    --skip-build)     SKIP_BUILD=1 ;;
    --rebuild-assets) REBUILD_ASSETS=1 ;;
    --assets-dir)     ASSETS="${2:?--assets-dir needs a directory}"; shift ;;
    --output)         OUT="${2:?--output needs a directory}"; shift ;;
    --arch)           DEB_ARCH="${2:?--arch needs an architecture}"; shift ;;
    -h|--help)        sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

command -v dpkg-deb >/dev/null || { echo "missing tool: dpkg-deb" >&2; exit 1; }

if [ -z "$DEB_ARCH" ]; then
  if command -v dpkg >/dev/null 2>&1; then
    DEB_ARCH="$(dpkg --print-architecture)"
  else
    case "$(uname -m)" in
      x86_64)  DEB_ARCH="amd64" ;;
      aarch64) DEB_ARCH="arm64" ;;
      *)       DEB_ARCH="$(uname -m)" ;;
    esac
  fi
fi

VERSION=$(awk -F'"' '/^version *=/{print $2; exit}' "$REPO_ROOT/Cargo.toml")
[ -n "$VERSION" ] || VERSION="0.0.1"

if [ "$REBUILD_ASSETS" = 1 ]; then
  echo "==> rebuilding guest assets"
  "$REPO_ROOT/guest/build-assets.sh" --offline --with-osbx
fi

for f in vmlinuz initramfs.cpio.gz osbx-agent; do
  if [ ! -f "$ASSETS/$f" ]; then
    echo "error: guest asset $ASSETS/$f missing (run ./guest/build-assets.sh --with-osbx first)" >&2
    exit 1
  fi
done

TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
BIN="$TARGET_DIR/release/osbx"
if [ "$SKIP_BUILD" = 0 ]; then
  echo "==> building osbx $VERSION (release)"
  ( cd "$REPO_ROOT" && cargo build --release -p osbx-cli )
fi
[ -x "$BIN" ] || { echo "error: $BIN not found (omit --skip-build)" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/pkg"

echo "==> staging Debian package osbx $VERSION ($DEB_ARCH)"
install -Dm0755 "$BIN" "$STAGE/usr/bin/osbx"
install -Dm0644 "$ASSETS/vmlinuz" "$STAGE/usr/share/osbx/guest/vmlinuz"
install -Dm0644 "$ASSETS/initramfs.cpio.gz" "$STAGE/usr/share/osbx/guest/initramfs.cpio.gz"
install -Dm0755 "$ASSETS/osbx-agent" "$STAGE/usr/share/osbx/guest/osbx-agent"
[ -f "$ASSETS/osbx-probe" ] && install -Dm0755 "$ASSETS/osbx-probe" "$STAGE/usr/share/osbx/guest/osbx-probe"
[ -f "$ASSETS/kernel-version" ] && install -Dm0644 "$ASSETS/kernel-version" "$STAGE/usr/share/osbx/guest/kernel-version"
install -Dm0644 "$REPO_ROOT/LICENSE" "$STAGE/usr/share/doc/osbx/copyright"

INSTALLED_SIZE=$(du -sk "$STAGE" | awk '{print $1}')

mkdir -p "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/control" <<EOF
Package: osbx
Version: $VERSION
Section: devel
Priority: optional
Architecture: $DEB_ARCH
Maintainer: lazarnerd <83029177+lazarnerd@users.noreply.github.com>
Installed-Size: $INSTALLED_SIZE
Depends: libc6, libgcc-s1, e2fsprogs, fakeroot, git
Homepage: https://github.com/lazarnerd/osbx
Description: Open-source microVM sandbox runtime for coding agents
 osbx runs coding agents inside lightweight KVM microVMs driven by its own
 VMM, with deny-by-default egress through a host-side policy proxy that
 injects credentials the sandbox never sees.
EOF

mkdir -p "$OUT"
DEB="$OUT/osbx_${VERSION}_${DEB_ARCH}.deb"
echo "==> building $DEB"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB"
cp -f "$DEB" "$OUT/osbx.deb"

if [ "$INSTALL" = 1 ]; then
  echo "==> installing $DEB"
  if command -v apt >/dev/null 2>&1; then
    sudo apt install -y "$DEB"
  else
    sudo dpkg -i "$DEB"
  fi
fi

echo
echo "Done:"
echo "  Package: $DEB"
echo "  Latest : $OUT/osbx.deb"
if [ "$INSTALL" = 1 ]; then
  echo "  Installed: osbx --version"
else
  echo "  Install: sudo apt install $DEB"
fi
