#!/usr/bin/env bash
# Build (and optionally install/upgrade) a self-hosted Flatpak bundle and OSTree repository for osbx.
#
#   scripts/build-flatpak.sh [OPTIONS]
#
#   --install            Install or upgrade io.github.lazarnerd.osbx for the current user from the
#                        local OSTree repo (so re-running this script upgrades in place cleanly).
#   --no-shim            With --install, do not install the ~/.local/bin/osbx wrapper script.
#   --skip-build         Reuse existing target/release/osbx instead of running `cargo build --release`.
#   --rebuild-assets     Also rebuild guest assets via `guest/build-assets.sh --offline --with-osbx`.
#   --output DIR         Output directory for repo and .flatpak bundle (default: <repo>/dist/flatpak).
#   --repo-url URL       Remote OSTree repository URL to embed in the .flatpak bundle and .flatpakrepo
#                        file so `flatpak update` upgrades automatically from your hosted repo.
#   --runtime-ver VER    org.freedesktop.Platform version (default: 25.08).
#   --branch NAME        Flatpak branch (default: stable).
#   --gpg-sign KEYID     Optional GPG key ID to sign the OSTree repo and bundle.
#   --gpg-homedir DIR    Optional GPG homedir for --gpg-sign.
#
# Outputs in <output>:
#   repo/                                 OSTree Flatpak repository (sync to GitHub Pages / static host)
#   osbx-<version>-<arch>.flatpak         Standalone single-file bundle (`flatpak install --user ...`)
#   osbx.flatpak                          Symlink/copy of the latest bundle
#   osbx.flatpakrepo                      Remote definition for `flatpak remote-add`
set -euo pipefail

APP_ID="io.github.lazarnerd.osbx"
RUNTIME="org.freedesktop.Platform"
RUNTIME_VER="${OSBX_FLATPAK_RUNTIME:-25.08}"
BRANCH="${OSBX_FLATPAK_BRANCH:-stable}"
ARCH="$(uname -m)"
FLATHUB_REPO="https://flathub.org/repo/flathub.flatpakrepo"

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/.." && pwd)
OUT="$REPO_ROOT/dist/flatpak"
INSTALL=0
INSTALL_SHIM=1
SKIP_BUILD=0
REBUILD_ASSETS=0
REPO_URL=""
GPG_SIGN=""
GPG_HOMEDIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --install)        INSTALL=1 ;;
    --no-shim)        INSTALL_SHIM=0 ;;
    --skip-build)     SKIP_BUILD=1 ;;
    --rebuild-assets) REBUILD_ASSETS=1 ;;
    --output)         OUT="${2:?--output needs a directory}"; shift ;;
    --repo-url)       REPO_URL="${2:?--repo-url needs a URL}"; shift ;;
    --runtime-ver)    RUNTIME_VER="${2:?--runtime-ver needs a version}"; shift ;;
    --branch)         BRANCH="${2:?--branch needs a branch}"; shift ;;
    --gpg-sign)       GPG_SIGN="${2:?--gpg-sign needs a key id}"; shift ;;
    --gpg-homedir)    GPG_HOMEDIR="${2:?--gpg-homedir needs a dir}"; shift ;;
    -h|--help)        sed -n '2,23p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

command -v flatpak >/dev/null || { echo "missing tool: flatpak" >&2; exit 1; }

# Verify runtime is installed locally (needed by flatpak build-init).
if ! flatpak info "$RUNTIME//$RUNTIME_VER" >/dev/null 2>&1; then
  echo "error: Flatpak runtime $RUNTIME//$RUNTIME_VER is not installed." >&2
  echo "Install it with: flatpak install --user flathub $RUNTIME//$RUNTIME_VER" >&2
  exit 1
fi

VERSION=$(awk -F'"' '/^version *=/{print $2; exit}' "$REPO_ROOT/Cargo.toml")
[ -n "$VERSION" ] || VERSION="0.0.1"

if [ "$REBUILD_ASSETS" = 1 ]; then
  echo "==> rebuilding guest assets"
  "$REPO_ROOT/guest/build-assets.sh" --offline --with-osbx
fi

ASSETS="$REPO_ROOT/guest/assets"
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
BUILD_DIR="$WORK/app"

echo "==> assembling Flatpak $APP_ID ($VERSION, $RUNTIME//$RUNTIME_VER, $ARCH)"
flatpak build-init --arch="$ARCH" "$BUILD_DIR" "$APP_ID" "$RUNTIME" "$RUNTIME" "$RUNTIME_VER"

install -Dm0755 "$BIN" "$BUILD_DIR/files/bin/osbx"
install -Dm0644 "$ASSETS/vmlinuz" "$BUILD_DIR/files/guest/vmlinuz"
install -Dm0644 "$ASSETS/initramfs.cpio.gz" "$BUILD_DIR/files/guest/initramfs.cpio.gz"
install -Dm0755 "$ASSETS/osbx-agent" "$BUILD_DIR/files/guest/osbx-agent"
[ -f "$ASSETS/osbx-probe" ] && install -Dm0755 "$ASSETS/osbx-probe" "$BUILD_DIR/files/guest/osbx-probe"
[ -f "$ASSETS/kernel-version" ] && install -Dm0644 "$ASSETS/kernel-version" "$BUILD_DIR/files/guest/kernel-version"

META="$REPO_ROOT/packaging/flatpak/$APP_ID.metainfo.xml"
install -Dm0644 "$META" "$BUILD_DIR/files/share/metainfo/$APP_ID.metainfo.xml"
install -Dm0644 "$REPO_ROOT/LICENSE" "$BUILD_DIR/files/share/licenses/osbx/LICENSE"

if command -v appstreamcli >/dev/null 2>&1; then
  appstreamcli validate --no-net "$META" >/dev/null
fi

# Permissions:
# - --share=network: OCI registry pulls and host egress policy proxy
# - --device=all: exposes both /dev/kvm and /dev/vhost-vsock (needed by the VMM and kvm@1 probe;
#   Flatpak's --device=kvm omits /dev/vhost-vsock)
# - --filesystem=host: osbx mounts the current working directory / workspace into the sandbox
# - --filesystem=/sys/module:ro: lets osbx read /sys/module/kvm_{intel,amd}/parameters/nested for kvm@1
# - --socket=ssh-auth: forwards host SSH_AUTH_SOCK for ssh-agent@1
# - --env=OSBX_ASSETS=/app/guest: guest kernel/initramfs/agent bundled inside the Flatpak
flatpak build-finish "$BUILD_DIR" \
  --command=osbx \
  --share=network \
  --device=all \
  --filesystem=host \
  --filesystem=/sys/module:ro \
  --socket=ssh-auth \
  --env=OSBX_ASSETS=/app/guest

mkdir -p "$OUT"
OSTREE_REPO="$OUT/repo"
EXPORT_ARGS=(--arch="$ARCH" --subject="osbx $VERSION" --body="Built from $(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)")
BUNDLE_ARGS=(--arch="$ARCH" --runtime-repo="$FLATHUB_REPO")
if [ -n "$GPG_SIGN" ]; then
  EXPORT_ARGS+=(--gpg-sign="$GPG_SIGN")
  BUNDLE_ARGS+=(--gpg-sign="$GPG_SIGN")
fi
if [ -n "$GPG_HOMEDIR" ]; then
  EXPORT_ARGS+=(--gpg-homedir="$GPG_HOMEDIR")
  BUNDLE_ARGS+=(--gpg-homedir="$GPG_HOMEDIR")
fi
if [ -n "$REPO_URL" ]; then
  BUNDLE_ARGS+=(--repo-url="$REPO_URL")
fi

echo "==> exporting OSTree repository to $OSTREE_REPO"
flatpak build-export "${EXPORT_ARGS[@]}" "$OSTREE_REPO" "$BUILD_DIR" "$BRANCH"
flatpak build-update-repo --prune "$OSTREE_REPO"

BUNDLE="$OUT/osbx-$VERSION-$ARCH.flatpak"
echo "==> creating standalone bundle $BUNDLE"
flatpak build-bundle "${BUNDLE_ARGS[@]}" "$OSTREE_REPO" "$BUNDLE" "$APP_ID" "$BRANCH"
cp -f "$BUNDLE" "$OUT/osbx.flatpak"

# Write a .flatpakrepo file for self-hosted remote upgrades (`flatpak update`).
REPO_TARGET="${REPO_URL:-file://$OSTREE_REPO}"
cat > "$OUT/osbx.flatpakrepo" <<EOF
[Flatpak Repo]
Title=osbx
Comment=Self-hosted Flatpak repository for osbx
Url=$REPO_TARGET
EOF

if [ "$INSTALL" = 1 ]; then
  REMOTE="osbx-local"
  echo "==> installing/upgrading $APP_ID from local remote '$REMOTE'"
  if [ -n "$GPG_SIGN" ]; then
    flatpak remote-add --user --if-not-exists "$REMOTE" "file://$OSTREE_REPO"
    flatpak remote-modify --user --url="file://$OSTREE_REPO" "$REMOTE"
  else
    flatpak remote-add --user --if-not-exists --no-gpg-verify "$REMOTE" "file://$OSTREE_REPO"
    flatpak remote-modify --user --no-gpg-verify --url="file://$OSTREE_REPO" "$REMOTE"
  fi
  if flatpak info --user "$APP_ID//$BRANCH" >/dev/null 2>&1; then
    flatpak update --user -y "$APP_ID//$BRANCH"
  else
    flatpak install --user -y "$REMOTE" "$APP_ID//$BRANCH"
  fi
  if [ "$INSTALL_SHIM" = 1 ]; then
    SHIM_DIR="$HOME/.local/bin"
    mkdir -p "$SHIM_DIR"
    cat > "$SHIM_DIR/osbx" <<EOF
#!/bin/sh
exec flatpak run $APP_ID "\$@"
EOF
    chmod 0755 "$SHIM_DIR/osbx"
    echo "==> installed wrapper $SHIM_DIR/osbx"
  fi
fi

echo
echo "Done:"
echo "  Bundle : $BUNDLE"
echo "  Latest : $OUT/osbx.flatpak"
echo "  Repo   : $OSTREE_REPO"
if [ "$INSTALL" = 1 ]; then
  echo "  Installed: flatpak run $APP_ID --version"
  echo "  Upgrade later: ./scripts/build-flatpak.sh --install"
else
  echo "  Install: flatpak install --user $OUT/osbx.flatpak"
  echo "  Or install & enable 1-command upgrades: ./scripts/build-flatpak.sh --install"
fi
