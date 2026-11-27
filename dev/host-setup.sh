#!/usr/bin/env bash
# HOST-side setup (macOS / Linux / WSL / Git-Bash).  Windows PowerShell: host-setup.ps1.
# Run on the machine that runs `sbx`, not inside the sandbox.
#
#   dev/host-setup.sh [--install-sbx] [--kvm] [--no-policy] [--force-env] [--provision] [--run]
#
#   (default)     create ../sessions and ../cache/*, install ../sbxenv.yaml from the
#                 template if missing, allow the Rust/crates network domains, and
#                 preview with `sbx env plan`
#   --install-sbx install sbx via apt if missing (Ubuntu 24.04+, uses sudo)
#   --kvm         use sbxenv.kvm.yaml.template (adds the kvm@1 kit; needs a host that can grant it)
#   --no-policy   do not touch the network policy
#   --force-env   overwrite ../sbxenv.yaml with the template
#   --provision   create the sandbox (`sbx env run -d`) and run sandbox-setup.sh in it
#   --run         like --provision, then attach to the sandbox
#
# "../" means the folder that contains osbx/ (the sbxenv.yaml folder).
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WORKSPACE=$(dirname "$HERE")
ROOT=$(dirname "$WORKSPACE")
POLICY=1 FORCE_ENV=0 PROVISION=0 RUN=0 INSTALL_SBX=0 KVM=0
while [ $# -gt 0 ]; do
  case "$1" in
    --install-sbx) INSTALL_SBX=1 ;;
    --kvm)       KVM=1 ;;
    --no-policy) POLICY=0 ;;
    --force-env) FORCE_ENV=1 ;;
    --provision) PROVISION=1 ;;
    --run)       PROVISION=1; RUN=1 ;;
    -h|--help)   sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$INSTALL_SBX" = 1 ] && ! command -v sbx >/dev/null; then
  echo "==> installing sbx (Ubuntu apt repo via get.docker.com, needs sudo)"
  curl -fsSL https://get.docker.com | sudo REPO_ONLY=1 sh
  sudo apt-get install -y docker-sbx
fi
command -v sbx >/dev/null || { echo "sbx not found. Re-run with --install-sbx (Ubuntu 24.04+) or see README.md." >&2; exit 1; }

# Linux preflight: local sandboxes are microVMs and need KVM.
if [ "$(uname -s)" = Linux ]; then
  . /etc/os-release 2>/dev/null || true
  [ "${ID:-}" = ubuntu ] || echo "WARN: sbx is only supported on Ubuntu 24.04+ (found: ${PRETTY_NAME:-unknown})" >&2
  if [ ! -e /dev/kvm ]; then
    echo "WARN: /dev/kvm missing: enable virtualization in firmware / nested virt (check: kvm-ok)" >&2
  elif ! id -nG | tr ' ' '\n' | grep -qx kvm; then
    echo "WARN: user is not in the kvm group: sudo usermod -aG kvm \$USER, then re-login" >&2
  fi
fi

echo "==> folders under $ROOT"
mkdir -p "$ROOT/sessions" "$ROOT/cache/cargo-registry" "$ROOT/cache/cargo-git" "$ROOT/cache/sccache"

echo "==> sbxenv.yaml"
if [ ! -f "$ROOT/sbxenv.yaml" ] || [ "$FORCE_ENV" = 1 ]; then
  TEMPLATE="$HERE/sbxenv.yaml.template"
  [ "$KVM" = 1 ] && TEMPLATE="$HERE/sbxenv.kvm.yaml.template"
  cp "$TEMPLATE" "$ROOT/sbxenv.yaml"
  echo "installed $ROOT/sbxenv.yaml (from $(basename "$TEMPLATE"))"
else
  echo "kept existing $ROOT/sbxenv.yaml (diff against dev/sbxenv.yaml.template if unsure)"
fi

if [ "$POLICY" = 1 ]; then
  echo "==> network policy (balanced preset + Rust domains)"
  sbx policy init balanced || true
  sbx policy allow network "sh.rustup.rs,static.rust-lang.org,index.crates.io,static.crates.io,crates.io,github.com,codeload.github.com,raw.githubusercontent.com,deb.debian.org"
  sbx policy ls
fi

cd "$ROOT"
echo "==> sbx env plan"
sbx env plan

if [ "$PROVISION" = 1 ]; then
  echo "==> create sandbox"
  if ! out=$(sbx env run -d 2>&1); then
    printf '%s\n' "$out" >&2
    if printf '%s' "$out" | grep -q "unsupported capability type"; then
      echo "" >&2
      echo "This sbx ($(sbx version 2>/dev/null | head -1)) does not implement a capability the environment requires." >&2
      echo "kvm@1 is not supported by sbx v0.54.x, on any host OS (verified on Linux with a usable /dev/kvm)." >&2
      echo "Re-run without --kvm. For VMM work use a host with /dev/kvm directly: 'osbx vmm probe --run-guest'." >&2
    fi
    exit 1
  fi
  printf '%s\n' "$out"
  echo "==> run sandbox-setup.sh inside the sandbox"
  sbx env exec -- bash -lc 'bash "$WORKSPACE_DIR/dev/sandbox-setup.sh"'
fi
if [ "$RUN" = 1 ]; then
  exec sbx env run
fi
echo
echo "Next: sbx env run   (first time: then, inside, run dev/sandbox-setup.sh)"
