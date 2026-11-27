#!/usr/bin/env bash
# Provision a fresh sandbox for the osbx (Rust) project.  Run INSIDE the sandbox
# as the normal user (sudo is used for apt).  Idempotent: safe to re-run.
#
#   dev/sandbox-setup.sh [--skip-apt] [--with-tools] [--skills project|user|none]
#
#   --skip-apt     do not apt-get install system packages
#   --with-tools   also `cargo install` cargo-nextest, cargo-deny, cargo-audit
#                  (compiled once; sccache makes later re-installs fast)
#   --skills MODE  project (default): <workspace>/.claude/skills, survives re-creation
#                  user: ~/.claude/skills (read-only in most sandboxes)   none: skip
#
# Env overrides: RUST_TOOLCHAIN (default: stable), SCCACHE_CACHE_SIZE (default: 20G)
#
# Build caching: sbxenv.yaml mounts host folders over ~/.cargo/registry,
# ~/.cargo/git and ~/.cache/sccache, and this script exports
# RUSTC_WRAPPER=sccache.  Compiled crates are therefore served from the host
# cache after the sandbox is removed and re-created; only linking and your own
# crates recompile.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-stable}"
SCCACHE_DIR="${SCCACHE_DIR:-$HOME/.cache/sccache}"
SCCACHE_CACHE_SIZE="${SCCACHE_CACHE_SIZE:-20G}"
SKIP_APT=0 WITH_TOOLS=0 SKILLS=project

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-apt)   SKIP_APT=1 ;;
    --with-tools) WITH_TOOLS=1 ;;
    --skills)     SKILLS="${2:?--skills needs project|user|none}"; shift ;;
    -h|--help)    sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

step() { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }

# --- 1. system packages ------------------------------------------------------
if [ "$SKIP_APT" = 0 ]; then
  step "apt packages"
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential pkg-config libssl-dev clang lld cmake git curl ca-certificates \
    jq zstd xz-utils unzip sccache
else
  step "apt packages (skipped)"
fi

# --- 2. directories that sbxenv.yaml mounts into ------------------------------
# A mount creates missing parents as root; rustup/cargo must own them.
step "ownership of cargo/rustup/cache dirs"
mkdir -p "$HOME/.cargo" "$HOME/.rustup" "$HOME/.cache" 2>/dev/null || true
for d in "$HOME/.cargo" "$HOME/.rustup" "$HOME/.cache"; do
  if [ -d "$d" ] && [ "$(stat -c %U "$d")" != "$(id -un)" ]; then
    sudo chown "$(id -un):$(id -gn)" "$d"
  fi
done

# --- 3. Rust toolchain --------------------------------------------------------
step "rust toolchain ($RUST_TOOLCHAIN)"
export PATH="$HOME/.cargo/bin:$PATH"
if command -v rustup >/dev/null 2>&1; then
  rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal -c clippy -c rustfmt
  rustup default "$RUST_TOOLCHAIN"
else
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN" -c clippy -c rustfmt
fi

# --- 4. persistent environment ------------------------------------------------
# /etc/sandbox-persistent.sh is sourced before every shell command: keep it
# cheap, and never put shell-completion scripts in it.
step "persistent env (/etc/sandbox-persistent.sh)"
PERSIST=/etc/sandbox-persistent.sh
BEGIN='# >>> osbx-setup >>>'
END='# <<< osbx-setup <<<'
block=$(cat <<EOF
$BEGIN
case ":\$PATH:" in *":\$HOME/.cargo/bin:"*) ;; *) export PATH="\$HOME/.cargo/bin:\$PATH" ;; esac
export SCCACHE_DIR="$SCCACHE_DIR"
export SCCACHE_CACHE_SIZE="$SCCACHE_CACHE_SIZE"
export CARGO_INCREMENTAL=0
if command -v sccache >/dev/null 2>&1; then export RUSTC_WRAPPER=sccache; fi
$END
EOF
)
sudo touch "$PERSIST"
sudo sed -i "\|^$BEGIN\$|,\|^$END\$|d" "$PERSIST"
printf '%s\n' "$block" | sudo tee -a "$PERSIST" >/dev/null
# shellcheck disable=SC1090
. "$PERSIST"

# --- 5. optional cargo tools --------------------------------------------------
if [ "$WITH_TOOLS" = 1 ]; then
  step "cargo tools"
  cargo install --locked cargo-nextest cargo-deny cargo-audit
fi

# --- 6. skills ----------------------------------------------------------------
case "$SKILLS" in
  none) step "skills (skipped)" ;;
  project|user) step "skills ($SKILLS)"; "$HERE/install-skills.sh" "--$SKILLS" ;;
  *) echo "bad --skills value: $SKILLS" >&2; exit 2 ;;
esac

# --- 7. verify ----------------------------------------------------------------
step "verification"
rustc --version
cargo --version
if command -v sccache >/dev/null 2>&1; then
  sccache --version
  echo "RUSTC_WRAPPER=${RUSTC_WRAPPER:-<unset>}  SCCACHE_DIR=$SCCACHE_DIR"
else
  warn "sccache not found; builds will not be cached (re-run without --skip-apt)"
fi
for p in "$SCCACHE_DIR" "$HOME/.cargo/registry" "$HOME/.cargo/git" "$HOME/claude-history"; do
  if ! grep -q " $p " /proc/mounts 2>/dev/null; then
    warn "$p is not a host mount: its contents are lost when this sandbox is removed."
    warn "  (create the sandbox from sbxenv.yaml: host-setup.* then 'sbx env run')"
  fi
done
[ -e /dev/kvm ] || warn "/dev/kvm is missing: the VMM cannot be run/tested inside this sandbox."
echo
echo "Done. Open a new shell (or: . $PERSIST) to pick up PATH and RUSTC_WRAPPER."
