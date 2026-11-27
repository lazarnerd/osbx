#!/usr/bin/env sh
# Install (or upgrade/uninstall) the osbx Flatpak and set up the `osbx` CLI wrapper in PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/lazarnerd/osbx/main/scripts/install-flatpak.sh | sh
#   ./scripts/install-flatpak.sh [OPTIONS] [BUNDLE.flatpak]
set -eu

APP_ID="io.github.lazarnerd.osbx"
REMOTE="osbx"
REPO_URL="${OSBX_FLATPAK_REPO_URL:-https://lazarnerd.github.io/osbx/flatpak-repo}"
FLATHUB_URL="https://flathub.org/repo/flathub.flatpakrepo"
BRANCH="${OSBX_FLATPAK_BRANCH:-stable}"
SCOPE="--user"
BIN_DIR="${OSBX_BIN_DIR:-}"
INSTALL_SHIM=1
SHIM_ONLY=0
UNINSTALL=0
FORCE=0
BUNDLE=""
SHIM_MARKER="# osbx Flatpak CLI wrapper"

usage() {
  cat <<'EOF'
Install (or upgrade/uninstall) the osbx Flatpak and set up the `osbx` CLI command.

Usage:
  install-flatpak.sh [OPTIONS] [BUNDLE.flatpak]

Options:
  --user            Install for the current user (default; wrapper in ~/.local/bin/osbx)
  --system          Install system-wide (wrapper in /usr/local/bin/osbx)
  --bin-dir DIR     Directory for the `osbx` wrapper (default: ~/.local/bin or /usr/local/bin)
  --bundle FILE     Install from a local .flatpak bundle instead of the hosted OSTree repo
  --repo-url URL    Flatpak OSTree repository URL (default: https://lazarnerd.github.io/osbx/flatpak-repo)
  --branch NAME     Flatpak branch to install (default: stable)
  --shim-only       Only install/update the `osbx` CLI wrapper (skip flatpak install/update)
  --no-shim         Install/update the Flatpak without creating the `osbx` CLI wrapper
  --force           Overwrite an existing non-Flatpak `osbx` file in --bin-dir
  --uninstall       Uninstall the Flatpak app and remove the managed `osbx` wrapper
  -h, --help        Show this help message
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --user)      SCOPE="--user" ;;
    --system)    SCOPE="--system" ;;
    --bin-dir)   [ $# -ge 2 ] || { echo "error: --bin-dir requires a directory" >&2; exit 2; }; BIN_DIR="$2"; shift ;;
    --bundle)    [ $# -ge 2 ] || { echo "error: --bundle requires a file path" >&2; exit 2; }; BUNDLE="$2"; shift ;;
    --repo-url)  [ $# -ge 2 ] || { echo "error: --repo-url requires a URL" >&2; exit 2; }; REPO_URL="$2"; shift ;;
    --branch)    [ $# -ge 2 ] || { echo "error: --branch requires a branch name" >&2; exit 2; }; BRANCH="$2"; shift ;;
    --shim-only) SHIM_ONLY=1 ;;
    --no-shim)   INSTALL_SHIM=0 ;;
    --force)     FORCE=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help)   usage; exit 0 ;;
    -*)          echo "error: unknown option: $1" >&2; exit 2 ;;
    *.flatpak)
      if [ -n "$BUNDLE" ]; then
        echo "error: multiple bundle paths specified" >&2
        exit 2
      fi
      BUNDLE="$1"
      ;;
    *)           echo "error: unexpected argument: $1" >&2; exit 2 ;;
  esac
  shift
done

case "$BRANCH" in
  ""|*[!A-Za-z0-9._-]*)
    echo "error: invalid Flatpak branch name: $BRANCH" >&2
    exit 2
    ;;
esac

if [ -z "$BIN_DIR" ]; then
  if [ "$SCOPE" = "--system" ]; then
    BIN_DIR="/usr/local/bin"
  else
    BIN_DIR="$HOME/.local/bin"
  fi
fi

SHIM_PATH="${BIN_DIR%/}/osbx"

is_flatpak_shim() {
  p="$1"
  if [ -L "$p" ]; then
    target=$(readlink "$p" 2>/dev/null || true)
    case "$target" in
      *"/flatpak/exports/bin/$APP_ID") return 0 ;;
    esac
  fi
  if [ -f "$p" ]; then
    if grep -Fq "$SHIM_MARKER" "$p" 2>/dev/null; then
      return 0
    fi
    if grep -Fq "flatpak run" "$p" 2>/dev/null && grep -Fq "$APP_ID" "$p" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

dir_in_path() {
  want="${1%/}"
  case ":${PATH:-}:" in
    *":$want:"*|*":$want/:"*) return 0 ;;
    *) return 1 ;;
  esac
}

if [ "$UNINSTALL" = 1 ]; then
  if command -v flatpak >/dev/null 2>&1; then
    if flatpak info "$SCOPE" "$APP_ID//$BRANCH" >/dev/null 2>&1; then
      echo "==> uninstalling $APP_ID//$BRANCH ($SCOPE)"
      flatpak uninstall "$SCOPE" -y "$APP_ID//$BRANCH"
    else
      echo "==> $APP_ID//$BRANCH is not installed ($SCOPE)"
    fi
  else
    echo "warning: flatpak not found; skipping Flatpak uninstall" >&2
  fi

  if [ -e "$SHIM_PATH" ] || [ -L "$SHIM_PATH" ]; then
    if is_flatpak_shim "$SHIM_PATH" || [ "$FORCE" = 1 ]; then
      rm -f "$SHIM_PATH"
      echo "==> removed wrapper $SHIM_PATH"
    else
      echo "note: leaving $SHIM_PATH untouched (not an osbx Flatpak wrapper; pass --force to remove)" >&2
    fi
  fi
  exit 0
fi

if [ "$SHIM_ONLY" = 0 ]; then
  if ! command -v flatpak >/dev/null 2>&1; then
    echo "error: flatpak is not installed. Install flatpak first (e.g. 'sudo apt install flatpak' or 'sudo dnf install flatpak')." >&2
    exit 1
  fi

  # Ensure Flathub is configured so Flatpak can fetch the org.freedesktop.Platform runtime.
  flatpak remote-add "$SCOPE" --if-not-exists flathub "$FLATHUB_URL"

  if [ -n "$BUNDLE" ]; then
    if [ ! -f "$BUNDLE" ]; then
      echo "error: Flatpak bundle not found: $BUNDLE" >&2
      exit 1
    fi
    echo "==> installing $APP_ID from bundle $BUNDLE ($SCOPE)"
    flatpak install "$SCOPE" -y --or-update --bundle "$BUNDLE"
  else
    echo "==> configuring Flatpak remote '$REMOTE' ($REPO_URL)"
    flatpak remote-add "$SCOPE" --if-not-exists --no-gpg-verify "$REMOTE" "$REPO_URL"
    if flatpak info "$SCOPE" "$APP_ID//$BRANCH" >/dev/null 2>&1; then
      echo "==> updating $APP_ID//$BRANCH ($SCOPE)"
      flatpak update "$SCOPE" -y "$APP_ID//$BRANCH"
    else
      echo "==> installing $APP_ID//$BRANCH from '$REMOTE' ($SCOPE)"
      flatpak install "$SCOPE" -y "$REMOTE" "$APP_ID//$BRANCH"
    fi
  fi
fi

if [ "$INSTALL_SHIM" = 1 ]; then
  if [ -e "$SHIM_PATH" ] || [ -L "$SHIM_PATH" ]; then
    if ! is_flatpak_shim "$SHIM_PATH" && [ "$FORCE" = 0 ]; then
      echo "error: $SHIM_PATH already exists and is not an osbx Flatpak wrapper." >&2
      echo "Re-run with --force to replace it, --bin-dir DIR to install elsewhere, or --no-shim to skip." >&2
      exit 1
    fi
  fi

  mkdir -p "$BIN_DIR"
  TMP_SHIM="${BIN_DIR%/}/.osbx.tmp.$$"
  trap 'rm -f "$TMP_SHIM"' EXIT

  if [ "$BRANCH" = "stable" ]; then
    RUN_ARGS="$APP_ID"
  else
    RUN_ARGS="--branch=$BRANCH $APP_ID"
  fi

  cat > "$TMP_SHIM" <<EOF
#!/bin/sh
$SHIM_MARKER (managed by scripts/install-flatpak.sh)
exec flatpak run $RUN_ARGS "\$@"
EOF
  chmod 0755 "$TMP_SHIM"
  mv -f "$TMP_SHIM" "$SHIM_PATH"
  trap - EXIT
  echo "==> installed CLI wrapper $SHIM_PATH"

  if ! dir_in_path "$BIN_DIR"; then
    echo
    echo "note: $BIN_DIR is not currently in your PATH."
    case "${SHELL:-}" in
      */fish)
        echo "Add it with: fish_add_path $BIN_DIR"
        ;;
      */zsh)
        echo "Add it to ~/.zshrc: export PATH=\"$BIN_DIR:\$PATH\""
        ;;
      *)
        echo "Add it to ~/.bashrc or ~/.profile: export PATH=\"$BIN_DIR:\$PATH\""
        ;;
    esac
  else
    RESOLVED=$(command -v osbx 2>/dev/null || true)
    if [ -n "$RESOLVED" ] && [ "$RESOLVED" != "$SHIM_PATH" ]; then
      echo "note: another 'osbx' appears earlier in PATH ($RESOLVED) and shadows $SHIM_PATH" >&2
    fi
  fi
fi

if [ "$SHIM_ONLY" = 0 ]; then
  echo
  echo "Done! Try:"
  if [ "$INSTALL_SHIM" = 1 ] && dir_in_path "$BIN_DIR"; then
    echo "  osbx --version"
    echo "  osbx vmm probe --run-guest"
  elif [ "$INSTALL_SHIM" = 1 ]; then
    echo "  $SHIM_PATH --version"
    echo "  $SHIM_PATH vmm probe --run-guest"
  else
    echo "  flatpak run $APP_ID --version"
  fi
  echo "Upgrade later with:"
  echo "  flatpak update $SCOPE $APP_ID"
fi
