#!/usr/bin/env bash
# Install the skills listed in skills.conf, each repo pinned to a commit.
#
#   ./install-skills.sh                 install into <workspace>/.claude/skills  (default)
#   ./install-skills.sh --user          install into ~/.claude/skills
#   ./install-skills.sh --dest DIR      install into DIR
#   ./install-skills.sh --force         overwrite skills whose content differs
#   ./install-skills.sh --list          show what would be installed, change nothing
#   ./install-skills.sh --show-latest   print the current HEAD SHA of every repo
#
# Why the project dir is the default: ~/.claude/skills is a read-only mount in
# the sandbox, and a project dir lives on the host with the workspace, so the
# skills survive removing and re-creating the sandbox.
#
# Downloaded repos are untrusted data: each is fetched into its own empty temp
# directory, nothing in it is executed, and only the listed skill folders are
# copied out.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WORKSPACE=$(dirname "$HERE")
CONF="$HERE/skills.conf"
DEST="$WORKSPACE/.claude/skills"
FORCE=0 LIST=0 SHOW_LATEST=0

while [ $# -gt 0 ]; do
  case "$1" in
    --user)        DEST="$HOME/.claude/skills" ;;
    --project)     DEST="$WORKSPACE/.claude/skills" ;;
    --dest)        DEST="${2:?--dest needs a directory}"; shift ;;
    --conf)        CONF="${2:?--conf needs a file}"; shift ;;
    --force)       FORCE=1 ;;
    --list)        LIST=1 ;;
    --show-latest) SHOW_LATEST=1 ;;
    -h|--help)     sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

[ -f "$CONF" ] || { echo "missing $CONF" >&2; exit 1; }

# `repo` lines: id url sha     `skill` lines: repo path [as]
repos() { awk '$1=="repo" {print $2, $3, $4}' "$CONF"; }
skills_of() { awk -v r="$1" '$1=="skill" && $2==r {print $3, $4}' "$CONF"; }

if [ "$SHOW_LATEST" = 1 ]; then
  while read -r id url sha; do
    latest=$(git ls-remote "$url" HEAD | cut -f1)
    mark=""; [ "$latest" = "$sha" ] && mark="(pinned, up to date)"
    printf '%-10s %s %s\n' "$id" "$latest" "$mark"
  done < <(repos)
  exit 0
fi

safe_rel() { case "$1" in /*|*..*|"") return 1 ;; esac; }

installed=0 unchanged=0 skipped=0 failed=0
[ "$LIST" = 1 ] || mkdir -p "$DEST"
echo "Destination: $DEST"

while read -r id url sha; do
  if [ "$LIST" = 1 ]; then
    echo "== $id @ ${sha:0:12} ($url)"
    skills_of "$id" | while read -r path as; do echo "   ${as:-$(basename "$path")}  <-  $path"; done
    continue
  fi

  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  echo "== $id @ ${sha:0:12}"
  if ! { git -C "$tmp" init -q \
         && git -C "$tmp" remote add origin "$url" \
         && GIT_TERMINAL_PROMPT=0 git -C "$tmp" -c advice.detachedHead=false fetch -q --depth 1 origin "$sha" \
         && git -C "$tmp" -c core.hooksPath=/dev/null checkout -q FETCH_HEAD; }; then
    echo "   FAILED to fetch $url @ $sha" >&2
    failed=$((failed + 1)); rm -rf "$tmp"; continue
  fi

  while read -r path as; do
    name="${as:-$(basename "$path")}"
    if ! safe_rel "$path" || ! safe_rel "$name"; then
      echo "   refusing unsafe path: $path -> $name" >&2; failed=$((failed + 1)); continue
    fi
    src="$tmp/$path"
    if [ ! -f "$src/SKILL.md" ]; then
      echo "   MISSING $path (no SKILL.md at that commit)" >&2; failed=$((failed + 1)); continue
    fi
    target="$DEST/$name"
    if [ -e "$target" ]; then
      if diff -rq "$src" "$target" >/dev/null 2>&1; then
        unchanged=$((unchanged + 1)); continue
      elif [ "$FORCE" = 1 ]; then
        rm -rf "$target"
      else
        echo "   SKIP $name: exists and differs (use --force)"; skipped=$((skipped + 1)); continue
      fi
    fi
    cp -a "$src" "$target"
    rm -rf "$target/.git"
    echo "   + $name"
    installed=$((installed + 1))
  done < <(skills_of "$id")

  rm -rf "$tmp"; trap - EXIT
done < <(repos)

[ "$LIST" = 1 ] && exit 0
echo
echo "installed=$installed unchanged=$unchanged skipped=$skipped failed=$failed"
[ "$failed" -eq 0 ]
