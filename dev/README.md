# osbx development environment (Docker `sbx`)

Everything needed to rebuild the development sandbox for working on osbx on a new machine
(target host: **Ubuntu 24.04+ with KVM**; on Windows use `host-setup.ps1`).

This is contributor tooling only; it is not part of the osbx runtime. To install osbx
itself see the top-level `README.md` (`scripts/install-osbx.ps1` on Windows).

## Layout (the folder that contains this repo, `osbx/`, is called ROOT)

```
ROOT/sbxenv.yaml          sandbox definition (copy of dev/sbxenv.yaml.template)
ROOT/sessions/            Claude sessions/todos/history  (was: an app-data folder)
ROOT/cache/               cargo-registry, cargo-git, sccache   (build cache)
ROOT/osbx/                this repository
  .claude/skills/         45 project skills (installed by install-skills.sh)
  dev/                    this folder
```

Move the whole ROOT folder to keep sessions and caches. Moving only `osbx/` is
enough to rebuild everything else (sessions and caches then start empty).

## New machine, step by step

```bash
# on the host (Ubuntu): sbx + KVM; log out/in if it adds you to the kvm group
osbx/dev/host-setup.sh --install-sbx --kvm   # (--kvm: add KVM passthrough; omit on a host without KVM)
# folders, sbxenv.yaml, network policy, `sbx env plan`
sbx login
osbx/dev/host-setup.sh --run           # create sandbox, run sandbox-setup.sh inside, attach
```

Re-creating the sandbox later: `sbx env rm`, then `host-setup.sh --run`. Cargo
downloads, sccache artifacts, sessions and skills all survive; only the apt
packages and the rustup toolchain are reinstalled (about a minute).

## Scripts

| Script | Where | What |
|---|---|---|
| `host-setup.sh` / `.ps1` | host | folders, env file, network allow-list, `sbx env plan`, optional provision/run |
| `sandbox-setup.sh` | sandbox | apt deps, rustup, sccache, persistent env, skills, verification |
| `install-skills.sh` | either | installs `skills.conf` (commit-pinned) into `osbx/.claude/skills` |
| `kits/kvm` | sbx | `kvm@1`: usable /dev/kvm for the VMM (used by `sbxenv.kvm.yaml.template`). **sbx v0.54.0 rejects it on every OS** ("unsupported capability type"); verified on Linux with working KVM. Keep for when sbx implements it, or for osbx itself |
| `kits/host-state` | sbx | declares the host-mount paths (sessions, caches) + session-link hook |

## Sessions

Docker's `sbx/claude-sessions` kit declares `host-mount@1` for `/home/agent/claude-history`,
and with no override sbx chooses the host folder (app data). `sbxenv.yaml` `mounts:` can only
re-point a path that some kit declares (otherwise: `no kit declares host-mount@1 at ...`),
so `kits/host-state` declares the session and cache paths, carries the same link hook, and
`mounts:` points them at ROOT. Do not use it together with `sbx/claude-sessions`. To keep old sessions, copy the old app-data
`claude-history` contents into `ROOT/sessions` before the first run.

## Build cache

`sandbox-setup.sh` exports `RUSTC_WRAPPER=sccache` (via `/etc/sandbox-persistent.sh`),
`CARGO_INCREMENTAL=0`, `SCCACHE_DIR=~/.cache/sccache`. The host mounts make
`sccache` and the cargo registry survive `sbx env rm`. Verified in this sandbox:
after `rm -rf target`, a rebuild was served from sccache (8 hits). `target/` itself
is not persisted (it is slow over virtiofs); sccache restores compiled crates.
Check with `sccache --show-stats`. Cap is 20G (`SCCACHE_CACHE_SIZE`).

## Skills

`./install-skills.sh --list` shows them; `--show-latest` compares pins to upstream
HEAD; `--force` overwrites changed skills. Sources are pinned to commit SHAs in
`skills.conf` (anthropics/skills, Jeffallan/claude-skills, trailofbits/skills,
zhanghandong/rust-skills). Third-party skills are instructions your agent
follows: review before bumping a pin. trailofbits skills are CC-BY-SA-4.0.

## Not verified here

`sbx` is not installed in this sandbox, so these were **not** run: `host-setup.*`,
`sbx env plan/run/exec`, the `mounts:` / `${{ env.fileDir }}` handling, the local
kit build, and the `sbx policy` commands. Run `sbx env plan` first and read what it
reports. Also: there is no `/dev/kvm` in this sandbox, so the VMM cannot be run
here (it needs a KVM host, or macOS Apple Silicon M3+ with `sandboxOptions.nested`).
