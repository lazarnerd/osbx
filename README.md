# osbx

An open-source (Apache-2.0) sandbox runtime for coding agents, modelled on Docker Sandboxes (`sbx`).
Each sandbox is a KVM microVM driven by osbx's own VMM, with deny-by-default egress through a
host-side policy proxy that injects credentials the sandbox never sees. Kits (Kit spec v3) add
tools, network rules, credentials, host mounts, lifecycle hooks and KVM access.

Status: works end to end on **Linux/KVM hosts** (tested on WSL2, Ubuntu 24.04) and **Windows hosts**
(native, Windows Hypervisor Platform; install with `scripts/install-osbx.ps1`). See
`docs/STATUS.md` for exactly what is and is not implemented, and `docs/PLAN.md` for the roadmap.

## Quick start

Requirements: Linux with usable `/dev/kvm` (you in the `kvm` group), Rust, Docker (only to read
images), `fakeroot`, `e2fsprogs` (`mke2fs`), `git`; for building guest assets also `apt-get`,
`dpkg-deb`, `cpio`, `zstd`, `kmod` and the `x86_64-unknown-linux-musl` Rust target.

```bash
./guest/build-assets.sh --with-osbx          # guest kernel, initramfs, agent (guest/assets/)
cargo build --release -p osbx-cli
export OSBX_ASSETS=$PWD/guest/assets PATH=$PWD/target/release:$PATH

osbx vmm probe --run-guest                    # can this host run sandboxes (and nest KVM)?
cd ~/my-project
osbx run shell                                # create + start + attach (workspace = cwd)
```

### Windows

Requirements: Windows 10 2004+ or 11 with the **Windows Hypervisor Platform** feature
(`Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform` in an elevated
PowerShell, then reboot), Rust (MSVC). Docker is not needed: images are pulled and unpacked
by osbx itself. Guest assets are built once on Linux or WSL (`guest/build-assets.sh --with-osbx`).

```powershell
scripts\install-osbx.ps1          # builds osbx.exe, installs it and the guest assets to %LOCALAPPDATA%\osbx
osbx vmm probe --run-guest       # WHP present, nested virtualization (kvm@1) available?
cd C:\src\my-project
osbx run shell                   # the project appears in the sandbox at /c/src/my-project
```

## Commands

| Command | What it does |
|---|---|
| `osbx create [--name N] [--image IMG] [-w DIR \| --no-workspace] [--clone] [--kit K]... [--kit-arg [K.]A=V]... [--kvm] [--docker] [--template T] [-e K=V] [--mem MiB] [--cpus N] [--disk 40g] [AGENT]` | Create a sandbox (root filesystem built from the image, cached) |
| `osbx run [create flags] [AGENT] [-- CMD...]` | Create if needed, start if needed, attach to the agent (TTY when interactive) |
| `osbx start/stop NAME`, `osbx rm [-f] NAME`, `osbx ls` | Lifecycle; the root disk persists across stop/start |
| `osbx exec [-i] [-t] [-u USER] [-w DIR] [-e K=V] NAME -- CMD` | Run a command (exit status and stderr pass through) |
| `osbx cp SRC DST` | Copy files; one side is `NAME:/abs/path` |
| `osbx ports NAME [--publish [IP:]HOST:GUEST]` | Publish a guest port on the host: a raw TCP forward (any protocol: HTTP, WebSockets, VNC, SSH), bound to 127.0.0.1 unless an IP is given |
| `osbx logs NAME` | Guest console |
| `osbx save NAME TEMPLATE`, `osbx templates`, `osbx create --template T` | Reuse a configured root disk |
| `osbx policy ls \| init PRESET \| allow DEST \| deny DEST \| rm DEST [--sandbox N]` | Network policy (live: running sandboxes reload) |
| `osbx policy pending NAME`, `osbx policy approve NAME DEST [--all-sandboxes]` | Destinations refused for want of a rule, and approving them |
| `osbx secret set SERVICE [--sandbox N] [--command CMD \| --ref REF]`, `ls`, `rm`, `bind`, `unbind`, `bindings` | Credentials the proxy injects (value from stdin by default) and `credentials.yaml` domain bindings |
| `osbx env run [FILE] [--env-arg k=v] [-d]` | Run the environment described by an `sbxenv.yaml` |
| `osbx kit validate FILE...`, `osbx env check [FILE]`, `osbx policy check ...` | Offline validation tools |
| `osbx vmm probe [--run-guest] [--require-nested]`, `osbx vmm boot --kernel K --initrd I` | Hypervisor tools |

Workspace modes: **direct** (default) shares the directory read-write at the same absolute path,
live in both directions; **clone** (`--clone`) gives the agent a private clone at that path and
the original read-only at `/run/sandbox/source`, and adds a `sandbox-<name>` remote to your repo
so you can `git fetch` the agent's commits; **none** (`--no-workspace`).

State lives in `$OSBX_HOME` (default `~/.local/share/osbx`).

## How it works

```
host                                              microVM (osbx VMM on KVM)
osbx CLI ── unix socket ── supervisor (per sandbox)   Linux 6.8, root fs from an OCI image
                            ├─ VM: vCPUs, virtio-blk, virtio-fs, virtio-vsock, serial
                            ├─ policy proxy  <── vsock ── guest agent: 127.0.0.1:3128 (egress)
                            │   (deny by default, TLS interception only where needed,
                            │    credential injection, approvals)
                            └─ exec / ports / cp ── vsock ── guest agent (PID 1)
```

There is no virtual NIC: the guest's only way out is the proxy.

## Crates

`osbx-policy` (rules, presets, precedence), `osbx-kit` (Kit v3 descriptors, validation, resolution,
selection), `osbx-secrets` (stores, sources, injection), `osbx-proxy` (egress proxy),
`osbx-env` (sbxenv.yaml), `osbx-vmm` (KVM VMM, virtio devices, probe), `osbx-proto` +
`osbx-agent` (host/guest protocol and the in-guest agent), `osbx-image` (OCI image -> ext4),
`osbx-sandbox` (VM + agent + proxy), `osbx-cli` (`osbx`).

## Repository layout

| Path | Contents |
|---|---|
| `crates/` | The Rust workspace (see above) |
| `guest/` | Guest init and `build-assets.sh` (kernel, initramfs, agent into `guest/assets/`, not committed) |
| `third_party/vm-memory/` | Patched `vm-memory` (see its `OSBX-PATCH.md`) |
| `scripts/` | Runtime install scripts (`install-osbx.ps1`) |
| `docs/` | `ARCHITECTURE.md`, `STATUS.md`, `PLAN.md`, `PROVENANCE.md` |
| `dev/` | Contributor dev environment (Docker `sbx` sandbox, skills); not part of the runtime |

## Tests

`cargo test --workspace` (138 tests). Tests that need KVM, guest assets, Docker images or the
spec checkout skip with a note when those are missing; set `OSBX_SPEC_EXAMPLES` to
`<sandbox-kit-spec>/examples` to check all upstream example kits.

## License

Apache-2.0, see `LICENSE`.
