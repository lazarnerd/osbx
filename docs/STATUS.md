# Status

Plan: `docs/PLAN.md`. Usage: `README.md`. Provenance rules: `docs/PROVENANCE.md`. Guest assets: `guest/README.md`.
Verify: `OSBX_SPEC_EXAMPLES=<spec checkout>/examples cargo test --workspace --no-fail-fast` (138 tests at last run,
including end-to-end tests that boot real sandboxes). Dev host: WSL2 Ubuntu 24.04, Intel i7-1360P, nested KVM.

## Windows hosts (Windows Hypervisor Platform)

Native, no WSL or Docker needed at run time. Dev host: Windows 11 Enterprise 26200, i7-1360P.

- **Backend** (`osbx-vmm/src/whp.rs`): WHP partitions with WHP's xAPIC emulation (timer,
  INIT/SIPI); osbx supplies the IOAPIC (`ioapic.rs`), a CMOS RTC, and decodes port/MMIO exits
  with Windows' instruction emulator (`WinHvEmulation.dll`). The guest gets `tsc_early_khz` and
  uses the TSC-deadline APIC timer (no PIT). Same devices as on KVM (virtio-MMIO blk, vsock, fs;
  16550). Linux boots to init in ~5 s; 4 vCPUs come up via INIT/SIPI.
- **`kvm@1` on Windows**: partitions are created with nested virtualization (WHP accepts it only
  together with its APIC emulation); the guest sees VMX, loads KVM and boots a nested VM
  (`osbx.mode=kvm`: `KVM-IN-GUEST OK`). `osbx vmm probe` reports the WHP equivalents.
- **Root filesystems without Docker** (`osbx-image::oci` + `::native`, used on every host without
  a Docker daemon, or with `OSBX_BUILDER=native`): registry client (anonymous bearer tokens,
  `~/.docker/config.json` basic auth, platform TLS store, digest-verified blob cache in
  `$OSBX_HOME/oci`) and a builder VM that makes the ext4 file system and extracts the layers as
  real root (whiteouts applied as deletions). `ubuntu:24.04`: pull + build 11 s; ownership and
  setuid bits preserved. Kit descriptors and image env are read from layers directly.
- **Workspace and kit mounts** (`osbx-vmm/src/fuse.rs`): osbx's own FUSE server over `std::fs`
  behind virtio-fs. Windows paths appear in the guest as `/c/Users/...`. Files are owned by the
  caller; `chmod` is kept in an NTFS alternate data stream; `#!`/ELF files are executable;
  names with `\`, `:` or `..` are refused. Verified live both ways, renames, deletes, 5 MB
  round trip, no escape.
- **CLI**: control sockets are AF_UNIX on Windows too (`uds_windows`); console raw mode / size via
  the console API; the supervisor is a detached process (std handles made non-inheritable so
  pipes see EOF); state in `%LOCALAPPDATA%\osbx`; sparse disk images (NTFS sparse flag);
  rootSize growth happens in the guest at boot (`resize2fs` online, now in the initramfs).
- **Install**: `scripts\install-osbx.ps1 [-Prefix DIR]` (osbx finds `DIR\guest` beside its `bin`). Guest assets are still built on Linux/WSL
  (`guest/build-assets.sh`; `--offline` reuses the kernel/modules when the archive is unreachable).
- Not yet on Windows: Docker-built templates via `docker` (native builder only), symlink creation
  in shares without Developer Mode, xattrs/locks in shares, interactive TTY verified only through
  the protocol (no console in the test harness).

## Works end to end (Linux/KVM hosts)

**VMM (`osbx-vmm`)**: KVM, direct 64-bit Linux boot (bzImage + initramfs), up to 32 vCPUs (MP table, IOAPIC),
up to 64 GiB RAM (split around the 32-bit MMIO hole), in-kernel irqchip/PIT, 16550 console, virtio-MMIO
transport, **virtio-blk**, **virtio-fs** (FUSE passthrough via fuse-backend-rs), **virtio-vsock** (userspace, so it
can serve other hypervisor backends later), clean shutdown, watchdog stop. Boot to a running agent: ~4 s.

**`kvm@1` (hard requirement)**: the `kvm@1` probe implements the spec's usability contract; a sandbox granted
`kvm@1` (kit capability or `--kvm`) gets usable `/dev/kvm` + `/dev/vhost-vsock` for every user, and a nested VM
boots inside it (verified as root and as an unprivileged user, and across restarts). Required `kvm@1` on a host
that cannot nest is refused at create and at start, naming the type. At every start the devices get group
`kvm` (created if missing) and the sandbox user joins it, so access survives packages that tighten
`/dev/kvm` (QEMU's postinst sets `root:kvm 0660`).

**Published ports** are raw TCP forwards (host listener -> vsock -> agent -> guest port): HTTP,
WebSockets (noVNC, HMR, ttyd, Jupyter), VNC, SSH all work. Fixed: on Windows hosts accepted sockets
inherited the listener's non-blocking mode and connections were dropped as soon as the client went
quiet (e.g. right after a WebSocket upgrade); regression test in `osbx-sandbox/tests/sandbox.rs`.

**Sandbox**: OCI image -> ext4 root filesystem (ownership preserved via fakeroot; cached per image + kit
layers + agent build), guest agent as PID 1 (exec with PTY/resize and user switching, zombie reaping, port
tunnels, egress forwarding), hostname, per-sandbox CA in the trust bundle.

**Network**: no NIC; all egress goes guest agent -> vsock -> host proxy. Deny by default (balanced/deny-all),
explicit deny wins, live policy changes, kit rules (with install-phase rules open only during install hooks),
pending/approve workflow, TLS interception only for hosts with credentials or HTTP-level rules, credential
injection (verified against the real GitHub API with a fake token: the guest sends no header, GitHub sees one;
the token appears nowhere in the guest).

**CLI**: create/run/start/stop/rm/ls/exec/cp/ports/logs, workspace modes direct/clone/none, policy and secret
management, `env run` from sbxenv.yaml (agent, workspace, env, memory, cpus, rootSize, ports, kits, mounts; resource changes to an existing sandbox apply at its next start, the root disk only ever grows), per-sandbox
detached supervisor with a control socket.

**Kits**: local directories (declaration-only) and OCI images (descriptor read from
`/usr/share/sandbox/kit/*/kit.yaml`, content layered onto the root filesystem; workload kits become the root
filesystem). Validation, composition (closed set, conflicts, integrates, one workload, one provider per name),
capability selection (unsupported required -> refused by name; optional -> skipped and recorded), create-phase
kit args (`--kit-arg [KIT.]NAME=VALUE`, `sbxenv.yaml` `kits[].args`, `Arg.env` delivery, post-expansion re-validation).
Implemented capability types: `network-policy@1`, `network-policy@2` (Layer-7 HTTP method/path/query rules wired
into the TLS-intercepting proxy), `credential@1` (runtime phase, API key + inject rules, sentinel in the declared
env var, OAuth, optional `credentials.yaml` binding enforcement via `osbx secret bind|unbind|bindings`), `sbx@1`
(agent launched by the host under bash with `BASH_ENV`, as the image's user, `WORKSPACE_DIR`/`SANDBOX_NAME` set),
`lifecycle@1` (install once, startup every boot, background, files with mode/overwrite, interactive tail),
`host-mount@1` (host dir per kit+path, overridable via sbxenv `mounts:`), `volume@1` (sandbox-private persistent
storage surviving stop/start), `port@1` (TCP ports auto-published on loopback at start), `resources@1` (max-reconciled
CPU/RAM floors), `ssh-agent@1` (host `SSH_AUTH_SOCK` forwarded over vsock with host-side `SSHSIG` namespace
filtering; fails closed on host-restricted `authenticate`), `kvm@1`, `dockerd@1`, `privileged@1`.

**Docker inside the sandbox** (`--docker` or a kit's `dockerd@1`): the guest loads overlay/bridge/veth/netfilter
modules and mounts cgroup2; the runtime starts `dockerd` (when the image has it) before startup hooks, with
pulls and container traffic going through the policy proxy (containers reach it on the bridge address).
Verified: `docker run hello-world`, container HTTPS to an allowed host (200), to an unlisted host (refused and
listed by `osbx policy pending`). The balanced baseline now includes Docker Hub's blob CDN hosts, found this way.

**Templates**: `osbx save NAME TEMPLATE` (stopped sandbox), `osbx templates`, `osbx create --template T`
(e.g. an image with Docker already installed: create 0.6 s, start with dockerd ~10 s).

**Docker's `sbx/claude` workload kit runs under osbx**: `agent: claude` resolves to `docker.io/sbx/claude:latest` and is composed as the workload (published descriptors validate with their derived `deb/` provides; create-phase kit args expand from defaults). The project's `sbxenv.yaml` (claude + host-state + kvm, 4 host mounts) starts as-is: Claude Code 2.1.332 as `agent`, kit-seeded settings, session links into `./sessions`, `/dev/kvm`. OAuth (`credential@1` `oauth`): the proxy intercepts the kit's token endpoint, keeps the real tokens in the host secret store (global entry `oauth/<service>`, so a login made in one sandbox serves all of them and survives re-creation; `osbx secret rm oauth/anthropic` logs out), gives the guest placeholders, swaps them back on resource hosts and refresh requests, and writes the kit's credential file (placeholders + real expiry) at every start. `NODE_EXTRA_CA_CERTS` points Node-based agents at the sandbox CA. Verified with a fake provider (proxy test) and a seeded login in a real Claude sandbox; not yet with a real claude.ai login. Not yet: agent-sessions/skills/context capabilities (skipped, optional).

**Libraries also verified**: Kit v3 decoding/validation against all 42 upstream example kits; sbxenv.yaml
parsing; secrets (file store 0600, scopes, command/vault sources with cache).

## Not done (honest list)

- **Other host OSes**: no macOS (Hypervisor.framework) backend; the stub compiles and refuses.
- **Docker**: images must contain dockerd (or install it, e.g. `apt-get install docker.io`, then restart); no
  IPv6 for containers; `dockerd@1`'s `autoStart: false` and engine settings from kits are not honored;
  container DNS is not provided (tools reach the network through the proxy settings).
- **Other capability types**: agent-context, agent-sessions, host-port, docker-auth, git-identity,
  kit-registry, usb-device, open-url, long-running, auto-restart, acp. Required ones are refused by name.
- **Kit details**: local kits with a build recipe must be built first; git kit sources unsupported;
  install-phase credentials unsupported; UDP `port@1` and host-restricted `ssh-agent@1` `authenticate` fail closed.
- **Secrets**: no OS keychain backends (file store only); OAuth `responseFields` mapping and TOML credential files not implemented.
- **MCP gateway**, **cloud sandboxes**, **organization governance**, templates/snapshots, `sbx move`: not done.
- **Networking**: HTTP/1.1 interception only (no HTTP/2, no WebSocket on intercepted hosts); no UDP.
- **Guest kernel**: Ubuntu's generic kernel from the archive; a purpose-built minimal kernel would boot faster.
- **CI**: the workflow has never run; KVM tests need runners with nested virtualization.

## Facts established about upstream `sbx`
- sbx v0.54.0 rejects `com.docker.sandbox/kvm@1` ("unsupported capability type") on Linux with working KVM as
  well as on Windows; `sbx env plan` and `sbx kit inspect` accept the kit, only create/run reject it.
- Multiple PATHs to `sbx env run` deep-merge and concatenate lists.

## Assumptions to confirm against real `sbx` (`grep -rn "ASSUMPTION:" crates/`)
Wildcard depth (`*` one label), port-less rules cover 80/443, our balanced baseline host list, built-in service
env/host/header table, version comparison details, sbxenv layering rules, agent-name -> image mapping
(`docker.io/sbx/<agent>`).
