# Plan: Open-source, feature-complete clone of the `sbx` runtime

## Context
Docker Sandboxes (`sbx`) runs coding agents in per-session microVMs with a host-side policy proxy, credential injection, an MCP gateway, v3 "Kits", cloud sandboxes and org governance. `sbx` and its VMM are closed source; only the Kit spec (`docker/sandbox-kit-spec`, Apache-2.0) is open. Goal: an Apache-2.0, Rust implementation with a custom VMM, covering local CLI, policy/proxy/secrets/MCP, Kit v3 + `kit-tck` conformance, and cloud + governance. This is a greenfield project; no existing code to reuse beyond external dependencies (spec repo, `kit-tck`, rust-vmm crates).

Working name: `osbx` (placeholder; must not imply Docker affiliation).

### Provenance and legal guardrail (decision needed before Phase 0 ends)
User permitted reverse engineering of `sbx`. Risk: Docker's EULA/ToS may prohibit decompilation, and copying code or assets would breach copyright. Recommended policy, recorded in `docs/PROVENANCE.md`:
1. Primary sources: public docs, the Apache-2.0 spec, blog posts, release notes.
2. Black-box observation of `sbx` (CLI output, on-the-wire behavior, files it writes, `strace`/pcap of its own traffic on a machine we own) to pin down undocumented behavior.
3. Binary decompilation only after a legal review of the EULA, performed by a separate "spec writer" who records behavior as prose; implementers never see decompiled code (clean-room split). Never copy code, strings tables or branding. Never reuse Docker's cloud endpoints or auth; cloud/governance is our own backend.

## Architecture (Cargo workspace)
| Crate | Role |
|---|---|
| `osbx-cli` | `osbx` binary (clap). Thin client over daemon API; interactive dashboard (ratatui) |
| `osbxd` | Per-user daemon: sandbox lifecycle, state DB (SQLite), policy, secrets, API over unix socket / named pipe |
| `osbx-vmm` | Custom VMM library: `Hypervisor` trait + backends (KVM, Hypervisor.framework, WHP) |
| `osbx-vmm-devices` | virtio-blk, virtio-net/vsock, virtio-fs (FUSE server), virtio-console, virtio-rng, balloon |
| `osbx-guest` | Guest init (PID 1 agent) over vsock: mounts, user setup, exec/attach/cp/ports, starts dockerd |
| `osbx-proxy` | Egress proxy: HTTP/HTTPS MITM forward proxy, transparent TCP, policy engine, credential injection |
| `osbx-policy` | Rule model, presets, precedence, approvals |
| `osbx-secrets` | Keychain/CredMan/SecretService/file backends, dynamic sources, bindings |
| `osbx-mcp` | Host-side MCP gateway (remote + stdio servers, policy) |
| `osbx-kit` | Kit v3 loader/resolver/assembler, OCI pull/push, capability registry |
| `osbx-image` | Guest rootfs/image building and caching (OCI -> ext4/erofs) |
| `osbx-cloud` + `osbx-cloudd` | Cloud API client and server (scheduler, VM fleet, billing hooks) |
| `osbx-gov` | Governance service: org policy, audit log, sign-in enforcement |
| `osbx-tck-adapter` | Adapter executable for `kit-tck runtime` |

Key design choices
- Custom VMM per the user's decision. Build on `rust-vmm` crates (`kvm-ioctls`, `vm-memory`, `virtio-queue`, `vhost`) on Linux; `objc2`/Hypervisor.framework on macOS (Apple silicon, arm64 only); WHP via `windows` crate on Windows. One device model, three `Hypervisor` backends. Guest arch: arm64 on Apple silicon; x86-64 and arm64 on Linux/Windows.
- Guest kernel: pinned minimal Linux config, built reproducibly; shipped as artifact.
- Guest <-> host control channel: virtio-vsock, no guest-visible network path to host except via proxy.
- All egress forced through host proxy: guest has a single virtio-net (or vsock-tunneled) interface with no route except to proxy; UDP/ICMP dropped unless experimental UDP flag.
- Credentials: guest only sees placeholders; proxy rewrites headers post-exit from the VM.
- Docker-in-VM: guest rootfs bundles dockerd/containerd/buildx/compose; `/var/lib/docker` on a per-sandbox disk.

## Hard requirement: `kvm@1` inside every sandbox, on every host OS
Decided 2026-11-25. osbx MUST be able to grant a sandbox usable `/dev/kvm` and `/dev/vhost-vsock`
(spec: `capabilities/com.docker.sandbox/kvm@1`: open read-write, `KVM_GET_API_VERSION` == 12,
`KVM_CREATE_VM` succeeds, `VHOST_GET_FEATURES` succeeds), whatever the host OS. Upstream `sbx` v0.54.0
rejects the type ("unsupported capability type") on both Windows and Linux, so this is a place where
osbx must go beyond the reference runtime.

Consequences for the design:
- Every `Hypervisor` backend must expose nested virtualization to the guest: KVM on Linux (guest CPUID
  must carry VMX/SVM; host `kvm_intel/kvm_amd nested=1`), Windows Hypervisor Platform (nested-virt
  processor feature, Windows 11 + supported CPU), Apple Hypervisor.framework (nested virt: Apple Silicon
  M3+ on a recent macOS). The guest kernel config ships `CONFIG_KVM`, `CONFIG_VHOST_VSOCK`.
- The runtime does the *preflight*: a required `kvm@1` that the host cannot satisfy is refused before any
  hook runs, naming the type; an optional one is skipped and recorded. "Recognizing the name" is not enough.
- A `kvm@1` grant is gated (explicit consent) and survives stop/start without reselection.
- Where a host genuinely cannot nest (older Apple Silicon, no VT-x exposure), osbx refuses clearly rather
  than emulating. Windows/macOS support is therefore "best effort per hardware", Linux is the reference.
- Test matrix: the probe in `osbx-vmm` (`osbx vmm probe`) runs in CI on each host class.

## Phases

### Phase 0: Foundations (2-3 wks)
- Repo, license, CI matrix (Linux x86/arm, macOS arm, Windows), `PROVENANCE.md`, contribution rules.
- Compatibility target document: freeze behavior matrix from the research (workspace modes, presets, secret services, flags). Record observed `sbx --help` tree for every subcommand via black-box capture.
- Spike: boot a stock Linux kernel on KVM with rust-vmm; measure boot time baseline.

### Phase 1: Custom VMM, Linux/KVM (8-10 wks)
- vCPU/memory setup, kernel loader, minimal firmware-less direct boot, virtio-mmio devices, serial console.
- virtio-blk, virtio-net, virtio-vsock, virtio-rng, balloon; snapshot-friendly state.
- virtio-fs server (passthrough with caching toggle equivalent to `DOCKER_SANDBOXES_ENABLE_VIRTIOFS_CACHE`).
- Guest init + agent over vsock; exec/attach/cp primitives.
- Exit: boots a rootfs, runs dockerd, `docker run hello-world` inside, <2 s boot target.

### Phase 2: Daemon + local CLI (6-8 wks)
- `osbxd` state DB, lifecycle (create/run/stop/rm/ls/exec/cp/reset/diagnose/settings/login stub).
- Workspace modes: direct (virtio-fs, same absolute path), clone (read-only `/run/sandbox/source`, private clone, `sandbox-<name>` git remote via daemon socket), mountless (workdir default `/home/agent/workspace`).
- Ports: `port ls|publish|unpublish`, loopback publication; SSH config setup.
- Image/template pipeline: OCI -> rootfs cache; save sandbox as template; agent images for the 10 agents plus `shell`.
- Env flags (`-e`, `--env-file`), clipboard image paste (off by default, 64 MiB cap), skills store (read-only default, `skills add|import`).
- Interactive dashboard (`osbx` with no args), telemetry opt-out (our own telemetry is off by default, document it).
- Exit: `osbx run claude` works end-to-end on Linux.

### Phase 3: Policy, proxy, secrets, MCP (8-10 wks, parallel with 2 once Phase 1 net works)
- Proxy: HTTP/HTTPS MITM with per-sandbox CA injected in guest trust store; transparent TCP forwarding; stalled-connection timeout; upstream proxy (system, URL, PAC, SOCKS5, experimental); post-quantum KEX setting.
- Policy engine: presets (`allow-all`, `balanced`, `deny-all`), rules on host/IP/CIDR/port, HTTP method/path/query (case-insensitive ASCII), wildcards incl. `**`; precedence (any deny wins; allow if any allow; kit rules apply under every preset; unmatched in balanced/locked -> approval prompt); `policy init|ls|allow|deny|rm`; per-sandbox scope; log.
- Secrets: services (anthropic, cursor, droid, github, google, groq, mistral, nebius, openai, openrouter, xai), `set|set-custom|import|ls|rm`, sandbox scoping, `--ref` (1Password, AWS SM), `--command`, 55-min cache, registry creds, backends (Keychain, CredMan, Secret Service, 0700 file fallback), credential bindings file, OAuth on host (Claude Code, Codex, Cursor, Droid), `passthrough`.
- SSH agent forwarding (keys stay on host).
- MCP gateway: one endpoint per sandbox, remote + host stdio servers, `mcp:` reserved secret names, separate MCP policy.
- Exit: deny-by-default verified by tests; no raw key ever appears in guest memory or disk.

### Phase 4: Kit v3 + conformance (6-8 wks, parallel)
- Use the spec repo's concepts as the oracle: descriptor grammar (strict decode, 512 KiB limit), kinds workload/mixin/set, `provides/requires/integrates/conflicts`, args (`buildArg/env/buildSecret`), capabilities (network-policy, credential, agent-context, resources, volume, port, ... read each page under `docs/spec/capabilities/com.docker.sandbox`), permission-surface diff and approval gating, dependency-ordered composition, OCI annotation `vnd.docker.sandbox.kit.descriptor`.
- Since Rust cannot link the Go libraries, either wrap the Go `load/resolve/assemble` packages via a sidecar for differential testing, or reimplement and differential-test against them.
- BuildKit frontend `docker/sandbox-kit:3` is Go; reuse it as-is for builds and implement the consumer side in Rust.
- `--kit` flag on run/create, `sbxenv.yaml` env file with `env plan|create|run|rm`.
- `osbx-tck-adapter` implementing adapter verbs; run `kit-tck validate` and `kit-tck runtime` in CI.
- Exit: both TCK suites green.

### Phase 5: macOS and Windows backends (10-12 wks, overlaps Phase 2-4)
- macOS Hypervisor.framework backend (arm64): GIC, virtio-mmio, same device crates.
- Windows WHP backend: partition, vCPU run loop, MMIO emulation, vsock transport via named pipes/hvsocket.
- Platform adapters: secret stores, installers (brew tap, winget + MSI, apt package), path handling for direct mount.
- Exit: Phase 2 exit criteria on all three OSes.

### Phase 6: Cloud sandboxes (10-12 wks)
- `osbx-cloudd`: API (auth via OIDC/PAT), VM fleet on KVM hosts, scheduler, 1 h default expiry with resumable stop, `--cloud` routing for `ls/create/exec/attach/cp/rm/secret/diagnose`, `schedule`, `move` local<->cloud, SDK (Rust + generated OpenAPI clients), billing/metering hooks.
- Separate cloud secrets, policy, ports; no host workspace (clone inside).

### Phase 7: Governance (6-8 wks)
- `osbx-gov`: org/team policy (default deny; destinations, host paths, MCP servers), org-allow-only precedence (local allows ignored, local denies kept), "Blocked by org policy" messaging, audit log per request with SIEM export (syslog/webhook/S3), sign-in enforcement on managed machines, license assignment.

### Phase 8: Hardening and release (ongoing, final 6 wks)
- Security: fuzz virtio devices and FUSE server, proxy parser fuzzing, seccomp/landlock/AppContainer on VMM process, external audit, VM-escape threat model doc.
- Perf: boot time, virtio-fs throughput vs native, disk usage reporting.
- Compatibility: scripted conformance suite comparing `osbx` against real `sbx` behaviors (flags, exit codes, messages) wherever legally permissible.
- Docs, packaging, reproducible builds, signed releases.

## Critical risks
1. Custom VMM x3 OSes is the dominant cost and security risk; start Linux-only and keep the `Hypervisor` trait honest. (A fallback to cloud-hypervisor on Linux is cheap insurance if the schedule slips.)
2. Legal exposure from reverse engineering (see guardrail).
3. Moving target: `sbx` ships breaking changes every ~week (v0.53/0.54); pin a target version (v0.54.1) and track deltas.
4. Windows WHP and macOS lack some virtio support in the ecosystem; budget device-model work.
5. "Feature complete" for cloud/governance means operating real infrastructure, not just code.

## Verification
- Unit/integration: `cargo test --workspace`; VMM boot tests under KVM in CI (nested virt runners).
- End-to-end: scripted scenarios per phase exit (boot + `docker run`; `run claude` with proxy-injected key; deny-by-default curl test; clone-mode git flow; kit compose).
- Security tests: assert no real secret in guest (memory/disk/env scan), UDP/ICMP blocked, sandbox-to-sandbox isolation, host path escape attempts via virtio-fs.
- Conformance: `kit-tck validate` and `kit-tck runtime` against our adapter.
- Compatibility matrix: run identical command scripts against real `sbx` v0.54.1 and `osbx`, diff outputs.
- Cross-platform CI: Linux x86/arm, macOS arm, Windows x64.

## Rough timeline
~12-15 months with a team of 6-8 (VMM x2, daemon/CLI, proxy/policy/secrets, kits, cloud/gov). Linux-local MVP (Phases 0-3) by month ~5-6.
