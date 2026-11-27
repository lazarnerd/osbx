# osbx architecture

From the outside in: the system and what it talks to, the crates, the host runtime, the main
flows (create, start, exec, egress), then the VMM and the guest at the bottom.

## 1. System context

```mermaid
flowchart LR
    user(["Developer / agent user"])
    subgraph host["Host: Linux (KVM) or Windows (WHP)"]
        cli["osbx CLI"]
        sup["Supervisor<br/>one per sandbox"]
        state[("State<br/>$OSBX_HOME")]
        ws[("Workspace +<br/>kit mount dirs")]
    end
    subgraph vm["Sandbox microVM"]
        guest["Linux guest<br/>agent as PID 1<br/>coding agent e.g. Claude Code"]
    end
    registry[("OCI registries<br/>Docker Hub, GHCR")]
    internet(("Internet APIs<br/>GitHub, Anthropic, ..."))

    user -->|"osbx run / exec / env run"| cli
    cli <-->|"control socket<br/>AF_UNIX"| sup
    cli --> state
    cli -->|"pull images, kit descriptors"| registry
    sup -->|"boots + owns"| vm
    sup <-->|"virtio-fs"| ws
    guest -->|"all egress via vsock"| sup
    sup -->|"policy-checked,<br/>credentials injected"| internet

    classDef ext fill:#eef,stroke:#88a
    class registry,internet ext
```

## 2. Crates

```mermaid
flowchart TD
    cli["osbx-cli<br/>CLI, supervisor, kits, images"]
    sandbox["osbx-sandbox<br/>VM + agent + proxy"]
    image["osbx-image<br/>OCI client, rootfs builders"]
    vmm["osbx-vmm<br/>VMM: KVM / WHP backends,<br/>virtio, FUSE server, probe"]
    proxy["osbx-proxy<br/>egress proxy, TLS MITM CA,<br/>credential + OAuth injection"]
    policy["osbx-policy<br/>rules, presets, decisions"]
    secrets["osbx-secrets<br/>stores, resolver, inject rules"]
    kit["osbx-kit<br/>Kit v3 descriptors,<br/>validate, resolve, expand"]
    env["osbx-env<br/>sbxenv.yaml"]
    proto["osbx-proto<br/>host/guest framing"]
    agent["osbx-agent<br/>in-guest PID 1<br/>static musl"]

    cli --> sandbox & image & kit & env & proxy & secrets & policy & vmm & proto
    image --> sandbox & vmm & proto & policy & proxy
    sandbox --> vmm & proxy & policy & secrets & proto
    proxy --> policy & secrets
    agent --> proto

    classDef guest fill:#efe,stroke:#6a6
    class agent guest
```

## 3. Host runtime

```mermaid
flowchart TB
    subgraph cliproc["osbx process (short-lived)"]
        cmds["create / start / stop / rm / ls<br/>exec / cp / ports / policy / secret / env run"]
        images["images.rs<br/>native or docker backend"]
        kits["kits.rs<br/>load, compose, select capabilities"]
        sys["sys.rs<br/>OS differences: sockets, console,<br/>detach, private files"]
    end

    subgraph supproc["osbx __supervise NAME (detached, long-lived)"]
        ctl["control socket server<br/>status, exec, publish, pending,<br/>reload-policy, stop"]
        life["kit lifecycle@1<br/>files, install, startup hooks"]
        creds["StoreCredentials<br/>kit + built-in services, OAuth"]
        subgraph sb["osbx_sandbox::Sandbox"]
            vmh["osbx_vmm::Vm<br/>vCPU threads + devices"]
            px["Policy proxy<br/>tokio runtime"]
            vs["VsockHost<br/>listen / connect"]
        end
    end

    files[("$OSBX_HOME<br/>sandboxes/NAME/root.img, ca.*, sandbox.json<br/>images/*.img, oci/blobs, secrets, policy.json")]

    cmds --> images & kits
    cmds -->|"spawn + wait ready"| supproc
    cmds <-->|"JSON line, then agent frames"| ctl
    ctl --> vs
    vs -->|"port 3128 egress"| px
    px --> creds
    life --> vs
    cmds --> files
    supproc --> files
```

## 4. Sandbox lifecycle

```mermaid
stateDiagram-v2
    [*] --> Created: osbx create<br/>rootfs copied, CA generated
    Created --> Starting: osbx start / run / env run
    Starting --> Running: agent answers on vsock<br/>first-boot setup, kit hooks
    Starting --> Created: boot or install hook failed
    Running --> Running: exec / cp / ports / policy reload
    Running --> Created: osbx stop<br/>or guest powers off
    Created --> [*]: osbx rm
    Running --> [*]: osbx rm -f
```

## 5. Create and start

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant C as osbx CLI
    participant K as kits.rs
    participant I as images.rs
    participant R as Registry
    participant B as Builder VM
    participant S as Supervisor
    participant G as Guest

    U->>C: osbx env run / create
    C->>K: load kits (dirs or images)
    K->>I: staged descriptor, image env
    I->>R: manifest, config, layers
    K-->>C: composed kits, granted / skipped capabilities
    C->>I: build_base(image, kit overlays)
    alt cached images/KEY.img
        I-->>C: reuse
    else native builder
        I->>B: boot initramfs, blank sparse disk
        I->>B: mke2fs, per layer: whiteout deletions + tar -x
        I->>B: inject osbx-agent, hostname, umount
        B-->>I: ext4 image
    end
    C->>C: copy_sparse to sandboxes/NAME/root.img, grow to rootSize
    C->>S: spawn detached supervisor
    S->>G: boot root=/dev/vda, shares, osbx.kvm / docker
    G->>G: init: modules, resize2fs, mount shares, switch_root
    G-->>S: agent ready on vsock
    S->>G: hostname, CA trust, kit files, install hooks, startup hooks
    S-->>C: control socket up
    C->>S: exec agent command, TTY attached
```

## 6. Egress, policy and credentials

```mermaid
sequenceDiagram
    autonumber
    participant P as Guest process
    participant A as Guest agent<br/>127.0.0.1:3128
    participant V as vsock
    participant X as Host policy proxy
    participant Pol as PolicySet
    participant Cr as Credentials
    participant N as Upstream server

    P->>A: CONNECT api.github.com:443 via http_proxy
    A->>V: new stream, guest port 3128
    V->>X: bridge_to_proxy
    X->>Pol: evaluate host, port, request
    alt deny or needs approval
        X-->>P: 403, recorded in osbx policy pending
    else allow, no credential and no HTTP rules
        X->>N: TCP tunnel, TLS end to end
    else allow and credential or HTTP rule
        X-->>P: TLS with per-sandbox CA
        X->>Cr: for_host / oauth_for_host
        X->>N: request with injected header,<br/>sentinels swapped for real tokens
        N-->>X: response, OAuth tokens kept on host
        X-->>P: response with placeholders only
    end
```

## 7. Image build pipeline

```mermaid
flowchart LR
    ref["image reference<br/>e.g. docker.io/sbx/claude"] --> parse["Reference::parse<br/>registry, repo, tag"]
    parse --> auth{"401?"}
    auth -->|"yes"| tok["Bearer token<br/>anonymous or docker config"]
    tok --> man
    auth -->|"no"| man["manifest or index"]
    man -->|"pick linux/amd64"| cfg["config blob<br/>argv, env, user, workdir"]
    man --> layers["layer blobs<br/>sha256-verified cache"]
    layers --> scan["host: scan whiteouts"]
    scan --> del["guest: delete hidden paths"]
    del --> untar["guest: decompressed layer<br/>streamed into tar -x"]
    untar --> mark["guest: remove .wh markers"]
    mark -->|"next layer / kit overlay"| scan
    mark --> inject["inject agent, probe,<br/>hostname, CA"]
    inject --> img[("images/KEY.img<br/>ext4, sparse")]

    docker["Linux + Docker daemon:<br/>docker export + fakeroot + mke2fs -d"] -.->|"alternative backend"| img
```

## 8. Kit composition

```mermaid
flowchart TD
    srcs["kit sources<br/>local dirs, image refs,<br/>agent image itself"] --> load["load descriptor<br/>validate authored / published"]
    load --> expand["expand create-phase args,<br/>kit.env from image Env + passwd"]
    expand --> plan["resolve composition<br/>one workload, requires, conflicts, provides"]
    plan --> select{"capability supported<br/>on this host?"}
    select -->|"yes"| grant["granted"]
    select -->|"no, optional"| skip["skipped, recorded"]
    select -->|"no, required"| refuse["create refused, named"]
    grant --> effects

    subgraph effects["Effects of granted capabilities"]
        np["network-policy@1 → policy rules"]
        cr["credential@1 → inject rules, sentinels, OAuth"]
        lc["lifecycle@1 → files, install, startup hooks"]
        hm["host-mount@1 → virtio-fs shares"]
        kv["kvm@1 → /dev/kvm, nested virt"]
        dk["dockerd@1 → modules + dockerd"]
        sbx["sbx@1 → bash launch, BASH_ENV"]
    end
```

## 9. VMM layers

```mermaid
flowchart TB
    vm["Vm::start / wait / stop<br/>boot.rs, hypervisor-neutral"]
    load["load_guest<br/>bzImage, initrd, cmdline,<br/>boot_params + e820, GDT, page tables"]
    mpt["mptable.rs<br/>CPUs, IOAPIC, ISA routes"]
    dev["Devices<br/>port + MMIO dispatch"]

    subgraph devices["Emulated devices"]
        uart["16550 UART COM1"]
        rtc["CMOS RTC"]
        bus["MmioBus"]
        ioa["IOAPIC<br/>WHP only"]
        subgraph virtio["virtio-MMIO transports"]
            blk["virtio-blk<br/>raw sparse image"]
            vsock["virtio-vsock<br/>userspace"]
            fs["virtio-fs"]
        end
    end

    subgraph hv["hv backend: Machine + Vcpu"]
        kvm["kvm.rs, Linux<br/>in-kernel PIC/IOAPIC/LAPIC/PIT,<br/>irqfd, SIGUSR1 kick"]
        whp["whp.rs, Windows<br/>WHP partition, xAPIC emulation,<br/>WinHvEmulation decoder,<br/>CPUID exits, cancel-run kick"]
    end

    fsl["fuse-backend-rs passthrough<br/>Linux"]
    fsw["fuse.rs over std::fs<br/>Windows"]

    vm --> load & mpt & dev & hv
    dev --> uart & rtc & bus & ioa
    bus --> blk & vsock & fs
    fs --> fsl & fsw
```

## 10. Guest physical memory map

```mermaid
block-beta
    columns 1
    a["0x0000_0500 GDT"]
    b["0x0000_7000 boot_params zero page"]
    c["0x0000_9000 to 0xC000 identity page tables, first GiB"]
    d["0x0002_0000 kernel command line"]
    e["0x0009_FC00 MP floating pointer + table"]
    f["0x0010_0000 kernel bzImage payload"]
    g["... RAM ... initrd at top of low RAM"]
    h["0xC000_0000 end of low RAM, start of MMIO hole"]
    i["0xD000_0000 virtio-MMIO windows, 4 KiB each, IRQs 5..23"]
    j["0xFEC0_0000 IOAPIC"]
    k["0xFEE0_0000 local APIC"]
    l["0x1_0000_0000 RAM above 4 GiB, if mem > 3 GiB"]
```

## 11. One vCPU exit, both backends

```mermaid
sequenceDiagram
    autonumber
    participant G as Guest vCPU
    participant H as Hypervisor
    participant L as Run loop
    participant E as WinHvEmulation
    participant D as Devices
    participant T as virtio transport

    G->>H: MMIO write: QueueNotify
    alt KVM
        H-->>L: VcpuExit::MmioWrite addr, data
        L->>D: mmio_write
    else WHP
        H-->>L: exit MemoryAccess
        L->>E: TryMmioEmulation
        E->>L: callback: get regs, translate GVA
        E->>D: memory callback: write
    end
    D->>T: write offset 0x50
    T->>T: device.queue_notify, process chains
    T->>D: Interrupt.signal
    alt KVM
        D->>H: irqfd write → in-kernel IOAPIC
    else WHP
        D->>D: IoApic.pulse pin → Message
        D->>H: WHvRequestInterrupt vector, dest
    end
    H->>G: interrupt delivered via LAPIC
```

## 12. Interrupt routing

```mermaid
flowchart LR
    devs["virtio devices,<br/>UART"] -->|"Interrupt.signal"| line{"IrqLine"}
    line -->|"Linux"| efd["EventFd irqfd"] --> kio["KVM in-kernel IOAPIC"] --> klapic["KVM LAPIC"]
    line -->|"Windows"| pin["IoApic pin<br/>edge, pending if masked"] --> msg["Message<br/>vector, mode, dest"] --> req["WHvRequestInterrupt"] --> wlapic["WHP xAPIC emulation"]
    klapic --> cpu["guest vCPU"]
    wlapic --> cpu
    timer["Timers: KVM PIT / kvm-clock<br/>WHP: TSC-deadline LAPIC timer,<br/>tsc_early_khz on cmdline"] -.-> cpu
```

## 13. virtio-vsock and agent protocol

```mermaid
flowchart LR
    subgraph hostside["Host"]
        vh["VsockHost"]
        exec["exec / cp / hooks<br/>connect port AGENT"]
        tun["published ports<br/>connect TUNNEL"]
        egress["listen EGRESS 3128<br/>→ policy proxy"]
    end
    subgraph dev["virtio-vsock device, userspace"]
        rx["rx queue"]
        tx["tx queue"]
        conn["connection table<br/>credit flow control"]
    end
    subgraph guestside["Guest"]
        agent["osbx-agent PID 1"]
        pty["exec: pipes or PTY,<br/>user switch, resize"]
        gproxy["127.0.0.1:3128 listener"]
    end
    exec & tun --> vh
    vh <--> conn
    egress <--> vh
    conn <--> rx & tx
    rx & tx <--> agent
    agent --> pty
    gproxy --> agent
```

```mermaid
packet-beta
    0-7: "type: EXEC, STDIN, STDIN_EOF, STDOUT, STDERR, RESIZE, EXIT, ERROR"
    8-39: "length, u32 LE"
    40-103: "payload: JSON ExecRequest, raw bytes, rows/cols, exit code ..."
```

## 14. virtio-fs on Windows

```mermaid
sequenceDiagram
    autonumber
    participant K as Guest kernel virtiofs
    participant Q as Request queue
    participant F as Fs device
    participant S as fuse::Server
    participant W as NTFS via std::fs

    K->>Q: in_header + body, e.g. LOOKUP parent, name
    K->>F: queue notify
    F->>S: handle request bytes
    S->>S: validate name, no backslash, colon, ..
    S->>W: symlink_metadata of root\rel\name
    W-->>S: metadata
    S->>S: node id table, mode: ADS osbx.mode<br/>or shebang / ELF, owner = caller uid
    S-->>F: out_header + entry_out
    F->>Q: write reply, add_used
    F->>K: interrupt
```

## 15. Guest boot

```mermaid
flowchart TD
    k["Linux kernel 6.8<br/>acpi=off, MP table, virtio_mmio.device=..."] --> init["initramfs /init<br/>busybox + e2fsprogs + osbx-agent"]
    init --> mode{"osbx.mode"}
    mode -->|"test"| t["self checks, reboot"]
    mode -->|"kvm"| kv["load kvm modules,<br/>osbx-probe nested guest"]
    mode -->|"shell"| sh["console shell"]
    mode -->|"agent"| ag["load vsock modules"]
    ag --> opt["docker / kvm modules if osbx.docker / osbx.kvm"]
    opt --> root{"root= given?"}
    root -->|"no: builder VM"| agentinit["exec /bin/osbx-agent<br/>from initramfs"]
    root -->|"yes"| mnt["mount ext4 root,<br/>resize2fs online"]
    mnt --> shares["mount virtiofs shares<br/>osbx.share=tag:path[:ro]"]
    shares --> move["move /proc /sys /dev, cgroup2"]
    move --> sr["switch_root →<br/>/usr/local/bin/osbx-agent"]
```

## 16. On-disk state

```mermaid
mindmap
  root(("$OSBX_HOME<br/>Linux ~/.local/share/osbx<br/>Windows %LOCALAPPDATA%\osbx"))
    policy.json
    secrets
      secrets.json
      oauth/service
    oci
      blobs/sha256
      refs
    images
      KEY.img read-only bases
    templates
      NAME.img + NAME.json
    kit-mounts
    sandboxes
      NAME
        sandbox.json
        root.img
        ca.pem / ca.key
        clone
        supervisor.log / console.log
        kit-install.done
    guest
      vmlinuz, initramfs, osbx-agent
```
