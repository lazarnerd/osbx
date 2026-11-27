# `osbx-compose.yml` Specification

`osbx-compose.yml` (or `osbx-compose.yaml`) is a Docker Compose-inspired declarative format for
defining one or more `osbx` sandboxes. It is implemented in the `osbx-compose` crate and compiles
into the same canonical internal verbose specification IR (`osbx-spec`) as `sbxenv.yaml`
(`osbx-env`), so both formats share one validation and execution pipeline in `osbx-cli`.

```text
osbx-compose.yml ──▶ osbx-compose ──┐
                                    ├──▶ osbx-spec (canonical verbose IR) ──▶ osbx-cli runner
sbxenv.yaml      ──▶ osbx-env     ──┘
```

## Quick Example

```yaml
sandboxes:
  synergy-plus:
    agent: claude
    workspace: /workspace
    cpus: 8
    memory: 8G
    disk: 128G
    volumes:
      - ./osbx:/workspace/osbx
    kits:
      - source: sbx/claude-sessions:1.0.0
        mounts:
          /home/agent/claude-history: ./.sessions
    firewall:
      default: deny
      allow:
        - google.com
```

## Commands

| Command | What it does |
|---|---|
| `osbx compose [-f FILE]... [--profile P]... [--arg K=V]... up [-d] [SANDBOX...]` | Create and start selected sandboxes (attaches automatically when one sandbox is active unless `-d`) |
| `osbx compose run [SANDBOX] [-- CMD...]` | Create/start one sandbox and attach (or run `CMD`) |
| `osbx compose down [--rm] [SANDBOX...]` | Stop sandboxes (with `--rm`, runs `pre_remove` hooks and deletes disks) |
| `osbx compose ps` | Show status and active profiles for sandboxes declared in the file |
| `osbx compose plan` / `check` | Offline validation and dry-run summary (mounts, kits, capabilities, firewall, hooks) |
| `osbx compose config [--json]` | Render the compiled canonical `osbx-spec` IR (YAML or JSON) |
| `osbx env config [FILE] [--json]` | Render the same canonical `osbx-spec` IR from an `sbxenv.yaml` |

## File Discovery & Layering

When `-f` / `--file` is omitted, `osbx compose` loads in ascending priority (later files win):

1. `~/.osbx-compose.yml` or `~/.osbx-compose.yaml` (unless `--no-user-base`)
2. `./osbx-compose.yml` or `./osbx-compose.yaml`
3. `./osbx-compose.override.yml` or `./osbx-compose.override.yaml` (if present)

Layering deep-merges mappings, replaces scalars and lists, and concatenates `hooks` lists (base
first). Top-level `x-*` extension fields and YAML anchors / `<<:` merge keys are supported; all
other unknown keys are rejected strictly.

## Interpolation & `.env`

String scalars support structural Docker Compose interpolation (values never inject YAML keys):

- `${VAR}`, `${VAR:-default}`, `${VAR-default}`, `${VAR:?err}`, `${VAR?err}`, and `$$` for a literal `$`
- Built-ins: `${OSBX_PROJECT_DIR}`, `${OSBX_FILE_DIR}`
- Precedence: host environment < sibling `.env` < built-ins < declared `args:` (validated against `enum`, `pattern`, `required`, and `default`, overridden via `--arg name=value`)

## Top-Level Sections

| Key | Purpose |
|---|---|
| `version` | Optional; if set, must be `"1"` |
| `name` | Optional project name (prefixes sandbox/volume names when different from sandbox key) |
| `args` | Typed CLI argument declarations (`description`, `default`, `required`, `enum`, `pattern`) |
| `secrets` | Reusable host-proxy-injected credentials (`ref` \| `command` \| `value`, `refresh`, `backend`, `no_verify`, `snapshot`, `bindings: { api_key, oauth }`, optional `inject`) |
| `volumes` | Named persistent volumes (`{}` / `driver: managed`, or `{ driver: host, path: ./dir }`) |
| `firewalls` | Reusable egress firewall profiles (`default`, `extends`, `allow`, `deny`) |
| `registries` | Reusable OCI registry logins (`secret`, optional `username`) |
| `mcp` | Reusable MCP server definitions (`url` or `command` + `args`) |
| `sandboxes` | Map of sandbox definitions (at least one required) |

## Sandbox Fields (`sandboxes.<key>`)

- **Identity & launch**: `sandbox_name`, `profiles`, `extends` (inherit from another sandbox key), `agent` (built-in or kit handle; defaults to `shell` if `image`/`template` is set), `image` (exclusive with `template`), `template`, `pull_policy` (`always` \| `missing` \| `never`), `entrypoint`, `command` (string or exec array).
- **Workspace & volumes**:
  - `workspace`: guest working directory (absolute path like `/workspace`), `none`, relative host path (`./repo`), or `{ path, target, mode: direct|clone }`.
  - `volumes`: short `SOURCE:TARGET[:rw|ro|clone]` or long `{ type: bind|volume|clone|kit-mount, source, target, read_only, mode, kit }`. Host paths starting with `.`, `/`, `~`, or containing `/` / `\` are bind mounts; bare names reference top-level `volumes:`.
- **Resources**: `cpus` (`0` = auto, `1..=32`), `memory` (e.g. `8G`, `2048M`), `disk` (scalar root size like `128G`, or `{ root, docker, clone }`).
- **Environment**: `env_file` (string or list, loaded relative to the compose file) and `environment` (map or `KEY=VALUE` list).
- **Ports**: short `"[HOST_IP:][HOST_PORT:]TARGET[/PROTO]"` (or bare port number) or long `{ target, host, host_ip, protocol }` (`tcp`, `tcp4`, `tcp6`, `udp`, `udp4`, `udp6`).
- **Capabilities**: `capabilities: { kvm, docker, privileged, nested, gpu, display, fuse, usb, ssh_agent }`. `kvm`, `docker`, and `privileged` accept `bool` or `{ enabled, required }`; `ssh_agent` accepts `bool` or `{ enabled, required, unrestricted, sign_namespaces }`.
- **Agent options**: `skills` (`off` \| `readonly` \| `readwrite`), `writable_env_files` (`bool`).
- **Kits**: string reference or `{ source, digest, args, mounts }`. `mounts` binds kit `host-mount@1` guest paths directly (`guest_path: host_path`).
- **Firewall**:
  ```yaml
  firewall:
    default: balanced    # deny | balanced | allow (omit to inherit host policy.json)
    extends: [rust]      # merge rules from top-level `firewalls:`
    allow:
      - google.com
      - hosts: [api.github.com]
        methods: [GET, POST]
        paths: ["/repos/org/*"]
        query: { per_page: "100" }
        phase: runtime   # runtime | install
    deny:
      - "169.254.169.254"
  ```
  > **Precedence**: Explicit `deny` rules always beat `allow` rules (see `osbx-policy`). To allow only specific domains, set `default: deny` and list them under `allow:`. Always quote wildcards like `"*.com"` in YAML.
- **Attachments**: `secrets` (`name` or `{ source, required }`), `registries`, `mcp`.
- **Hooks**: `hooks: { initialize, post_create, pre_remove, guest: { files, install, startup } }`. Host hooks run with the user's privileges and are surfaced by `osbx compose plan`.
