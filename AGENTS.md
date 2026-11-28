# osbx Repository Guardrails

## Git, PRs, and Releases
- **Never push directly to `main`** and never pass `--admin` to bypass branch protection. Always commit on a feature branch, open a PR via `gh pr create --base main`, wait for all CI checks (`ubuntu-24.04`, `ubuntu-24.04-arm`, `windows-2022`, `macos-15`) to pass, and wait for the user to merge on GitHub before tagging a release.
- **Integration tests before release:** Before opening a release PR or tagging a release for new behavior, add and run real integration tests (`crates/*/tests/*.rs`) covering the feature — including live VM/KVM E2E tests when local templates and `/dev/kvm` are present — not only unit tests or ad-hoc shell commands.
- **Leave untracked local files untouched** (e.g., user `osbx-compose.yml` in the repo root) when staging commits.

## Code Quality & Cross-Target Verification
- Maintain crate lints: `unsafe_code = "deny"` (where enabled), `undocumented_unsafe_blocks = "deny"` (every `unsafe` block requires a `// SAFETY:` comment), and `missing_docs = "warn"`.
- Before committing or opening a PR, verify all three gates pass:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo clippy -p osbx-vmm -p osbx-sandbox -p osbx-agent -p osbx-cli --target x86_64-pc-windows-gnu --all-targets -- -D warnings`

## Windows Sandbox Architecture & License Hygiene
- **Apache-2.0 hygiene:** Never statically link, embed, or redistribute GPLv3/LGPL-3.0 drivers or libraries (WinFsp, Dokany). Dynamically load optional guest DLLs at runtime (`LoadLibraryW`/`GetProcAddress`) or spawn out-of-process (`virtiofs.exe`). Never introduce SMB/Samba.
- **Self-sufficient `osbx-agent.exe`:** Do not shell out to `powershell.exe`, `netsh.exe`, `tar.exe`, or WMI `Win32_Process.Create` for CA/proxy setup, share mounting, or `osbx cp`, and never hardcode Windows user passwords in `osbx-agent.exe` (use WinHTTP API, `tar` crate over `CP_PUT`/`CP_GET`, in-agent mount supervision, and passwordless S4U logon).
