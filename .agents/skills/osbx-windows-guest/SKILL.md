---
name: osbx-windows-guest
description: >-
  Use this skill when building, debugging, or running live E2E tests for Windows
  sandboxes, `osbx-agent.exe`, Windows file-sharing backends (sync/projfs/dokany/winfsp),
  or `osbx windows build-base` unattended templates.
---

# Windows Guest & Agent Runbook

## Cross-Compiling `osbx-agent.exe`
```bash
cargo clippy -p osbx-vmm -p osbx-sandbox -p osbx-agent -p osbx-cli --target x86_64-pc-windows-gnu --all-targets -- -D warnings
cargo build --release -p osbx-agent --target x86_64-pc-windows-gnu
```

## Live E2E Testing Without Mutating Sealed Templates
- Sealed templates may live under `~/.local/share/osbx/templates/` or Flatpak's `~/.var/app/io.github.lazarnerd.osbx/data/osbx/templates/`.
- Run the automated E2E suite (which creates a throwaway `OSBX_HOME` in `/tmp`, symlinks the sealed `win11` template, hot-swaps the newly built `osbx-agent.exe`, and cleans up on drop):
  ```bash
  cargo test -p osbx-cli --test windows_backends -- --nocapture
  ```
- **Hot-swapping a running `osbx-agent.exe` inside a throwaway clone:** Windows allows renaming a running `.exe`. Use PowerShell (`Move-Item -Force` old `.exe` aside, `Copy-Item -Force` new `.exe` into `C:\Program Files\osbx\osbx-agent.exe`), then `osbx stop` + `osbx start`.
- **Inspecting unattended `osbx windows build-base` progress:** set `OSBX_WIN_FB=/tmp/win-fb.ppm` to dump live GOP framebuffer screenshots during install.

## Verified Windows Guest & Agent Pitfalls
- **Passwordless S4U (`LsaLogonUser` + `MsV1_0S4ULogon`):** Non-admin `Users` accounts (like `agent`) do not have `SeBatchLogonRight` by default; always fall back from `SECURITY_LOGON_TYPE(4)` (`Batch`) to `SECURITY_LOGON_TYPE(3)` (`Network`) and `DuplicateTokenEx(..., TokenPrimary, ...)`. Keep `UserPrincipalName` and `DomainName` UTF-16 buffers inside the same contiguous `AuthenticationInformation` allocation.
- **`Client-ProjFS` (`ProjectedFSLib.dll`):** Only exists on Windows 10/11 Client editions (`dism` returns `0x800f080c` on Windows Server 2025 Core). Probe `HKLM\SYSTEM\CurrentControlSet\Services\PrjFlt` in addition to `LoadLibraryW("ProjectedFSLib.dll")`, and prefer a `win11` template when testing `projfs`.
- **`virtiofs.exe` / WinFsp early-boot race:** `osbx-agent` starts right after `VirtioSocketWSP`, often before `viofs.sys`/`WinFsp` finish initializing (especially after `dism` servicing reboots). Wait for `std::fs::read_dir(target).is_ok()` (not just `exists()`) and retry on early exit.
- **`FileSyncServer::handle_watch`:** Always capture the initial `snapshot_tree` *before* replying `FileSyncResp::Ok` so host mutations immediately after subscribing cannot be lost in the baseline.
- **`viofs.sys` & Dokan v2 ABI:** `GUID_DEVINTERFACE_VIRT_FS` is `{a1b0cbf2-f488-4b29-b89f-16c78e68c737}`, `IOCTL_VIRTFS_GET_VOLUME_NAME = 0x0022_6000`, `IOCTL_VIRTFS_FUSE_REQUEST = 0x0022_E006`. In Dokan v2 (`dokan2.dll`), `Cleanup`/`CloseFile` return `void`, `Mounted`/`Unmounted` precede `GetFileSecurity`, and `VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE = 16384`.
- **`cmd.exe` quirks in tests:** Use parentheses around `if ... else` (`if exist X (exit 0) else (exit 1)`), and avoid multiple quoted paths in one `cmd /c` string (use PowerShell or separate invocations).
- **Windows 11 unattended install (`autounattend.xml`):** Include empty `<ProductKey><WillShowUI>Never</WillShowUI></ProductKey>`, default to image index `6` (Win11 Pro) on multi-edition Client ISOs, always set `BypassSecureBootCheck=1` and `BypassRAMCheck=1`, include `Microsoft-Windows-International-Core` in `oobeSystem`, and delete `Winlogon\AutoLogonCount` so Session 1 auto-logon persists across boots.
