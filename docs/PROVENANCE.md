# Provenance and clean-room policy

`osbx` is an independent implementation of the *behavior* documented for Docker
Sandboxes (`sbx`). It is not affiliated with Docker, and must not use Docker's
names, logos, endpoints, or code.

## Allowed sources
1. Public documentation, blog posts and release notes (cite in code comments or docs).
2. The Apache-2.0 Kit specification (`docker/sandbox-kit-spec`).
3. Black-box observation of `sbx` on a machine we own: CLI output, files it writes,
   traffic of its own sandboxes.

## Decompilation / binary reverse engineering
Permitted by the project owner, but **not started**. Docker's EULA may prohibit it.
Before any decompilation: get a legal review, then use a two-role split: a "spec writer"
records behavior as prose in `docs/behavior/`; implementers read only that prose.
Never copy code, string tables, assets, or branding.

## Recording assumptions
Where the public docs are silent, the code states the assumption in a doc comment
tagged `ASSUMPTION:` and a test pins it, so a later black-box check against real `sbx`
can confirm or correct it. `grep -rn "ASSUMPTION:" crates/` lists them all.

## Third-party guest-only runtime dependencies (Windows sandboxes)
- **Red Hat `virtio-win` drivers (`viostor`, `viosock`, `viofs`):** Signed Windows guest drivers
  provided by the user via `--virtio-win <iso>` during `osbx windows build-base`. Licensed under
  BSD-3-Clause / Apache-2.0; never bundled into or linked with `osbx` binaries.
- **WinFsp (Windows File System Proxy):** Optional user-supplied MSI (`--winfsp <msi>`) installed
  inside the Windows guest during template build to back `virtiofs.exe` (`viofs.sys`). WinFsp is
  licensed under GPLv3 with the FLOSS License Exception (compatible with Apache-2.0). `osbx` does
  not link against, embed, or redistribute WinFsp; it only invokes the user-supplied installer
  inside the guest VM and launches `virtiofs.exe` out-of-process.
- **Dokany 2 (`dokan2.dll`):** Optional user-supplied MSI (`--dokany <msi>`) installed inside the
  Windows guest during template build for LGPL-3.0 `virtio-fs` mounts (`backend: dokany`). `osbx`
  does not link against, embed, or redistribute Dokany; `osbx-agent.exe` dynamically loads
  `dokan2.dll` at runtime via `LoadLibraryW`/`GetProcAddress` only when installed in the guest.
- **Windows Projected File System (`ProjectedFSLib.dll` / `Client-ProjFS`):** Built-in Windows
  optional OS component enabled via `dism` during template build and dynamically loaded at runtime
  via `LoadLibraryW`/`GetProcAddress` for `backend: projfs` mounts. No third-party driver is
  bundled or redistributed.
- **EDK2 OVMF firmware (`OVMF_CODE_4M.fd`, `OVMF_VARS_4M.fd`):** Loaded at runtime from the host
  system or `$OSBX_HOME/guest`; licensed under BSD-2-Clause-Patent.
