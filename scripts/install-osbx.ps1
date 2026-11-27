<#
Install osbx on a Windows host (the native Windows Hypervisor Platform backend).

  scripts\install-osbx.ps1 [-Prefix DIR] [-SkipBuild] [-Force]

Builds `osbx.exe` (release) from this checkout, installs it to <Prefix>\bin, copies the guest
assets (kernel, initramfs, agent) to <Prefix>\guest, puts <Prefix>\bin on your user PATH and
runs the hypervisor probe.

  -Prefix DIR   where the program goes (default %LOCALAPPDATA%\osbx). osbx finds its guest
                assets in <Prefix>\guest by itself; no environment variables are needed.
                Sandboxes, images and secrets are state, not program files: they stay in
                %LOCALAPPDATA%\osbx (set OSBX_HOME to move them).

Requirements: Windows 10 2004+ / 11 with the "Windows Hypervisor Platform" optional feature
(elevated: Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform, then reboot),
Rust (MSVC toolchain), and built guest assets in guest\assets (see guest\README.md; they are
built on Linux or WSL: guest/build-assets.sh --with-osbx).

A running sandbox's supervisor runs osbx.exe from <Prefix>\bin, which Windows keeps locked:
stop your sandboxes (osbx ls / osbx stop NAME) before reinstalling, or pass -Force to stop them.
#>
[CmdletBinding()]
param(
  [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'osbx'),
  [switch]$SkipBuild,
  [switch]$Force
)
$ErrorActionPreference = 'Stop'
$Repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Bin = Join-Path $Prefix 'bin'
$Guest = Join-Path $Prefix 'guest'

if (-not $SkipBuild) {
  Write-Host '==> building osbx (release)'
  Push-Location $Repo
  try {
    & cargo build --release -p osbx-cli
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    $meta = & cargo metadata --format-version 1 --no-deps | ConvertFrom-Json
  } finally { Pop-Location }
  $Built = Join-Path $meta.target_directory 'release\osbx.exe'
} else {
  $Built = Join-Path $Bin 'osbx.exe'
}

$Installed = Join-Path $Bin 'osbx.exe'
$running = Get-Process osbx -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Installed }
if ($running) {
  if (-not $Force) {
    throw "osbx.exe in $Bin is in use (running sandboxes). Stop them first (osbx ls; osbx stop NAME) or pass -Force."
  }
  Write-Host '==> stopping running sandboxes'
  & $Installed ls | Select-Object -Skip 1 | ForEach-Object {
    $f = ($_ -split '\s+')
    if ($f[2] -eq 'running') { & $Installed stop $f[0] }
  }
}

New-Item -ItemType Directory -Force $Bin, $Guest | Out-Null
if (-not $SkipBuild) {
  Copy-Item $Built $Installed -Force
  Write-Host "installed $Installed"
}

$Assets = Join-Path $Repo 'guest\assets'
$need = 'vmlinuz', 'initramfs.cpio.gz', 'osbx-agent'
foreach ($f in $need) {
  if (-not (Test-Path (Join-Path $Assets $f))) {
    throw "guest asset $f missing in $Assets (build them on Linux/WSL: guest/build-assets.sh --with-osbx)"
  }
}
foreach ($f in $need + 'osbx-probe', 'kernel-version') {
  $src = Join-Path $Assets $f
  if (Test-Path $src) { Copy-Item $src (Join-Path $Guest $f) -Force }
}
Write-Host "guest assets in $Guest"

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not (($userPath -split ';') -contains $Bin)) {
  [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $Bin), 'User')
  Write-Host "added $Bin to your user PATH (open a new terminal to pick it up)"
}
$env:Path = "$Bin;$env:Path"

Write-Host '==> hypervisor probe'
& $Installed vmm probe --run-guest
if ($LASTEXITCODE -ne 0) {
  Write-Warning 'the probe failed: enable the Windows Hypervisor Platform feature (see the top of this script)'
} else {
  Write-Host 'osbx is ready: try  osbx run shell  in a project folder, or  osbx env run  next to an sbxenv.yaml'
}
