<#
HOST-side setup for Windows (PowerShell 5.1+ / 7).  macOS/Linux/WSL: host-setup.sh.
Run on the machine that runs `sbx`, not inside the sandbox.

  dev\host-setup.ps1 [-Kvm] [-NoPolicy] [-ForceEnv] [-Provision] [-Run]

  (default)   create ..\sessions and ..\cache\*, install ..\sbxenv.yaml from the
              template if missing, allow the Rust/crates network domains, and
              preview with `sbx env plan`
  -Kvm        use sbxenv.kvm.yaml.template (adds the kvm@1 kit; needs a host that can grant it)
  -NoPolicy   do not touch the network policy
  -ForceEnv   overwrite ..\sbxenv.yaml with the template
  -Provision  create the sandbox (`sbx env run -d`) and run sandbox-setup.sh in it
  -Run        like -Provision, then attach to the sandbox

"..\" means the folder that contains osbx\ (the sbxenv.yaml folder).
#>
[CmdletBinding()]
param([switch]$NoPolicy, [switch]$ForceEnv, [switch]$Provision, [switch]$Run, [switch]$Kvm)
$ErrorActionPreference = 'Stop'

$Here      = Split-Path -Parent $MyInvocation.MyCommand.Path
$Workspace = Split-Path -Parent $Here
$Root      = Split-Path -Parent $Workspace
if ($Run) { $Provision = $true }

function Invoke-Sbx { & sbx @args; if ($LASTEXITCODE -ne 0) { throw "sbx $($args -join ' ') failed ($LASTEXITCODE)" } }

if (-not (Get-Command sbx -ErrorAction SilentlyContinue)) {
  throw 'sbx not found. Install it first: winget install -h Docker.sbx (see README.md).'
}

Write-Host "==> folders under $Root"
foreach ($d in 'sessions', 'cache\cargo-registry', 'cache\cargo-git', 'cache\sccache') {
  New-Item -ItemType Directory -Force -Path (Join-Path $Root $d) | Out-Null
}

Write-Host '==> sbxenv.yaml'
$envFile = Join-Path $Root 'sbxenv.yaml'
if (-not (Test-Path $envFile) -or $ForceEnv) {
  $tpl = if ($Kvm) { 'sbxenv.kvm.yaml.template' } else { 'sbxenv.yaml.template' }
  Copy-Item (Join-Path $Here $tpl) $envFile -Force
  Write-Host "installed $envFile (from $tpl)"
} else {
  Write-Host "kept existing $envFile (diff against dev\sbxenv.yaml.template if unsure)"
}

if (-not $NoPolicy) {
  Write-Host '==> network policy (balanced preset + Rust domains)'
  & sbx policy init balanced
  Invoke-Sbx policy allow network 'sh.rustup.rs,static.rust-lang.org,index.crates.io,static.crates.io,crates.io,github.com,codeload.github.com,raw.githubusercontent.com,deb.debian.org'
  Invoke-Sbx policy ls
}

Set-Location $Root
Write-Host '==> sbx env plan'
Invoke-Sbx env plan

if ($Provision) {
  Write-Host '==> create sandbox'
  Invoke-Sbx env run -d
  Write-Host '==> run sandbox-setup.sh inside the sandbox'
  Invoke-Sbx env exec -- bash -lc 'bash "$WORKSPACE_DIR/dev/sandbox-setup.sh"'
}
if ($Run) { & sbx env run; exit $LASTEXITCODE }
Write-Host ''
Write-Host 'Next: sbx env run   (first time: then, inside, run dev/sandbox-setup.sh)'
