//! Windows-guest base template builder (`osbx windows build-base`).
//!
//! Generates an unattended Windows installation seed ISO (`autounattend.xml`, `setup_osbx.cmd`,
//! `osbx-agent.exe`, optional `winfsp.msi`) using the built-in pure-Rust ISO9660/Joliet writer,
//! attaches it alongside the Windows ISO and Red Hat `virtio-win.iso`, boots the unattended
//! installation inside `osbx-vmm`'s Q35 PCIe UEFI VM (Linux/KVM or Windows/WHP), and seals the
//! resulting QCOW2 base disk + persistent `OVMF_VARS_4M.fd` as a reusable template in
//! `$OSBX_HOME/templates/`.

use crate::iso9660::{IsoFile, write_iso};
use crate::state::{Launch, assets_dir, check_name, home, write_atomic};
use serde_json::json;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Windows edition profile for `osbx windows build-base`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WindowsProfile {
    /// Windows Server Core (headless, smallest footprint; default image index 1).
    #[default]
    Core,
    /// Windows Server Desktop Experience (full GUI, RDP enabled, Session 1 auto-logon; default image index 2).
    Desktop,
    /// Windows 11 Pro/Enterprise (GUI, RDP, OOBE local-account bypass, optional LabConfig bypass when `--vtpm` is off).
    Win11,
}

impl WindowsProfile {
    /// Parse CLI `--profile` value.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "core" => Ok(Self::Core),
            "desktop" => Ok(Self::Desktop),
            "win11" | "windows11" => Ok(Self::Win11),
            other => Err(format!(
                "unknown Windows profile {other:?} (expected core, desktop, or win11)"
            )),
        }
    }

    /// Default `install.wim` image index for this profile when `--image-index` is not explicitly set.
    pub fn default_image_index(self) -> u32 {
        match self {
            Self::Core => 1,
            Self::Desktop => 2,
            // Multi-edition Windows 11 Client ISOs place Windows 11 Pro (with RDP server) at index 6
            // (pass `--image-index 1` for single-edition Enterprise Evaluation ISOs).
            Self::Win11 => 6,
        }
    }

    /// Primary `virtio-win` driver OS subdirectory to inject in WinPE.
    fn virtio_subdir(self) -> &'static str {
        match self {
            Self::Core | Self::Desktop => "2k25",
            Self::Win11 => "w11",
        }
    }

    /// Whether this profile includes an interactive desktop shell (Session 1 + RDP).
    pub fn has_desktop(self) -> bool {
        matches!(self, Self::Desktop | Self::Win11)
    }

    /// Canonical string name stored in template metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Desktop => "desktop",
            Self::Win11 => "win11",
        }
    }
}

/// Options for `osbx windows build-base`.
#[derive(Debug, Clone)]
pub struct BuildBaseOpts {
    /// Path to the Windows installation ISO (e.g., Windows Server 2025 Evaluation ISO).
    pub iso: PathBuf,
    /// Path to Red Hat's signed `virtio-win.iso`.
    pub virtio_win: PathBuf,
    /// Template name saved under `$OSBX_HOME/templates/<name>.*`.
    pub name: String,
    /// Windows edition profile (`core`, `desktop`, `win11`).
    pub profile: WindowsProfile,
    /// Explicit image index inside `install.wim` (`None` uses the profile default).
    pub image_index: Option<u32>,
    /// Virtual disk size in GiB (default: 40).
    pub disk_gib: u64,
    /// Guest RAM in MiB during unattended install (default: 4096).
    pub mem_mib: usize,
    /// Guest vCPUs during unattended install (default: 4).
    pub cpus: u8,
    /// Optional explicit path to `OVMF_CODE_4M.fd`.
    pub firmware_code: Option<PathBuf>,
    /// Optional explicit path to `OVMF_VARS_4M.fd`.
    pub firmware_vars: Option<PathBuf>,
    /// Optional explicit path to `osbx-agent.exe`.
    pub agent_exe: Option<PathBuf>,
    /// Optional path to a WinFsp MSI installer (`winfsp-*.msi`) for in-guest `virtio-fs` mounts.
    pub winfsp_msi: Option<PathBuf>,
    /// Attach an emulated CRB vTPM 2.0 device during installation (recommended for Windows 11).
    pub vtpm: bool,
    /// Optional Windows product key (empty by default, skipping the interactive Product Key screen).
    pub product_key: Option<String>,
    /// Maximum minutes to wait for unattended Windows Setup to finish (default: 45).
    pub timeout_mins: u64,
}

/// Locate `(OVMF_CODE_4M.fd, OVMF_VARS_4M.fd)` on the host.
pub fn find_ovmf(
    code_override: Option<&Path>,
    vars_override: Option<&Path>,
) -> io::Result<(PathBuf, PathBuf)> {
    let code = code_override
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("OSBX_OVMF_CODE").map(PathBuf::from))
        .or_else(|| {
            [
                assets_dir().join("OVMF_CODE_4M.fd"),
                home().join("guest/OVMF_CODE_4M.fd"),
                PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.fd"),
                PathBuf::from("/usr/share/edk2/ovmf/OVMF_CODE.fd"),
            ]
            .into_iter()
            .find(|p| p.exists())
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "OVMF_CODE_4M.fd not found (install ovmf package, place in $OSBX_HOME/guest, or set OSBX_OVMF_CODE)",
            )
        })?;
    let vars = vars_override
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("OSBX_OVMF_VARS").map(PathBuf::from))
        .or_else(|| {
            [
                assets_dir().join("OVMF_VARS_4M.fd"),
                home().join("guest/OVMF_VARS_4M.fd"),
                PathBuf::from("/usr/share/OVMF/OVMF_VARS_4M.fd"),
                PathBuf::from("/usr/share/edk2/ovmf/OVMF_VARS.fd"),
            ]
            .into_iter()
            .find(|p| p.exists())
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "OVMF_VARS_4M.fd not found (install ovmf package, place in $OSBX_HOME/guest, or set OSBX_OVMF_VARS)",
            )
        })?;
    Ok((code, vars))
}

fn find_windows_agent(override_path: Option<&Path>) -> io::Result<PathBuf> {
    override_path
        .map(Path::to_path_buf)
        .or_else(|| {
            [
                assets_dir().join("osbx-agent.exe"),
                home().join("guest/osbx-agent.exe"),
                PathBuf::from("target/x86_64-pc-windows-gnu/release/osbx-agent.exe"),
                PathBuf::from("target/x86_64-pc-windows-msvc/release/osbx-agent.exe"),
            ]
            .into_iter()
            .find(|p| p.exists())
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "osbx-agent.exe not found (build with `cargo build --release -p osbx-agent --target x86_64-pc-windows-gnu` or pass --agent-exe)",
            )
        })
}

fn find_winfsp_msi(override_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = override_path {
        return Some(p.to_path_buf());
    }
    if let Some(p) = std::env::var_os("OSBX_WINFSP_MSI") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    for dir in [assets_dir(), home().join("guest")] {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_ascii_lowercase();
                if name.starts_with("winfsp") && name.ends_with(".msi") {
                    return Some(e.path());
                }
            }
        }
    }
    None
}

/// Generate a UEFI GPT `autounattend.xml` for headless unattended Windows Server / Win 11 install
/// using `virtio-win` (`viostor`, `viosock`, `viofs`) drivers and `osbx-agent.exe`.
pub fn generate_autounattend_xml(
    profile: WindowsProfile,
    image_index: u32,
    vtpm: bool,
    product_key: Option<&str>,
) -> String {
    let os_sub = profile.virtio_subdir();
    let mut driver_paths = String::new();
    for (idx, drive) in ['C', 'D', 'E', 'F'].iter().enumerate() {
        let key = idx + 1;
        driver_paths.push_str(&format!(
            "        <PathAndCredentials wcm:action=\"add\" wcm:keyValue=\"{key}\"><Path>{drive}:\\viostor\\{os_sub}\\amd64</Path></PathAndCredentials>\n"
        ));
    }
    // Windows 11 Setup checks Secure Boot (not enrolled in standard OVMF_CODE_4M.fd) and TPM 2.0.
    // Always bypass Secure Boot + RAM checks on Win11; bypass TPM check when `--vtpm` is off.
    let winpe_run_sync = if profile == WindowsProfile::Win11 {
        let mut cmds = String::from("      <RunSynchronous>\n");
        cmds.push_str(
            "        <RunSynchronousCommand wcm:action=\"add\"><Order>1</Order><Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>\n",
        );
        cmds.push_str(
            "        <RunSynchronousCommand wcm:action=\"add\"><Order>2</Order><Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>\n",
        );
        if !vtpm {
            cmds.push_str(
                "        <RunSynchronousCommand wcm:action=\"add\"><Order>3</Order><Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>\n",
            );
        }
        cmds.push_str("      </RunSynchronous>\n");
        cmds
    } else {
        String::new()
    };
    let product_key_xml = {
        let k = product_key.unwrap_or("");
        format!(
            "        <ProductKey>\n          <Key>{k}</Key>\n          <WillShowUI>Never</WillShowUI>\n        </ProductKey>\n"
        )
    };
    let specialize_bypass_nro = if profile == WindowsProfile::Win11 {
        r#"    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add"><Order>1</Order><Path>reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v BypassNRO /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>
      </RunSynchronous>
    </component>
"#
    } else {
        ""
    };
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>0409:00000409</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-PnpCustomizationsWinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <DriverPaths>
{driver_paths}      </DriverPaths>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
{winpe_run_sync}      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
          </ModifyPartitions>
        </Disk>
        <WillShowUI>OnError</WillShowUI>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallFrom>
            <MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>{image_index}</Value></MetaData>
          </InstallFrom>
          <InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>
          <WillShowUI>OnError</WillShowUI>
        </OSImage>
      </ImageInstall>
      <UserData>
{product_key_xml}        <AcceptEula>true</AcceptEula>
        <FullName>osbx</FullName>
        <Organization>osbx</Organization>
      </UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>osbx-win</ComputerName>
      <TimeZone>UTC</TimeZone>
    </component>
{specialize_bypass_nro}  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <InputLocale>0409:00000409</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <AdministratorPassword><Value>Osbx-Admin-2025!</Value><PlainText>true</PlainText></AdministratorPassword>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>agent</Name>
            <DisplayName>Sandbox Agent</DisplayName>
            <Group>Users</Group>
            <Password><Value>Osbx-Agent-2025!</Value><PlainText>true</PlainText></Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Enabled>true</Enabled>
        <LogonCount>1</LogonCount>
        <Username>Administrator</Username>
        <Password><Value>Osbx-Admin-2025!</Value><PlainText>true</PlainText></Password>
      </AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <CommandLine>cmd /c for %d in (D E F G) do if exist %d:\setup_osbx.cmd call %d:\setup_osbx.cmd %d</CommandLine>
          <Description>Install virtio-win drivers and register osbx-agent service</Description>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
"#
    )
}

fn setup_osbx_cmd(profile: WindowsProfile, has_winfsp: bool) -> String {
    let winfsp_block = if has_winfsp {
        r#"if exist "%SEED%:\winfsp.msi" (
  echo [osbx] installing WinFsp from %SEED%: >> %LOG%
  msiexec /i "%SEED%:\winfsp.msi" /qn /norestart >> %LOG% 2>&1
)
"#
    } else {
        ""
    };
    let desktop_block = if profile.has_desktop() {
        r#"echo [osbx] configuring Desktop Experience (RDP, Session 1 auto-logon, no screen lock) >> %LOG%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f >> %LOG% 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f >> %LOG% 2>&1
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes >> %LOG% 2>&1
net localgroup "Remote Desktop Users" agent /add >> %LOG% 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f >> %LOG% 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoLogonCount /f >> %LOG% 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d agent /f >> %LOG% 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d "Osbx-Agent-2025!" /f >> %LOG% 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /t REG_DWORD /d 1 /f >> %LOG% 2>&1
"#
    } else {
        ""
    };
    format!(
        r#"@echo off
set SEED=%1
mkdir "C:\Program Files\osbx" 2>nul
mkdir "C:\ProgramData\osbx" 2>nul
set LOG=C:\ProgramData\osbx\setup.log
echo [osbx] starting unattended post-install from %SEED%: >> %LOG%
for %%d in (D E F G) do (
  if exist %%d:\viosock\2k25\amd64\viosock.inf (
    echo [osbx] installing viosock 2k25 from %%d: >> %LOG%
    pnputil /add-driver %%d:\viosock\2k25\amd64\viosock.inf /install >> %LOG% 2>&1
  ) else if exist %%d:\viosock\w11\amd64\viosock.inf (
    echo [osbx] installing viosock w11 from %%d: >> %LOG%
    pnputil /add-driver %%d:\viosock\w11\amd64\viosock.inf /install >> %LOG% 2>&1
  ) else if exist %%d:\viosock\2k22\amd64\viosock.inf (
    echo [osbx] installing viosock 2k22 from %%d: >> %LOG%
    pnputil /add-driver %%d:\viosock\2k22\amd64\viosock.inf /install >> %LOG% 2>&1
  )
  if exist %%d:\viofs\2k25\amd64\viofs.inf (
    echo [osbx] installing viofs 2k25 from %%d: >> %LOG%
    pnputil /add-driver %%d:\viofs\2k25\amd64\viofs.inf /install >> %LOG% 2>&1
    if exist %%d:\viofs\2k25\amd64\virtiofs.exe copy /Y %%d:\viofs\2k25\amd64\virtiofs.exe "C:\Program Files\osbx\virtiofs.exe" >> %LOG% 2>&1
  ) else if exist %%d:\viofs\w11\amd64\viofs.inf (
    echo [osbx] installing viofs w11 from %%d: >> %LOG%
    pnputil /add-driver %%d:\viofs\w11\amd64\viofs.inf /install >> %LOG% 2>&1
    if exist %%d:\viofs\w11\amd64\virtiofs.exe copy /Y %%d:\viofs\w11\amd64\virtiofs.exe "C:\Program Files\osbx\virtiofs.exe" >> %LOG% 2>&1
  ) else if exist %%d:\viofs\2k22\amd64\viofs.inf (
    echo [osbx] installing viofs 2k22 from %%d: >> %LOG%
    pnputil /add-driver %%d:\viofs\2k22\amd64\viofs.inf /install >> %LOG% 2>&1
    if exist %%d:\viofs\2k22\amd64\virtiofs.exe copy /Y %%d:\viofs\2k22\amd64\virtiofs.exe "C:\Program Files\osbx\virtiofs.exe" >> %LOG% 2>&1
  )
)
{winfsp_block}sc.exe start VirtioSocketWSP >> %LOG% 2>&1
copy /Y "%SEED%:\osbx-agent.exe" "C:\Program Files\osbx\osbx-agent.exe" >> %LOG% 2>&1
sc.exe create osbx-agent binPath= "\"C:\Program Files\osbx\osbx-agent.exe\"" start= auto depend= VirtioSocketWSP DisplayName= "osbx Guest Agent" >> %LOG% 2>&1
sc.exe start osbx-agent >> %LOG% 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v EnableActiveProbing /t REG_DWORD /d 0 /f >> %LOG% 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v NoActiveProbe /t REG_DWORD /d 1 /f >> %LOG% 2>&1
powercfg /h off >> %LOG% 2>&1
powercfg /change standby-timeout-ac 0 >> %LOG% 2>&1
powercfg /change monitor-timeout-ac 0 >> %LOG% 2>&1
{desktop_block}echo [osbx] setup complete, shutting down template ... >> %LOG%
shutdown /s /t 5 /f /c "osbx template build complete"
"#
    )
}

/// Build a reusable Windows base template unattended inside `osbx-vmm` (Linux/KVM or Windows/WHP).
pub fn build_base(o: &BuildBaseOpts) -> io::Result<()> {
    check_name(&o.name).map_err(io::Error::other)?;
    for (label, p) in [("Windows ISO", &o.iso), ("virtio-win ISO", &o.virtio_win)] {
        if !p.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{label} not found: {}", p.display()),
            ));
        }
    }
    let (fw_code, fw_vars_src) = find_ovmf(o.firmware_code.as_deref(), o.firmware_vars.as_deref())?;
    let agent_exe = find_windows_agent(o.agent_exe.as_deref())?;
    let winfsp_msi = find_winfsp_msi(o.winfsp_msi.as_deref());
    if let Some(msi) = &winfsp_msi
        && !msi.exists()
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("WinFsp MSI not found: {}", msi.display()),
        ));
    }

    let image_index = o
        .image_index
        .unwrap_or_else(|| o.profile.default_image_index());

    let tpl_dir = home().join("templates");
    std::fs::create_dir_all(&tpl_dir)?;
    let work = tpl_dir.join(format!(".building-{}", o.name));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work)?;

    let mut seed_files = vec![
        IsoFile {
            name: "autounattend.xml".into(),
            data: generate_autounattend_xml(
                o.profile,
                image_index,
                o.vtpm,
                o.product_key.as_deref(),
            )
            .into_bytes(),
        },
        IsoFile {
            name: "setup_osbx.cmd".into(),
            data: setup_osbx_cmd(o.profile, winfsp_msi.is_some()).into_bytes(),
        },
        IsoFile {
            name: "osbx-agent.exe".into(),
            data: std::fs::read(&agent_exe)?,
        },
    ];
    if let Some(msi) = &winfsp_msi {
        seed_files.push(IsoFile {
            name: "winfsp.msi".into(),
            data: std::fs::read(msi)?,
        });
    }
    let seed_iso = work.join("seed.iso");
    write_iso(&seed_iso, "OSBX_SEED", &seed_files)?;

    let disk_path = work.join("base.qcow2");
    let vars_path = work.join("vars.fd");
    osbx_vmm::qcow2::create_base(&disk_path, o.disk_gib << 30)?;
    std::fs::copy(&fw_vars_src, &vars_path)?;

    let mut cfg = osbx_vmm::UefiConfig::new(fw_code);
    cfg.vars = Some(vars_path.clone());
    cfg.mem_mib = o.mem_mib;
    cfg.cpus = o.cpus;
    cfg.disks = vec![osbx_vmm::DiskConfig {
        path: disk_path.clone(),
        read_only: false,
    }];
    cfg.cdroms = vec![o.iso.clone(), o.virtio_win.clone(), seed_iso];
    cfg.vsock_cid = Some(osbx_sandbox::GUEST_CID);
    cfg.hyperv = true;
    cfg.vtpm = o.vtpm.then(|| work.join("tpm.state"));
    cfg.timeout = Some(Duration::from_secs(o.timeout_mins * 60));

    eprintln!(
        "building Windows template {:?} (profile={}, index={}, {} GiB QCOW2, {} MiB RAM, {} vCPUs{}) ...",
        o.name,
        o.profile.as_str(),
        image_index,
        o.disk_gib,
        o.mem_mib,
        o.cpus,
        if winfsp_msi.is_some() {
            ", +WinFsp"
        } else {
            ""
        }
    );
    let fb_path = std::env::var_os("OSBX_WIN_FB").map(PathBuf::from);
    let started = Instant::now();
    let deadline = started + Duration::from_secs(o.timeout_mins * 60);
    // Windows Setup reboots 1–3 times before FirstLogonCommands completes and runs `shutdown /s`
    // (which triggers ACPI S5 poweroff -> `vm.powered_off() == true`).
    let mut boots = 0u8;
    loop {
        boots += 1;
        if boots > 6 {
            return Err(io::Error::other(format!(
                "Windows template build exceeded 6 reboots after {:.0}s",
                started.elapsed().as_secs_f64()
            )));
        }
        let vm = osbx_vmm::UefiVm::start(&cfg).map_err(|e| io::Error::other(e.to_string()))?;
        if boots == 1 {
            // Wait for OVMF `BdsDxe` to launch `cdboot.efi`, then tap Enter so the ISO boots
            // unattended even when GOP redirects "Press any key" away from serial.
            let key_deadline = Instant::now() + Duration::from_secs(15);
            while Instant::now() < key_deadline && !vm.finished() {
                if vm.console().contains("BdsDxe: starting Boot") {
                    for _ in 0..5 {
                        std::thread::sleep(Duration::from_millis(700));
                        if vm.finished() {
                            break;
                        }
                        vm.send_serial(b"\r");
                    }
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        let exit = loop {
            let now = Instant::now();
            if now >= deadline {
                let _ = vm.stop();
                break osbx_vmm::ExitReason::Timeout;
            }
            let slice = (deadline - now).min(Duration::from_secs(10));
            match vm.wait(Some(slice)) {
                Some(Ok(r)) => break r,
                Some(Err(e)) => return Err(io::Error::other(e.to_string())),
                None => {
                    if let Some(p) = &fb_path {
                        save_fb_ppm(&vm, p);
                    }
                }
            }
        };
        if let Some(p) = &fb_path {
            save_fb_ppm(&vm, p);
        }
        let powered_off = vm.powered_off();
        drop(vm);
        match exit {
            osbx_vmm::ExitReason::GuestReset if powered_off => {
                eprintln!(
                    "  stage {boots} powered off cleanly via ACPI S5 ({:.0}s)",
                    started.elapsed().as_secs_f64()
                );
                break;
            }
            osbx_vmm::ExitReason::GuestReset => {
                // On the first reboot, detach the Windows install ISO so OVMF boots straight
                // from the newly installed EFI System Partition on disk 0 while keeping
                // virtio-win + seed ISOs attached for FirstLogonCommands.
                cfg.cdroms = vec![o.virtio_win.clone(), work.join("seed.iso")];
                eprintln!(
                    "  stage {boots} rebooted ({:.0}s); continuing Windows setup ...",
                    started.elapsed().as_secs_f64()
                );
            }
            other => {
                return Err(io::Error::other(format!(
                    "Windows template build ended unexpectedly ({other:?}) after {:.0}s",
                    started.elapsed().as_secs_f64()
                )));
            }
        }
    }

    let final_disk = tpl_dir.join(format!("{}.qcow2", o.name));
    let final_vars = tpl_dir.join(format!("{}.vars.fd", o.name));
    std::fs::rename(&disk_path, &final_disk)?;
    std::fs::rename(&vars_path, &final_vars)?;
    let _ = std::fs::remove_dir_all(&work);

    let meta = json!({
        "from": o.iso.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "windows.iso".into()),
        "image": format!("windows-template:{}", o.name),
        "guest_os": "windows",
        "profile": o.profile.as_str(),
        "disk_format": "qcow2",
        "vtpm": o.vtpm,
        "launch": Launch {
            argv: vec!["cmd.exe".into()],
            env: vec![],
            user: String::new(),
            workdir: String::new(),
        },
    });
    write_atomic(
        &tpl_dir.join(format!("{}.json", o.name)),
        meta.to_string().as_bytes(),
    )?;
    eprintln!(
        "saved Windows template {:?} in {:.1}s",
        o.name,
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn save_fb_ppm(vm: &osbx_vmm::UefiVm, path: &Path) {
    if let Some((w, h, bpp, data)) = vm.framebuffer() {
        let stride = usize::from(bpp / 8);
        if stride >= 3 {
            let mut ppm = format!("P6\n{w} {h}\n255\n").into_bytes();
            for px in data.chunks_exact(stride) {
                ppm.extend_from_slice(&[px[2], px[1], px[0]]);
            }
            let tmp = path.with_extension("ppm.tmp");
            if std::fs::write(&tmp, &ppm).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autounattend_xml_contains_gpt_and_virtio_drivers() {
        let xml = generate_autounattend_xml(WindowsProfile::Core, 1, false, None);
        assert!(xml.contains("<Key>/IMAGE/INDEX</Key><Value>1</Value>"));
        assert!(xml.contains("viostor\\2k25\\amd64"));
        assert!(xml.contains("<Type>EFI</Type>"));
        assert!(xml.contains("setup_osbx.cmd"));
        assert!(xml.contains("<WillShowUI>Never</WillShowUI>"));
        assert!(!xml.contains("BypassTPMCheck"));
    }

    #[test]
    fn win11_profile_adds_labconfig_and_skips_product_key() {
        let xml_no_tpm = generate_autounattend_xml(WindowsProfile::Win11, 6, false, None);
        assert!(xml_no_tpm.contains("BypassTPMCheck"));
        assert!(xml_no_tpm.contains("BypassSecureBootCheck"));
        assert!(xml_no_tpm.contains("BypassNRO"));
        assert!(xml_no_tpm.contains("<Key></Key>"));
        assert!(xml_no_tpm.contains("viostor\\w11\\amd64"));
        assert!(xml_no_tpm.contains("Microsoft-Windows-International-Core\""));

        let xml_with_tpm = generate_autounattend_xml(WindowsProfile::Win11, 6, true, None);
        assert!(!xml_with_tpm.contains("BypassTPMCheck"));
        assert!(xml_with_tpm.contains("BypassSecureBootCheck"));
        assert!(xml_with_tpm.contains("BypassNRO"));
    }

    #[test]
    fn desktop_setup_script_enables_rdp_and_viofs() {
        let cmd = setup_osbx_cmd(WindowsProfile::Desktop, true);
        assert!(cmd.contains("viofs.inf"));
        assert!(cmd.contains("virtiofs.exe"));
        assert!(cmd.contains("winfsp.msi"));
        assert!(cmd.contains("fDenyTSConnections"));
        assert!(cmd.contains("AutoAdminLogon"));
    }
}
