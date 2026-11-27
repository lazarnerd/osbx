//! Windows-guest base template builder (`osbx windows build-base`).
//!
//! Generates an unattended Windows installation seed ISO (`autounattend.xml`, `SetupComplete.cmd`,
//! `osbx-agent.exe`), attaches it alongside the Windows ISO and Red Hat `virtio-win.iso` over
//! `virtio-scsi`, boots the unattended installation inside `osbx-vmm`'s Q35 PCIe UEFI VM, and
//! seals the resulting QCOW2 base disk + persistent `OVMF_VARS_4M.fd` as a reusable template in
//! `$OSBX_HOME/templates/`.

use crate::state::{Launch, assets_dir, check_name, home, write_atomic};
use serde_json::json;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Options for `osbx windows build-base`.
#[derive(Debug, Clone)]
pub struct BuildBaseOpts {
    /// Path to the Windows installation ISO (e.g., Windows Server 2025 Evaluation ISO).
    pub iso: PathBuf,
    /// Path to Red Hat's signed `virtio-win.iso`.
    pub virtio_win: PathBuf,
    /// Template name saved under `$OSBX_HOME/templates/<name>.*`.
    pub name: String,
    /// Windows image index inside `install.wim` (1 = Server Standard Core on MS Server 2025 Eval).
    pub image_index: u32,
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
                "OVMF_CODE_4M.fd not found (install ovmf package or set OSBX_OVMF_CODE)",
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
                "OVMF_VARS_4M.fd not found (install ovmf package or set OSBX_OVMF_VARS)",
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

/// Generate a UEFI GPT `autounattend.xml` for headless unattended Windows Server / Win 11 install
/// using `virtio-win` (`viostor`, `viosock`) drivers and `osbx-agent.exe`.
pub fn generate_autounattend_xml(image_index: u32) -> String {
    let mut driver_paths = String::new();
    for (idx, drive) in ['C', 'D', 'E', 'F'].iter().enumerate() {
        let key = idx + 1;
        driver_paths.push_str(&format!(
            "        <PathAndCredentials wcm:action=\"add\" wcm:keyValue=\"{key}\"><Path>{drive}:\\viostor\\2k25\\amd64</Path></PathAndCredentials>\n"
        ));
    }
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
      <DiskConfiguration>
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
        <AcceptEula>true</AcceptEula>
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
  </settings>
  <settings pass="oobeSystem">
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

fn setup_osbx_cmd() -> &'static str {
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
)
sc.exe start VirtioSocketWSP >> %LOG% 2>&1
copy /Y "%SEED%:\osbx-agent.exe" "C:\Program Files\osbx\osbx-agent.exe" >> %LOG% 2>&1
sc.exe create osbx-agent binPath= "\"C:\Program Files\osbx\osbx-agent.exe\"" start= auto depend= VirtioSocketWSP DisplayName= "osbx Guest Agent" >> %LOG% 2>&1
sc.exe start osbx-agent >> %LOG% 2>&1
powercfg /h off >> %LOG% 2>&1
powercfg /change standby-timeout-ac 0 >> %LOG% 2>&1
powercfg /change monitor-timeout-ac 0 >> %LOG% 2>&1
echo [osbx] setup complete, shutting down template ... >> %LOG%
shutdown /s /t 5 /f /c "osbx template build complete"
"#
}

fn make_seed_iso(dir: &Path, iso_out: &Path) -> io::Result<()> {
    let status = if Command::new("xorriso").arg("--version").output().is_ok() {
        Command::new("xorriso")
            .args([
                "-as",
                "mkisofs",
                "-quiet",
                "-J",
                "-R",
                "-V",
                "OSBX_SEED",
                "-o",
            ])
            .arg(iso_out)
            .arg(dir)
            .status()?
    } else if Command::new("genisoimage")
        .arg("--version")
        .output()
        .is_ok()
    {
        Command::new("genisoimage")
            .args(["-quiet", "-J", "-R", "-V", "OSBX_SEED", "-o"])
            .arg(iso_out)
            .arg(dir)
            .status()?
    } else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "xorriso or genisoimage is required to create the unattended seed ISO",
        ));
    };
    if !status.success() {
        return Err(io::Error::other("failed to build unattended seed ISO"));
    }
    Ok(())
}

/// Build a reusable Windows base template unattended inside `osbx-vmm` (Linux/KVM).
#[cfg(target_os = "linux")]
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

    let tpl_dir = home().join("templates");
    std::fs::create_dir_all(&tpl_dir)?;
    let work = tpl_dir.join(format!(".building-{}", o.name));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(work.join("seed"))?;

    std::fs::write(
        work.join("seed/autounattend.xml"),
        generate_autounattend_xml(o.image_index),
    )?;
    std::fs::write(work.join("seed/setup_osbx.cmd"), setup_osbx_cmd())?;
    std::fs::copy(&agent_exe, work.join("seed/osbx-agent.exe"))?;
    let seed_iso = work.join("seed.iso");
    make_seed_iso(&work.join("seed"), &seed_iso)?;

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
    cfg.timeout = Some(Duration::from_secs(o.timeout_mins * 60));

    eprintln!(
        "building Windows template {:?} ({} GiB QCOW2, {} MiB RAM, {} vCPUs) ...",
        o.name, o.disk_gib, o.mem_mib, o.cpus
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
        "disk_format": "qcow2",
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

#[cfg(target_os = "linux")]
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

/// Build a reusable Windows base template (currently Linux/KVM only; WHP support is Phase W2).
#[cfg(not(target_os = "linux"))]
pub fn build_base(_o: &BuildBaseOpts) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "osbx windows build-base currently requires a Linux/KVM host (WHP support is Phase W2)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autounattend_xml_contains_gpt_and_virtio_drivers() {
        let xml = generate_autounattend_xml(1);
        assert!(xml.contains("<Key>/IMAGE/INDEX</Key><Value>1</Value>"));
        assert!(xml.contains("viostor\\2k25\\amd64"));
        assert!(xml.contains("<Type>EFI</Type>"));
        assert!(xml.contains("setup_osbx.cmd"));
    }
}
