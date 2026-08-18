use crate::{bundle::StagedBundle, secrets::redact, EncvolError};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Handoff {
    Kexec,
    UefiBootnext,
    GrubOnce,
    Unsupported,
}

impl Handoff {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kexec => "kexec",
            Self::UefiBootnext => "uefi-bootnext",
            Self::GrubOnce => "grub-once",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostCapabilities {
    pub kexec: bool,
    pub uefi: bool,
    pub writable_esp: Option<PathBuf>,
    pub efi_variables: bool,
    pub grub: bool,
}

pub fn select_handoff(c: &HostCapabilities) -> Handoff {
    if c.grub {
        Handoff::GrubOnce
    } else if c.uefi && c.efi_variables && c.writable_esp.is_some() {
        Handoff::UefiBootnext
    } else {
        Handoff::Unsupported
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub program: String,
    pub args: Vec<String>,
}
impl Command {
    fn new(program: impl Into<String>, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

/// Commands use one-time selection. If the staged installer cannot boot, a
/// later reboot follows the ordinary boot order and returns to the old system.
pub fn handoff_commands(
    handoff: Handoff,
    kernel: &str,
    initrd: &str,
    esp: Option<&str>,
) -> Result<Vec<Command>, EncvolError> {
    match handoff {
        Handoff::Kexec => Ok(vec![
            Command::new(
                "kexec",
                [
                    "--load",
                    kernel,
                    "--initrd",
                    initrd,
                    "--command-line=encvol.installer=1",
                ],
            ),
            Command::new("systemctl", ["kexec"]),
        ]),
        Handoff::UefiBootnext => {
            let esp = esp.ok_or_else(|| EncvolError::Unsupported("no writable ESP".into()))?;
            Ok(vec![
                Command::new(
                    "install",
                    [
                        "-D",
                        "-m",
                        "0700",
                        kernel,
                        &format!("{esp}/EFI/encvol/installer.efi"),
                    ],
                ),
                Command::new(
                    "efibootmgr",
                    [
                        "--create",
                        "--disk",
                        "ESP-DISK",
                        "--part",
                        "ESP-PART",
                        "--label",
                        "encvol-installer",
                        "--loader",
                        "\\EFI\\encvol\\installer.efi",
                    ],
                ),
                Command::new("efibootmgr", ["--bootnext", "ENCVOL_BOOTNUM"]),
                Command::new("systemctl", ["reboot"]),
            ])
        }
        Handoff::GrubOnce => Ok(vec![
            Command::new(
                "install",
                ["-D", "-m", "0600", kernel, "/boot/encvol/installer.kernel"],
            ),
            Command::new(
                "install",
                ["-D", "-m", "0600", initrd, "/boot/encvol/installer.initrd"],
            ),
            Command::new("grub-reboot", ["encvol-installer"]),
            Command::new("systemctl", ["reboot"]),
        ]),
        Handoff::Unsupported => Err(EncvolError::Unsupported(
            "neither GRUB one-shot boot nor UEFI BootNext is usable".into(),
        )),
    }
}

fn checked(program: &str, args: &[&str]) -> Result<String, EncvolError> {
    let output = ProcessCommand::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| EncvolError::Unsupported(format!("cannot run {program}: {e}")))?;
    if !output.status.success() {
        return Err(EncvolError::Unsupported(format!(
            "{program} failed: {}",
            redact(&String::from_utf8_lossy(&output.stderr))
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
fn require_root() -> Result<(), EncvolError> {
    let is_root = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .and_then(|uids| uids.split_whitespace().next())
                .map(|uid| uid == "0")
        })
        .unwrap_or(false);
    if is_root {
        Ok(())
    } else {
        Err(EncvolError::Unsupported(
            "staging an installer requires root".into(),
        ))
    }
}
fn copy(source: &Path, destination: &Path) -> Result<(), EncvolError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            EncvolError::Unsupported(format!("cannot create staging directory: {e}"))
        })?;
    }
    fs::copy(source, destination)
        .map_err(|e| EncvolError::Unsupported(format!("cannot stage installer: {e}")))?;
    Ok(())
}
fn esp_identity(esp: &Path) -> Result<(String, String), EncvolError> {
    let target = esp
        .to_str()
        .ok_or_else(|| EncvolError::Unsupported("ESP path is invalid".into()))?;
    let source = checked("findmnt", &["-n", "-o", "SOURCE", "--target", target])?;
    let output = checked("lsblk", &["-n", "-o", "PKNAME,PARTN", source.trim()])?;
    let parts: Vec<_> = output.split_whitespace().collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].parse::<u32>().is_err() {
        return Err(EncvolError::Unsupported(
            "cannot identify ESP disk and partition".into(),
        ));
    }
    Ok((format!("/dev/{}", parts[0]), parts[1].into()))
}
fn boot_number(output: &str) -> Option<String> {
    output.split_whitespace().find_map(|word| {
        word.strip_prefix("Boot")
            .and_then(|value| value.strip_suffix('*'))
            .filter(|value| value.len() == 4)
            .map(str::to_owned)
    })
}

fn installer_command_line(extra_args: &[&str]) -> String {
    let mut args = vec!["encvol.installer=1".to_owned()];
    args.extend(extra_args.iter().map(|arg| (*arg).to_owned()));
    if let Ok(cmdline) = fs::read_to_string("/proc/cmdline") {
        for arg in cmdline.split_whitespace().filter(|arg| {
            arg.starts_with("console=")
                || arg.starts_with("earlycon=")
                || arg.starts_with("earlyprintk=")
                || arg.starts_with("panic=")
                || arg.starts_with("encvol.qemu_firmware=")
                || arg.starts_with("encvol.test_case=")
                || arg.starts_with("encvol.test_fault=")
        }) {
            if !args.iter().any(|existing| existing == arg) {
                args.push(arg.to_owned());
            }
        }
    }
    args.join(" ")
}

fn qemu_direct_kexec_requested() -> bool {
    env::var_os("ENCVOL_QEMU_DIRECT_KEXEC").is_some()
        && fs::read_to_string("/proc/cmdline")
            .map(|cmdline| {
                cmdline
                    .split_whitespace()
                    .any(|arg| arg == "encvol.qemu.source=1")
            })
            .unwrap_or(false)
}

/// Stage a verified bundle and select it for exactly one boot. This function is
/// intentionally never called by preflight or a dry run.
pub fn execute_handoff(
    handoff: Handoff,
    bundle: &StagedBundle,
    version: &str,
    esp: Option<&Path>,
) -> Result<(), EncvolError> {
    execute_handoff_with_args(handoff, bundle, version, esp, &[])
}

/// Stage a verified bundle and select it for exactly one boot with extra
/// encvol-specific kernel arguments.
pub fn execute_handoff_with_args(
    handoff: Handoff,
    bundle: &StagedBundle,
    version: &str,
    esp: Option<&Path>,
    extra_args: &[&str],
) -> Result<(), EncvolError> {
    require_root()?;
    match handoff {
        Handoff::Kexec => {
            let kernel = bundle
                .kernel
                .as_ref()
                .ok_or_else(|| EncvolError::Unsupported("kexec bundle lacks kernel".into()))?;
            let initrd = bundle
                .initrd
                .as_ref()
                .ok_or_else(|| EncvolError::Unsupported("kexec bundle lacks initrd".into()))?;
            eprintln!("encvol: loading installer with kexec");
            checked(
                "kexec",
                &[
                    "--load",
                    kernel.to_str().unwrap_or_default(),
                    "--initrd",
                    initrd.to_str().unwrap_or_default(),
                    &format!("--command-line={}", installer_command_line(extra_args)),
                ],
            )?;
            if qemu_direct_kexec_requested() {
                eprintln!("encvol: executing direct kexec for QEMU fixture");
                checked("sync", &[])?;
                checked("kexec", &["--exec"])?;
            } else {
                eprintln!("encvol: handing off to systemd kexec");
                checked("systemctl", &["kexec"])?;
            }
        }
        Handoff::UefiBootnext => {
            let esp = esp.ok_or_else(|| EncvolError::Unsupported("no writable ESP".into()))?;
            let uki = bundle.uki.as_ref().ok_or_else(|| {
                EncvolError::Unsupported("UEFI fallback requires installer.efi".into())
            })?;
            copy(
                uki,
                &esp.join("EFI/encvol").join(version).join("installer.efi"),
            )?;
            let (disk, part) = esp_identity(esp)?;
            let output = checked(
                "efibootmgr",
                &[
                    "--create",
                    "--disk",
                    &disk,
                    "--part",
                    &part,
                    "--label",
                    "encvol-installer",
                    "--loader",
                    &format!("\\EFI\\encvol\\{version}\\installer.efi"),
                    "--unicode",
                    &installer_command_line(extra_args),
                ],
            )?;
            let number = boot_number(&output).ok_or_else(|| {
                EncvolError::Unsupported(
                    "efibootmgr did not report the temporary boot number".into(),
                )
            })?;
            checked("efibootmgr", &["--bootnext", &number])?;
            checked("systemctl", &["reboot"])?;
        }
        Handoff::GrubOnce => {
            let kernel = bundle.kernel.as_ref().ok_or_else(|| {
                EncvolError::Unsupported("GRUB fallback bundle lacks kernel".into())
            })?;
            let initrd = bundle.initrd.as_ref().ok_or_else(|| {
                EncvolError::Unsupported("GRUB fallback bundle lacks initrd".into())
            })?;
            copy(kernel, Path::new("/boot/encvol/installer.kernel"))?;
            copy(initrd, Path::new("/boot/encvol/installer.initrd"))?;
            fs::create_dir_all("/var/lib/encvol").map_err(|e| {
                EncvolError::Unsupported(format!("cannot create recovery metadata directory: {e}"))
            })?;
            let script = Path::new("/etc/grub.d/42_encvol_installer");
            if script.exists() {
                fs::copy(script, "/var/lib/encvol/42_encvol_installer.backup").map_err(|e| {
                    EncvolError::Unsupported(format!("cannot preserve GRUB snippet: {e}"))
                })?;
            }
            fs::write(script, format!("#!/bin/sh\ncat <<'EOF'\nmenuentry 'encvol-installer' --id encvol-installer {{\n linux /boot/encvol/installer.kernel {}\n initrd /boot/encvol/installer.initrd\n}}\nEOF\n", installer_command_line(extra_args))).map_err(|e| EncvolError::Unsupported(format!("cannot write GRUB installer entry: {e}")))?;
            checked("chmod", &["0755", "/etc/grub.d/42_encvol_installer"])?;
            checked("update-grub", &[])?;
            checked("grub-reboot", &["encvol-installer"])?;
            checked("systemctl", &["reboot"])?;
        }
        Handoff::Unsupported => {
            return Err(EncvolError::Unsupported("no supported handoff".into()))
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preference_is_safe_and_predictable() {
        let mut c = HostCapabilities {
            kexec: true,
            uefi: true,
            writable_esp: Some("/boot/efi".into()),
            efi_variables: true,
            grub: true,
        };
        assert_eq!(select_handoff(&c), Handoff::GrubOnce);
        c.grub = false;
        assert_eq!(select_handoff(&c), Handoff::UefiBootnext);
        c.efi_variables = false;
        assert_eq!(select_handoff(&c), Handoff::Unsupported);
    }
    #[test]
    fn grub_has_one_shot_command() {
        let p = handoff_commands(Handoff::GrubOnce, "k", "i", None).unwrap();
        assert!(p.iter().any(|c| c.program == "grub-reboot"));
    }
    #[test]
    fn parses_created_efi_boot_number() {
        assert_eq!(
            boot_number("Boot000A* encvol-installer\n"),
            Some("000A".into())
        );
    }
}
