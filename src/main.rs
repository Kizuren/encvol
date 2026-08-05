use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use encvol::{
    bundle, handoff, installer,
    manifest::{InstallationManifest, Layout},
    preflight,
    rootfs::{self, ArchiveFormat, RootfsDescriptor},
    runtime::{Firmware, RuntimeOptions},
    safety,
};
use std::{
    env, fs,
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
};
use url::Url;

#[derive(Parser)]
#[command(
    name = "encvol",
    version,
    about = "Provider-neutral encrypted VPS reinstaller"
)]
struct Cli {
    #[command(subcommand)]
    command: Top,
}
#[derive(Subcommand)]
enum Top {
    Preflight(PreflightArgs),
    Install(InstallArgs),
    Rootfs {
        #[command(subcommand)]
        command: RootfsCommand,
    },
    Bundle {
        #[command(subcommand)]
        command: BundleCommand,
    },
    #[command(hide = true)]
    InstallerRun(InstallerRunArgs),
}
#[derive(Args)]
struct PreflightArgs {
    #[arg(long)]
    disk: String,
    #[arg(long)]
    pretty: bool,
}
#[derive(Args)]
struct InstallArgs {
    #[arg(long)]
    disk: String,
    #[arg(long)]
    rootfs_descriptor: Url,
    #[arg(long)]
    tang_url: Url,
    #[arg(long)]
    tang_thumbprint: String,
    #[arg(long)]
    recovery_authorized_key: PathBuf,
    #[arg(long, default_value_t = 1024)]
    swap_mib: u64,
    #[arg(long)]
    data_volume: bool,
    /// Exact acknowledgement: WIPE:/dev/the-selected-disk
    #[arg(long)]
    confirm: Option<String>,
    /// Signed installer release version already stored in --bundle-directory.
    #[arg(long)]
    bundle_version: String,
    #[arg(
        long,
        env = "ENCVOL_BUNDLE_DIR",
        default_value = "/var/lib/encvol/releases"
    )]
    bundle_directory: PathBuf,
    /// Stage the verified installer and reboot through the selected handoff.
    #[arg(long)]
    execute: bool,
    /// Permit a missing or invalid signature for this caller-selected local bundle.
    #[arg(long)]
    allow_unsigned_bundle: bool,
}
#[derive(Subcommand)]
enum RootfsCommand {
    /// Bootstrap an editable amd64 Debian root filesystem workspace.
    Init {
        #[arg(long)]
        release: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        mirror: Option<Url>,
    },
    /// Validate and package an editable root filesystem workspace.
    Pack {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        archive_url: Url,
        #[arg(long, default_value = "tar", value_parser = ["tar", "tar.zst"])]
        format: String,
    },
    /// Read-only mount a filesystem partition and package it as a rootfs archive.
    Import {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        archive_url: Url,
        #[arg(long, default_value = "tar", value_parser = ["tar", "tar.zst"])]
        format: String,
    },
}
#[derive(Args)]
struct InstallerRunArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long, value_parser = ["uefi", "bios"])]
    firmware: String,
    #[arg(long)]
    execute: bool,
    #[arg(long, hide = true)]
    allow_non_ram: bool,
}
#[derive(Subcommand)]
enum BundleCommand {
    Fetch {
        #[arg(long)]
        version: String,
        #[arg(long)]
        base_url: Url,
        #[arg(
            long,
            env = "ENCVOL_BUNDLE_DIR",
            default_value = "/var/lib/encvol/releases"
        )]
        directory: PathBuf,
    },
    Verify {
        #[arg(long)]
        version: String,
        #[arg(
            long,
            env = "ENCVOL_BUNDLE_DIR",
            default_value = "/var/lib/encvol/releases"
        )]
        directory: PathBuf,
        /// Permit a missing or invalid signature for this caller-selected local bundle.
        #[arg(long)]
        allow_unsigned_bundle: bool,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Top::Preflight(args) => {
            let report = preflight::probe(&args.disk).map_err(anyhow::Error::msg)?;
            if args.pretty {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", serde_json::to_string(&report)?);
            }
            if report.handoff == encvol::handoff::Handoff::Unsupported {
                bail!("host has no supported handoff")
            }
        }
        Top::Bundle {
            command:
                BundleCommand::Verify {
                    version,
                    directory,
                    allow_unsigned_bundle,
                },
        } => {
            if !bundle::valid_version(&version) {
                bail!("invalid bundle version")
            };
            let policy = if allow_unsigned_bundle {
                bundle::SignaturePolicy::AllowUnsignedLocal
            } else {
                bundle::SignaturePolicy::Strict
            };
            if allow_unsigned_bundle {
                eprintln!("WARNING: installer signature verification disabled");
            }
            let (digest, _) = bundle::verify_bundle_with_policy(
                &bundle::bundle_path(&directory, &version),
                &bundle::signature_path(&directory, &version),
                policy,
            )
            .map_err(anyhow::Error::msg)?;
            println!("verified installer {version}: sha256:{digest}");
        }
        Top::Bundle {
            command:
                BundleCommand::Fetch {
                    version,
                    base_url,
                    directory,
                },
        } => {
            let (bundle_path, signature_path) =
                bundle::fetch_bundle(&base_url, &version, &directory)
                    .map_err(anyhow::Error::msg)?;
            let digest =
                bundle::verify_bundle(&bundle_path, &signature_path).map_err(anyhow::Error::msg)?;
            println!("fetched and verified installer {version}: sha256:{digest}");
        }
        Top::Install(args) => install(args)?,
        Top::Rootfs { command } => rootfs_command(command)?,
        Top::InstallerRun(args) => installer_run(args)?,
    }
    Ok(())
}

fn install(args: InstallArgs) -> Result<()> {
    safety::validate_disk_path(&args.disk).map_err(anyhow::Error::msg)?;
    safety::require_confirmation(&args.disk, args.confirm.as_deref())
        .map_err(anyhow::Error::msg)?;
    let report = preflight::probe(&args.disk).map_err(anyhow::Error::msg)?;
    if report.handoff == encvol::handoff::Handoff::Unsupported {
        bail!("preflight rejected this host; no changes were made")
    }
    let bytes = bundle::download(&args.rootfs_descriptor).map_err(anyhow::Error::msg)?;
    let rootfs: RootfsDescriptor =
        serde_json::from_slice(&bytes).context("rootfs descriptor is not valid JSON")?;
    rootfs.validate().map_err(anyhow::Error::msg)?;
    let recovery_authorized_key = fs::read_to_string(&args.recovery_authorized_key)
        .context("cannot read recovery authorized key")?
        .trim()
        .into();
    let network = report
        .network
        .ok_or_else(|| anyhow::anyhow!("could not capture active network configuration"))?;
    let manifest = InstallationManifest {
        schema_version: 1,
        target_disk: args.disk,
        rootfs,
        tang_url: args.tang_url,
        tang_thumbprint: args.tang_thumbprint,
        recovery_authorized_key,
        network,
        layout: Some(Layout {
            swap_mib: args.swap_mib,
            data_volume: args.data_volume,
        }),
    };
    manifest.validate().map_err(anyhow::Error::msg)?;
    let requested_verification = if args.allow_unsigned_bundle {
        bundle::SignatureVerification::Disabled
    } else {
        bundle::SignatureVerification::Verified
    };
    let plan = installer::build_plan_with_signature_verification(
        &manifest,
        report.handoff,
        requested_verification,
    )
    .map_err(anyhow::Error::msg)?;
    if args.allow_unsigned_bundle {
        eprintln!("WARNING: installer signature verification disabled");
    }
    if !args.execute {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }
    if !bundle::valid_version(&args.bundle_version) {
        bail!("invalid bundle version")
    }
    let stage = args
        .bundle_directory
        .join("staged")
        .join(&args.bundle_version);
    let policy = if args.allow_unsigned_bundle {
        bundle::SignaturePolicy::AllowUnsignedLocal
    } else {
        bundle::SignaturePolicy::Strict
    };
    let mut installer_bundle = bundle::stage_bundle_with_policy(
        &bundle::bundle_path(&args.bundle_directory, &args.bundle_version),
        &bundle::signature_path(&args.bundle_directory, &args.bundle_version),
        &stage,
        policy,
    )
    .map_err(anyhow::Error::msg)?;
    eprintln!("encvol: staged installer bundle");
    bundle::embed_manifest(&mut installer_bundle, &serde_json::to_vec(&manifest)?)
        .map_err(anyhow::Error::msg)?;
    eprintln!("encvol: embedded installer manifest");
    handoff::execute_handoff(
        report.handoff,
        &installer_bundle,
        &args.bundle_version,
        report.capabilities.writable_esp.as_deref(),
    )
    .map_err(anyhow::Error::msg)?;
    Ok(())
}

fn rootfs_command(command: RootfsCommand) -> Result<()> {
    match command {
        RootfsCommand::Init {
            release,
            root,
            mirror,
        } => {
            rootfs::init_workspace(&release, &root, mirror.as_ref()).map_err(anyhow::Error::msg)?;
            println!(
                "initialized editable Debian {release} rootfs at {}",
                root.display()
            );
        }
        RootfsCommand::Pack {
            root,
            output,
            archive_url,
            format,
        } => {
            let descriptor = rootfs::pack_workspace(
                &root,
                &output,
                archive_url,
                ArchiveFormat::parse(&format).map_err(anyhow::Error::msg)?,
            )
            .map_err(anyhow::Error::msg)?;
            println!("rootfs SHA-256: {}", descriptor.sha256);
            println!(
                "wrote descriptor: {}",
                rootfs::descriptor_path(&output).display()
            );
        }
        RootfsCommand::Import {
            source,
            output,
            archive_url,
            format,
        } => {
            eprintln!("warning: imported filesystem consistency requires it to be offline or an externally created snapshot");
            let descriptor = rootfs::import_source(
                &source,
                &output,
                archive_url,
                ArchiveFormat::parse(&format).map_err(anyhow::Error::msg)?,
            )
            .map_err(anyhow::Error::msg)?;
            println!("rootfs SHA-256: {}", descriptor.sha256);
            println!(
                "wrote descriptor: {}",
                rootfs::descriptor_path(&output).display()
            );
        }
    }
    Ok(())
}

fn installer_run(args: InstallerRunArgs) -> Result<()> {
    let text = fs::read(&args.manifest).context("cannot read installer manifest")?;
    let manifest: InstallationManifest =
        serde_json::from_slice(&text).context("installer manifest is not valid JSON")?;
    safety::require_confirmation(
        &manifest.target_disk,
        std::env::var("ENCVOL_CONFIRM").ok().as_deref(),
    )
    .map_err(anyhow::Error::msg)?;
    let firmware = match args.firmware.as_str() {
        "uefi" => Firmware::Uefi,
        "bios" => Firmware::Bios,
        _ => unreachable!(),
    };
    let passphrase = ask_passphrase()?;
    encvol::runtime::run(
        &manifest,
        &RuntimeOptions {
            firmware,
            execute: args.execute,
            allow_non_ram: args.allow_non_ram,
        },
        &passphrase,
    )
    .map_err(anyhow::Error::msg)
}

fn ask_passphrase() -> Result<Vec<u8>> {
    if let Some(passphrase) = qemu_recovery_passphrase() {
        return Ok(passphrase.into_bytes());
    }
    let mut child = Command::new("systemd-ask-password")
        .args(["--no-tty", "encvol LUKS recovery passphrase"])
        .stdout(Stdio::piped())
        .spawn()
        .context("cannot prompt for recovery passphrase")?;
    let mut value = Vec::new();
    child
        .stdout
        .take()
        .context("cannot read recovery passphrase")?
        .read_to_end(&mut value)?;
    if !child.wait()?.success() || value.is_empty() {
        bail!("recovery passphrase was not provided")
    }
    Ok(value)
}

fn qemu_recovery_passphrase() -> Option<String> {
    let passphrase = env::var("ENCVOL_QEMU_RECOVERY_PASSPHRASE").ok()?;
    if passphrase.is_empty() {
        return None;
    }
    let cmdline = fs::read_to_string("/proc/cmdline").ok()?;
    cmdline
        .split_whitespace()
        .any(|arg| arg.starts_with("encvol.test_case="))
        .then_some(passphrase)
}
