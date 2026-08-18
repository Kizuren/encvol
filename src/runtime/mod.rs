//! The executable half of the RAM-resident installer.
//!
//! It is deliberately separate from client-side staging. `run()` only proceeds
//! when booted with `encvol.installer=1`, all validation succeeds, and the
//! caller supplies the same explicit disk acknowledgement used by the client.
mod command;
mod config;
mod environment;
mod install;
mod layout;
mod self_install;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Firmware {
    Uefi,
    Bios,
}

#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    pub firmware: Firmware,
    pub execute: bool,
    pub allow_non_ram: bool,
}

pub use install::run;
pub use self_install::run as run_self_install;

#[cfg(test)]
use config::{prepare_target_runtime_directories, tang_config, write_root_configuration_at};
#[cfg(test)]
use environment::root_mount_is_ram;
#[cfg(test)]
use layout::runtime_commands;

#[cfg(test)]
mod tests;
