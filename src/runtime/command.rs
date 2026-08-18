use crate::{secrets::redact, EncvolError};
use std::{
    io::Write,
    process::{Command, Stdio},
};

pub(super) fn run_command(command: &[String], stdin: Option<&[u8]>) -> Result<(), EncvolError> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| EncvolError::Unsupported("empty installer command".into()))?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| EncvolError::Unsupported(format!("cannot run {program}: {e}")))?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .ok_or_else(|| EncvolError::Unsupported("cannot provide command input".into()))?
            .write_all(input)
            .map_err(|e| {
                EncvolError::Unsupported(format!("cannot provide installer input: {e}"))
            })?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| EncvolError::Unsupported(format!("cannot wait for {program}: {e}")))?;
    if !output.status.success() {
        return Err(EncvolError::Unsupported(format!(
            "{program} failed: {}",
            redact(&String::from_utf8_lossy(&output.stderr))
        )));
    }
    Ok(())
}
