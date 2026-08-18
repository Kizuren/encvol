use crate::EncvolError;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn download(url: &url::Url) -> Result<Vec<u8>, EncvolError> {
    let response = ureq::get(url.as_str())
        .call()
        // Transport libraries commonly include the complete URL in their
        // diagnostic, including any accidentally supplied userinfo.  URLs
        // are inputs here, so keep that value out of caller-visible errors.
        .map_err(|_| EncvolError::Verification("download failed".into()))?;
    let mut reader = response.into_reader();
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut out)
        .map_err(|_| EncvolError::Verification("download failed".into()))?;
    Ok(out)
}

pub fn download_to_path(url: &url::Url, destination: &Path) -> Result<String, EncvolError> {
    let response = ureq::get(url.as_str())
        .call()
        // Keep potentially sensitive URL userinfo out of diagnostics.
        .map_err(|_| EncvolError::Verification("download failed".into()))?;
    let file = fs::File::create(destination)
        .map_err(|e| EncvolError::Unsupported(format!("cannot create download cache: {e}")))?;
    copy_and_hash(response.into_reader(), file)
}

pub(crate) fn copy_and_hash(
    mut reader: impl Read,
    mut writer: impl Write,
) -> Result<String, EncvolError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| EncvolError::Verification("download failed".into()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        writer
            .write_all(&buffer[..read])
            .map_err(|e| EncvolError::Unsupported(format!("cannot write download cache: {e}")))?;
    }
    writer
        .flush()
        .map_err(|e| EncvolError::Unsupported(format!("cannot flush download cache: {e}")))?;
    Ok(hex::encode(hasher.finalize()))
}
