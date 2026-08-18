use crate::{bundle::StagedBundle, EncvolError};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::{
    fs,
    io::{Read, Write},
    process::{Command as ProcessCommand, Stdio},
    thread,
};

pub(crate) fn append_newc_entry(output: &mut Vec<u8>, name: &str, data: &[u8]) {
    append_newc_node(output, name, data, 0o100600, 1);
}

fn append_newc_dir(output: &mut Vec<u8>, name: &str) {
    append_newc_node(output, name, &[], 0o040700, 2);
}

fn append_newc_node(output: &mut Vec<u8>, name: &str, data: &[u8], mode: u32, nlink: u32) {
    let fields = [
        0_u32,
        mode,
        0,
        0,
        nlink,
        0,
        data.len() as u32,
        0,
        0,
        0,
        0,
        (name.len() + 1) as u32,
        0,
    ];
    output.extend_from_slice(b"070701");
    for field in fields {
        output.extend_from_slice(format!("{field:08x}").as_bytes());
    }
    output.extend_from_slice(name.as_bytes());
    output.push(0);
    while !output.len().is_multiple_of(4) {
        output.push(0);
    }
    output.extend_from_slice(data);
    while !output.len().is_multiple_of(4) {
        output.push(0);
    }
}

/// Concatenate a newc CPIO overlay to the initramfs. Linux initramfs accepts
/// concatenated archives in some formats, but Debian's zstd-compressed images
/// are more reliable when the manifest is inserted into the existing CPIO
/// stream before the final trailer and then recompressed as one stream.  That
/// keeps the exact preflighted configuration available in RAM without modifying
/// the signed base installer artifact.
pub fn embed_manifest(bundle: &mut StagedBundle, manifest: &[u8]) -> Result<(), EncvolError> {
    let initrd = bundle.initrd.as_ref().ok_or_else(|| {
        EncvolError::Verification("installer needs kernel/initrd to embed its manifest".into())
    })?;
    let initrd_bytes = fs::read(initrd)
        .map_err(|e| EncvolError::Verification(format!("cannot read staged initrd: {e}")))?;
    let updated = embed_manifest_for_initrd(&initrd_bytes, manifest)?;
    fs::write(initrd, updated)
        .map_err(|e| EncvolError::Verification(format!("cannot embed installer manifest: {e}")))?;
    Ok(())
}

fn manifest_cpio_entries(manifest: &[u8]) -> Vec<u8> {
    let mut entries = Vec::new();
    append_newc_dir(&mut entries, "etc/encvol");
    append_newc_entry(&mut entries, "etc/encvol/manifest.json", manifest);
    entries
}

fn embed_manifest_for_initrd(initrd: &[u8], manifest: &[u8]) -> Result<Vec<u8>, EncvolError> {
    if initrd.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let cpio = zstd_decompress(initrd)?;
        let cpio = insert_manifest_entries(&cpio, manifest)?;
        return zstd_compress(&cpio);
    }
    if initrd.starts_with(&[0x1f, 0x8b]) {
        let mut cpio = Vec::new();
        GzDecoder::new(initrd).read_to_end(&mut cpio).map_err(|e| {
            EncvolError::Verification(format!("cannot decompress initrd for manifest: {e}"))
        })?;
        let cpio = insert_manifest_entries(&cpio, manifest)?;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&cpio).map_err(|e| {
            EncvolError::Verification(format!("cannot compress manifest overlay: {e}"))
        })?;
        return encoder.finish().map_err(|e| {
            EncvolError::Verification(format!("cannot finish manifest overlay compression: {e}"))
        });
    }
    insert_manifest_entries(initrd, manifest)
}

fn insert_manifest_entries(cpio: &[u8], manifest: &[u8]) -> Result<Vec<u8>, EncvolError> {
    let trailer = find_first_newc_trailer(cpio).ok_or_else(|| {
        EncvolError::Verification("installer initrd is not a readable newc archive".into())
    })?;
    let mut updated = Vec::with_capacity(cpio.len() + manifest.len() + 512);
    updated.extend_from_slice(&cpio[..trailer]);
    updated.extend_from_slice(&manifest_cpio_entries(manifest));
    updated.extend_from_slice(&cpio[trailer..]);
    Ok(updated)
}

fn find_first_newc_trailer(cpio: &[u8]) -> Option<usize> {
    let mut offset = 0;
    while offset + 110 <= cpio.len() {
        match &cpio[offset..offset + 6] {
            b"070701" | b"070702" => {}
            _ if cpio[offset] == 0 => {
                offset += 1;
                continue;
            }
            _ => return None,
        }

        let filesize = parse_newc_hex(cpio, offset + 54)? as usize;
        let namesize = parse_newc_hex(cpio, offset + 94)? as usize;
        let name_start = offset + 110;
        let name_end = name_start.checked_add(namesize)?;
        if name_end > cpio.len() || namesize == 0 {
            return None;
        }
        let name = &cpio[name_start..name_end - 1];
        if name == b"TRAILER!!!" {
            return Some(offset);
        }
        let data_start = align4(name_end);
        let data_end = data_start.checked_add(filesize)?;
        if data_end > cpio.len() {
            return None;
        }
        offset = align4(data_end);
    }
    None
}

fn parse_newc_hex(cpio: &[u8], offset: usize) -> Option<u32> {
    let field = cpio.get(offset..offset + 8)?;
    let text = std::str::from_utf8(field).ok()?;
    u32::from_str_radix(text, 16).ok()
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn zstd_decompress(initrd: &[u8]) -> Result<Vec<u8>, EncvolError> {
    zstd_filter(
        &["-q", "-d", "-c"],
        initrd,
        "zstd failed while decompressing installer initrd",
    )
}

fn zstd_filter(args: &[&str], input: &[u8], failure: &str) -> Result<Vec<u8>, EncvolError> {
    let mut child = ProcessCommand::new("zstd")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            EncvolError::Verification(format!("cannot start zstd for initrd manifest: {e}"))
        })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| EncvolError::Verification("cannot open zstd stdin".into()))?;
    let input = input.to_vec();
    let writer = thread::spawn(move || stdin.write_all(&input));
    let output = child.wait_with_output().map_err(|e| {
        EncvolError::Verification(format!("cannot finish zstd initrd decompression: {e}"))
    })?;
    writer
        .join()
        .map_err(|_| EncvolError::Verification("zstd input writer panicked".into()))?
        .map_err(|e| EncvolError::Verification(format!("cannot write input to zstd: {e}")))?;
    if !output.status.success() {
        return Err(EncvolError::Verification(failure.into()));
    }
    Ok(output.stdout)
}

fn zstd_compress(cpio: &[u8]) -> Result<Vec<u8>, EncvolError> {
    zstd_filter(
        &["-q", "-1", "-c"],
        cpio,
        "zstd failed while compressing manifest overlay",
    )
}
