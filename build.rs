use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=ENCVOL_INSTALLER_BUNDLE");
    println!("cargo:rerun-if-env-changed=ENCVOL_BOOTSTRAP_WITHOUT_INSTALLER_BUNDLE");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let generated = out_dir.join("embedded_bundle.rs");
    let bundle = env::var_os("ENCVOL_INSTALLER_BUNDLE").map(PathBuf::from);
    let profile = env::var("PROFILE").unwrap_or_default();
    let bootstrap = env::var_os("ENCVOL_BOOTSTRAP_WITHOUT_INSTALLER_BUNDLE").is_some();

    match bundle {
        Some(path) => {
            let canonical = fs::canonicalize(&path).unwrap_or_else(|error| {
                panic!("ENCVOL_INSTALLER_BUNDLE must point to a readable installer bundle: {error}")
            });
            println!("cargo:rerun-if-changed={}", canonical.display());
            fs::write(
                generated,
                format!(
                    "pub const EMBEDDED_INSTALLER_BUNDLE: Option<&'static [u8]> = Some(include_bytes!(r#\"{}\"#));\n",
                    canonical.display()
                ),
            )
            .expect("write generated embedded bundle module");
        }
        None if profile == "release" && !bootstrap => {
            eprintln!(
                "release builds require ENCVOL_INSTALLER_BUNDLE=/path/to/bundle; set ENCVOL_BOOTSTRAP_WITHOUT_INSTALLER_BUNDLE=1 only for bootstrap packaging builds"
            );
            std::process::exit(1);
        }
        None => {
            fs::write(
                generated,
                "pub const EMBEDDED_INSTALLER_BUNDLE: Option<&'static [u8]> = None;\n",
            )
            .expect("write generated embedded bundle module");
        }
    }
}
