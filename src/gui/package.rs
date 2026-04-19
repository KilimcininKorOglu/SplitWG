//! Encrypted `.splitwgpkg` backups of `.conf` + `<name>.rules.json`.
//!
//! The archive is a standard Zip with AES-256 encryption. Each tunnel lives
//! under `<name>/<name>.conf` (plus an optional `<name>/<name>.rules.json`)
//! and the top of the archive carries a `manifest.json` describing the
//! schema and payload.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use zip::write::SimpleFileOptions;
use zip::{AesMode, ZipArchive, ZipWriter};

use crate::config::{self, Rules};

/// Minimum password length enforced by the UI and reconfirmed here.
pub const MIN_PASSWORD_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("password too short")]
    PasswordTooShort,
    #[error("wrong password or corrupt archive")]
    WrongPassword,
    #[error("invalid package")]
    InvalidPackage,
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    schema: u32,
    tool: String,
    tool_version: String,
    tunnels: Vec<ManifestTunnel>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestTunnel {
    name: String,
    has_rules: bool,
}

/// Writes a password-protected archive with the selected tunnels.
pub fn export(dest: &Path, names: &[String], password: &str) -> Result<(), PackageError> {
    log::info!("splitwg: package: exporting {} tunnel(s) to {:?}", names.len(), dest);
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(PackageError::PasswordTooShort);
    }

    let file = File::create(dest)?;
    let mut zip = ZipWriter::new(file);
    let make_options = || {
        SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .with_aes_encryption(AesMode::Aes256, password)
            .unix_permissions(0o600)
    };

    let dir = config::config_dir();
    let mut manifest = Manifest {
        schema: 1,
        tool: "splitwg".into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        tunnels: Vec::new(),
    };

    for name in names {
        let conf_path = dir.join(format!("{name}.conf"));
        if !conf_path.exists() {
            log::warn!("splitwg: package: skipping {:?}, config not found", name);
            continue;
        }
        let conf_bytes = fs::read(&conf_path)?;
        zip.start_file(format!("{name}/{name}.conf"), make_options())?;
        zip.write_all(&conf_bytes)?;
        log::info!("splitwg: package: added {}.conf", name);

        let rules_path = dir.join(format!("{name}.rules.json"));
        let has_rules = rules_path.exists();
        if has_rules {
            let rules_bytes = fs::read(&rules_path)?;
            zip.start_file(format!("{name}/{name}.rules.json"), make_options())?;
            zip.write_all(&rules_bytes)?;
            log::info!("splitwg: package: added {}.rules.json", name);
        }

        manifest.tunnels.push(ManifestTunnel {
            name: name.clone(),
            has_rules,
        });
    }

    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    zip.start_file("manifest.json", make_options())?;
    zip.write_all(&manifest_bytes)?;

    zip.finish()?;
    log::info!("splitwg: package: export complete with {} tunnel(s)", manifest.tunnels.len());
    Ok(())
}

/// Extracts a package's tunnels into the config directory. Collisions are
/// renamed with an `-imported` suffix so existing tunnels are never
/// overwritten. Returns the list of imported names (possibly suffixed).
pub fn import(src: &Path, password: &str) -> Result<Vec<String>, PackageError> {
    log::info!("splitwg: package: importing from {:?}", src);
    let file = File::open(src)?;
    let mut archive = ZipArchive::new(file)?;

    // Read manifest first so a malformed archive fails before we touch disk.
    let manifest: Manifest = {
        let mut entry = archive
            .by_name_decrypt("manifest.json", password.as_bytes())
            .map_err(map_zip_err)?;
        let mut body = String::new();
        entry.read_to_string(&mut body).map_err(|_| PackageError::WrongPassword)?;
        serde_json::from_str(&body).map_err(|_| PackageError::InvalidPackage)?
    };

    if manifest.schema != 1 {
        return Err(PackageError::InvalidPackage);
    }

    let dir = config::config_dir();
    config::ensure_config_dir()?;

    let mut imported = Vec::with_capacity(manifest.tunnels.len());
    for t in &manifest.tunnels {
        let target_name = pick_unique_name(&t.name, &dir);
        log::info!("splitwg: package: importing tunnel {:?} as {:?}", t.name, target_name);

        // .conf
        {
            let mut entry = archive
                .by_name_decrypt(&format!("{}/{}.conf", t.name, t.name), password.as_bytes())
                .map_err(map_zip_err)?;
            let mut body = Vec::new();
            entry.read_to_end(&mut body)?;
            let path = dir.join(format!("{target_name}.conf"));
            write_with_mode(&path, &body, 0o600)?;
        }

        // rules.json (optional)
        if t.has_rules {
            if let Ok(mut entry) = archive.by_name_decrypt(
                &format!("{}/{}.rules.json", t.name, t.name),
                password.as_bytes(),
            ) {
                let mut body = Vec::new();
                entry.read_to_end(&mut body)?;
                // Validate JSON so we never persist garbage rules files.
                let _: Rules = serde_json::from_slice(&body)
                    .map_err(|_| PackageError::InvalidPackage)?;
                let path = dir.join(format!("{target_name}.rules.json"));
                write_with_mode(&path, &body, 0o644)?;
            }
        }

        imported.push(target_name);
    }

    log::info!("splitwg: package: import complete, {} tunnel(s) imported", imported.len());
    Ok(imported)
}

fn map_zip_err(e: zip::result::ZipError) -> PackageError {
    match e {
        zip::result::ZipError::InvalidPassword => PackageError::WrongPassword,
        zip::result::ZipError::UnsupportedArchive(_) => PackageError::WrongPassword,
        other => PackageError::Zip(other),
    }
}

fn pick_unique_name(base: &str, dir: &Path) -> String {
    let candidate = dir.join(format!("{base}.conf"));
    if !candidate.exists() {
        return base.to_string();
    }
    for n in 1..1000 {
        let name = format!("{base}-imported-{n}");
        if !dir.join(format!("{name}.conf")).exists() {
            return name;
        }
    }
    format!("{base}-imported")
}

fn write_with_mode(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, data)?;
    let mut p = fs::metadata(path)?.permissions();
    p.set_mode(mode);
    fs::set_permissions(path, p)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_unique_name_suffixes_on_collision() {
        let dir = std::env::temp_dir().join(format!("splitwg-pkg-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("demo.conf");
        fs::write(&path, b"[Interface]\n").unwrap();

        let name = pick_unique_name("demo", &dir);
        assert_eq!(name, "demo-imported-1");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn export_rejects_short_password() {
        let tmp = std::env::temp_dir().join("splitwg-export-test.splitwgpkg");
        let err = export(&tmp, &[], "short").unwrap_err();
        assert!(matches!(err, PackageError::PasswordTooShort));
    }
}
