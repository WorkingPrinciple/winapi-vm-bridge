//! Deterministic unsigned runtime package verification and slot lifecycle.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wvb_integrity::{
    IntegrityError, canonical_root, resolve_regular_file, sha256_bytes, sha256_file,
    validate_portable_relative_path,
};

pub const MANIFEST_IDENTIFIER: &str = "winapi-vm-bridge.runtime-package.v1";
pub const MANIFEST_MAJOR: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageFile {
    pub relative_path: String,
    pub sha256: [u8; 32],
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageManifest {
    pub identifier: String,
    pub major: u32,
    pub package_version: String,
    pub source_sha256: [u8; 32],
    pub sbom_sha256: [u8; 32],
    pub files: Vec<PackageFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveSlot {
    pub package_version: String,
    pub manifest_sha256: [u8; 32],
}

#[derive(Debug)]
pub enum PackageError {
    Integrity(IntegrityError),
    Io(io::Error),
    Canonicalization(String),
    InvalidManifest(&'static str),
    DuplicatePath(String),
    HashMismatch(PathBuf),
    AlreadyInstalled,
    NotInstalled,
    HealthCheckFailed,
    RollbackUnavailable,
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PackageError {}

impl From<IntegrityError> for PackageError {
    fn from(value: IntegrityError) -> Self {
        Self::Integrity(value)
    }
}

impl From<io::Error> for PackageError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl PackageManifest {
    pub fn validate(&self) -> Result<(), PackageError> {
        if self.identifier != MANIFEST_IDENTIFIER
            || self.major != MANIFEST_MAJOR
            || !valid_version(&self.package_version)
            || self.files.is_empty()
            || self.files.len() > 16_384
        {
            return Err(PackageError::InvalidManifest("header"));
        }
        let mut paths = BTreeSet::new();
        for file in &self.files {
            validate_portable_relative_path(&file.relative_path)?;
            if !paths.insert(file.relative_path.to_ascii_lowercase()) {
                return Err(PackageError::DuplicatePath(file.relative_path.clone()));
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PackageError> {
        self.validate()?;
        serde_jcs::to_vec(self).map_err(|error| PackageError::Canonicalization(error.to_string()))
    }

    pub fn sha256(&self) -> Result<[u8; 32], PackageError> {
        Ok(sha256_bytes(&self.canonical_bytes()?))
    }

    pub fn verify_source(&self, source_root: &Path) -> Result<(), PackageError> {
        self.validate()?;
        let root = canonical_root(source_root)?;
        for file in &self.files {
            let path = resolve_regular_file(&root, &file.relative_path)?;
            if sha256_file(&path)? != file.sha256 {
                return Err(PackageError::HashMismatch(path));
            }
        }
        Ok(())
    }
}

pub struct PackageManager {
    root: PathBuf,
}

impl PackageManager {
    pub fn open(root: &Path) -> Result<Self, PackageError> {
        fs::create_dir_all(root)?;
        let root = canonical_root(root)?;
        let versions = root.join("versions");
        fs::create_dir_all(&versions)?;
        canonical_root(&versions)?;
        Ok(Self { root })
    }

    pub fn stage(
        &self,
        source_root: &Path,
        manifest: &PackageManifest,
    ) -> Result<PathBuf, PackageError> {
        manifest.verify_source(source_root)?;
        let source_root = canonical_root(source_root)?;
        let manifest_hash = manifest.sha256()?;
        let versions = self.root.join("versions");
        let final_path = versions.join(&manifest.package_version);
        if final_path.exists() {
            return Err(PackageError::AlreadyInstalled);
        }
        let staging = versions.join(format!(
            ".{}.{}.staging",
            manifest.package_version,
            short_hash(manifest_hash)
        ));
        if staging.exists() {
            remove_controlled_tree(&versions, &staging)?;
        }
        fs::create_dir(&staging)?;
        for file in &manifest.files {
            let source = resolve_regular_file(&source_root, &file.relative_path)?;
            let destination = staging.join(&file.relative_path);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(source, &destination)?;
            if sha256_file(&destination)? != file.sha256 {
                return Err(PackageError::HashMismatch(destination));
            }
            set_executable(&destination, file.executable)?;
        }
        fs::write(staging.join("manifest.jcs"), manifest.canonical_bytes()?)?;
        fs::rename(&staging, &final_path)?;
        Ok(final_path)
    }

    pub fn activate(
        &self,
        manifest: &PackageManifest,
        health_check: impl FnOnce(&Path) -> bool,
    ) -> Result<ActiveSlot, PackageError> {
        let version_path = self.root.join("versions").join(&manifest.package_version);
        if !version_path.is_dir() {
            return Err(PackageError::NotInstalled);
        }
        if !health_check(&version_path) {
            return Err(PackageError::HealthCheckFailed);
        }
        let slot = ActiveSlot {
            package_version: manifest.package_version.clone(),
            manifest_sha256: manifest.sha256()?,
        };
        let bytes = serde_jcs::to_vec(&slot)
            .map_err(|error| PackageError::Canonicalization(error.to_string()))?;
        let pending = self.root.join("active.pending");
        fs::write(&pending, bytes)?;
        let active = self.root.join("active.jcs");
        let previous = self.root.join("previous.jcs");
        if active.exists() {
            fs::rename(&active, &previous)?;
        }
        fs::rename(pending, active)?;
        Ok(slot)
    }

    pub fn rollback(&self) -> Result<ActiveSlot, PackageError> {
        let active = self.root.join("active.jcs");
        let previous = self.root.join("previous.jcs");
        if !previous.is_file() {
            return Err(PackageError::RollbackUnavailable);
        }
        let prior = decode_slot(&previous)?;
        let prior_path = self.root.join("versions").join(&prior.package_version);
        if !prior_path.is_dir() {
            return Err(PackageError::RollbackUnavailable);
        }
        let displaced = self.root.join("active.displaced");
        if displaced.exists() {
            fs::remove_file(&displaced)?;
        }
        if active.exists() {
            fs::rename(&active, &displaced)?;
        }
        fs::rename(&previous, &active)?;
        if displaced.exists() {
            fs::rename(&displaced, &previous)?;
        }
        Ok(prior)
    }

    pub fn active(&self) -> Result<Option<ActiveSlot>, PackageError> {
        let active = self.root.join("active.jcs");
        if active.is_file() {
            Ok(Some(decode_slot(&active)?))
        } else {
            Ok(None)
        }
    }

    pub fn uninstall_preflight(&self, package_version: &str) -> Result<Vec<PathBuf>, PackageError> {
        let version = self.root.join("versions").join(package_version);
        if !version.is_dir() {
            return Err(PackageError::NotInstalled);
        }
        let mut paths = fs::read_dir(&version)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();
        Ok(paths)
    }

    pub fn uninstall(&self, package_version: &str) -> Result<(), PackageError> {
        if self
            .active()?
            .is_some_and(|slot| slot.package_version == package_version)
        {
            return Err(PackageError::InvalidManifest(
                "active package must be rolled back first",
            ));
        }
        let versions = self.root.join("versions");
        let version = versions.join(package_version);
        remove_controlled_tree(&versions, &version)
    }
}

fn decode_slot(path: &Path) -> Result<ActiveSlot, PackageError> {
    serde_json::from_slice(&fs::read(path)?)
        .map_err(|error| PackageError::Canonicalization(error.to_string()))
}

fn remove_controlled_tree(root: &Path, path: &Path) -> Result<(), PackageError> {
    let root = canonical_root(root)?;
    let parent = path
        .parent()
        .ok_or(PackageError::InvalidManifest("invalid package path"))?;
    if canonical_root(parent)? != root || path == root {
        return Err(PackageError::InvalidManifest("package path escaped root"));
    }
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(PackageError::InvalidManifest(
                "package path is not a directory",
            ));
        }
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path, executable: bool) -> Result<(), PackageError> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(if executable { 0o755 } else { 0o644 });
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path, _executable: bool) -> Result<(), PackageError> {
    Ok(())
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn short_hash(value: [u8; 32]) -> String {
    use std::fmt::Write;

    value[..8].iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
        output
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn manifest(version: &str, file_hash: [u8; 32]) -> PackageManifest {
        PackageManifest {
            identifier: String::from(MANIFEST_IDENTIFIER),
            major: MANIFEST_MAJOR,
            package_version: String::from(version),
            source_sha256: [1; 32],
            sbom_sha256: [2; 32],
            files: vec![PackageFile {
                relative_path: String::from("bin/wvb"),
                sha256: file_hash,
                executable: true,
            }],
        }
    }

    fn source(bytes: &[u8]) -> tempfile::TempDir {
        let directory = tempdir().unwrap();
        fs::create_dir(directory.path().join("bin")).unwrap();
        fs::write(directory.path().join("bin/wvb"), bytes).unwrap();
        directory
    }

    #[test]
    fn stage_activate_update_rollback_and_uninstall_are_transactional() {
        let install = tempdir().unwrap();
        let manager = PackageManager::open(install.path()).unwrap();
        let first_source = source(b"first");
        let first = manifest("1.0.0", sha256_bytes(b"first"));
        manager.stage(first_source.path(), &first).unwrap();
        manager.activate(&first, |_| true).unwrap();
        assert_eq!(manager.active().unwrap().unwrap().package_version, "1.0.0");

        let second_source = source(b"second");
        let second = manifest("1.1.0", sha256_bytes(b"second"));
        manager.stage(second_source.path(), &second).unwrap();
        assert!(matches!(
            manager.activate(&second, |_| false),
            Err(PackageError::HealthCheckFailed)
        ));
        assert_eq!(manager.active().unwrap().unwrap().package_version, "1.0.0");
        manager.activate(&second, |_| true).unwrap();
        assert_eq!(manager.active().unwrap().unwrap().package_version, "1.1.0");
        assert_eq!(manager.rollback().unwrap().package_version, "1.0.0");
        manager.uninstall("1.1.0").unwrap();
        assert!(matches!(
            manager.uninstall_preflight("1.1.0"),
            Err(PackageError::NotInstalled)
        ));
    }

    #[test]
    fn manifests_reject_traversal_collisions_and_hash_mismatch() {
        let source = source(b"runtime");
        let mut value = manifest("1.0.0", sha256_bytes(b"changed"));
        assert!(matches!(
            value.verify_source(source.path()),
            Err(PackageError::HashMismatch(_))
        ));
        value.files[0].relative_path = String::from("../wvb");
        assert!(value.validate().is_err());
        value.files = vec![
            PackageFile {
                relative_path: String::from("bin/wvb"),
                sha256: [1; 32],
                executable: false,
            },
            PackageFile {
                relative_path: String::from("BIN/WVB"),
                sha256: [2; 32],
                executable: false,
            },
        ];
        assert!(matches!(
            value.validate(),
            Err(PackageError::DuplicatePath(_))
        ));
    }
}
