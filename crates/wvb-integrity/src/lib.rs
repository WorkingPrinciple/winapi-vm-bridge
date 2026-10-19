//! Shared path and content-integrity checks for runtime-controlled artifacts.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum IntegrityError {
    InvalidPath(String),
    PathEscape(PathBuf),
    SymlinkOrReparsePoint(PathBuf),
    NotRegularFile(PathBuf),
    Io(io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StableFileIdentity {
    volume: u64,
    file: u64,
}

impl std::fmt::Display for IntegrityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for IntegrityError {}

impl From<io::Error> for IntegrityError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn canonical_root(path: &Path) -> Result<PathBuf, IntegrityError> {
    let metadata = fs::symlink_metadata(path)?;
    if is_symlink_or_reparse(&metadata) {
        return Err(IntegrityError::SymlinkOrReparsePoint(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(IntegrityError::InvalidPath(path.display().to_string()));
    }
    Ok(fs::canonicalize(path)?)
}

pub fn validate_portable_relative_path(value: &str) -> Result<(), IntegrityError> {
    if value.is_empty()
        || value.len() > 240
        || value.contains(['\\', ':', '\0'])
        || value.starts_with('/')
        || value.ends_with('/')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        || value.split('/').any(|component| {
            component.is_empty()
                || matches!(component, "." | "..")
                || component.ends_with(['.', ' '])
                || is_reserved_windows_component(component)
        })
    {
        return Err(IntegrityError::InvalidPath(value.to_owned()));
    }

    Ok(())
}

fn is_reserved_windows_component(value: &str) -> bool {
    let stem = value.split('.').next().unwrap_or(value);
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

pub fn resolve_regular_file(
    canonical_root: &Path,
    relative_path: &str,
) -> Result<PathBuf, IntegrityError> {
    validate_portable_relative_path(relative_path)?;
    let relative = Path::new(relative_path);
    let mut current = canonical_root.to_path_buf();
    let component_count = relative.components().count();
    for (index, component) in relative.components().enumerate() {
        let Component::Normal(component) = component else {
            return Err(IntegrityError::InvalidPath(relative_path.to_owned()));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        if is_symlink_or_reparse(&metadata) {
            return Err(IntegrityError::SymlinkOrReparsePoint(current));
        }
        if index + 1 == component_count {
            if !metadata.is_file() {
                return Err(IntegrityError::NotRegularFile(current));
            }
        } else if !metadata.is_dir() {
            return Err(IntegrityError::InvalidPath(relative_path.to_owned()));
        }
    }
    let canonical = fs::canonicalize(&current)?;
    if !canonical.starts_with(canonical_root) {
        return Err(IntegrityError::PathEscape(canonical));
    }
    Ok(canonical)
}

pub fn sha256_file(path: &Path) -> Result<[u8; 32], IntegrityError> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        digest.update(&buffer[..length]);
    }
    Ok(digest.finalize().into())
}

pub fn stable_file_identity(path: &Path) -> Result<StableFileIdentity, IntegrityError> {
    Ok(stable_identity(&fs::metadata(path)?))
}

#[must_use]
pub fn sha256_bytes(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

#[cfg(windows)]
fn is_symlink_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn stable_identity(metadata: &fs::Metadata) -> StableFileIdentity {
    use std::os::windows::fs::MetadataExt;

    StableFileIdentity {
        volume: metadata.volume_serial_number().unwrap_or(0).into(),
        file: metadata.file_index().unwrap_or(0),
    }
}

#[cfg(not(windows))]
fn is_symlink_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(unix)]
fn stable_identity(metadata: &fs::Metadata) -> StableFileIdentity {
    use std::os::unix::fs::MetadataExt;

    StableFileIdentity {
        volume: metadata.dev(),
        file: metadata.ino(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn portable_paths_and_hashes_are_exact() {
        let directory = tempdir().unwrap();
        fs::create_dir(directory.path().join("bin")).unwrap();
        fs::write(directory.path().join("bin/runtime.dll"), b"runtime").unwrap();
        let root = canonical_root(directory.path()).unwrap();
        let path = resolve_regular_file(&root, "bin/runtime.dll").unwrap();
        assert_eq!(sha256_file(&path).unwrap(), sha256_bytes(b"runtime"));
        for invalid in [
            "",
            "../x",
            "/x",
            "C:/x",
            "bin\\x",
            "bin/./x",
            "CON",
            "bin/Lpt1.dll",
            "bin/candidate.dll.",
        ] {
            assert!(validate_portable_relative_path(invalid).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_ancestor_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("runtime.dll"), b"runtime").unwrap();
        symlink(outside.path(), root.path().join("bin")).unwrap();
        let root = canonical_root(root.path()).unwrap();
        assert!(matches!(
            resolve_regular_file(&root, "bin/runtime.dll"),
            Err(IntegrityError::SymlinkOrReparsePoint(_))
        ));
    }
}
