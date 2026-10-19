//! Admission of immutable, operator-approved Whiny bundles into the runtime.

mod correlated;
mod handoff;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

use wvb_authz::{ActorId, AuthorizationError, Registry, Role};
use wvb_integrity::{
    IntegrityError, canonical_root, resolve_regular_file, sha256_bytes, sha256_file,
    stable_file_identity, validate_portable_relative_path,
};

pub use correlated::{
    BoundCorrelatedEvidence, Cleanup as CorrelatedCleanup, CorrelatedEvidenceApproval,
    CorrelatedEvidenceError, CorrelatedEvidenceInputs, FileDigest as CorrelatedFileDigest,
};
pub use handoff::{
    BoundFrozenHandoff, ChallengeSequence, Custody, FileIdentity, FrozenHandoffApproval,
    FrozenHandoffInputs, HandoffAdmissionError, ReceiptPolicy, SideEffects,
    WHINY_FROZEN_HANDOFF_IDENTIFIER, WHINY_VALIDATOR_REVISION,
};

const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024 * 1024;
const MAX_FILES: usize = 4_096;
const MAX_OPERATIONS: usize = 65_536;
pub const CONTRACT_FORMAT_IDENTIFIER: &str = "whiny.adapter-contract.v3";
pub const CONTRACT_FORMAT_MAJOR: u32 = 3;
pub const BUNDLE_FORMAT_IDENTIFIER: &str = "whiny.adapter-bundle.v1";
pub const BUNDLE_FORMAT_MAJOR: u32 = 1;
pub const DISPATCHER_ABI_IDENTIFIER: &str = "whiny.dispatch.v1";
pub const DISPATCHER_ABI_MAJOR: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatVersion {
    pub identifier: String,
    pub major: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compatibility {
    pub contract: FormatVersion,
    pub bundle: FormatVersion,
    pub dispatcher_abi: FormatVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleFileKind {
    Dispatcher,
    Target,
    Dependency,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFile {
    pub kind: BundleFileKind,
    pub relative_path: String,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationAdmission {
    pub operation_id: u32,
    pub request_schema_id: u32,
    pub response_schema_id: u32,
}

/// Runtime-owned approval record created by an authorized operator after a
/// Whiny validator has frozen the bundle. It is not the Whiny contract schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorAdmission {
    pub compatibility: Compatibility,
    pub contract_sha256: [u8; 32],
    pub bundle_descriptor_sha256: [u8; 32],
    pub files: Vec<BundleFile>,
    pub operations: Vec<OperationAdmission>,
}

#[derive(Clone, Copy)]
pub struct FrozenInputs<'a> {
    pub contract: &'a [u8],
    pub bundle_descriptor: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedFile {
    pub kind: BundleFileKind,
    pub relative_path: String,
    pub canonical_path: PathBuf,
    pub sha256: [u8; 32],
    stable_identity: wvb_integrity::StableFileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedBundle {
    load_root: PathBuf,
    contract_sha256: [u8; 32],
    bundle_descriptor_sha256: [u8; 32],
    files: Vec<AdmittedFile>,
    operations: BTreeMap<u32, OperationAdmission>,
}

impl AdmittedBundle {
    #[must_use]
    pub fn contract_sha256(&self) -> [u8; 32] {
        self.contract_sha256
    }

    #[must_use]
    pub fn bundle_descriptor_sha256(&self) -> [u8; 32] {
        self.bundle_descriptor_sha256
    }

    #[must_use]
    pub fn files(&self) -> &[AdmittedFile] {
        &self.files
    }

    pub(crate) fn authorize_operation(
        &self,
        registry: &Registry,
        actor_id: ActorId,
        operation_id: u32,
        now_unix_ms: u64,
    ) -> Result<(), AdmissionError> {
        if !self.operations.contains_key(&operation_id) {
            return Err(AdmissionError::OperationNotInBundle);
        }
        registry
            .authorize_invoke(actor_id, self.contract_sha256, operation_id, now_unix_ms)
            .map_err(AdmissionError::Authorization)
    }

    #[must_use]
    pub fn operation(&self, operation_id: u32) -> Option<OperationAdmission> {
        self.operations.get(&operation_id).copied()
    }

    pub fn reverify_files(&self) -> Result<(), AdmissionError> {
        for file in &self.files {
            let resolved = resolve_regular_file(&self.load_root, &file.relative_path)?;
            if resolved != file.canonical_path {
                return Err(AdmissionError::PathIdentityChanged {
                    expected: file.canonical_path.clone(),
                    observed: resolved,
                });
            }
            if sha256_file(&resolved)? != file.sha256 {
                return Err(AdmissionError::HashMismatch(resolved));
            }
            if stable_file_identity(&resolved)? != file.stable_identity {
                return Err(AdmissionError::PathIdentityChanged {
                    expected: file.canonical_path.clone(),
                    observed: resolved,
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum AdmissionError {
    Authorization(AuthorizationError),
    Compatibility(&'static str),
    InvalidFormatIdentifier,
    DescriptorBoundExceeded,
    FileBoundExceeded,
    OperationBoundExceeded,
    EmptyOperations,
    DuplicateOperation(u32),
    OperationNotInBundle,
    InvalidFileSet,
    InvalidPath(String),
    DuplicatePath(String),
    PathEscape(PathBuf),
    PathIdentityChanged {
        expected: PathBuf,
        observed: PathBuf,
    },
    SymlinkOrReparsePoint(PathBuf),
    NotRegularFile(PathBuf),
    HashMismatch(PathBuf),
    Io(io::Error),
    ContractHashMismatch,
    BundleDescriptorHashMismatch,
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for AdmissionError {}

impl From<io::Error> for AdmissionError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<IntegrityError> for AdmissionError {
    fn from(value: IntegrityError) -> Self {
        match value {
            IntegrityError::InvalidPath(path) => Self::InvalidPath(path),
            IntegrityError::PathEscape(path) => Self::PathEscape(path),
            IntegrityError::SymlinkOrReparsePoint(path) => Self::SymlinkOrReparsePoint(path),
            IntegrityError::NotRegularFile(path) => Self::NotRegularFile(path),
            IntegrityError::Io(error) => Self::Io(error),
        }
    }
}

pub struct AdmissionEngine {
    load_root: PathBuf,
    compatibility: Compatibility,
}

impl AdmissionEngine {
    pub fn new(load_root: &Path) -> Result<Self, AdmissionError> {
        let compatibility = current_compatibility();
        verify_compatibility_identifiers(&compatibility)?;
        Ok(Self {
            load_root: canonical_root(load_root)?,
            compatibility,
        })
    }

    pub fn admit(
        &self,
        registry: &Registry,
        operator_actor: ActorId,
        now_unix_ms: u64,
        approval: &OperatorAdmission,
        inputs: FrozenInputs<'_>,
    ) -> Result<AdmittedBundle, AdmissionError> {
        registry
            .authorize_role_exact(
                operator_actor,
                Role::AdapterAdmin,
                approval.contract_sha256,
                None,
                now_unix_ms,
            )
            .map_err(AdmissionError::Authorization)?;
        verify_compatibility_identifiers(&approval.compatibility)?;
        self.verify_compatibility(&approval.compatibility)?;
        if inputs.contract.len() > MAX_DESCRIPTOR_BYTES
            || inputs.bundle_descriptor.len() > MAX_DESCRIPTOR_BYTES
        {
            return Err(AdmissionError::DescriptorBoundExceeded);
        }
        if sha256_bytes(inputs.contract) != approval.contract_sha256 {
            return Err(AdmissionError::ContractHashMismatch);
        }
        if sha256_bytes(inputs.bundle_descriptor) != approval.bundle_descriptor_sha256 {
            return Err(AdmissionError::BundleDescriptorHashMismatch);
        }
        if approval.files.len() > MAX_FILES {
            return Err(AdmissionError::FileBoundExceeded);
        }
        if approval.operations.is_empty() {
            return Err(AdmissionError::EmptyOperations);
        }
        if approval.operations.len() > MAX_OPERATIONS {
            return Err(AdmissionError::OperationBoundExceeded);
        }

        let mut operations = BTreeMap::new();
        for operation in &approval.operations {
            if operation.operation_id == 0
                || operation.request_schema_id == 0
                || operation.response_schema_id == 0
                || operations
                    .insert(operation.operation_id, *operation)
                    .is_some()
            {
                return Err(AdmissionError::DuplicateOperation(operation.operation_id));
            }
        }

        let mut dispatcher_count = 0;
        let mut target_count = 0;
        let mut normalized_paths = BTreeSet::new();
        let mut stable_identities = BTreeSet::new();
        let mut admitted_files = Vec::with_capacity(approval.files.len());
        for file in &approval.files {
            match file.kind {
                BundleFileKind::Dispatcher => dispatcher_count += 1,
                BundleFileKind::Target => target_count += 1,
                BundleFileKind::Dependency => {}
            }
            validate_portable_relative_path(&file.relative_path)?;
            let normalized = file.relative_path.to_ascii_lowercase();
            if !normalized_paths.insert(normalized) {
                return Err(AdmissionError::DuplicatePath(file.relative_path.clone()));
            }
            let path = self.resolve_file(&file.relative_path)?;
            let stable_identity = stable_file_identity(&path)?;
            if !stable_identities.insert(stable_identity) {
                return Err(AdmissionError::InvalidFileSet);
            }
            if sha256_file(&path)? != file.sha256 {
                return Err(AdmissionError::HashMismatch(path));
            }
            admitted_files.push(AdmittedFile {
                kind: file.kind,
                relative_path: file.relative_path.clone(),
                canonical_path: path,
                sha256: file.sha256,
                stable_identity,
            });
        }
        if dispatcher_count != 1 || target_count != 1 {
            return Err(AdmissionError::InvalidFileSet);
        }

        Ok(AdmittedBundle {
            load_root: self.load_root.clone(),
            contract_sha256: approval.contract_sha256,
            bundle_descriptor_sha256: approval.bundle_descriptor_sha256,
            files: admitted_files,
            operations,
        })
    }

    fn verify_compatibility(&self, observed: &Compatibility) -> Result<(), AdmissionError> {
        if observed.contract.identifier != self.compatibility.contract.identifier {
            return Err(AdmissionError::Compatibility("contract identifier"));
        }
        if observed.contract.major != self.compatibility.contract.major {
            return Err(AdmissionError::Compatibility("contract major"));
        }
        if observed.bundle.identifier != self.compatibility.bundle.identifier {
            return Err(AdmissionError::Compatibility("bundle identifier"));
        }
        if observed.bundle.major != self.compatibility.bundle.major {
            return Err(AdmissionError::Compatibility("bundle major"));
        }
        if observed.dispatcher_abi.identifier != self.compatibility.dispatcher_abi.identifier {
            return Err(AdmissionError::Compatibility("dispatcher ABI identifier"));
        }
        if observed.dispatcher_abi.major != self.compatibility.dispatcher_abi.major {
            return Err(AdmissionError::Compatibility("dispatcher ABI major"));
        }
        Ok(())
    }

    fn resolve_file(&self, relative_path: &str) -> Result<PathBuf, AdmissionError> {
        Ok(resolve_regular_file(&self.load_root, relative_path)?)
    }
}

#[must_use]
pub fn current_compatibility() -> Compatibility {
    Compatibility {
        contract: FormatVersion {
            identifier: String::from(CONTRACT_FORMAT_IDENTIFIER),
            major: CONTRACT_FORMAT_MAJOR,
        },
        bundle: FormatVersion {
            identifier: String::from(BUNDLE_FORMAT_IDENTIFIER),
            major: BUNDLE_FORMAT_MAJOR,
        },
        dispatcher_abi: FormatVersion {
            identifier: String::from(DISPATCHER_ABI_IDENTIFIER),
            major: DISPATCHER_ABI_MAJOR,
        },
    }
}

fn verify_compatibility_identifiers(value: &Compatibility) -> Result<(), AdmissionError> {
    verify_format_identifier(&value.contract.identifier)?;
    verify_format_identifier(&value.bundle.identifier)?;
    verify_format_identifier(&value.dispatcher_abi.identifier)
}

fn verify_format_identifier(value: &str) -> Result<(), AdmissionError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AdmissionError::InvalidFormatIdentifier);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use wvb_authz::{Grant, Role};

    const OPERATOR: ActorId = [1; 16];
    const CALLER: ActorId = [2; 16];

    fn compatibility() -> Compatibility {
        current_compatibility()
    }

    fn fixture() -> (
        tempfile::TempDir,
        OperatorAdmission,
        Vec<u8>,
        Vec<u8>,
        Registry,
    ) {
        let directory = tempdir().unwrap();
        fs::create_dir(directory.path().join("bin")).unwrap();
        fs::create_dir(directory.path().join("lib")).unwrap();
        fs::write(directory.path().join("bin/dispatcher.dll"), b"dispatcher").unwrap();
        fs::write(directory.path().join("bin/target.dll"), b"target").unwrap();
        fs::write(directory.path().join("lib/dependency.dll"), b"dependency").unwrap();
        let contract = b"frozen-contract".to_vec();
        let descriptor = b"frozen-bundle".to_vec();
        let approval = OperatorAdmission {
            compatibility: compatibility(),
            contract_sha256: sha256_bytes(&contract),
            bundle_descriptor_sha256: sha256_bytes(&descriptor),
            files: vec![
                BundleFile {
                    kind: BundleFileKind::Dispatcher,
                    relative_path: String::from("bin/dispatcher.dll"),
                    sha256: sha256_bytes(b"dispatcher"),
                },
                BundleFile {
                    kind: BundleFileKind::Target,
                    relative_path: String::from("bin/target.dll"),
                    sha256: sha256_bytes(b"target"),
                },
                BundleFile {
                    kind: BundleFileKind::Dependency,
                    relative_path: String::from("lib/dependency.dll"),
                    sha256: sha256_bytes(b"dependency"),
                },
            ],
            operations: vec![OperationAdmission {
                operation_id: 7,
                request_schema_id: 0x3000_0007,
                response_schema_id: 0x3000_0008,
            }],
        };
        let mut registry = Registry::default();
        registry.register(OPERATOR, [3; 32]).unwrap();
        registry.register(CALLER, [4; 32]).unwrap();
        registry
            .grant(
                OPERATOR,
                Grant {
                    role: Role::AdapterAdmin,
                    adapter_hash: Some(approval.contract_sha256),
                    operation_id: None,
                    expires_at_unix_ms: None,
                },
            )
            .unwrap();
        (directory, approval, contract, descriptor, registry)
    }

    #[test]
    fn operator_admission_does_not_grant_invocation() {
        let (directory, approval, contract, descriptor, mut registry) = fixture();
        let engine = AdmissionEngine::new(directory.path()).unwrap();
        let bundle = engine
            .admit(
                &registry,
                OPERATOR,
                1,
                &approval,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            )
            .unwrap();
        assert!(matches!(
            bundle.authorize_operation(&registry, CALLER, 7, 1),
            Err(AdmissionError::Authorization(AuthorizationError::Denied))
        ));
        registry
            .grant(
                CALLER,
                Grant {
                    role: Role::Invoke,
                    adapter_hash: Some(approval.contract_sha256),
                    operation_id: Some(7),
                    expires_at_unix_ms: None,
                },
            )
            .unwrap();
        bundle.authorize_operation(&registry, CALLER, 7, 1).unwrap();
        assert_eq!(
            bundle.operation(7),
            Some(OperationAdmission {
                operation_id: 7,
                request_schema_id: 0x3000_0007,
                response_schema_id: 0x3000_0008,
            })
        );
        assert!(matches!(
            bundle.authorize_operation(&registry, CALLER, 8, 1),
            Err(AdmissionError::OperationNotInBundle)
        ));
    }

    #[test]
    fn admission_requires_exact_active_adapter_admin_grant() {
        let (directory, approval, contract, descriptor, _) = fixture();
        let engine = AdmissionEngine::new(directory.path()).unwrap();
        for grant in [
            Grant {
                role: Role::AdapterAdmin,
                adapter_hash: None,
                operation_id: None,
                expires_at_unix_ms: None,
            },
            Grant {
                role: Role::AdapterAdmin,
                adapter_hash: Some([9; 32]),
                operation_id: None,
                expires_at_unix_ms: None,
            },
            Grant {
                role: Role::AdapterAdmin,
                adapter_hash: Some(approval.contract_sha256),
                operation_id: None,
                expires_at_unix_ms: Some(1),
            },
        ] {
            let mut registry = Registry::default();
            registry.register(OPERATOR, [3; 32]).unwrap();
            registry.grant(OPERATOR, grant).unwrap();
            assert!(matches!(
                engine.admit(
                    &registry,
                    OPERATOR,
                    1,
                    &approval,
                    FrozenInputs {
                        contract: &contract,
                        bundle_descriptor: &descriptor,
                    },
                ),
                Err(AdmissionError::Authorization(AuthorizationError::Denied))
            ));
        }
    }

    #[test]
    fn invocation_requires_exact_contract_and_operation_grant() {
        let (directory, approval, contract, descriptor, registry) = fixture();
        let engine = AdmissionEngine::new(directory.path()).unwrap();
        let bundle = engine
            .admit(
                &registry,
                OPERATOR,
                1,
                &approval,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            )
            .unwrap();
        for grant in [
            Grant {
                role: Role::Invoke,
                adapter_hash: None,
                operation_id: None,
                expires_at_unix_ms: None,
            },
            Grant {
                role: Role::Invoke,
                adapter_hash: Some([9; 32]),
                operation_id: Some(7),
                expires_at_unix_ms: None,
            },
            Grant {
                role: Role::Invoke,
                adapter_hash: Some(approval.contract_sha256),
                operation_id: Some(8),
                expires_at_unix_ms: None,
            },
        ] {
            let mut registry = Registry::default();
            registry.register(CALLER, [4; 32]).unwrap();
            registry.grant(CALLER, grant).unwrap();
            assert!(matches!(
                bundle.authorize_operation(&registry, CALLER, 7, 1),
                Err(AdmissionError::Authorization(AuthorizationError::Denied))
            ));
        }
    }

    #[test]
    fn admission_rejects_hash_and_abi_mismatches() {
        let (directory, mut approval, contract, descriptor, registry) = fixture();
        let engine = AdmissionEngine::new(directory.path()).unwrap();
        approval.compatibility.dispatcher_abi.major += 1;
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &approval,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            ),
            Err(AdmissionError::Compatibility("dispatcher ABI major"))
        ));
        approval.compatibility = compatibility();
        approval.files[0].sha256 = [9; 32];
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &approval,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            ),
            Err(AdmissionError::HashMismatch(_))
        ));
    }

    #[test]
    fn admission_rejects_every_incompatible_format() {
        let (directory, mut approval, contract, descriptor, registry) = fixture();
        let engine = AdmissionEngine::new(directory.path()).unwrap();
        let cases = [
            (
                "contract identifier",
                Compatibility {
                    contract: FormatVersion {
                        identifier: String::from("other.contract"),
                        ..compatibility().contract
                    },
                    ..compatibility()
                },
            ),
            (
                "contract major",
                Compatibility {
                    contract: FormatVersion {
                        major: 4,
                        ..compatibility().contract
                    },
                    ..compatibility()
                },
            ),
            (
                "bundle identifier",
                Compatibility {
                    bundle: FormatVersion {
                        identifier: String::from("other.bundle"),
                        ..compatibility().bundle
                    },
                    ..compatibility()
                },
            ),
            (
                "bundle major",
                Compatibility {
                    bundle: FormatVersion {
                        major: 2,
                        ..compatibility().bundle
                    },
                    ..compatibility()
                },
            ),
            (
                "dispatcher ABI identifier",
                Compatibility {
                    dispatcher_abi: FormatVersion {
                        identifier: String::from("other.dispatch"),
                        ..compatibility().dispatcher_abi
                    },
                    ..compatibility()
                },
            ),
        ];
        for (expected, observed) in cases {
            approval.compatibility = observed;
            assert!(matches!(
                engine.admit(
                    &registry,
                    OPERATOR,
                    1,
                    &approval,
                    FrozenInputs {
                        contract: &contract,
                        bundle_descriptor: &descriptor,
                    },
                ),
                Err(AdmissionError::Compatibility(actual)) if actual == expected
            ));
        }
    }

    #[test]
    fn admission_rejects_contract_and_descriptor_hash_mismatches() {
        let (directory, approval, contract, descriptor, registry) = fixture();
        let engine = AdmissionEngine::new(directory.path()).unwrap();
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &approval,
                FrozenInputs {
                    contract: b"changed",
                    bundle_descriptor: &descriptor,
                },
            ),
            Err(AdmissionError::ContractHashMismatch)
        ));
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &approval,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: b"changed",
                },
            ),
            Err(AdmissionError::BundleDescriptorHashMismatch)
        ));
    }

    #[test]
    fn admission_rejects_path_traversal_and_case_collisions() {
        let (directory, mut approval, contract, descriptor, registry) = fixture();
        let engine = AdmissionEngine::new(directory.path()).unwrap();
        approval.files[0].relative_path = String::from("../dispatcher.dll");
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &approval,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            ),
            Err(AdmissionError::InvalidPath(_))
        ));
        approval.files[0].relative_path = String::from("bin/dispatcher.dll");
        approval.files.push(BundleFile {
            kind: BundleFileKind::Dependency,
            relative_path: String::from("BIN/DISPATCHER.DLL"),
            sha256: approval.files[0].sha256,
        });
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &approval,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            ),
            Err(AdmissionError::DuplicatePath(_))
        ));
    }

    #[test]
    fn admission_rejects_all_prohibited_path_forms() {
        let (directory, mut approval, contract, descriptor, registry) = fixture();
        let engine = AdmissionEngine::new(directory.path()).unwrap();
        for path in [
            "",
            "/absolute.dll",
            "C:/drive.dll",
            "\\\\server\\share.dll",
            "bin\\dispatcher.dll",
            "bin/./dispatcher.dll",
            "bin/../dispatcher.dll",
            "bin//dispatcher.dll",
            "bin/dispatcher.dll/",
            "bin/dispat cher.dll",
        ] {
            approval.files[0].relative_path = String::from(path);
            assert!(matches!(
                engine.admit(
                    &registry,
                    OPERATOR,
                    1,
                    &approval,
                    FrozenInputs {
                        contract: &contract,
                        bundle_descriptor: &descriptor,
                    },
                ),
                Err(AdmissionError::InvalidPath(_))
            ));
        }
    }

    #[test]
    fn admission_rejects_invalid_file_and_operation_sets() {
        let (directory, approval, contract, descriptor, registry) = fixture();
        let engine = AdmissionEngine::new(directory.path()).unwrap();

        let mut value = approval.clone();
        value
            .files
            .retain(|file| file.kind != BundleFileKind::Target);
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &value,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            ),
            Err(AdmissionError::InvalidFileSet)
        ));

        let mut value = approval.clone();
        value.files[2].kind = BundleFileKind::Dispatcher;
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &value,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            ),
            Err(AdmissionError::InvalidFileSet)
        ));

        let mut value = approval.clone();
        value.operations.clear();
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &value,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            ),
            Err(AdmissionError::EmptyOperations)
        ));

        let mut value = approval.clone();
        value.operations.push(value.operations[0]);
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &value,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            ),
            Err(AdmissionError::DuplicateOperation(7))
        ));
    }

    #[test]
    fn admission_enforces_resource_bounds() {
        let (directory, approval, contract, descriptor, registry) = fixture();
        let engine = AdmissionEngine::new(directory.path()).unwrap();

        let mut value = approval.clone();
        value.files = vec![value.files[0].clone(); MAX_FILES + 1];
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &value,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            ),
            Err(AdmissionError::FileBoundExceeded)
        ));

        let mut value = approval.clone();
        value.operations = (0..=MAX_OPERATIONS)
            .map(|id| {
                let operation_id = u32::try_from(id + 1).unwrap();
                OperationAdmission {
                    operation_id,
                    request_schema_id: operation_id,
                    response_schema_id: operation_id,
                }
            })
            .collect();
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &value,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            ),
            Err(AdmissionError::OperationBoundExceeded)
        ));

        let oversized = vec![0_u8; MAX_DESCRIPTOR_BYTES + 1];
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &approval,
                FrozenInputs {
                    contract: &oversized,
                    bundle_descriptor: &descriptor,
                },
            ),
            Err(AdmissionError::DescriptorBoundExceeded)
        ));
    }

    #[test]
    fn admitted_files_are_reverified_before_load() {
        let (directory, approval, contract, descriptor, registry) = fixture();
        let engine = AdmissionEngine::new(directory.path()).unwrap();
        let bundle = engine
            .admit(
                &registry,
                OPERATOR,
                1,
                &approval,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            )
            .unwrap();
        fs::write(directory.path().join("bin/target.dll"), b"changed").unwrap();
        assert!(matches!(
            bundle.reverify_files(),
            Err(AdmissionError::HashMismatch(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn admission_rejects_symlinked_bundle_files() {
        use std::os::unix::fs::symlink;

        let (directory, approval, contract, descriptor, registry) = fixture();
        fs::remove_file(directory.path().join("bin/target.dll")).unwrap();
        fs::write(directory.path().join("outside.dll"), b"target").unwrap();
        symlink(
            directory.path().join("outside.dll"),
            directory.path().join("bin/target.dll"),
        )
        .unwrap();
        let engine = AdmissionEngine::new(directory.path()).unwrap();
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &approval,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            ),
            Err(AdmissionError::SymlinkOrReparsePoint(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn admission_rejects_hard_linked_bundle_identities() {
        let (directory, mut approval, contract, descriptor, registry) = fixture();
        fs::remove_file(directory.path().join("bin/target.dll")).unwrap();
        fs::hard_link(
            directory.path().join("bin/dispatcher.dll"),
            directory.path().join("bin/target.dll"),
        )
        .unwrap();
        approval.files[1].sha256 = approval.files[0].sha256;
        let engine = AdmissionEngine::new(directory.path()).unwrap();
        assert!(matches!(
            engine.admit(
                &registry,
                OPERATOR,
                1,
                &approval,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            ),
            Err(AdmissionError::InvalidFileSet)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn reverify_rejects_replaced_parent_symlink() {
        use std::os::unix::fs::symlink;

        let (directory, approval, contract, descriptor, registry) = fixture();
        let engine = AdmissionEngine::new(directory.path()).unwrap();
        let bundle = engine
            .admit(
                &registry,
                OPERATOR,
                1,
                &approval,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor,
                },
            )
            .unwrap();
        fs::rename(
            directory.path().join("bin"),
            directory.path().join("bin-original"),
        )
        .unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("target.dll"), b"target").unwrap();
        fs::write(outside.path().join("dispatcher.dll"), b"dispatcher").unwrap();
        symlink(outside.path(), directory.path().join("bin")).unwrap();
        assert!(matches!(
            bundle.reverify_files(),
            Err(AdmissionError::SymlinkOrReparsePoint(_))
        ));
    }
}
