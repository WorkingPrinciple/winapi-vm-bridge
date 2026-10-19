use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use wvb_authz::{ActorId, AuthorizationError, Registry};
use wvb_integrity::{
    resolve_regular_file, sha256_bytes, sha256_file, stable_file_identity,
    validate_portable_relative_path,
};
use wvb_receipt::RuntimeReceipt;

use crate::{
    AdmissionEngine, ChallengeSequence, Custody, FileIdentity, OperationAdmission, SideEffects,
};

pub const WHINY_SCALAR_ARTIFACTS_REVISION: &str = "f968659d4cee38bb30595e776e796cba45a611cc";
pub const WHINY_SCALAR_ARTIFACTS_MANIFEST_SHA256: [u8; 32] = [
    0x6b, 0xd6, 0xc8, 0xee, 0xe2, 0xe5, 0x5b, 0xc3, 0x0a, 0x8b, 0xba, 0xa7, 0x54, 0xa3, 0xb1, 0xfc,
    0xd7, 0xeb, 0x4b, 0xd2, 0xe2, 0x40, 0x2e, 0xac, 0x93, 0x1f, 0x41, 0x0e, 0x7d, 0x41, 0x96, 0xe8,
];
pub const WHINY_SCALAR_AUTHORITY_REGISTRY_SHA256: [u8; 32] = [
    0xb3, 0x9d, 0x8c, 0x49, 0xda, 0x63, 0x62, 0x62, 0xf1, 0x8a, 0xb1, 0x90, 0x58, 0xc6, 0x55, 0x51,
    0x9c, 0x60, 0xcf, 0x87, 0x97, 0xd2, 0x6d, 0xe8, 0x2d, 0xd9, 0x37, 0x78, 0xbf, 0xc3, 0x02, 0x98,
];
pub const WHINY_SCALAR_SOURCE_EVIDENCE_SHA256: [u8; 32] = [
    0x2f, 0xb9, 0x0b, 0x21, 0x92, 0x98, 0x0f, 0x8b, 0x87, 0xf2, 0x38, 0x6a, 0x1e, 0x70, 0x09, 0xb7,
    0xbf, 0xf5, 0xd0, 0x89, 0xe1, 0x21, 0xfd, 0xea, 0xd0, 0x38, 0x82, 0xa4, 0xf7, 0xd5, 0x47, 0x34,
];

const MANIFEST_SCHEMA: &str = "whiny.scalar-test-artifacts.v1";
const REGISTRY_SCHEMA: &str = "whiny.scalar-test-authority-registry.v1";
const HANDOFF_SCHEMA: &str = "whiny.scalar-frozen-adapter-handoff.v1";
const EXPECTATIONS_SCHEMA: &str = "whiny.scalar-correlated-runtime-expectations.v1";
const ADMISSION_SCHEMA: &str = "whiny.scalar-correlated-runtime-admission.v1";
const BUILD_RECEIPT_SCHEMA: &str = "whiny.scalar-artifact-build-receipt.v1";
const TRUST_POLICY_SCHEMA: &str = "whiny.runtime-receipt.trust-policy.v1";
const SOURCE_REVISION: &str = "870da868f3d3d48f1da1a36123a9aaf1a6435e53";
const ARTIFACT_IMPORT_REVISION: &str = "ee5dfe35a9c16d9e80b7952a05521373bf997c0f";
const VALIDATOR_PACKAGE_SHA256: &str =
    "e95244e9056997a1887052744c1e235403f8e560cc2fa80d23ad14a4094c7a6f";
const VALIDATOR_MANIFEST_SHA256: &str =
    "11dd56f11e9f46b5099fd8b842a3b4455298698d570706fb267f329598da2731";
const REPLAY_STATE_SHA256: &str =
    "c6269edc801213a0bdc8ccac590f6e419b7aad6a08671d2d25bc56d59e85b56a";
const CONSUMER_REPOSITORY: &str = "https://github.com/dragoshont/winapi-vm-bridge";
const CONSUMER_REVISION: &str = "57ccb935a011efc72c9585048c85bd615f6b73b7";
const QUALIFICATION: &str = "development-only";
const SUPPORT_CLAIM: &str = "none";
const AUTHORIZATION_STATE: &str = "test-execution-authorized";
const EXTERNAL_INVOKE_GRANT: &str = "bridge-owned-invoke-required";
const REGISTRY_ID: &str = "whiny.scalar_test_authority";
const MANIFEST_PATH: &str = "scalar-test-artifacts.json";
const ACCEPTANCE_COMMAND: [&str; 4] = [
    "whiny",
    "scalar-test-artifacts-validate",
    ".",
    "scalar-test-artifacts.json",
];
const CONSUMER_FLOW: [&str; 4] = [
    "AdmissionEngine::bind_frozen_handoff",
    "bind_correlated_evidence",
    "external Invoke",
    "wvb-runtime complete-receipt",
];
const FORBIDDEN_AUTHORITY_KEYS: [&str; 18] = [
    "actor",
    "actors",
    "role",
    "roles",
    "grant",
    "grants",
    "acl",
    "acls",
    "credential",
    "credentials",
    "password",
    "private_key",
    "private_state",
    "secret",
    "secrets",
    "token",
    "tokens",
    "trusted",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalarTestAuthorityApproval {
    pub producer_revision: String,
    pub manifest_sha256: [u8; 32],
    pub registry_sha256: [u8; 32],
}

impl Default for ScalarTestAuthorityApproval {
    fn default() -> Self {
        Self {
            producer_revision: String::from(WHINY_SCALAR_ARTIFACTS_REVISION),
            manifest_sha256: WHINY_SCALAR_ARTIFACTS_MANIFEST_SHA256,
            registry_sha256: WHINY_SCALAR_AUTHORITY_REGISTRY_SHA256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarProfile {
    Native,
    Managed,
}

impl ScalarProfile {
    const fn name(self) -> &'static str {
        match self {
            Self::Native => "native-scalar",
            Self::Managed => "managed-scalar",
        }
    }

    const fn profile_id(self) -> &'static str {
        match self {
            Self::Native => "native-c-scalar-x64-v1",
            Self::Managed => "dotnet-static-scalar-net8-x64-v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalarTestExecutionAuthorization {
    contract_sha256: [u8; 32],
    bundle_sha256: [u8; 32],
    operation: OperationAdmission,
    authorization_state: &'static str,
    qualification: &'static str,
}

impl ScalarTestExecutionAuthorization {
    #[must_use]
    pub fn contract_sha256(&self) -> [u8; 32] {
        self.contract_sha256
    }

    #[must_use]
    pub fn bundle_sha256(&self) -> [u8; 32] {
        self.bundle_sha256
    }

    #[must_use]
    pub fn operation(&self) -> OperationAdmission {
        self.operation
    }

    #[must_use]
    pub fn authorization_state(&self) -> &str {
        self.authorization_state
    }

    #[must_use]
    pub fn qualification(&self) -> &str {
        self.qualification
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundScalarTestProfile {
    profile: ScalarProfile,
    entry_id: String,
    handoff_id: String,
    contract_sha256: [u8; 32],
    bundle_sha256: [u8; 32],
    operation: OperationAdmission,
    candidate: FileIdentity,
    receipt_sha256: [u8; 32],
    policy_sha256: [u8; 32],
    replay_state_sha256: [u8; 32],
    authorization_receipt_sha256: [u8; 32],
    challenge_sha256: [u8; 32],
    sequence: u64,
    key_id: [u8; 32],
}

impl BoundScalarTestProfile {
    #[must_use]
    pub fn profile(&self) -> ScalarProfile {
        self.profile
    }

    #[must_use]
    pub fn entry_id(&self) -> &str {
        &self.entry_id
    }

    #[must_use]
    pub fn handoff_id(&self) -> &str {
        &self.handoff_id
    }

    #[must_use]
    pub fn operation(&self) -> OperationAdmission {
        self.operation
    }

    #[must_use]
    pub fn contract_sha256(&self) -> [u8; 32] {
        self.contract_sha256
    }

    #[must_use]
    pub fn bundle_sha256(&self) -> [u8; 32] {
        self.bundle_sha256
    }

    #[must_use]
    pub fn candidate(&self) -> &FileIdentity {
        &self.candidate
    }

    #[must_use]
    pub fn receipt_sha256(&self) -> [u8; 32] {
        self.receipt_sha256
    }

    #[must_use]
    pub fn policy_sha256(&self) -> [u8; 32] {
        self.policy_sha256
    }

    #[must_use]
    pub fn replay_state_sha256(&self) -> [u8; 32] {
        self.replay_state_sha256
    }

    #[must_use]
    pub fn authorization_receipt_sha256(&self) -> [u8; 32] {
        self.authorization_receipt_sha256
    }

    #[must_use]
    pub fn challenge_sha256(&self) -> [u8; 32] {
        self.challenge_sha256
    }

    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    #[must_use]
    pub const fn qualification(&self) -> &'static str {
        QUALIFICATION
    }

    #[must_use]
    pub const fn support_claim(&self) -> &'static str {
        SUPPORT_CLAIM
    }

    #[must_use]
    pub const fn runtime_support(&self) -> bool {
        false
    }

    pub fn authorize_test_execution(
        &self,
        registry: &Registry,
        actor_id: ActorId,
        now_unix_ms: u64,
    ) -> Result<ScalarTestExecutionAuthorization, ScalarTestAuthorityError> {
        registry
            .authorize_invoke(
                actor_id,
                self.contract_sha256,
                self.operation.operation_id,
                now_unix_ms,
            )
            .map_err(ScalarTestAuthorityError::Authorization)?;
        Ok(ScalarTestExecutionAuthorization {
            contract_sha256: self.contract_sha256,
            bundle_sha256: self.bundle_sha256,
            operation: self.operation,
            authorization_state: AUTHORIZATION_STATE,
            qualification: QUALIFICATION,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundScalarTestAuthority {
    manifest_sha256: [u8; 32],
    registry_sha256: [u8; 32],
    source_evidence_sha256: [u8; 32],
    source_replay_state_sha256: [u8; 32],
    profiles: Vec<BoundScalarTestProfile>,
    bound_files: Vec<ScalarBoundFile>,
    load_root: PathBuf,
}

impl BoundScalarTestAuthority {
    #[must_use]
    pub fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }

    #[must_use]
    pub fn registry_sha256(&self) -> [u8; 32] {
        self.registry_sha256
    }

    #[must_use]
    pub fn source_evidence_sha256(&self) -> [u8; 32] {
        self.source_evidence_sha256
    }

    #[must_use]
    pub fn source_replay_state_sha256(&self) -> [u8; 32] {
        self.source_replay_state_sha256
    }

    #[must_use]
    pub fn profile(&self, profile: ScalarProfile) -> Option<&BoundScalarTestProfile> {
        self.profiles
            .iter()
            .find(|candidate| candidate.profile == profile)
    }

    pub fn reverify_files(&self) -> Result<(), ScalarTestAuthorityError> {
        for file in &self.bound_files {
            let resolved = resolve_regular_file(&self.load_root, &file.path)
                .map_err(|_| ScalarTestAuthorityError::Binding("bound file path"))?;
            if resolved != file.canonical_path
                || sha256_file(&resolved)? != file.sha256
                || stable_file_identity(&resolved)? != file.stable_identity
            {
                return Err(ScalarTestAuthorityError::Binding("bound file identity"));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ScalarTestAuthorityError {
    Authorization(AuthorizationError),
    Invalid(&'static str),
    Binding(&'static str),
    ProducerRevisionMismatch,
    Receipt(wvb_receipt::ReceiptError),
    Io(std::io::Error),
    Integrity(wvb_integrity::IntegrityError),
}

impl std::fmt::Display for ScalarTestAuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ScalarTestAuthorityError {}

impl From<std::io::Error> for ScalarTestAuthorityError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<wvb_integrity::IntegrityError> for ScalarTestAuthorityError {
    fn from(value: wvb_integrity::IntegrityError) -> Self {
        Self::Integrity(value)
    }
}

impl From<wvb_receipt::ReceiptError> for ScalarTestAuthorityError {
    fn from(value: wvb_receipt::ReceiptError) -> Self {
        Self::Receipt(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScalarBoundFile {
    path: String,
    canonical_path: PathBuf,
    sha256: [u8; 32],
    stable_identity: wvb_integrity::StableFileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Consumer {
    repository: String,
    revision: String,
    flow: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestPolicy {
    authorization_state: String,
    qualification: String,
    support_claim: String,
    runtime_support: bool,
    external_invoke_grant: String,
    challenge_sequence: ChallengeSequence,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactManifest {
    schema: String,
    source_revision: String,
    consumer: Consumer,
    source_evidence: SourceEvidenceIdentity,
    qualification: String,
    support_claim: String,
    runtime_support: bool,
    authorization_state: String,
    external_invoke_grant: String,
    acceptance_command: Vec<String>,
    trust_policy: FileDigest,
    source_replay_state_sha256: String,
    registry: FileDigest,
    profiles: Vec<ManifestProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDigest {
    path: String,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestProfile {
    name: String,
    handoff: FileDigest,
    expectations: FileDigest,
    admission: FileDigest,
    runtime_receipt: FileDigest,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityRegistry {
    schema: String,
    registry_id: String,
    consumer: Consumer,
    source_evidence: SourceEvidenceIdentity,
    entries: Vec<AuthorityEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEvidenceIdentity {
    path: String,
    sha256: String,
    validator_package_sha256: String,
    validator_manifest_sha256: String,
    artifact_import_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityEntry {
    entry_id: String,
    profile_id: String,
    provider: FileIdentity,
    candidate: FileIdentity,
    operation: PublicOperation,
    side_effects: SideEffects,
    policy: TestPolicy,
    source_revision: String,
    custody: Custody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicOperation {
    id: u32,
    request_schema_id: u32,
    response_schema_id: u32,
}

impl From<PublicOperation> for OperationAdmission {
    fn from(value: PublicOperation) -> Self {
        Self {
            operation_id: value.id,
            request_schema_id: value.request_schema_id,
            response_schema_id: value.response_schema_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryIdentity {
    path: String,
    sha256: String,
    registry_id: String,
    entry_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorrelatedRegistryIdentity {
    sha256: String,
    registry_id: String,
    entry_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffIdentity {
    sha256: String,
    handoff_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractIdentity {
    path: String,
    file_sha256: String,
    canonical_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorrelatedContractIdentity {
    file_sha256: String,
    canonical_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScalarHandoff {
    schema: String,
    handoff_id: String,
    consumer: Consumer,
    source_evidence: SourceEvidenceIdentity,
    registry: RegistryIdentity,
    contract: ContractIdentity,
    bundle: FileDigest,
    build_receipt: FileDigest,
    dispatcher: FileIdentity,
    provider: FileIdentity,
    candidate: FileIdentity,
    operation: PublicOperation,
    side_effects: SideEffects,
    policy: TestPolicy,
    acceptance_command: Vec<String>,
    source_revision: String,
    custody: Custody,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScalarExpectations {
    schema: String,
    correlation_id: String,
    consumer: Consumer,
    source_evidence: SourceEvidenceIdentity,
    registry: CorrelatedRegistryIdentity,
    handoff: HandoffIdentity,
    contract: CorrelatedContractIdentity,
    bundle_sha256: String,
    build_receipt_sha256: String,
    dispatcher: FileIdentity,
    provider: FileIdentity,
    candidate: FileIdentity,
    operation: PublicOperation,
    side_effects: SideEffects,
    policy: TestPolicy,
    runtime: RuntimeExpectations,
    acceptance_command: Vec<String>,
    source_revision: String,
    custody: Custody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeExpectations {
    policy_sha256: String,
    receipt_id: String,
    host_id: String,
    key_id: String,
    authorization_receipt_sha256: String,
    challenge_sha256: String,
    sequence: u64,
    request_sha256: String,
    expected_response_sha256: String,
    loaded_files: Vec<FileDigest>,
    cleanup: Cleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cleanup {
    status: String,
    diagnostics: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScalarAdmission {
    schema: String,
    correlation_id: String,
    consumer: Consumer,
    source_evidence: SourceEvidenceIdentity,
    expectations_sha256: String,
    receipt_sha256: String,
    registry: CorrelatedRegistryIdentity,
    handoff: HandoffIdentity,
    runtime: AdmittedRuntime,
    replay_binding: ReplayBinding,
    authorization_state: String,
    external_invoke_grant: String,
    evidence_admitted: bool,
    receipt_eligible: bool,
    qualification: String,
    support_claim: String,
    runtime_support: bool,
    source_revision: String,
    custody: Custody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmittedRuntime {
    receipt_id: String,
    host_id: String,
    key_id: String,
    authorization_receipt_sha256: String,
    challenge_sha256: String,
    sequence: u64,
    request_sha256: String,
    response_sha256: String,
    loaded_files: Vec<FileDigest>,
    status: String,
    cleanup: Cleanup,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayBinding {
    state_sha256: String,
    challenge_consumed: bool,
    sequence_current: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildReceipt {
    schema: String,
    command: Vec<String>,
    source_revision: String,
    profile_id: String,
    inputs: Vec<FileDigest>,
    bundle_sha256: String,
    determinism: Determinism,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Determinism {
    build_count: u32,
    rebuild_comparison: String,
}

#[derive(Debug, Deserialize)]
struct BundleBinding {
    schema: String,
    profile: String,
    contract: BundleContract,
    dispatcher: BundleFile,
    target: BundleFile,
    operations: Vec<PublicOperation>,
}

#[derive(Debug, Deserialize)]
struct BundleContract {
    format: String,
    path: String,
    file_sha256: String,
    canonical_sha256: String,
}

#[derive(Debug, Deserialize)]
struct BundleFile {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustPolicy {
    schema: String,
    scheme: String,
    signing_domain: String,
    source_policy_sha256: String,
    host_ids: Vec<String>,
    signers: Vec<TrustSigner>,
    historical_invalid_receipts: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustSigner {
    name: String,
    key_id: String,
    public_key_file: String,
    public_key_hex: String,
    scope: String,
    production_runtime_identity: bool,
    host_ids: Vec<String>,
    bundle_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEvidenceManifest {
    schema: String,
    source_revision: String,
    validator_package_sha256: String,
    validator_manifest_sha256: String,
    trust_policy_sha256: String,
    custody_artifacts: BTreeMap<String, String>,
    corrected_receipts: BTreeMap<String, String>,
    historical_invalid_receipts: BTreeMap<String, HistoricalInvalidReceipt>,
    assurance: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalInvalidReceipt {
    sha256: String,
    reason: String,
}

impl AdmissionEngine {
    pub fn bind_scalar_test_authority(
        &self,
        approval: &ScalarTestAuthorityApproval,
    ) -> Result<BoundScalarTestAuthority, ScalarTestAuthorityError> {
        if approval.producer_revision != WHINY_SCALAR_ARTIFACTS_REVISION {
            return Err(ScalarTestAuthorityError::ProducerRevisionMismatch);
        }
        if approval.manifest_sha256 != WHINY_SCALAR_ARTIFACTS_MANIFEST_SHA256
            || approval.registry_sha256 != WHINY_SCALAR_AUTHORITY_REGISTRY_SHA256
        {
            return Err(ScalarTestAuthorityError::Binding(
                "frozen scalar artifact pin",
            ));
        }
        let mut files = BTreeMap::new();
        let mut stable_identities = HashSet::new();
        let manifest_bytes = self.bind_scalar_file(
            &mut files,
            &mut stable_identities,
            MANIFEST_PATH,
            approval.manifest_sha256,
        )?;
        let manifest: ArtifactManifest = parse_exact(&manifest_bytes, "manifest")?;
        validate_manifest(&manifest)?;
        let registry_expected = decode_hash(&manifest.registry.sha256)?;
        if registry_expected != approval.registry_sha256 {
            return Err(ScalarTestAuthorityError::Binding("approved registry"));
        }
        let registry_bytes = self.bind_scalar_file(
            &mut files,
            &mut stable_identities,
            &manifest.registry.path,
            registry_expected,
        )?;
        let registry: AuthorityRegistry = parse_exact(&registry_bytes, "registry")?;
        validate_registry(&registry)?;
        if canonical_hash(&registry)? != approval.registry_sha256 {
            return Err(ScalarTestAuthorityError::Binding(
                "canonical registry identity",
            ));
        }
        if registry.source_evidence != manifest.source_evidence {
            return Err(ScalarTestAuthorityError::Binding(
                "registry source evidence",
            ));
        }

        let source_evidence_sha256 = decode_hash(&manifest.source_evidence.sha256)?;
        let source_evidence_bytes = self.bind_scalar_file(
            &mut files,
            &mut stable_identities,
            &manifest.source_evidence.path,
            source_evidence_sha256,
        )?;
        let source_evidence: SourceEvidenceManifest =
            parse_exact(&source_evidence_bytes, "source evidence manifest")?;
        validate_source_evidence_manifest(&source_evidence, &manifest)?;

        let policy_sha256 = decode_hash(&manifest.trust_policy.sha256)?;
        let policy_bytes = self.bind_scalar_file(
            &mut files,
            &mut stable_identities,
            &manifest.trust_policy.path,
            policy_sha256,
        )?;
        let policy: TrustPolicy = parse_exact(&policy_bytes, "trust policy")?;
        validate_trust_policy(&policy)?;

        let mut profiles = Vec::with_capacity(2);
        for profile_manifest in &manifest.profiles {
            let profile = match profile_manifest.name.as_str() {
                "native-scalar" => ScalarProfile::Native,
                "managed-scalar" => ScalarProfile::Managed,
                _ => return Err(ScalarTestAuthorityError::Invalid("scalar profile")),
            };
            profiles.push(self.bind_scalar_profile(
                &manifest,
                &registry,
                &policy,
                policy_sha256,
                profile,
                profile_manifest,
                &mut files,
                &mut stable_identities,
            )?);
        }
        profiles.sort_by_key(|profile| match profile.profile {
            ScalarProfile::Native => 0,
            ScalarProfile::Managed => 1,
        });
        if profiles.len() != 2
            || profiles[0].profile != ScalarProfile::Native
            || profiles[1].profile != ScalarProfile::Managed
        {
            return Err(ScalarTestAuthorityError::Invalid("scalar profile coverage"));
        }
        Ok(BoundScalarTestAuthority {
            manifest_sha256: approval.manifest_sha256,
            registry_sha256: approval.registry_sha256,
            source_evidence_sha256,
            source_replay_state_sha256: decode_hash(&manifest.source_replay_state_sha256)?,
            profiles,
            bound_files: files.into_values().collect(),
            load_root: self.load_root.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn bind_scalar_profile(
        &self,
        manifest: &ArtifactManifest,
        registry: &AuthorityRegistry,
        policy: &TrustPolicy,
        policy_sha256: [u8; 32],
        profile: ScalarProfile,
        profile_manifest: &ManifestProfile,
        files: &mut BTreeMap<String, ScalarBoundFile>,
        stable_identities: &mut HashSet<wvb_integrity::StableFileIdentity>,
    ) -> Result<BoundScalarTestProfile, ScalarTestAuthorityError> {
        if profile_manifest.name != profile.name() {
            return Err(ScalarTestAuthorityError::Binding("profile name"));
        }
        let handoff_bytes =
            self.bind_manifest_file(files, stable_identities, &profile_manifest.handoff)?;
        let handoff: ScalarHandoff = parse_exact(&handoff_bytes, "scalar handoff")?;
        validate_handoff(&handoff, profile)?;
        if handoff.source_evidence != registry.source_evidence {
            return Err(ScalarTestAuthorityError::Binding("handoff source evidence"));
        }
        let entry_hash = decode_hash(&handoff.registry.entry_sha256)?;
        let entries = registry
            .entries
            .iter()
            .filter(|entry| canonical_hash(*entry).ok() == Some(entry_hash))
            .collect::<Vec<_>>();
        let [entry] = entries.as_slice() else {
            return Err(ScalarTestAuthorityError::Binding("registry entry"));
        };
        bind_entry(entry, &handoff)?;

        let contract_bytes = self.bind_scalar_file(
            files,
            stable_identities,
            &handoff.contract.path,
            decode_hash(&handoff.contract.file_sha256)?,
        )?;
        if canonical_json_hash(&contract_bytes)? != decode_hash(&handoff.contract.canonical_sha256)?
        {
            return Err(ScalarTestAuthorityError::Binding(
                "canonical contract identity",
            ));
        }
        let bundle_bytes = self.bind_manifest_file(files, stable_identities, &handoff.bundle)?;
        let bundle: BundleBinding = parse_exact(&bundle_bytes, "bundle")?;
        bind_bundle(&bundle, &handoff, profile)?;
        let build_receipt_bytes =
            self.bind_manifest_file(files, stable_identities, &handoff.build_receipt)?;
        let build_receipt: BuildReceipt = parse_exact(&build_receipt_bytes, "build receipt")?;
        validate_build_receipt(&build_receipt, profile, &handoff.bundle.sha256)?;
        for input in &build_receipt.inputs {
            self.bind_manifest_file(files, stable_identities, input)?;
        }
        self.bind_scalar_file(
            files,
            stable_identities,
            &handoff.dispatcher.path,
            decode_hash(&handoff.dispatcher.sha256)?,
        )?;
        self.bind_scalar_file(
            files,
            stable_identities,
            &handoff.candidate.path,
            decode_hash(&handoff.candidate.sha256)?,
        )?;

        let expectations_bytes =
            self.bind_manifest_file(files, stable_identities, &profile_manifest.expectations)?;
        let expectations: ScalarExpectations =
            parse_exact(&expectations_bytes, "scalar expectations")?;
        bind_expectations(&expectations, &handoff, policy_sha256)?;

        let receipt_bytes =
            self.bind_manifest_file(files, stable_identities, &profile_manifest.runtime_receipt)?;
        require_receipt_shape(&receipt_bytes)?;
        let receipt: RuntimeReceipt = serde_json::from_slice(&receipt_bytes)
            .map_err(|_| ScalarTestAuthorityError::Invalid("runtime receipt"))?;
        if receipt.canonical_bytes()? != receipt_bytes {
            return Err(ScalarTestAuthorityError::Binding(
                "canonical runtime receipt",
            ));
        }
        verify_receipt(policy, &receipt, profile)?;
        bind_receipt(&receipt, &expectations, &handoff)?;

        let admission_bytes =
            self.bind_manifest_file(files, stable_identities, &profile_manifest.admission)?;
        let admission: ScalarAdmission = parse_exact(&admission_bytes, "scalar admission")?;
        bind_admission(
            &admission,
            &expectations,
            &handoff,
            &receipt,
            &manifest.source_replay_state_sha256,
        )?;

        Ok(BoundScalarTestProfile {
            profile,
            entry_id: entry.entry_id.clone(),
            handoff_id: handoff.handoff_id,
            contract_sha256: decode_hash(&handoff.contract.canonical_sha256)?,
            bundle_sha256: decode_hash(&handoff.bundle.sha256)?,
            operation: handoff.operation.into(),
            candidate: handoff.candidate,
            receipt_sha256: decode_hash(&admission.receipt_sha256)?,
            policy_sha256,
            replay_state_sha256: decode_hash(&admission.replay_binding.state_sha256)?,
            authorization_receipt_sha256: decode_hash(
                &admission.runtime.authorization_receipt_sha256,
            )?,
            challenge_sha256: decode_hash(&admission.runtime.challenge_sha256)?,
            sequence: admission.runtime.sequence,
            key_id: decode_hash(&admission.runtime.key_id)?,
        })
    }

    fn bind_manifest_file(
        &self,
        files: &mut BTreeMap<String, ScalarBoundFile>,
        stable_identities: &mut HashSet<wvb_integrity::StableFileIdentity>,
        identity: &FileDigest,
    ) -> Result<Vec<u8>, ScalarTestAuthorityError> {
        validate_digest(identity)?;
        self.bind_scalar_file(
            files,
            stable_identities,
            &identity.path,
            decode_hash(&identity.sha256)?,
        )
    }

    fn bind_scalar_file(
        &self,
        files: &mut BTreeMap<String, ScalarBoundFile>,
        stable_identities: &mut HashSet<wvb_integrity::StableFileIdentity>,
        path: &str,
        expected_sha256: [u8; 32],
    ) -> Result<Vec<u8>, ScalarTestAuthorityError> {
        validate_portable_relative_path(path)
            .map_err(|_| ScalarTestAuthorityError::Invalid("artifact path"))?;
        let folded = path.to_ascii_lowercase();
        if let Some(existing) = files.get(&folded) {
            if existing.path != path || existing.sha256 != expected_sha256 {
                return Err(ScalarTestAuthorityError::Binding(
                    "case-colliding artifact path",
                ));
            }
            let bytes = fs::read(&existing.canonical_path)?;
            if sha256_bytes(&bytes) != existing.sha256 {
                return Err(ScalarTestAuthorityError::Binding("artifact file identity"));
            }
            return Ok(bytes);
        }
        let canonical_path = resolve_regular_file(&self.load_root, path)
            .map_err(|_| ScalarTestAuthorityError::Binding("artifact path"))?;
        let bytes = fs::read(&canonical_path)?;
        let sha256 = sha256_bytes(&bytes);
        if sha256 != expected_sha256 {
            return Err(ScalarTestAuthorityError::Binding("artifact file identity"));
        }
        let stable_identity = stable_file_identity(&canonical_path)?;
        if !stable_identities.insert(stable_identity.clone()) {
            return Err(ScalarTestAuthorityError::Binding(
                "duplicate stable artifact identity",
            ));
        }
        files.insert(
            folded,
            ScalarBoundFile {
                path: path.to_owned(),
                canonical_path,
                sha256,
                stable_identity,
            },
        );
        Ok(bytes)
    }
}

fn validate_manifest(value: &ArtifactManifest) -> Result<(), ScalarTestAuthorityError> {
    validate_consumer(&value.consumer)?;
    validate_source_evidence_identity(&value.source_evidence)?;
    validate_acceptance_command(&value.acceptance_command)?;
    validate_digest(&value.trust_policy)?;
    validate_digest(&value.registry)?;
    if value.schema != MANIFEST_SCHEMA
        || value.source_revision != SOURCE_REVISION
        || value.source_replay_state_sha256 != REPLAY_STATE_SHA256
        || value.qualification != QUALIFICATION
        || value.support_claim != SUPPORT_CLAIM
        || value.runtime_support
        || value.authorization_state != AUTHORIZATION_STATE
        || value.external_invoke_grant != EXTERNAL_INVOKE_GRANT
        || value.profiles.len() != 2
    {
        return Err(ScalarTestAuthorityError::Invalid("artifact manifest"));
    }
    let names = value
        .profiles
        .iter()
        .map(|profile| profile.name.as_str())
        .collect::<BTreeSet<_>>();
    if names != BTreeSet::from(["managed-scalar", "native-scalar"]) {
        return Err(ScalarTestAuthorityError::Invalid(
            "artifact manifest profiles",
        ));
    }
    for profile in &value.profiles {
        validate_digest(&profile.handoff)?;
        validate_digest(&profile.expectations)?;
        validate_digest(&profile.admission)?;
        validate_digest(&profile.runtime_receipt)?;
    }
    Ok(())
}

fn validate_source_evidence_identity(
    value: &SourceEvidenceIdentity,
) -> Result<(), ScalarTestAuthorityError> {
    if value.path != "source-evidence-manifest.json"
        || decode_hash(&value.sha256)? != WHINY_SCALAR_SOURCE_EVIDENCE_SHA256
        || value.validator_package_sha256 != VALIDATOR_PACKAGE_SHA256
        || value.validator_manifest_sha256 != VALIDATOR_MANIFEST_SHA256
        || value.artifact_import_revision != ARTIFACT_IMPORT_REVISION
    {
        return Err(ScalarTestAuthorityError::Invalid(
            "source evidence identity",
        ));
    }
    Ok(())
}

fn validate_source_evidence_manifest(
    value: &SourceEvidenceManifest,
    manifest: &ArtifactManifest,
) -> Result<(), ScalarTestAuthorityError> {
    for hash in value
        .custody_artifacts
        .values()
        .chain(value.corrected_receipts.values())
    {
        decode_hash(hash)?;
    }
    let custody_names = value
        .custody_artifacts
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_custody_names = BTreeSet::from([
        "index.json",
        "managed-scalar-authorization.json",
        "managed-scalar-correlation.json",
        "managed-scalar-host-state.json",
        "managed-scalar-public-key-jcs.bin",
        "native-scalar-authorization.json",
        "native-scalar-correlation.json",
        "native-scalar-host-state.json",
        "native-scalar-public-key-jcs.bin",
        "whiny-trust-policy.json",
    ]);
    let expected_receipts = BTreeMap::from([
        (
            String::from("managed-scalar-receipt-jcs.json"),
            String::from("bcbb3a8086fca5aa705e9577bdc93e875ea51e76aca514314d54867814e458b6"),
        ),
        (
            String::from("native-scalar-receipt-jcs.json"),
            String::from("eb02139899a73b93f11bd273ee9a27c9d599b7e0723c0a2695eb91d39ce422cd"),
        ),
    ]);
    if value.schema != "whiny.vm-bridge-scalar-runtime-evidence.v1"
        || value.source_revision != SOURCE_REVISION
        || value.validator_package_sha256 != VALIDATOR_PACKAGE_SHA256
        || value.validator_manifest_sha256 != VALIDATOR_MANIFEST_SHA256
        || value.trust_policy_sha256 != manifest.trust_policy.sha256
        || custody_names != expected_custody_names
        || value.corrected_receipts != expected_receipts
        || value.assurance != "acceptance-only runtime identities; not production runtime keys"
        || value.historical_invalid_receipts.len() != 2
    {
        return Err(ScalarTestAuthorityError::Invalid(
            "source evidence manifest",
        ));
    }
    for (name, expected_hash) in [
        (
            "native-scalar-receipt.json",
            "f1a6b46da911033d5aef97570ead963fc9b6819d7c4051782db6a666ca8abad8",
        ),
        (
            "managed-scalar-receipt.json",
            "f2f3c804a25af272ad62bffaead6746f91730e21b33611147ec9cb09734f4380",
        ),
    ] {
        let receipt = value.historical_invalid_receipts.get(name).ok_or(
            ScalarTestAuthorityError::Invalid("historical receipt evidence"),
        )?;
        decode_hash(&receipt.sha256)?;
        if receipt.sha256 != expected_hash
            || receipt.reason != "legacy non-JCS signed payload; rejected by current ingestor"
        {
            return Err(ScalarTestAuthorityError::Invalid(
                "historical receipt evidence",
            ));
        }
    }
    Ok(())
}

fn validate_registry(value: &AuthorityRegistry) -> Result<(), ScalarTestAuthorityError> {
    validate_consumer(&value.consumer)?;
    validate_source_evidence_identity(&value.source_evidence)?;
    if value.schema != REGISTRY_SCHEMA
        || value.registry_id != REGISTRY_ID
        || value.entries.len() != 2
    {
        return Err(ScalarTestAuthorityError::Invalid("authority registry"));
    }
    let mut profiles = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut schema_ids = BTreeSet::new();
    for entry in &value.entries {
        let profile = match entry.profile_id.as_str() {
            "native-c-scalar-x64-v1" => ScalarProfile::Native,
            "dotnet-static-scalar-net8-x64-v1" => ScalarProfile::Managed,
            _ => return Err(ScalarTestAuthorityError::Invalid("registry profile")),
        };
        if !profiles.insert(profile.name()) {
            return Err(ScalarTestAuthorityError::Invalid(
                "registry profile collision",
            ));
        }
        validate_entry(entry, profile)?;
        for identity in [&entry.provider, &entry.candidate] {
            if !paths.insert(identity.path.to_ascii_lowercase()) {
                return Err(ScalarTestAuthorityError::Invalid("registry path collision"));
            }
        }
        for schema_id in [
            entry.operation.request_schema_id,
            entry.operation.response_schema_id,
        ] {
            if !schema_ids.insert(schema_id) {
                return Err(ScalarTestAuthorityError::Invalid(
                    "registry schema collision",
                ));
            }
        }
    }
    Ok(())
}

fn validate_entry(
    entry: &AuthorityEntry,
    profile: ScalarProfile,
) -> Result<(), ScalarTestAuthorityError> {
    validate_file_identity(&entry.provider)?;
    validate_file_identity(&entry.candidate)?;
    validate_operation(entry.operation)?;
    validate_side_effects(&entry.side_effects)?;
    validate_policy(&entry.policy)?;
    validate_custody(&entry.custody)?;
    if entry.entry_id.is_empty()
        || entry.profile_id != profile.profile_id()
        || entry.source_revision != SOURCE_REVISION
    {
        return Err(ScalarTestAuthorityError::Invalid("registry entry"));
    }
    Ok(())
}

fn validate_handoff(
    value: &ScalarHandoff,
    profile: ScalarProfile,
) -> Result<(), ScalarTestAuthorityError> {
    validate_consumer(&value.consumer)?;
    validate_source_evidence_identity(&value.source_evidence)?;
    validate_file_identity(&value.dispatcher)?;
    validate_file_identity(&value.provider)?;
    validate_file_identity(&value.candidate)?;
    validate_operation(value.operation)?;
    validate_side_effects(&value.side_effects)?;
    validate_policy(&value.policy)?;
    validate_acceptance_command(&value.acceptance_command)?;
    validate_custody(&value.custody)?;
    validate_digest(&value.bundle)?;
    validate_digest(&value.build_receipt)?;
    validate_portable_relative_path(&value.registry.path)
        .map_err(|_| ScalarTestAuthorityError::Invalid("registry path"))?;
    validate_portable_relative_path(&value.contract.path)
        .map_err(|_| ScalarTestAuthorityError::Invalid("contract path"))?;
    for hash in [
        &value.registry.sha256,
        &value.registry.entry_sha256,
        &value.contract.file_sha256,
        &value.contract.canonical_sha256,
    ] {
        decode_hash(hash)?;
    }
    if value.schema != HANDOFF_SCHEMA
        || value.handoff_id.is_empty()
        || value.registry.registry_id != REGISTRY_ID
        || value.registry.path != "authority-registry.json"
        || value.dispatcher != value.provider
        || value.source_revision != SOURCE_REVISION
        || !value.candidate.path.starts_with(profile.name())
        || !value.provider.path.starts_with(profile.name())
    {
        return Err(ScalarTestAuthorityError::Invalid("scalar handoff"));
    }
    Ok(())
}

fn bind_entry(
    entry: &AuthorityEntry,
    handoff: &ScalarHandoff,
) -> Result<(), ScalarTestAuthorityError> {
    if entry.provider != handoff.provider
        || entry.candidate != handoff.candidate
        || entry.operation != handoff.operation
        || entry.side_effects != handoff.side_effects
        || entry.policy != handoff.policy
        || entry.source_revision != handoff.source_revision
        || entry.custody != handoff.custody
    {
        return Err(ScalarTestAuthorityError::Binding("registry handoff chain"));
    }
    Ok(())
}

fn bind_bundle(
    bundle: &BundleBinding,
    handoff: &ScalarHandoff,
    profile: ScalarProfile,
) -> Result<(), ScalarTestAuthorityError> {
    let prefix = format!("{}/", profile.name());
    let contract_path = handoff
        .contract
        .path
        .strip_prefix(&prefix)
        .ok_or(ScalarTestAuthorityError::Binding("bundle contract path"))?;
    let dispatcher_path = handoff
        .dispatcher
        .path
        .strip_prefix(&prefix)
        .ok_or(ScalarTestAuthorityError::Binding("bundle dispatcher path"))?;
    let target_path = handoff
        .candidate
        .path
        .strip_prefix(&prefix)
        .ok_or(ScalarTestAuthorityError::Binding("bundle target path"))?;
    if bundle.schema != crate::BUNDLE_FORMAT_IDENTIFIER
        || bundle.profile != profile.profile_id()
        || bundle.contract.format != crate::CONTRACT_FORMAT_IDENTIFIER
        || bundle.contract.path != contract_path
        || bundle.contract.file_sha256 != handoff.contract.file_sha256
        || bundle.contract.canonical_sha256 != handoff.contract.canonical_sha256
        || bundle.dispatcher.path != dispatcher_path
        || bundle.dispatcher.sha256 != handoff.dispatcher.sha256
        || bundle.target.path != target_path
        || bundle.target.sha256 != handoff.candidate.sha256
        || bundle.operations.as_slice() != [handoff.operation]
    {
        return Err(ScalarTestAuthorityError::Binding("bundle handoff chain"));
    }
    Ok(())
}

fn validate_build_receipt(
    value: &BuildReceipt,
    profile: ScalarProfile,
    bundle_sha256: &str,
) -> Result<(), ScalarTestAuthorityError> {
    for input in &value.inputs {
        validate_digest(input)?;
    }
    if value.schema != BUILD_RECEIPT_SCHEMA
        || value.command
            != [
                "whiny",
                "scalar-test-artifacts-build",
                "--output",
                "SCALAR_TEST_ARTIFACT_ROOT",
            ]
        || value.source_revision != SOURCE_REVISION
        || value.profile_id != profile.profile_id()
        || value.inputs.is_empty()
        || value.bundle_sha256 != bundle_sha256
        || value.determinism
            != (Determinism {
                build_count: 2,
                rebuild_comparison: String::from("byte-for-byte"),
            })
    {
        return Err(ScalarTestAuthorityError::Invalid("build receipt"));
    }
    Ok(())
}

fn bind_expectations(
    value: &ScalarExpectations,
    handoff: &ScalarHandoff,
    policy_sha256: [u8; 32],
) -> Result<(), ScalarTestAuthorityError> {
    validate_consumer(&value.consumer)?;
    validate_source_evidence_identity(&value.source_evidence)?;
    validate_file_identity(&value.dispatcher)?;
    validate_file_identity(&value.provider)?;
    validate_file_identity(&value.candidate)?;
    validate_operation(value.operation)?;
    validate_side_effects(&value.side_effects)?;
    validate_policy(&value.policy)?;
    validate_acceptance_command(&value.acceptance_command)?;
    validate_custody(&value.custody)?;
    validate_runtime_expectations(&value.runtime, &value.candidate)?;
    if value.schema != EXPECTATIONS_SCHEMA
        || value.correlation_id.is_empty()
        || value.consumer != handoff.consumer
        || value.source_evidence != handoff.source_evidence
        || value.registry
            != (CorrelatedRegistryIdentity {
                sha256: handoff.registry.sha256.clone(),
                registry_id: handoff.registry.registry_id.clone(),
                entry_sha256: handoff.registry.entry_sha256.clone(),
            })
        || value.handoff
            != (HandoffIdentity {
                sha256: hex(canonical_hash(handoff)?),
                handoff_id: handoff.handoff_id.clone(),
            })
        || value.contract
            != (CorrelatedContractIdentity {
                file_sha256: handoff.contract.file_sha256.clone(),
                canonical_sha256: handoff.contract.canonical_sha256.clone(),
            })
        || value.bundle_sha256 != handoff.bundle.sha256
        || value.build_receipt_sha256 != handoff.build_receipt.sha256
        || value.dispatcher != handoff.dispatcher
        || value.provider != handoff.provider
        || value.candidate != handoff.candidate
        || value.operation != handoff.operation
        || value.side_effects != handoff.side_effects
        || value.policy != handoff.policy
        || value.acceptance_command != handoff.acceptance_command
        || value.source_revision != handoff.source_revision
        || value.custody != handoff.custody
        || decode_hash(&value.runtime.policy_sha256)? != policy_sha256
    {
        return Err(ScalarTestAuthorityError::Binding(
            "expectation handoff chain",
        ));
    }
    Ok(())
}

fn validate_runtime_expectations(
    value: &RuntimeExpectations,
    candidate: &FileIdentity,
) -> Result<(), ScalarTestAuthorityError> {
    if value.receipt_id.is_empty()
        || value.host_id.is_empty()
        || value.sequence == 0
        || value.loaded_files.is_empty()
        || !matches!(
            value.cleanup.status.as_str(),
            "verified" | "failed" | "not-required" | "unknown"
        )
    {
        return Err(ScalarTestAuthorityError::Invalid("runtime expectations"));
    }
    for hash in [
        &value.policy_sha256,
        &value.key_id,
        &value.authorization_receipt_sha256,
        &value.challenge_sha256,
        &value.request_sha256,
        &value.expected_response_sha256,
    ] {
        decode_hash(hash)?;
    }
    let mut paths = BTreeSet::new();
    for file in &value.loaded_files {
        validate_digest(file)?;
        if !paths.insert(file.path.to_ascii_lowercase()) {
            return Err(ScalarTestAuthorityError::Invalid(
                "loaded file path collision",
            ));
        }
    }
    if !value
        .loaded_files
        .iter()
        .any(|file| file.sha256 == candidate.sha256)
    {
        return Err(ScalarTestAuthorityError::Binding("candidate loaded file"));
    }
    Ok(())
}

fn validate_trust_policy(value: &TrustPolicy) -> Result<(), ScalarTestAuthorityError> {
    decode_hash(&value.source_policy_sha256)?;
    if value.schema != TRUST_POLICY_SCHEMA
        || value.scheme != "ed25519"
        || value.signing_domain != "whiny.runtime-receipt.v1\\u0000"
        || value.host_ids != ["crossover-XOdeLabRPC"]
        || value.historical_invalid_receipts
            != ["native-scalar-receipt.json", "managed-scalar-receipt.json"]
        || value.signers.len() != 2
    {
        return Err(ScalarTestAuthorityError::Invalid("trust policy"));
    }
    let mut names = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for signer in &value.signers {
        validate_portable_relative_path(&signer.public_key_file)
            .map_err(|_| ScalarTestAuthorityError::Invalid("public key path"))?;
        decode_hash(&signer.key_id)?;
        decode_hex::<32>(&signer.public_key_hex)?;
        decode_hash(&signer.bundle_sha256)?;
        if !names.insert(signer.name.as_str())
            || !keys.insert(signer.key_id.as_str())
            || signer.scope != "acceptance-only"
            || signer.production_runtime_identity
            || signer.host_ids != ["crossover-XOdeLabRPC"]
        {
            return Err(ScalarTestAuthorityError::Invalid("trust signer"));
        }
    }
    if names != BTreeSet::from(["managed-scalar", "native-scalar"]) {
        return Err(ScalarTestAuthorityError::Invalid("trust signer coverage"));
    }
    Ok(())
}

fn verify_receipt(
    policy: &TrustPolicy,
    receipt: &RuntimeReceipt,
    profile: ScalarProfile,
) -> Result<(), ScalarTestAuthorityError> {
    let signers = policy
        .signers
        .iter()
        .filter(|signer| signer.key_id == receipt.authentication.key_id)
        .collect::<Vec<_>>();
    let [signer] = signers.as_slice() else {
        return Err(ScalarTestAuthorityError::Binding("receipt signer"));
    };
    if signer.name != profile.name()
        || signer.bundle_sha256 != receipt.bundle_sha256
        || !signer
            .host_ids
            .iter()
            .any(|host| host == &receipt.runtime_identity.host_id)
    {
        return Err(ScalarTestAuthorityError::Binding("receipt policy"));
    }
    let public_key = decode_hex::<32>(&signer.public_key_hex)?;
    if sha256_bytes(&public_key) != decode_hash(&signer.key_id)? {
        return Err(ScalarTestAuthorityError::Binding(
            "receipt public key identity",
        ));
    }
    receipt.verify(&public_key)?;
    Ok(())
}

fn bind_receipt(
    receipt: &RuntimeReceipt,
    expectations: &ScalarExpectations,
    handoff: &ScalarHandoff,
) -> Result<(), ScalarTestAuthorityError> {
    let runtime = &expectations.runtime;
    let loaded_files = receipt
        .loaded_files
        .iter()
        .map(|file| FileDigest {
            path: file.path.clone(),
            sha256: file.sha256.clone(),
        })
        .collect::<Vec<_>>();
    let cleanup = Cleanup {
        status: receipt.cleanup.status.clone(),
        diagnostics: receipt.cleanup.diagnostics.clone(),
    };
    if receipt.receipt_id != runtime.receipt_id
        || receipt.bundle_sha256 != expectations.bundle_sha256
        || receipt.contract_sha256 != handoff.contract.canonical_sha256
        || receipt.dispatcher_abi != crate::DISPATCHER_ABI_IDENTIFIER
        || receipt.operation_id != handoff.operation.id
        || receipt.request_sha256 != runtime.request_sha256
        || receipt.response_sha256 != runtime.expected_response_sha256
        || receipt.runtime_identity.host_id != runtime.host_id
        || receipt.authentication.key_id != runtime.key_id
        || receipt.authorization_receipt_sha256 != runtime.authorization_receipt_sha256
        || receipt.challenge_sha256 != runtime.challenge_sha256
        || receipt.sequence != runtime.sequence
        || loaded_files != runtime.loaded_files
        || cleanup != runtime.cleanup
    {
        return Err(ScalarTestAuthorityError::Binding(
            "signed receipt expectations",
        ));
    }
    Ok(())
}

fn bind_admission(
    value: &ScalarAdmission,
    expectations: &ScalarExpectations,
    handoff: &ScalarHandoff,
    receipt: &RuntimeReceipt,
    replay_state_sha256: &str,
) -> Result<(), ScalarTestAuthorityError> {
    validate_consumer(&value.consumer)?;
    validate_source_evidence_identity(&value.source_evidence)?;
    validate_custody(&value.custody)?;
    let expected_runtime = AdmittedRuntime {
        receipt_id: receipt.receipt_id.clone(),
        host_id: receipt.runtime_identity.host_id.clone(),
        key_id: receipt.authentication.key_id.clone(),
        authorization_receipt_sha256: receipt.authorization_receipt_sha256.clone(),
        challenge_sha256: receipt.challenge_sha256.clone(),
        sequence: receipt.sequence,
        request_sha256: receipt.request_sha256.clone(),
        response_sha256: receipt.response_sha256.clone(),
        loaded_files: receipt
            .loaded_files
            .iter()
            .map(|file| FileDigest {
                path: file.path.clone(),
                sha256: file.sha256.clone(),
            })
            .collect(),
        status: receipt.status.clone(),
        cleanup: Cleanup {
            status: receipt.cleanup.status.clone(),
            diagnostics: receipt.cleanup.diagnostics.clone(),
        },
    };
    if value.schema != ADMISSION_SCHEMA
        || value.correlation_id != expectations.correlation_id
        || value.consumer != expectations.consumer
        || value.source_evidence != expectations.source_evidence
        || value.expectations_sha256 != hex(canonical_hash(expectations)?)
        || value.receipt_sha256 != hex(sha256_bytes(&receipt.canonical_bytes()?))
        || value.registry != expectations.registry
        || value.handoff != expectations.handoff
        || value.runtime != expected_runtime
        || value.replay_binding.state_sha256 != REPLAY_STATE_SHA256
        || value.replay_binding.state_sha256 != replay_state_sha256
        || !value.replay_binding.challenge_consumed
        || !value.replay_binding.sequence_current
        || value.authorization_state != AUTHORIZATION_STATE
        || value.external_invoke_grant != EXTERNAL_INVOKE_GRANT
        || !value.evidence_admitted
        || value.receipt_eligible
            != (receipt.status == "ok"
                && matches!(receipt.cleanup.status.as_str(), "verified" | "not-required"))
        || value.qualification != QUALIFICATION
        || value.support_claim != SUPPORT_CLAIM
        || value.runtime_support
        || value.source_revision != SOURCE_REVISION
        || value.custody != handoff.custody
    {
        return Err(ScalarTestAuthorityError::Binding(
            "correlated scalar admission",
        ));
    }
    decode_hash(&value.replay_binding.state_sha256)?;
    Ok(())
}

fn validate_consumer(value: &Consumer) -> Result<(), ScalarTestAuthorityError> {
    if value.repository != CONSUMER_REPOSITORY
        || value.revision != CONSUMER_REVISION
        || value.flow != CONSUMER_FLOW
    {
        return Err(ScalarTestAuthorityError::Invalid("consumer identity"));
    }
    Ok(())
}

fn validate_policy(value: &TestPolicy) -> Result<(), ScalarTestAuthorityError> {
    if value.authorization_state != AUTHORIZATION_STATE
        || value.qualification != QUALIFICATION
        || value.support_claim != SUPPORT_CLAIM
        || value.runtime_support
        || value.external_invoke_grant != EXTERNAL_INVOKE_GRANT
        || value.challenge_sequence
            != (ChallengeSequence {
                challenge: String::from("authenticated-one-time"),
                sequence: String::from("strict-monotonic"),
                correlation: String::from("receipt-bound"),
            })
    {
        return Err(ScalarTestAuthorityError::Invalid(
            "test authorization policy",
        ));
    }
    Ok(())
}

fn validate_side_effects(value: &SideEffects) -> Result<(), ScalarTestAuthorityError> {
    if !value.allowed.is_empty()
        || value.cleanup_required != ["release-loaded-files"]
        || !value.success_requires_cleanup
    {
        return Err(ScalarTestAuthorityError::Invalid("scalar side effects"));
    }
    Ok(())
}

fn validate_custody(value: &Custody) -> Result<(), ScalarTestAuthorityError> {
    decode_hash(&value.identity)?;
    if value.direction != "frozen-bundle-to-vm-bridge"
        || value.request_boundary != "immutable-package-only"
        || value.receipt_boundary != "authenticated-correlated-only"
    {
        return Err(ScalarTestAuthorityError::Invalid("custody"));
    }
    Ok(())
}

fn validate_file_identity(value: &FileIdentity) -> Result<(), ScalarTestAuthorityError> {
    validate_portable_relative_path(&value.path)
        .map_err(|_| ScalarTestAuthorityError::Invalid("file identity path"))?;
    decode_hash(&value.sha256)?;
    if value.expected_exports.is_empty()
        || value.expected_exports.iter().any(String::is_empty)
        || value.expected_exports.iter().collect::<BTreeSet<_>>().len()
            != value.expected_exports.len()
    {
        return Err(ScalarTestAuthorityError::Invalid("file identity exports"));
    }
    Ok(())
}

fn validate_digest(value: &FileDigest) -> Result<(), ScalarTestAuthorityError> {
    validate_portable_relative_path(&value.path)
        .map_err(|_| ScalarTestAuthorityError::Invalid("file digest path"))?;
    decode_hash(&value.sha256)?;
    Ok(())
}

fn validate_operation(value: PublicOperation) -> Result<(), ScalarTestAuthorityError> {
    if value.id == 0
        || value.request_schema_id == 0
        || value.response_schema_id == 0
        || value.request_schema_id == value.response_schema_id
    {
        return Err(ScalarTestAuthorityError::Invalid("operation identity"));
    }
    Ok(())
}

fn validate_acceptance_command(value: &[String]) -> Result<(), ScalarTestAuthorityError> {
    if value != ACCEPTANCE_COMMAND {
        return Err(ScalarTestAuthorityError::Invalid("acceptance command"));
    }
    Ok(())
}

fn parse_exact<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    label: &'static str,
) -> Result<T, ScalarTestAuthorityError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| ScalarTestAuthorityError::Invalid(label))?;
    reject_external_authority(&value)?;
    serde_json::from_value(value).map_err(|_| ScalarTestAuthorityError::Invalid(label))
}

fn reject_external_authority(value: &Value) -> Result<(), ScalarTestAuthorityError> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized = key.to_ascii_lowercase().replace('-', "_");
                if FORBIDDEN_AUTHORITY_KEYS.contains(&normalized.as_str()) {
                    return Err(ScalarTestAuthorityError::Invalid(
                        "external authority field",
                    ));
                }
                reject_external_authority(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_external_authority(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn require_receipt_shape(bytes: &[u8]) -> Result<(), ScalarTestAuthorityError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| ScalarTestAuthorityError::Invalid("runtime receipt"))?;
    reject_external_authority(&value)?;
    let object = value
        .as_object()
        .ok_or(ScalarTestAuthorityError::Invalid("runtime receipt"))?;
    let observed = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        "schema",
        "receipt_id",
        "bundle_sha256",
        "contract_sha256",
        "dispatcher_abi",
        "operation_id",
        "request_sha256",
        "response_sha256",
        "status",
        "runtime_identity",
        "loaded_files",
        "authorization_receipt_sha256",
        "challenge_sha256",
        "sequence",
        "started_at",
        "completed_at",
        "cleanup",
        "authentication",
    ]);
    if observed != expected {
        return Err(ScalarTestAuthorityError::Invalid("runtime receipt shape"));
    }
    Ok(())
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<[u8; 32], ScalarTestAuthorityError> {
    let bytes = serde_jcs::to_vec(value)
        .map_err(|_| ScalarTestAuthorityError::Invalid("canonical json"))?;
    Ok(sha256_bytes(&bytes))
}

fn canonical_json_hash(bytes: &[u8]) -> Result<[u8; 32], ScalarTestAuthorityError> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| ScalarTestAuthorityError::Invalid("canonical json"))?;
    canonical_hash(&value)
}

fn decode_hash(value: &str) -> Result<[u8; 32], ScalarTestAuthorityError> {
    decode_hex(value)
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], ScalarTestAuthorityError> {
    if value.len() != N * 2 {
        return Err(ScalarTestAuthorityError::Invalid("hex"));
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ScalarTestAuthorityError::Invalid("hex"))?;
    }
    Ok(output)
}

fn hex(value: [u8; 32]) -> String {
    use std::fmt::Write;

    value.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
        output
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../runtime-artifacts/whiny-v0.3.0/acceptance/scalar-test-artifacts")
    }

    fn document<T: for<'de> Deserialize<'de>>(path: &str) -> T {
        parse_exact(&fs::read(root().join(path)).unwrap(), "test document").unwrap()
    }

    fn receipt(path: &str) -> RuntimeReceipt {
        serde_json::from_slice(&fs::read(root().join(path)).unwrap()).unwrap()
    }

    #[test]
    fn targeted_scalar_mutations_reach_their_intended_validators() {
        let mut registry: AuthorityRegistry = document("authority-registry.json");
        registry.entries[0].profile_id = String::from("native-cpp-bounded-x64-v1");
        assert!(matches!(
            validate_registry(&registry),
            Err(ScalarTestAuthorityError::Invalid("registry profile"))
        ));

        let registry: AuthorityRegistry = document("authority-registry.json");
        let entry = registry
            .entries
            .iter()
            .find(|entry| entry.profile_id == ScalarProfile::Native.profile_id())
            .unwrap();
        let mut handoff: ScalarHandoff = document("native-scalar/scalar-frozen-handoff.json");
        handoff.candidate.sha256 = "00".repeat(32);
        assert!(matches!(
            bind_entry(entry, &handoff),
            Err(ScalarTestAuthorityError::Binding("registry handoff chain"))
        ));

        let handoff: ScalarHandoff = document("native-scalar/scalar-frozen-handoff.json");
        let policy_sha256 = sha256_file(&root().join("runtime-trust-policy.json")).unwrap();
        let mut expectations: ScalarExpectations =
            document("native-scalar/correlated-expectations.json");
        expectations.policy.challenge_sequence.sequence = String::from("unsupported");
        assert!(matches!(
            bind_expectations(&expectations, &handoff, policy_sha256),
            Err(ScalarTestAuthorityError::Invalid(
                "test authorization policy"
            ))
        ));

        let mut expectations: ScalarExpectations =
            document("native-scalar/correlated-expectations.json");
        expectations.bundle_sha256 = "11".repeat(32);
        assert!(matches!(
            bind_expectations(&expectations, &handoff, policy_sha256),
            Err(ScalarTestAuthorityError::Binding(
                "expectation handoff chain"
            ))
        ));

        let mut expectations: ScalarExpectations =
            document("native-scalar/correlated-expectations.json");
        expectations.runtime.sequence += 1;
        let signed_receipt = receipt("native-scalar/runtime-receipt.json");
        assert!(matches!(
            bind_receipt(&signed_receipt, &expectations, &handoff),
            Err(ScalarTestAuthorityError::Binding(
                "signed receipt expectations"
            ))
        ));

        let expectations: ScalarExpectations =
            document("native-scalar/correlated-expectations.json");
        let mut admission: ScalarAdmission = document("native-scalar/correlated-admission.json");
        admission.replay_binding.challenge_consumed = false;
        assert!(matches!(
            bind_admission(
                &admission,
                &expectations,
                &handoff,
                &signed_receipt,
                REPLAY_STATE_SHA256
            ),
            Err(ScalarTestAuthorityError::Binding(
                "correlated scalar admission"
            ))
        ));

        let mut admission: ScalarAdmission = document("native-scalar/correlated-admission.json");
        admission.runtime.response_sha256 = "22".repeat(32);
        assert!(matches!(
            bind_admission(
                &admission,
                &expectations,
                &handoff,
                &signed_receipt,
                REPLAY_STATE_SHA256
            ),
            Err(ScalarTestAuthorityError::Binding(
                "correlated scalar admission"
            ))
        ));

        let policy: TrustPolicy = document("runtime-trust-policy.json");
        let mut invalid_receipt = receipt("native-scalar/runtime-receipt.json");
        invalid_receipt.authentication.signature = "00".repeat(64);
        assert!(matches!(
            verify_receipt(&policy, &invalid_receipt, ScalarProfile::Native),
            Err(ScalarTestAuthorityError::Receipt(
                wvb_receipt::ReceiptError::Verification
            ))
        ));

        let mut invalid_policy: TrustPolicy = document("runtime-trust-policy.json");
        invalid_policy.signers[0].public_key_hex = "00".repeat(32);
        assert!(matches!(
            verify_receipt(&invalid_policy, &signed_receipt, ScalarProfile::Native),
            Err(ScalarTestAuthorityError::Binding(
                "receipt public key identity"
            ))
        ));
    }
}
