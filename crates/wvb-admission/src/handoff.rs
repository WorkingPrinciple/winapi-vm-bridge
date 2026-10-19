use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use wvb_authz::{ActorId, Registry};
use wvb_integrity::{resolve_regular_file, sha256_bytes, sha256_file, stable_file_identity};

use crate::{
    AdmissionEngine, AdmissionError, AdmittedBundle, BundleFileKind, FrozenInputs,
    OperationAdmission, OperatorAdmission,
};

pub const WHINY_VALIDATOR_REVISION: &str = "c48db610ef2e9505b0fbc577a76704a1214bc83f";
pub const WHINY_FROZEN_HANDOFF_IDENTIFIER: &str = "whiny.frozen-adapter-handoff.v1";
const WHINY_AUTHORITY_REGISTRY_IDENTIFIER: &str = "whiny.authority-registry.v1";
const WHINY_BUILD_RECEIPT_IDENTIFIER: &str = "whiny.deterministic-build-receipt.v1";
const DEVELOPMENT_ONLY: &str = "development-only";
const MAX_HANDOFF_BYTES: usize = 16 * 1024 * 1024;
const ACCEPTANCE_COMMAND: [&str; 4] = [
    "whiny",
    "frozen-adapter-handoff-validate",
    ".",
    "frozen-adapter-handoff.json",
];
const ADAPTERS: [&str; 3] = ["shell_hook", "nt_wait_completion", "alpc"];
const PROFILES: [&str; 9] = [
    "native-c-scalar-x64-v1",
    "native-cpp-bounded-x64-v1",
    "com-x64-v1",
    "winrt-x64-v1",
    "native-c-bounded-memory-x64-v1",
    "dotnet-static-scalar-net8-x64-v1",
    "dotnet-static-bounded-net8-x64-v1",
    "native-exe-x64-v1",
    "dotnet-exe-net8-x64-v1",
];
const EVIDENCE_KINDS: [&str; 10] = [
    "provider-identity-receipt",
    "declaration-authority",
    "status-authority",
    "review-receipt",
    "shell-event-policy",
    "absence-window",
    "window-categories",
    "helper-source",
    "helper-admission",
    "authenticated-runtime-receipt",
];
type EvidenceKinds = BTreeSet<&'static str>;
type EvidenceRequirements = (EvidenceKinds, EvidenceKinds, EvidenceKinds);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenHandoffApproval {
    pub validator_revision: String,
    pub handoff_sha256: [u8; 32],
    pub validator_result_sha256: [u8; 32],
}

#[derive(Clone, Copy)]
pub struct FrozenHandoffInputs<'a> {
    pub validator_result: &'a [u8],
    pub handoff: &'a [u8],
    pub contract: &'a [u8],
    pub bundle_descriptor: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub path: String,
    pub sha256: String,
    pub expected_exports: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SideEffects {
    pub allowed: Vec<String>,
    pub cleanup_required: Vec<String>,
    pub success_requires_cleanup: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeSequence {
    pub challenge: String,
    pub sequence: String,
    pub correlation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPolicy {
    pub runtime_admission: String,
    pub authentication: String,
    pub correlation: String,
    pub uncorrelated_receipts: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Custody {
    pub identity: String,
    pub direction: String,
    pub request_boundary: String,
    pub receipt_boundary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundFrozenHandoff {
    pub(crate) load_root: PathBuf,
    pub(crate) admitted: AdmittedBundle,
    pub(crate) bound_files: Vec<BoundFile>,
    pub(crate) handoff_sha256: [u8; 32],
    pub(crate) registry_sha256: [u8; 32],
    pub(crate) registry_entry_sha256: [u8; 32],
    pub(crate) registry_id: String,
    pub(crate) contract_file_sha256: [u8; 32],
    pub(crate) build_receipt_sha256: [u8; 32],
    pub(crate) handoff_id: String,
    pub(crate) scenario_id: String,
    pub(crate) profile_id: String,
    pub(crate) adapter: String,
    pub(crate) qualification: String,
    pub(crate) source_revision: String,
    pub(crate) dispatcher_path: String,
    pub(crate) dispatcher_sha256: [u8; 32],
    pub(crate) provider: FileIdentity,
    pub(crate) candidate: FileIdentity,
    pub(crate) operation: OperationAdmission,
    pub(crate) side_effects: SideEffects,
    pub(crate) challenge_sequence: ChallengeSequence,
    pub(crate) receipt_policy: ReceiptPolicy,
    pub(crate) acceptance_command: Vec<String>,
    pub(crate) custody: Custody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundFile {
    path: String,
    canonical_path: PathBuf,
    sha256: [u8; 32],
    stable_identity: wvb_integrity::StableFileIdentity,
}

struct HandoffFiles {
    registry: BoundFile,
    contract: BoundFile,
    bundle: BoundFile,
    dispatcher: BoundFile,
    build_receipt: BoundFile,
    provider: BoundFile,
    candidate: BoundFile,
    transitive: Vec<BoundFile>,
}

impl HandoffFiles {
    fn into_vec(self) -> Vec<BoundFile> {
        let mut files = vec![
            self.registry,
            self.contract,
            self.bundle,
            self.dispatcher,
            self.build_receipt,
            self.provider,
            self.candidate,
        ];
        files.extend(self.transitive);
        files
    }
}

struct BoundDocuments {
    entry: AuthorityEntry,
    registry_sha256: [u8; 32],
    registry_entry_sha256: [u8; 32],
    build_receipt_sha256: [u8; 32],
}

impl BoundFrozenHandoff {
    #[must_use]
    pub fn handoff_sha256(&self) -> [u8; 32] {
        self.handoff_sha256
    }

    #[must_use]
    pub fn registry_sha256(&self) -> [u8; 32] {
        self.registry_sha256
    }

    #[must_use]
    pub fn registry_entry_sha256(&self) -> [u8; 32] {
        self.registry_entry_sha256
    }

    #[must_use]
    pub fn build_receipt_sha256(&self) -> [u8; 32] {
        self.build_receipt_sha256
    }

    #[must_use]
    pub fn handoff_id(&self) -> &str {
        &self.handoff_id
    }

    #[must_use]
    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub fn adapter(&self) -> &str {
        &self.adapter
    }

    #[must_use]
    pub fn qualification(&self) -> &str {
        &self.qualification
    }

    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    #[must_use]
    pub fn provider(&self) -> &FileIdentity {
        &self.provider
    }

    #[must_use]
    pub fn candidate(&self) -> &FileIdentity {
        &self.candidate
    }

    #[must_use]
    pub fn operation(&self) -> OperationAdmission {
        self.operation
    }

    #[must_use]
    pub fn side_effects(&self) -> &SideEffects {
        &self.side_effects
    }

    #[must_use]
    pub fn challenge_sequence(&self) -> &ChallengeSequence {
        &self.challenge_sequence
    }

    #[must_use]
    pub fn receipt_policy(&self) -> &ReceiptPolicy {
        &self.receipt_policy
    }

    #[must_use]
    pub fn acceptance_command(&self) -> &[String] {
        &self.acceptance_command
    }

    #[must_use]
    pub fn custody(&self) -> &Custody {
        &self.custody
    }

    pub fn authorize_invocation_grant(
        &self,
        registry: &Registry,
        actor_id: ActorId,
        now_unix_ms: u64,
    ) -> Result<(), HandoffAdmissionError> {
        self.admitted
            .authorize_operation(registry, actor_id, self.operation.operation_id, now_unix_ms)
            .map_err(HandoffAdmissionError::Admission)
    }

    pub fn authorize_runtime_operation(
        &self,
        registry: &Registry,
        actor_id: ActorId,
        now_unix_ms: u64,
    ) -> Result<(), HandoffAdmissionError> {
        self.authorize_invocation_grant(registry, actor_id, now_unix_ms)?;
        Err(HandoffAdmissionError::RuntimeAuthorityUnsupported {
            adapter: self.adapter.clone(),
            qualification: self.qualification.clone(),
        })
    }

    pub fn reverify_files(&self) -> Result<(), HandoffAdmissionError> {
        self.admitted
            .reverify_files()
            .map_err(HandoffAdmissionError::Admission)?;
        for file in &self.bound_files {
            let resolved = resolve_regular_file(&self.load_root, &file.path)
                .map_err(AdmissionError::from)
                .map_err(HandoffAdmissionError::Admission)?;
            if resolved != file.canonical_path || sha256_file(&resolved)? != file.sha256 {
                return Err(HandoffAdmissionError::Binding("bound file identity"));
            }
            if stable_file_identity(&resolved)? != file.stable_identity {
                return Err(HandoffAdmissionError::Binding("bound stable identity"));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum HandoffAdmissionError {
    Admission(AdmissionError),
    Invalid(&'static str),
    Binding(&'static str),
    HandoffHashMismatch,
    ValidatorRevisionMismatch,
    RuntimeAuthorityUnsupported {
        adapter: String,
        qualification: String,
    },
}

impl std::fmt::Display for HandoffAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for HandoffAdmissionError {}

impl From<AdmissionError> for HandoffAdmissionError {
    fn from(value: AdmissionError) -> Self {
        Self::Admission(value)
    }
}

impl From<std::io::Error> for HandoffAdmissionError {
    fn from(value: std::io::Error) -> Self {
        Self::Admission(AdmissionError::Io(value))
    }
}

impl From<wvb_integrity::IntegrityError> for HandoffAdmissionError {
    fn from(value: wvb_integrity::IntegrityError) -> Self {
        Self::Admission(AdmissionError::from(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenHandoff {
    schema: String,
    handoff_id: String,
    qualification: String,
    registry: HandoffRegistry,
    contract: HandoffContract,
    bundle: HandoffBundle,
    dispatcher: DispatcherIdentity,
    build_receipt: HandoffBuildReceipt,
    provider: FileIdentity,
    candidate: FileIdentity,
    operation: PublicOperation,
    side_effects: SideEffects,
    challenge_sequence: ChallengeSequence,
    receipt_policy: ReceiptPolicy,
    acceptance_command: Vec<String>,
    source_revision: String,
    custody: Custody,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatorResult {
    schema: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffRegistry {
    path: String,
    sha256: String,
    registry_id: String,
    entry_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffContract {
    path: String,
    file_sha256: String,
    canonical_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffBundle {
    path: String,
    canonical_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatcherIdentity {
    abi: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffBuildReceipt {
    path: String,
    sha256: String,
    command: Vec<String>,
    output_path: String,
    output_sha256: String,
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
struct AuthorityRegistry {
    schema: String,
    registry_id: String,
    entries: Vec<AuthorityEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityEntry {
    scenario_id: String,
    profile_id: String,
    adapter: String,
    provider: FileIdentity,
    candidate: FileIdentity,
    operation: PublicOperation,
    evidence: Evidence,
    side_effects: SideEffects,
    challenge_sequence: ChallengeSequence,
    qualification: String,
    source_revision: String,
    custody: Custody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    authority: Vec<EvidenceIdentity>,
    calibration: Vec<EvidenceIdentity>,
    helper: Vec<EvidenceIdentity>,
    runtime: Vec<EvidenceIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceIdentity {
    kind: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct BundleDocument {
    schema: String,
    bundle_id: String,
    contract: BundleContract,
    dispatcher: DispatcherIdentity,
    target: FileDigest,
    dependencies: Vec<BundleDependency>,
    operations: Vec<PublicOperation>,
    artifacts: Vec<FileDigest>,
}

#[derive(Debug, Deserialize)]
struct BundleContract {
    format: String,
    path: String,
    file_sha256: String,
    canonical_sha256: String,
}

#[derive(Debug, Deserialize)]
struct BundleDependency {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct FileDigest {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct ContractDocument {
    contract_id: String,
    target: ContractTarget,
    dependencies: Vec<ContractDependency>,
    operations: Vec<PublicOperation>,
}

#[derive(Debug, Deserialize)]
struct ContractTarget {
    relative_path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct ContractDependency {
    relative_path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct BuildReceiptDocument {
    schema: String,
    command: Vec<String>,
    output: String,
    source_sha256: String,
    project_sha256: String,
    output_sha256: String,
}

impl AdmissionEngine {
    pub fn bind_frozen_handoff(
        &self,
        registry: &Registry,
        operator_actor: ActorId,
        now_unix_ms: u64,
        approval: &OperatorAdmission,
        handoff_approval: &FrozenHandoffApproval,
        inputs: FrozenHandoffInputs<'_>,
    ) -> Result<BoundFrozenHandoff, HandoffAdmissionError> {
        if handoff_approval.validator_revision != WHINY_VALIDATOR_REVISION {
            return Err(HandoffAdmissionError::ValidatorRevisionMismatch);
        }
        if inputs.handoff.len() > MAX_HANDOFF_BYTES {
            return Err(HandoffAdmissionError::Invalid("handoff bound"));
        }
        if sha256_bytes(inputs.validator_result) != handoff_approval.validator_result_sha256 {
            return Err(HandoffAdmissionError::Binding("validator result bytes"));
        }
        let validator_result: ValidatorResult = parse(inputs.validator_result, "validator result")?;
        if validator_result.schema != WHINY_FROZEN_HANDOFF_IDENTIFIER
            || decode_hash(&validator_result.sha256)? != handoff_approval.handoff_sha256
        {
            return Err(HandoffAdmissionError::Binding("validator result"));
        }
        let handoff: FrozenHandoff = parse(inputs.handoff, "handoff")?;
        validate_handoff(&handoff)?;
        if canonical_hash(&handoff)? != handoff_approval.handoff_sha256 {
            return Err(HandoffAdmissionError::HandoffHashMismatch);
        }

        let mut files = self.bind_handoff_files(&handoff)?;
        let documents = bind_documents(self, approval, inputs, &handoff, &mut files)?;

        let admitted = self.admit(
            registry,
            operator_actor,
            now_unix_ms,
            approval,
            FrozenInputs {
                contract: inputs.contract,
                bundle_descriptor: inputs.bundle_descriptor,
            },
        )?;
        let operation = OperationAdmission::from(handoff.operation);
        Ok(BoundFrozenHandoff {
            load_root: self.load_root.clone(),
            admitted,
            bound_files: files.into_vec(),
            handoff_sha256: handoff_approval.handoff_sha256,
            registry_sha256: documents.registry_sha256,
            registry_entry_sha256: documents.registry_entry_sha256,
            registry_id: handoff.registry.registry_id,
            contract_file_sha256: decode_hash(&handoff.contract.file_sha256)?,
            build_receipt_sha256: documents.build_receipt_sha256,
            handoff_id: handoff.handoff_id,
            scenario_id: documents.entry.scenario_id,
            profile_id: documents.entry.profile_id,
            adapter: documents.entry.adapter,
            qualification: handoff.qualification,
            source_revision: handoff.source_revision,
            dispatcher_path: handoff.dispatcher.path,
            dispatcher_sha256: decode_hash(&handoff.dispatcher.sha256)?,
            provider: handoff.provider,
            candidate: handoff.candidate,
            operation,
            side_effects: handoff.side_effects,
            challenge_sequence: handoff.challenge_sequence,
            receipt_policy: handoff.receipt_policy,
            acceptance_command: handoff.acceptance_command,
            custody: handoff.custody,
        })
    }

    fn bind_handoff_files(
        &self,
        handoff: &FrozenHandoff,
    ) -> Result<HandoffFiles, HandoffAdmissionError> {
        let mut paths = BTreeSet::new();
        let files = HandoffFiles {
            registry: self.bind_file(
                &mut paths,
                &handoff.registry.path,
                &handoff.registry.sha256,
            )?,
            contract: self.bind_file(
                &mut paths,
                &handoff.contract.path,
                &handoff.contract.file_sha256,
            )?,
            bundle: self.bind_file(
                &mut paths,
                &handoff.bundle.path,
                &handoff.bundle.canonical_sha256,
            )?,
            dispatcher: self.bind_file(
                &mut paths,
                &handoff.dispatcher.path,
                &handoff.dispatcher.sha256,
            )?,
            build_receipt: self.bind_file(
                &mut paths,
                &handoff.build_receipt.path,
                &handoff.build_receipt.sha256,
            )?,
            provider: self.bind_file(
                &mut paths,
                &handoff.provider.path,
                &handoff.provider.sha256,
            )?,
            candidate: self.bind_file(
                &mut paths,
                &handoff.candidate.path,
                &handoff.candidate.sha256,
            )?,
            transitive: Vec::new(),
        };
        let mut identities = BTreeSet::new();
        for file in [
            &files.registry,
            &files.contract,
            &files.bundle,
            &files.dispatcher,
            &files.build_receipt,
            &files.provider,
            &files.candidate,
        ] {
            if !identities.insert(file.stable_identity) {
                return Err(HandoffAdmissionError::Binding(
                    "duplicate stable file identity",
                ));
            }
        }
        Ok(files)
    }

    fn bind_file(
        &self,
        observed: &mut BTreeSet<String>,
        relative_path: &str,
        expected_sha256: &str,
    ) -> Result<BoundFile, HandoffAdmissionError> {
        let folded = relative_path.to_ascii_lowercase();
        if !observed.insert(folded) {
            return Err(HandoffAdmissionError::Binding("case-colliding path"));
        }
        let canonical_path = resolve_regular_file(&self.load_root, relative_path)?;
        let stable_identity = stable_file_identity(&canonical_path)?;
        let sha256 = decode_hash(expected_sha256)?;
        if sha256_file(&canonical_path)? != sha256 {
            return Err(HandoffAdmissionError::Binding("file hash"));
        }
        Ok(BoundFile {
            path: relative_path.to_owned(),
            canonical_path,
            sha256,
            stable_identity,
        })
    }
}

fn bind_documents(
    engine: &AdmissionEngine,
    approval: &OperatorAdmission,
    inputs: FrozenHandoffInputs<'_>,
    handoff: &FrozenHandoff,
    files: &mut HandoffFiles,
) -> Result<BoundDocuments, HandoffAdmissionError> {
    let registry_bytes = fs::read(&files.registry.canonical_path)?;
    let public_registry: AuthorityRegistry = parse(&registry_bytes, "registry")?;
    validate_registry(&public_registry)?;
    let registry_sha256 = decode_hash(&handoff.registry.sha256)?;
    if canonical_hash(&public_registry)? != registry_sha256
        || public_registry.registry_id != handoff.registry.registry_id
    {
        return Err(HandoffAdmissionError::Binding("registry identity"));
    }
    let registry_entry_sha256 = decode_hash(&handoff.registry.entry_sha256)?;
    let matching_entries: Vec<&AuthorityEntry> = public_registry
        .entries
        .iter()
        .filter(|entry| canonical_hash(*entry).ok() == Some(registry_entry_sha256))
        .collect();
    let [entry] = matching_entries.as_slice() else {
        return Err(HandoffAdmissionError::Binding("registry entry identity"));
    };
    bind_entry(entry, handoff)?;

    let contract_bytes = fs::read(&files.contract.canonical_path)?;
    if contract_bytes != inputs.contract
        || canonical_json_hash(&contract_bytes)? != decode_hash(&handoff.contract.canonical_sha256)?
        || approval.contract_sha256 != decode_hash(&handoff.contract.canonical_sha256)?
    {
        return Err(HandoffAdmissionError::Binding("contract identity"));
    }
    let contract: ContractDocument = parse(&contract_bytes, "contract")?;
    bind_contract(&contract, handoff)?;

    let bundle_bytes = fs::read(&files.bundle.canonical_path)?;
    if bundle_bytes != inputs.bundle_descriptor
        || approval.bundle_descriptor_sha256 != decode_hash(&handoff.bundle.canonical_sha256)?
    {
        return Err(HandoffAdmissionError::Binding("bundle identity"));
    }
    let bundle: BundleDocument = parse(&bundle_bytes, "bundle")?;
    bind_bundle(&bundle, handoff)?;

    let build_receipt_bytes = fs::read(&files.build_receipt.canonical_path)?;
    let build_receipt: BuildReceiptDocument = parse(&build_receipt_bytes, "build receipt")?;
    bind_build_receipt(&build_receipt, handoff)?;
    bind_operator_approval(approval, handoff)?;
    bind_transitive_files(
        engine,
        files,
        &public_registry,
        &contract,
        &bundle,
        &build_receipt,
    )?;
    Ok(BoundDocuments {
        entry: (*entry).clone(),
        registry_sha256,
        registry_entry_sha256,
        build_receipt_sha256: decode_hash(&handoff.build_receipt.sha256)?,
    })
}

fn bind_transitive_files(
    engine: &AdmissionEngine,
    files: &mut HandoffFiles,
    registry: &AuthorityRegistry,
    contract: &ContractDocument,
    bundle: &BundleDocument,
    receipt: &BuildReceiptDocument,
) -> Result<(), HandoffAdmissionError> {
    let mut observed = BTreeMap::new();
    let mut stable_identities = BTreeSet::new();
    for file in [
        &files.registry,
        &files.contract,
        &files.bundle,
        &files.dispatcher,
        &files.build_receipt,
        &files.provider,
        &files.candidate,
    ] {
        observed.insert(
            file.path.to_ascii_lowercase(),
            (file.path.clone(), file.sha256),
        );
        stable_identities.insert(file.stable_identity);
    }
    bind_registry_files(
        engine,
        files,
        &mut observed,
        &mut stable_identities,
        registry,
    )?;
    bind_contract_and_bundle_files(
        engine,
        files,
        &mut observed,
        &mut stable_identities,
        contract,
        bundle,
    )?;
    bind_build_files(
        engine,
        files,
        &mut observed,
        &mut stable_identities,
        receipt,
    )
}

fn bind_registry_files(
    engine: &AdmissionEngine,
    files: &mut HandoffFiles,
    observed: &mut BTreeMap<String, (String, [u8; 32])>,
    stable_identities: &mut BTreeSet<wvb_integrity::StableFileIdentity>,
    registry: &AuthorityRegistry,
) -> Result<(), HandoffAdmissionError> {
    for entry in &registry.entries {
        bind_transitive_file(
            engine,
            observed,
            stable_identities,
            &mut files.transitive,
            &entry.provider.path,
            &entry.provider.sha256,
        )?;
        bind_transitive_file(
            engine,
            observed,
            stable_identities,
            &mut files.transitive,
            &entry.candidate.path,
            &entry.candidate.sha256,
        )?;
        for identity in entry
            .evidence
            .authority
            .iter()
            .chain(&entry.evidence.calibration)
            .chain(&entry.evidence.helper)
            .chain(&entry.evidence.runtime)
        {
            bind_transitive_file(
                engine,
                observed,
                stable_identities,
                &mut files.transitive,
                &identity.path,
                &identity.sha256,
            )?;
        }
    }
    Ok(())
}

fn bind_contract_and_bundle_files(
    engine: &AdmissionEngine,
    files: &mut HandoffFiles,
    observed: &mut BTreeMap<String, (String, [u8; 32])>,
    stable_identities: &mut BTreeSet<wvb_integrity::StableFileIdentity>,
    contract: &ContractDocument,
    bundle: &BundleDocument,
) -> Result<(), HandoffAdmissionError> {
    bind_transitive_file(
        engine,
        observed,
        stable_identities,
        &mut files.transitive,
        &contract.target.relative_path,
        &contract.target.sha256,
    )?;
    for dependency in &contract.dependencies {
        bind_transitive_file(
            engine,
            observed,
            stable_identities,
            &mut files.transitive,
            &dependency.relative_path,
            &dependency.sha256,
        )?;
    }
    bind_transitive_file(
        engine,
        observed,
        stable_identities,
        &mut files.transitive,
        &bundle.contract.path,
        &bundle.contract.file_sha256,
    )?;
    bind_transitive_file(
        engine,
        observed,
        stable_identities,
        &mut files.transitive,
        &bundle.dispatcher.path,
        &bundle.dispatcher.sha256,
    )?;
    bind_transitive_file(
        engine,
        observed,
        stable_identities,
        &mut files.transitive,
        &bundle.target.path,
        &bundle.target.sha256,
    )?;
    for dependency in &bundle.dependencies {
        bind_transitive_file(
            engine,
            observed,
            stable_identities,
            &mut files.transitive,
            &dependency.path,
            &dependency.sha256,
        )?;
    }
    for artifact in &bundle.artifacts {
        bind_transitive_file(
            engine,
            observed,
            stable_identities,
            &mut files.transitive,
            &artifact.path,
            &artifact.sha256,
        )?;
    }
    Ok(())
}

fn bind_build_files(
    engine: &AdmissionEngine,
    files: &mut HandoffFiles,
    observed: &mut BTreeMap<String, (String, [u8; 32])>,
    stable_identities: &mut BTreeSet<wvb_integrity::StableFileIdentity>,
    receipt: &BuildReceiptDocument,
) -> Result<(), HandoffAdmissionError> {
    bind_transitive_file(
        engine,
        observed,
        stable_identities,
        &mut files.transitive,
        &receipt.output,
        &receipt.output_sha256,
    )?;
    bind_transitive_file(
        engine,
        observed,
        stable_identities,
        &mut files.transitive,
        "dispatcher.generated.c",
        &receipt.source_sha256,
    )?;
    bind_transitive_file(
        engine,
        observed,
        stable_identities,
        &mut files.transitive,
        "Makefile.generated",
        &receipt.project_sha256,
    )
}

fn bind_transitive_file(
    engine: &AdmissionEngine,
    observed: &mut BTreeMap<String, (String, [u8; 32])>,
    stable_identities: &mut BTreeSet<wvb_integrity::StableFileIdentity>,
    files: &mut Vec<BoundFile>,
    path: &str,
    hash: &str,
) -> Result<(), HandoffAdmissionError> {
    let digest = decode_hash(hash)?;
    let folded = path.to_ascii_lowercase();
    if let Some(previous) = observed.get(&folded) {
        if previous != &(path.to_owned(), digest) {
            return Err(HandoffAdmissionError::Binding("transitive path collision"));
        }
        return Ok(());
    }
    let canonical_path = resolve_regular_file(&engine.load_root, path)?;
    let stable_identity = stable_file_identity(&canonical_path)?;
    if !stable_identities.insert(stable_identity) {
        return Err(HandoffAdmissionError::Binding(
            "duplicate transitive file identity",
        ));
    }
    if sha256_file(&canonical_path)? != digest {
        return Err(HandoffAdmissionError::Binding("transitive file hash"));
    }
    observed.insert(folded, (path.to_owned(), digest));
    files.push(BoundFile {
        path: path.to_owned(),
        canonical_path,
        sha256: digest,
        stable_identity,
    });
    Ok(())
}

fn validate_handoff(value: &FrozenHandoff) -> Result<(), HandoffAdmissionError> {
    if value.schema != WHINY_FROZEN_HANDOFF_IDENTIFIER {
        return Err(HandoffAdmissionError::Invalid("handoff schema"));
    }
    if value.qualification != DEVELOPMENT_ONLY {
        return Err(HandoffAdmissionError::Invalid("handoff qualification"));
    }
    validate_dotted_id(&value.handoff_id)?;
    validate_dotted_id(&value.registry.registry_id)?;
    validate_source_revision(&value.source_revision)?;
    validate_hashes([
        &value.registry.sha256,
        &value.registry.entry_sha256,
        &value.contract.file_sha256,
        &value.contract.canonical_sha256,
        &value.bundle.canonical_sha256,
        &value.dispatcher.sha256,
        &value.build_receipt.sha256,
        &value.build_receipt.output_sha256,
        &value.provider.sha256,
        &value.candidate.sha256,
        &value.custody.identity,
    ])?;
    validate_file_identity(&value.provider)?;
    validate_file_identity(&value.candidate)?;
    validate_operation(value.operation)?;
    validate_effects(&value.side_effects)?;
    if value.dispatcher.abi != crate::DISPATCHER_ABI_IDENTIFIER
        || value.dispatcher.path != value.build_receipt.output_path
        || value.dispatcher.sha256 != value.build_receipt.output_sha256
        || value.challenge_sequence
            != (ChallengeSequence {
                challenge: String::from("unsupported"),
                sequence: String::from("unsupported"),
                correlation: String::from("unsupported"),
            })
        || value.receipt_policy
            != (ReceiptPolicy {
                runtime_admission: String::from("required"),
                authentication: String::from("required"),
                correlation: String::from("required"),
                uncorrelated_receipts: String::from("rejected"),
            })
        || value.acceptance_command != ACCEPTANCE_COMMAND.map(String::from).to_vec()
    {
        return Err(HandoffAdmissionError::Binding("handoff policy"));
    }
    validate_custody(&value.custody)
}

fn validate_registry(value: &AuthorityRegistry) -> Result<(), HandoffAdmissionError> {
    if value.schema != WHINY_AUTHORITY_REGISTRY_IDENTIFIER || value.entries.is_empty() {
        return Err(HandoffAdmissionError::Invalid("registry schema"));
    }
    validate_dotted_id(&value.registry_id)?;
    let mut scenarios = BTreeSet::new();
    let mut operations = BTreeSet::new();
    let mut schemas = BTreeSet::new();
    for entry in &value.entries {
        validate_dotted_id(&entry.scenario_id)?;
        if !PROFILES.contains(&entry.profile_id.as_str())
            || !ADAPTERS.contains(&entry.adapter.as_str())
        {
            return Err(HandoffAdmissionError::Invalid("registry profile"));
        }
        validate_file_identity(&entry.provider)?;
        validate_file_identity(&entry.candidate)?;
        validate_operation(entry.operation)?;
        validate_effects(&entry.side_effects)?;
        validate_source_revision(&entry.source_revision)?;
        validate_custody(&entry.custody)?;
        if entry.qualification != DEVELOPMENT_ONLY
            || !entry.evidence.runtime.is_empty()
            || entry.challenge_sequence.challenge != "unsupported"
            || entry.challenge_sequence.sequence != "unsupported"
            || entry.challenge_sequence.correlation != "unsupported"
            || !scenarios.insert((&entry.scenario_id, &entry.profile_id))
            || !operations.insert(entry.operation.id)
            || !schemas.insert(entry.operation.request_schema_id)
            || !schemas.insert(entry.operation.response_schema_id)
        {
            return Err(HandoffAdmissionError::Invalid("registry authority"));
        }
        validate_evidence(&entry.adapter, &entry.evidence)?;
    }
    Ok(())
}

fn validate_evidence(adapter: &str, value: &Evidence) -> Result<(), HandoffAdmissionError> {
    let mut paths = BTreeSet::new();
    let mut observed = BTreeMap::new();
    for (group, identities) in [
        ("authority", &value.authority),
        ("calibration", &value.calibration),
        ("helper", &value.helper),
        ("runtime", &value.runtime),
    ] {
        let mut kinds = BTreeSet::new();
        for identity in identities {
            if !EVIDENCE_KINDS.contains(&identity.kind.as_str())
                || decode_hash(&identity.sha256).is_err()
                || !paths.insert(identity.path.to_ascii_lowercase())
                || !kinds.insert(identity.kind.as_str())
            {
                return Err(HandoffAdmissionError::Invalid("registry evidence"));
            }
        }
        observed.insert(group, kinds);
    }
    let (authority, calibration, helper) = required_evidence(adapter)?;
    if observed["authority"] != authority
        || observed["calibration"] != calibration
        || observed["helper"] != helper
        || !observed["runtime"].is_empty()
    {
        return Err(HandoffAdmissionError::Invalid(
            "registry evidence authority",
        ));
    }
    Ok(())
}

fn required_evidence(adapter: &str) -> Result<EvidenceRequirements, HandoffAdmissionError> {
    let values = match adapter {
        "shell_hook" => (
            &["provider-identity-receipt", "review-receipt"][..],
            &["shell-event-policy", "absence-window", "window-categories"][..],
            &[][..],
        ),
        "nt_wait_completion" | "alpc" => (
            &[
                "provider-identity-receipt",
                "declaration-authority",
                "status-authority",
                "review-receipt",
            ][..],
            &[][..],
            &["helper-source", "helper-admission"][..],
        ),
        _ => return Err(HandoffAdmissionError::Invalid("registry adapter")),
    };
    Ok((
        values.0.iter().copied().collect(),
        values.1.iter().copied().collect(),
        values.2.iter().copied().collect(),
    ))
}

fn bind_entry(
    entry: &AuthorityEntry,
    handoff: &FrozenHandoff,
) -> Result<(), HandoffAdmissionError> {
    if entry.provider != handoff.provider
        || entry.candidate != handoff.candidate
        || entry.operation != handoff.operation
        || entry.side_effects != handoff.side_effects
        || entry.challenge_sequence != handoff.challenge_sequence
        || entry.qualification != handoff.qualification
        || entry.source_revision != handoff.source_revision
        || entry.custody != handoff.custody
    {
        return Err(HandoffAdmissionError::Binding("registry handoff chain"));
    }
    Ok(())
}

fn bind_contract(
    contract: &ContractDocument,
    handoff: &FrozenHandoff,
) -> Result<(), HandoffAdmissionError> {
    if contract.contract_id != handoff.handoff_id
        || contract.target.relative_path != handoff.candidate.path
        || contract.target.sha256 != handoff.candidate.sha256
        || contract.operations.as_slice() != [handoff.operation]
    {
        return Err(HandoffAdmissionError::Binding("contract handoff chain"));
    }
    Ok(())
}

fn bind_bundle(
    bundle: &BundleDocument,
    handoff: &FrozenHandoff,
) -> Result<(), HandoffAdmissionError> {
    if bundle.schema != crate::BUNDLE_FORMAT_IDENTIFIER
        || bundle.bundle_id != handoff.handoff_id
        || bundle.contract.format != crate::CONTRACT_FORMAT_IDENTIFIER
        || bundle.contract.path != handoff.contract.path
        || bundle.contract.file_sha256 != handoff.contract.file_sha256
        || bundle.contract.canonical_sha256 != handoff.contract.canonical_sha256
        || bundle.dispatcher != handoff.dispatcher
        || bundle.target.path != handoff.candidate.path
        || bundle.target.sha256 != handoff.candidate.sha256
        || bundle.operations.as_slice() != [handoff.operation]
    {
        return Err(HandoffAdmissionError::Binding("bundle handoff chain"));
    }
    Ok(())
}

fn bind_build_receipt(
    receipt: &BuildReceiptDocument,
    handoff: &FrozenHandoff,
) -> Result<(), HandoffAdmissionError> {
    if receipt.schema != WHINY_BUILD_RECEIPT_IDENTIFIER
        || receipt.command != handoff.build_receipt.command
        || receipt.output != handoff.build_receipt.output_path
        || receipt.output_sha256 != handoff.build_receipt.output_sha256
    {
        return Err(HandoffAdmissionError::Binding("build receipt chain"));
    }
    Ok(())
}

fn bind_operator_approval(
    approval: &OperatorAdmission,
    handoff: &FrozenHandoff,
) -> Result<(), HandoffAdmissionError> {
    let operation = OperationAdmission::from(handoff.operation);
    if approval.operations.as_slice() != [operation] {
        return Err(HandoffAdmissionError::Binding("operation approval"));
    }
    let dispatcher = approval
        .files
        .iter()
        .filter(|file| file.kind == BundleFileKind::Dispatcher)
        .collect::<Vec<_>>();
    let target = approval
        .files
        .iter()
        .filter(|file| file.kind == BundleFileKind::Target)
        .collect::<Vec<_>>();
    if dispatcher.len() != 1
        || target.len() != 1
        || dispatcher[0].relative_path != handoff.dispatcher.path
        || dispatcher[0].sha256 != decode_hash(&handoff.dispatcher.sha256)?
        || target[0].relative_path != handoff.candidate.path
        || target[0].sha256 != decode_hash(&handoff.candidate.sha256)?
    {
        return Err(HandoffAdmissionError::Binding("artifact approval"));
    }
    Ok(())
}

fn validate_file_identity(value: &FileIdentity) -> Result<(), HandoffAdmissionError> {
    if value.expected_exports.is_empty()
        || value.expected_exports.iter().any(String::is_empty)
        || value.expected_exports.iter().collect::<BTreeSet<_>>().len()
            != value.expected_exports.len()
    {
        return Err(HandoffAdmissionError::Invalid("file exports"));
    }
    decode_hash(&value.sha256)?;
    Ok(())
}

fn validate_operation(value: PublicOperation) -> Result<(), HandoffAdmissionError> {
    if value.id == 0
        || value.request_schema_id == 0
        || value.response_schema_id == 0
        || value.request_schema_id == value.response_schema_id
    {
        return Err(HandoffAdmissionError::Invalid("operation identity"));
    }
    Ok(())
}

fn validate_effects(value: &SideEffects) -> Result<(), HandoffAdmissionError> {
    if !value.success_requires_cleanup
        || value.cleanup_required.is_empty()
        || value.allowed.iter().any(String::is_empty)
        || value.cleanup_required.iter().any(String::is_empty)
        || value.allowed.iter().collect::<BTreeSet<_>>().len() != value.allowed.len()
        || value.cleanup_required.iter().collect::<BTreeSet<_>>().len()
            != value.cleanup_required.len()
    {
        return Err(HandoffAdmissionError::Invalid("side effects"));
    }
    Ok(())
}

fn validate_custody(value: &Custody) -> Result<(), HandoffAdmissionError> {
    decode_hash(&value.identity)?;
    if value.direction != "frozen-bundle-to-vm-bridge"
        || value.request_boundary != "immutable-package-only"
        || value.receipt_boundary != "authenticated-correlated-only"
    {
        return Err(HandoffAdmissionError::Invalid("custody"));
    }
    Ok(())
}

fn validate_source_revision(value: &str) -> Result<(), HandoffAdmissionError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(HandoffAdmissionError::Invalid("source revision"));
    }
    Ok(())
}

fn validate_dotted_id(value: &str) -> Result<(), HandoffAdmissionError> {
    if !value.contains('.')
        || value.split('.').any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                || !part.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        })
    {
        return Err(HandoffAdmissionError::Invalid("dotted identifier"));
    }
    Ok(())
}

fn validate_hashes<'a>(
    values: impl IntoIterator<Item = &'a String>,
) -> Result<(), HandoffAdmissionError> {
    for value in values {
        decode_hash(value)?;
    }
    Ok(())
}

fn decode_hash(value: &str) -> Result<[u8; 32], HandoffAdmissionError> {
    if value.len() != 64 {
        return Err(HandoffAdmissionError::Invalid("sha256"));
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| HandoffAdmissionError::Invalid("sha256"))?;
    }
    Ok(output)
}

fn parse<T: DeserializeOwned>(
    bytes: &[u8],
    label: &'static str,
) -> Result<T, HandoffAdmissionError> {
    serde_json::from_slice(bytes).map_err(|_| HandoffAdmissionError::Invalid(label))
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<[u8; 32], HandoffAdmissionError> {
    let bytes =
        serde_jcs::to_vec(value).map_err(|_| HandoffAdmissionError::Invalid("canonical json"))?;
    Ok(sha256_bytes(&bytes))
}

fn canonical_json_hash(bytes: &[u8]) -> Result<[u8; 32], HandoffAdmissionError> {
    let value: serde_json::Value = parse(bytes, "json")?;
    canonical_hash(&value)
}
