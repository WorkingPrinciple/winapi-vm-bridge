use serde::{Deserialize, Serialize};
use wvb_authz::{ActorId, Registry};
use wvb_integrity::{sha256_bytes, validate_portable_relative_path};

use crate::{BoundFrozenHandoff, Custody, FileIdentity, OperationAdmission};

const EXPECTATIONS_SCHEMA: &str = "whiny.correlated-runtime-expectations.v1";
const ADMISSION_SCHEMA: &str = "whiny.correlated-runtime-admission.v1";

#[derive(Debug, Clone, Copy)]
pub struct CorrelatedEvidenceInputs<'a> {
    pub expectations: &'a [u8],
    pub admission: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelatedEvidenceApproval {
    pub expectations_sha256: [u8; 32],
    pub admission_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundCorrelatedEvidence {
    expectations_sha256: [u8; 32],
    admission_sha256: [u8; 32],
    contract_sha256: [u8; 32],
    operation: OperationAdmission,
    adapter: String,
    qualification: String,
    correlation_id: String,
    receipt_id: String,
    host_id: String,
    key_id: [u8; 32],
    authorization_receipt_sha256: [u8; 32],
    challenge_sha256: [u8; 32],
    sequence: u64,
    request_sha256: [u8; 32],
    response_sha256: [u8; 32],
    loaded_files: Vec<FileDigest>,
    cleanup: Cleanup,
}

impl BoundCorrelatedEvidence {
    #[must_use]
    pub fn expectations_sha256(&self) -> [u8; 32] {
        self.expectations_sha256
    }

    #[must_use]
    pub fn admission_sha256(&self) -> [u8; 32] {
        self.admission_sha256
    }

    #[must_use]
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    #[must_use]
    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    #[must_use]
    pub fn key_id(&self) -> [u8; 32] {
        self.key_id
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
    pub fn request_sha256(&self) -> [u8; 32] {
        self.request_sha256
    }

    #[must_use]
    pub fn response_sha256(&self) -> [u8; 32] {
        self.response_sha256
    }

    #[must_use]
    pub fn loaded_files(&self) -> &[FileDigest] {
        &self.loaded_files
    }

    #[must_use]
    pub fn cleanup(&self) -> &Cleanup {
        &self.cleanup
    }

    pub fn authorize_runtime_operation(
        &self,
        registry: &Registry,
        actor_id: ActorId,
        now_unix_ms: u64,
    ) -> Result<(), CorrelatedEvidenceError> {
        registry
            .authorize_invoke(
                actor_id,
                self.contract_sha256,
                self.operation.operation_id,
                now_unix_ms,
            )
            .map_err(CorrelatedEvidenceError::Authorization)?;
        Err(CorrelatedEvidenceError::RuntimeAuthorityUnsupported {
            adapter: self.adapter.clone(),
            qualification: self.qualification.clone(),
        })
    }
}

#[derive(Debug)]
pub enum CorrelatedEvidenceError {
    Authorization(wvb_authz::AuthorizationError),
    Invalid(&'static str),
    Binding(&'static str),
    RuntimeAuthorityUnsupported {
        adapter: String,
        qualification: String,
    },
}

impl std::fmt::Display for CorrelatedEvidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CorrelatedEvidenceError {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expectations {
    schema: String,
    correlation_id: String,
    qualification: String,
    support_claim: String,
    registry: RegistryIdentity,
    handoff: HandoffIdentity,
    contract: ContractIdentity,
    bundle_sha256: String,
    build_receipt_sha256: String,
    dispatcher: DispatcherIdentity,
    provider: FileIdentity,
    candidate: FileIdentity,
    operation: PublicOperation,
    runtime: RuntimeExpectations,
    source_revision: String,
    custody: Custody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryIdentity {
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractIdentity {
    file_sha256: String,
    canonical_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatcherIdentity {
    abi: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicOperation {
    id: u32,
    request_schema_id: u32,
    response_schema_id: u32,
}

#[derive(Debug, Serialize, Deserialize)]
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
    response_sha256: String,
    loaded_files: Vec<FileDigest>,
    cleanup: Cleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileDigest {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cleanup {
    pub status: String,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    schema: String,
    correlation_id: String,
    expectations_sha256: String,
    receipt_sha256: String,
    registry: RegistryIdentity,
    handoff: HandoffIdentity,
    runtime: AdmittedRuntime,
    evidence_admitted: bool,
    receipt_eligible: bool,
    qualification: String,
    runtime_support: bool,
    source_revision: String,
    custody: Custody,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmittedRuntime {
    receipt_id: String,
    host_id: String,
    key_id: String,
    challenge_sha256: String,
    sequence: u64,
    status: String,
    cleanup: Cleanup,
}

impl BoundFrozenHandoff {
    pub fn bind_correlated_evidence(
        &self,
        approval: &CorrelatedEvidenceApproval,
        inputs: CorrelatedEvidenceInputs<'_>,
    ) -> Result<BoundCorrelatedEvidence, CorrelatedEvidenceError> {
        let expectations: Expectations = serde_json::from_slice(inputs.expectations)
            .map_err(|_| CorrelatedEvidenceError::Invalid("expectations"))?;
        let admission: Admission = serde_json::from_slice(inputs.admission)
            .map_err(|_| CorrelatedEvidenceError::Invalid("admission"))?;
        let expectations_sha256 = canonical_hash(&expectations)?;
        let admission_sha256 = canonical_hash(&admission)?;
        if expectations_sha256 != approval.expectations_sha256
            || admission_sha256 != approval.admission_sha256
        {
            return Err(CorrelatedEvidenceError::Binding("approved hashes"));
        }
        self.bind_expectations(&expectations)?;
        bind_admission(&expectations, &admission, expectations_sha256)?;
        let runtime = expectations.runtime;
        Ok(BoundCorrelatedEvidence {
            expectations_sha256,
            admission_sha256,
            contract_sha256: self.admitted.contract_sha256(),
            operation: self.operation,
            adapter: self.adapter.clone(),
            qualification: expectations.qualification,
            correlation_id: expectations.correlation_id,
            receipt_id: runtime.receipt_id,
            host_id: runtime.host_id,
            key_id: decode_hash(&runtime.key_id)?,
            authorization_receipt_sha256: decode_hash(&runtime.authorization_receipt_sha256)?,
            challenge_sha256: decode_hash(&runtime.challenge_sha256)?,
            sequence: runtime.sequence,
            request_sha256: decode_hash(&runtime.request_sha256)?,
            response_sha256: decode_hash(&runtime.response_sha256)?,
            loaded_files: runtime.loaded_files,
            cleanup: runtime.cleanup,
        })
    }

    fn bind_expectations(&self, value: &Expectations) -> Result<(), CorrelatedEvidenceError> {
        if value.schema != EXPECTATIONS_SCHEMA
            || value.correlation_id.is_empty()
            || value.qualification != "development-only"
            || value.support_claim != "none"
            || value.registry.sha256 != hex(self.registry_sha256)
            || value.registry.registry_id != self.registry_id
            || value.registry.entry_sha256 != hex(self.registry_entry_sha256)
            || value.handoff.sha256 != hex(self.handoff_sha256)
            || value.handoff.handoff_id != self.handoff_id
            || value.contract.file_sha256 != hex(self.contract_file_sha256)
            || value.contract.canonical_sha256 != hex(self.admitted.contract_sha256())
            || value.bundle_sha256 != hex(self.admitted.bundle_descriptor_sha256())
            || value.build_receipt_sha256 != hex(self.build_receipt_sha256)
            || value.dispatcher.abi != crate::DISPATCHER_ABI_IDENTIFIER
            || value.dispatcher.path != self.dispatcher_path
            || value.dispatcher.sha256 != hex(self.dispatcher_sha256)
            || value.provider != self.provider
            || value.candidate != self.candidate
            || value.operation
                != (PublicOperation {
                    id: self.operation.operation_id,
                    request_schema_id: self.operation.request_schema_id,
                    response_schema_id: self.operation.response_schema_id,
                })
            || value.source_revision != self.source_revision
            || value.custody != self.custody
        {
            return Err(CorrelatedEvidenceError::Binding(
                "expectation handoff chain",
            ));
        }
        validate_runtime(&value.runtime, &self.candidate)
    }
}

fn validate_runtime(
    value: &RuntimeExpectations,
    candidate: &FileIdentity,
) -> Result<(), CorrelatedEvidenceError> {
    if value.receipt_id.is_empty()
        || value.host_id.is_empty()
        || value.sequence == 0
        || !matches!(
            value.cleanup.status.as_str(),
            "verified" | "failed" | "not-required" | "unknown"
        )
        || value
            .cleanup
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains('\0'))
    {
        return Err(CorrelatedEvidenceError::Invalid("runtime expectations"));
    }
    for hash in [
        &value.policy_sha256,
        &value.key_id,
        &value.authorization_receipt_sha256,
        &value.challenge_sha256,
        &value.request_sha256,
        &value.response_sha256,
    ] {
        decode_hash(hash)?;
    }
    if value.loaded_files.is_empty() {
        return Err(CorrelatedEvidenceError::Invalid("loaded files"));
    }
    let mut paths = std::collections::BTreeSet::new();
    for file in &value.loaded_files {
        decode_hash(&file.sha256)?;
        if validate_portable_relative_path(&file.path).is_err()
            || !paths.insert(file.path.to_ascii_lowercase())
        {
            return Err(CorrelatedEvidenceError::Invalid("loaded file path"));
        }
    }
    if !value.loaded_files.iter().any(|file| {
        file.path.eq_ignore_ascii_case(&candidate.path) && file.sha256 == candidate.sha256
    }) {
        return Err(CorrelatedEvidenceError::Binding("candidate loaded file"));
    }
    Ok(())
}

fn bind_admission(
    expectations: &Expectations,
    value: &Admission,
    expectations_sha256: [u8; 32],
) -> Result<(), CorrelatedEvidenceError> {
    if value.schema != ADMISSION_SCHEMA
        || value.correlation_id != expectations.correlation_id
        || value.expectations_sha256 != hex(expectations_sha256)
        || decode_hash(&value.receipt_sha256).is_err()
        || value.registry != expectations.registry
        || value.handoff != expectations.handoff
        || value.runtime.receipt_id != expectations.runtime.receipt_id
        || value.runtime.host_id != expectations.runtime.host_id
        || value.runtime.key_id != expectations.runtime.key_id
        || value.runtime.challenge_sha256 != expectations.runtime.challenge_sha256
        || value.runtime.sequence != expectations.runtime.sequence
        || value.runtime.cleanup != expectations.runtime.cleanup
        || !matches!(
            value.runtime.status.as_str(),
            "ok" | "invalid-request"
                | "operation-unknown"
                | "target-failure"
                | "timeout"
                | "cancelled"
                | "internal"
        )
        || !value.evidence_admitted
        || value.qualification != "development-only"
        || value.runtime_support
        || value.source_revision != expectations.source_revision
        || value.custody != expectations.custody
    {
        return Err(CorrelatedEvidenceError::Binding("runtime admission"));
    }
    Ok(())
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<[u8; 32], CorrelatedEvidenceError> {
    let bytes =
        serde_jcs::to_vec(value).map_err(|_| CorrelatedEvidenceError::Invalid("canonical json"))?;
    Ok(sha256_bytes(&bytes))
}

fn decode_hash(value: &str) -> Result<[u8; 32], CorrelatedEvidenceError> {
    if value.len() != 64 {
        return Err(CorrelatedEvidenceError::Invalid("sha256"));
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| CorrelatedEvidenceError::Invalid("sha256"))?;
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
