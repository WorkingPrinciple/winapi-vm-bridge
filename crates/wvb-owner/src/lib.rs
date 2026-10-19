//! Typed Runtime Owner operations and deterministic multi-host selection.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wvb_receipt::{LoadedFile, RuntimeIdentity, RuntimeReceipt};
use wvb_state::{OperationRecord, OperationStatus, Store, TerminalReceiptCommit};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HostKind {
    LocalWindowsArm64,
    AuthoritativeWindowsX64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCapability {
    pub host_id: String,
    pub kind: HostKind,
    pub ready: bool,
    pub authoritative: bool,
    pub profiles: BTreeSet<String>,
    pub maximum_payload_bytes: u64,
    pub capability_revision: u64,
}

pub trait HostProbe {
    fn discover(&self) -> Result<Vec<HostCapability>, OwnerError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRequirement {
    pub profile: String,
    pub require_authoritative: bool,
    pub require_x64: bool,
    pub payload_bytes: u64,
}

#[derive(Debug, Default)]
pub struct HostCatalog {
    hosts: BTreeMap<String, HostCapability>,
}

impl HostCatalog {
    pub fn refresh(&mut self, probe: &dyn HostProbe) -> Result<(), OwnerError> {
        let discovered = probe.discover()?;
        let mut hosts = BTreeMap::new();
        for host in discovered {
            if host.host_id.is_empty()
                || host.profiles.is_empty()
                || host.maximum_payload_bytes == 0
                || hosts.insert(host.host_id.clone(), host).is_some()
            {
                return Err(OwnerError::InvalidCapability);
            }
        }
        self.hosts = hosts;
        Ok(())
    }

    pub fn select(&self, requirement: &HostRequirement) -> Result<&HostCapability, OwnerError> {
        self.hosts
            .values()
            .filter(|host| {
                host.ready
                    && host.profiles.contains(&requirement.profile)
                    && host.maximum_payload_bytes >= requirement.payload_bytes
                    && (!requirement.require_authoritative || host.authoritative)
                    && (!requirement.require_x64 || host.kind == HostKind::AuthoritativeWindowsX64)
            })
            .min_by_key(|host| {
                let kind_rank = match host.kind {
                    HostKind::LocalWindowsArm64 if !requirement.require_authoritative => 0,
                    HostKind::AuthoritativeWindowsX64 => 1,
                    HostKind::LocalWindowsArm64 => 2,
                };
                (
                    kind_rank,
                    std::cmp::Reverse(host.capability_revision),
                    &host.host_id,
                )
            })
            .ok_or(OwnerError::NoCompatibleHost)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeOwnerOperation {
    InstallBundle {
        bundle_sha256: [u8; 32],
    },
    ActivateBundle {
        bundle_sha256: [u8; 32],
    },
    RollbackBundle {
        bundle_sha256: [u8; 32],
    },
    Execute {
        bundle_sha256: [u8; 32],
        operation_id: u32,
        request_sha256: [u8; 32],
    },
    QueryReceipt {
        receipt_id: [u8; 16],
    },
    Diagnose {
        host_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptCorrelation {
    pub workload_id: [u8; 16],
    pub attempt_id: [u8; 16],
    pub receipt_id: [u8; 16],
    pub host_id: String,
    pub bundle_sha256: [u8; 32],
    pub contract_sha256: [u8; 32],
    pub operation_id: u32,
    pub request_sha256: [u8; 32],
    pub expected_response_sha256: [u8; 32],
    pub authorization_receipt_sha256: [u8; 32],
    pub challenge_sha256: [u8; 32],
    pub sequence: u64,
    pub runtime_key_id: [u8; 32],
    pub expected_runtime_identity: RuntimeIdentity,
    pub expected_loaded_files: Vec<LoadedArtifact>,
}

impl AttemptCorrelation {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OwnerError> {
        if self.host_id.is_empty()
            || self.workload_id == [0; 16]
            || self.attempt_id == [0; 16]
            || self.receipt_id == [0; 16]
            || self.bundle_sha256 == [0; 32]
            || self.contract_sha256 == [0; 32]
            || self.request_sha256 == [0; 32]
            || self.expected_response_sha256 == [0; 32]
            || self.authorization_receipt_sha256 == [0; 32]
            || self.challenge_sha256 == [0; 32]
            || self.runtime_key_id == [0; 32]
            || self.sequence == 0
            || self.operation_id == 0
            || self.expected_runtime_identity.host_id != self.host_id
            || self.expected_loaded_files.is_empty()
        {
            return Err(OwnerError::InvalidCorrelation);
        }
        serde_jcs::to_vec(self).map_err(|_| OwnerError::InvalidCorrelation)
    }

    pub fn sha256(&self) -> Result<[u8; 32], OwnerError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }

    pub fn operation_record(
        &self,
        actor_id: [u8; 16],
        now_unix_ms: u64,
        trace_id: [u8; 16],
    ) -> Result<OperationRecord, OwnerError> {
        Ok(OperationRecord {
            operation_id: self.attempt_id,
            operation_type: String::from("runtime-owner-attempt"),
            actor_id,
            target_hash: self.bundle_sha256,
            status: OperationStatus::Queued,
            stage: 0,
            attempt: 1,
            idempotency_hash: Some(self.sha256()?),
            retryable: true,
            cancellable: true,
            rerunnable: false,
            created_unix_ms: now_unix_ms,
            updated_unix_ms: now_unix_ms,
            started_unix_ms: None,
            completed_unix_ms: None,
            trace_id,
            terminal_receipt_id: None,
            detail: self.canonical_bytes()?,
        })
    }

    pub fn complete_with_receipt(
        &mut self,
        store: &mut Store,
        input: TerminalReceiptInput,
    ) -> Result<EmittedReceipt, OwnerError> {
        let receipt = input.receipt;
        let expected_loaded_files: Vec<LoadedFile> = self
            .expected_loaded_files
            .iter()
            .map(|file| LoadedFile {
                path: file.path.clone(),
                sha256: hex(&file.sha256),
            })
            .collect();
        if receipt.verify(&input.public_key).is_err()
            || receipt.receipt_id != uuid_text(self.receipt_id)
            || receipt.bundle_sha256 != hex(&self.bundle_sha256)
            || receipt.contract_sha256 != hex(&self.contract_sha256)
            || receipt.operation_id != self.operation_id
            || receipt.request_sha256 != hex(&self.request_sha256)
            || receipt.response_sha256 != hex(&self.expected_response_sha256)
            || receipt.authorization_receipt_sha256 != hex(&self.authorization_receipt_sha256)
            || receipt.challenge_sha256 != hex(&self.challenge_sha256)
            || receipt.sequence != self.sequence
            || receipt.authentication.key_id != hex(&self.runtime_key_id)
            || receipt.runtime_identity != self.expected_runtime_identity
            || receipt.loaded_files != expected_loaded_files
        {
            return Err(OwnerError::InvalidCorrelation);
        }
        let mut operation = store
            .operation(self.attempt_id)
            .map_err(|_| OwnerError::State)?
            .ok_or(OwnerError::State)?;
        if operation.status != OperationStatus::Running {
            return Err(OwnerError::State);
        }
        if operation.operation_type != "runtime-owner-attempt"
            || operation.target_hash != self.bundle_sha256
            || operation.idempotency_hash != Some(self.sha256()?)
            || serde_json::from_slice::<AttemptCorrelation>(&operation.detail)
                .map_err(|_| OwnerError::State)?
                != *self
        {
            return Err(OwnerError::InvalidCorrelation);
        }
        let receipt_bytes = receipt.canonical_bytes().map_err(|_| OwnerError::Receipt)?;
        operation.status = terminal_operation_status(&receipt);
        operation.stage = operation.stage.checked_add(1).ok_or(OwnerError::State)?;
        operation.updated_unix_ms = input.completed_unix_ms;
        operation.completed_unix_ms = Some(input.completed_unix_ms);
        operation.cancellable = false;
        operation.terminal_receipt_id = Some(self.receipt_id);
        operation.detail = self.canonical_bytes()?;
        store
            .commit_terminal_operation(
                OperationStatus::Running,
                &operation,
                &TerminalReceiptCommit {
                    receipt_id: self.receipt_id,
                    request_hash: Some(self.request_sha256),
                    terminal_status: i32::from(operation.status != OperationStatus::Succeeded),
                    receipt_payload: &receipt_bytes,
                    audit_payload: b"runtime owner terminal receipt",
                },
            )
            .map_err(|_| OwnerError::State)?;
        Ok(EmittedReceipt {
            receipt,
            public_key: input.public_key,
            operation,
        })
    }
}

fn terminal_operation_status(receipt: &RuntimeReceipt) -> OperationStatus {
    if receipt.status == "ok"
        && matches!(receipt.cleanup.status.as_str(), "verified" | "not-required")
    {
        OperationStatus::Succeeded
    } else if receipt.status == "cancelled" {
        OperationStatus::Canceled
    } else {
        OperationStatus::Failed
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedArtifact {
    pub path: String,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalReceiptInput {
    pub receipt: RuntimeReceipt,
    pub public_key: Vec<u8>,
    pub completed_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedReceipt {
    pub receipt: RuntimeReceipt,
    pub public_key: Vec<u8>,
    pub operation: OperationRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerError {
    Discovery,
    InvalidCapability,
    NoCompatibleHost,
    InvalidCorrelation,
    State,
    Receipt,
}

fn hex(value: &[u8]) -> String {
    use std::fmt::Write;

    value.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
        output
    })
}

fn uuid_text(value: [u8; 16]) -> String {
    let hex = hex(&value);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

impl std::fmt::Display for OwnerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for OwnerError {}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticProbe(Vec<HostCapability>);

    impl HostProbe for StaticProbe {
        fn discover(&self) -> Result<Vec<HostCapability>, OwnerError> {
            Ok(self.0.clone())
        }
    }

    fn host(id: &str, kind: HostKind, authoritative: bool, profiles: &[&str]) -> HostCapability {
        HostCapability {
            host_id: String::from(id),
            kind,
            ready: true,
            authoritative,
            profiles: profiles.iter().map(|value| String::from(*value)).collect(),
            maximum_payload_bytes: 1024 * 1024,
            capability_revision: 1,
        }
    }

    fn terminal_input(correlation: &AttemptCorrelation, host_id: String) -> TerminalReceiptInput {
        let mut receipt = RuntimeReceipt {
            schema: String::from(wvb_receipt::RECEIPT_IDENTIFIER),
            receipt_id: uuid_text(correlation.receipt_id),
            bundle_sha256: hex(&correlation.bundle_sha256),
            contract_sha256: hex(&correlation.contract_sha256),
            dispatcher_abi: String::from(wvb_receipt::DISPATCHER_ABI),
            operation_id: correlation.operation_id,
            request_sha256: hex(&correlation.request_sha256),
            response_sha256: hex(&correlation.expected_response_sha256),
            status: String::from("ok"),
            runtime_identity: RuntimeIdentity {
                host_id,
                ..correlation.expected_runtime_identity.clone()
            },
            loaded_files: correlation
                .expected_loaded_files
                .iter()
                .map(|file| LoadedFile {
                    path: file.path.clone(),
                    sha256: hex(&file.sha256),
                })
                .collect(),
            authorization_receipt_sha256: hex(&correlation.authorization_receipt_sha256),
            challenge_sha256: hex(&correlation.challenge_sha256),
            sequence: correlation.sequence,
            started_at: String::from("2026-10-18T00:00:00Z"),
            completed_at: String::from("2026-10-18T00:00:01Z"),
            cleanup: wvb_receipt::Cleanup {
                status: String::from("verified"),
                diagnostics: Vec::new(),
            },
            authentication: wvb_receipt::Authentication {
                scheme: String::new(),
                key_id: String::new(),
                signed_payload_sha256: String::new(),
                signature: String::new(),
            },
        };
        let seed = [9; 32];
        receipt.sign(&seed).unwrap();
        TerminalReceiptInput {
            receipt,
            public_key: wvb_receipt::public_key(&seed).unwrap(),
            completed_unix_ms: 12,
        }
    }

    fn correlation() -> AttemptCorrelation {
        let public_key = wvb_receipt::public_key(&[9; 32]).unwrap();
        AttemptCorrelation {
            workload_id: [1; 16],
            attempt_id: [2; 16],
            receipt_id: [8; 16],
            host_id: String::from("windows-x64"),
            bundle_sha256: [3; 32],
            contract_sha256: [10; 32],
            operation_id: 7,
            request_sha256: [11; 32],
            expected_response_sha256: [12; 32],
            authorization_receipt_sha256: [14; 32],
            challenge_sha256: [15; 32],
            sequence: 1,
            runtime_key_id: Sha256::digest(&public_key).into(),
            expected_runtime_identity: RuntimeIdentity {
                host_id: String::from("windows-x64"),
                os_build: String::from("Windows 11"),
                architecture: String::from("x86-64"),
                bridge_version: String::from("0.2.0"),
            },
            expected_loaded_files: vec![LoadedArtifact {
                path: String::from("dispatcher.dll"),
                sha256: [13; 32],
            }],
        }
    }

    #[test]
    fn selection_prefers_local_arm64_but_routes_x64_to_authority() {
        let mut catalog = HostCatalog::default();
        catalog
            .refresh(&StaticProbe(vec![
                host(
                    "local-arm64",
                    HostKind::LocalWindowsArm64,
                    false,
                    &["managed-anycpu"],
                ),
                host(
                    "windows-x64",
                    HostKind::AuthoritativeWindowsX64,
                    true,
                    &["managed-anycpu", "native-x64"],
                ),
            ]))
            .unwrap();
        assert_eq!(
            catalog
                .select(&HostRequirement {
                    profile: String::from("managed-anycpu"),
                    require_authoritative: false,
                    require_x64: false,
                    payload_bytes: 10,
                })
                .unwrap()
                .host_id,
            "local-arm64"
        );
        assert_eq!(
            catalog
                .select(&HostRequirement {
                    profile: String::from("native-x64"),
                    require_authoritative: true,
                    require_x64: true,
                    payload_bytes: 10,
                })
                .unwrap()
                .host_id,
            "windows-x64"
        );
    }

    #[test]
    fn attempt_correlation_binds_durable_operation_and_receipt() {
        let correlation = correlation();
        let operation = correlation.operation_record([5; 16], 10, [6; 16]).unwrap();
        assert_eq!(operation.operation_id, correlation.attempt_id);
        assert_eq!(operation.target_hash, correlation.bundle_sha256);
        assert_eq!(
            operation.idempotency_hash,
            Some(correlation.sha256().unwrap())
        );
        assert_eq!(
            serde_json::from_slice::<AttemptCorrelation>(&operation.detail).unwrap(),
            correlation
        );
    }

    #[test]
    fn terminal_receipt_and_attempt_commit_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owner.db");
        let actor_id = [5; 16];
        let mut store = Store::open(&path).unwrap();
        store
            .commit_pairing(
                &wvb_state::ActorRecord {
                    actor_id,
                    public_key: [7; 32],
                    label: String::from("runtime owner"),
                    active: true,
                },
                &[],
                b"owner paired",
            )
            .unwrap();
        let mut correlation = correlation();
        let mut operation = correlation.operation_record(actor_id, 10, [6; 16]).unwrap();
        store
            .create_operation(&operation, b"attempt created")
            .unwrap();
        operation.status = OperationStatus::Running;
        operation.stage = 1;
        operation.updated_unix_ms = 11;
        operation.started_unix_ms = Some(11);
        store
            .transition_operation(OperationStatus::Queued, &operation, b"attempt running")
            .unwrap();
        let receipt_id = correlation.receipt_id;
        let mut wrong = correlation.clone();
        wrong.host_id = String::from("other-host");
        assert_eq!(
            wrong.complete_with_receipt(
                &mut store,
                terminal_input(&correlation, wrong.host_id.clone()),
            ),
            Err(OwnerError::InvalidCorrelation)
        );
        assert!(store.receipt(receipt_id).unwrap().is_none());
        let mut wrong_host_input = terminal_input(&correlation, String::from("other-host"));
        assert_eq!(
            correlation
                .clone()
                .complete_with_receipt(&mut store, wrong_host_input.clone()),
            Err(OwnerError::InvalidCorrelation)
        );
        wrong_host_input.receipt.runtime_identity.host_id = correlation.host_id.clone();
        wrong_host_input.receipt.request_sha256 = hex(&[99; 32]);
        wrong_host_input.receipt.sign(&[9; 32]).unwrap();
        assert_eq!(
            correlation
                .clone()
                .complete_with_receipt(&mut store, wrong_host_input),
            Err(OwnerError::InvalidCorrelation)
        );
        assert!(store.receipt(receipt_id).unwrap().is_none());
        let emitted = correlation
            .complete_with_receipt(
                &mut store,
                terminal_input(&correlation, correlation.host_id.clone()),
            )
            .unwrap();
        emitted.receipt.verify(&emitted.public_key).unwrap();
        assert_eq!(emitted.operation.status, OperationStatus::Succeeded);
        assert_eq!(
            store.receipt(receipt_id).unwrap().unwrap().payload,
            emitted.receipt.canonical_bytes().unwrap()
        );
        let restored = store.operation(correlation.attempt_id).unwrap().unwrap();
        assert_eq!(restored.terminal_receipt_id, Some(receipt_id));
        assert_eq!(
            serde_json::from_slice::<AttemptCorrelation>(&restored.detail)
                .unwrap()
                .receipt_id,
            receipt_id
        );
    }

    #[test]
    fn successful_status_requires_honest_cleanup() {
        let correlation = correlation();
        let mut input = terminal_input(&correlation, correlation.host_id.clone());
        input.receipt.cleanup.status = String::from("failed");
        input.receipt.cleanup.diagnostics = vec![String::from("owned child remained active")];
        input.receipt.sign(&[9; 32]).unwrap();
        assert_eq!(
            terminal_operation_status(&input.receipt),
            OperationStatus::Failed
        );
    }
}
