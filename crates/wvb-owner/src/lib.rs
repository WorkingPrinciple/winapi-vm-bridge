//! Typed Runtime Owner operations and deterministic multi-host selection.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wvb_receipt::{
    Authentication, Cleanup, LoadedFile, RuntimeIdentity, RuntimeReceipt, public_key,
};
use wvb_state::{OperationRecord, OperationStatus, Store, TerminalReceiptCommit};
use zeroize::Zeroize;

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
    pub host_id: String,
    pub bundle_sha256: [u8; 32],
    pub operation_id: Option<u32>,
    pub receipt_id: Option<[u8; 16]>,
}

impl AttemptCorrelation {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OwnerError> {
        if self.host_id.is_empty() {
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
        mut signing_seed: [u8; 32],
        input: TerminalReceiptInput,
    ) -> Result<EmittedReceipt, OwnerError> {
        let result = self.complete_with_receipt_inner(store, &signing_seed, input);
        signing_seed.zeroize();
        result
    }

    fn complete_with_receipt_inner(
        &mut self,
        store: &mut Store,
        signing_seed: &[u8; 32],
        input: TerminalReceiptInput,
    ) -> Result<EmittedReceipt, OwnerError> {
        if input.bundle_sha256 != self.bundle_sha256
            || input.operation_id != self.operation_id
            || input.receipt_id == [0; 16]
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
        self.receipt_id = Some(input.receipt_id);
        let status = input.status.clone();
        let mut receipt = RuntimeReceipt {
            schema: String::from(wvb_receipt::RECEIPT_IDENTIFIER),
            receipt_id: uuid_text(input.receipt_id),
            bundle_sha256: hex(&input.bundle_sha256),
            contract_sha256: hex(&input.contract_sha256),
            dispatcher_abi: String::from(wvb_receipt::DISPATCHER_ABI),
            operation_id: input.operation_id.unwrap_or(0),
            request_sha256: hex(&input.request_sha256),
            response_sha256: hex(&input.response_sha256),
            status,
            runtime_identity: input.runtime_identity,
            loaded_files: input
                .loaded_files
                .into_iter()
                .map(|file| LoadedFile {
                    path: file.path,
                    sha256: hex(&file.sha256),
                })
                .collect(),
            authorization_receipt_sha256: hex(&input.authorization_receipt_sha256),
            challenge_sha256: hex(&input.challenge_sha256),
            sequence: input.sequence,
            started_at: input.started_at,
            completed_at: input.completed_at,
            cleanup: input.cleanup,
            authentication: Authentication {
                scheme: String::new(),
                key_id: String::new(),
                signed_payload_sha256: String::new(),
                signature: String::new(),
            },
        };
        receipt
            .sign(signing_seed)
            .map_err(|_| OwnerError::Receipt)?;
        let receipt_bytes = receipt.canonical_bytes().map_err(|_| OwnerError::Receipt)?;
        operation.status = if receipt.status == "ok" {
            OperationStatus::Succeeded
        } else if receipt.status == "cancelled" {
            OperationStatus::Canceled
        } else {
            OperationStatus::Failed
        };
        operation.stage = operation.stage.checked_add(1).ok_or(OwnerError::State)?;
        operation.updated_unix_ms = input.completed_unix_ms;
        operation.completed_unix_ms = Some(input.completed_unix_ms);
        operation.cancellable = false;
        operation.terminal_receipt_id = Some(input.receipt_id);
        operation.detail = self.canonical_bytes()?;
        store
            .commit_terminal_operation(
                OperationStatus::Running,
                &operation,
                &TerminalReceiptCommit {
                    receipt_id: input.receipt_id,
                    request_hash: Some(input.request_sha256),
                    terminal_status: i32::from(receipt.status != "ok"),
                    receipt_payload: &receipt_bytes,
                    audit_payload: b"runtime owner terminal receipt",
                },
            )
            .map_err(|_| OwnerError::State)?;
        Ok(EmittedReceipt {
            receipt,
            public_key: public_key(signing_seed).map_err(|_| OwnerError::Receipt)?,
            operation,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedArtifact {
    pub path: String,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalReceiptInput {
    pub receipt_id: [u8; 16],
    pub bundle_sha256: [u8; 32],
    pub contract_sha256: [u8; 32],
    pub operation_id: Option<u32>,
    pub request_sha256: [u8; 32],
    pub response_sha256: [u8; 32],
    pub status: String,
    pub runtime_identity: RuntimeIdentity,
    pub loaded_files: Vec<LoadedArtifact>,
    pub authorization_receipt_sha256: [u8; 32],
    pub challenge_sha256: [u8; 32],
    pub sequence: u64,
    pub started_at: String,
    pub completed_at: String,
    pub completed_unix_ms: u64,
    pub cleanup: Cleanup,
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
        let correlation = AttemptCorrelation {
            workload_id: [1; 16],
            attempt_id: [2; 16],
            host_id: String::from("windows-x64"),
            bundle_sha256: [3; 32],
            operation_id: Some(7),
            receipt_id: Some([4; 16]),
        };
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
        let mut correlation = AttemptCorrelation {
            workload_id: [1; 16],
            attempt_id: [2; 16],
            host_id: String::from("windows-x64"),
            bundle_sha256: [3; 32],
            operation_id: Some(7),
            receipt_id: None,
        };
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
        let receipt_id = [8; 16];
        let emitted = correlation
            .complete_with_receipt(
                &mut store,
                [9; 32],
                TerminalReceiptInput {
                    receipt_id,
                    bundle_sha256: correlation.bundle_sha256,
                    contract_sha256: [10; 32],
                    operation_id: correlation.operation_id,
                    request_sha256: [11; 32],
                    response_sha256: [12; 32],
                    status: String::from("ok"),
                    runtime_identity: RuntimeIdentity {
                        host_id: correlation.host_id.clone(),
                        os_build: String::from("Windows 11"),
                        architecture: String::from("x86-64"),
                        bridge_version: String::from("0.2.0"),
                    },
                    loaded_files: vec![LoadedArtifact {
                        path: String::from("dispatcher.dll"),
                        sha256: [13; 32],
                    }],
                    authorization_receipt_sha256: [14; 32],
                    challenge_sha256: [15; 32],
                    sequence: 1,
                    started_at: String::from("2026-10-18T00:00:00Z"),
                    completed_at: String::from("2026-10-18T00:00:01Z"),
                    completed_unix_ms: 12,
                    cleanup: Cleanup {
                        status: String::from("verified"),
                        diagnostics: Vec::new(),
                    },
                },
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
            Some(receipt_id)
        );
    }
}
