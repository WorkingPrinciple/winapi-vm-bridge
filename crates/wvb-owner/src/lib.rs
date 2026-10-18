//! Typed Runtime Owner operations and deterministic multi-host selection.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wvb_state::{OperationRecord, OperationStatus};

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerError {
    Discovery,
    InvalidCapability,
    NoCompatibleHost,
    InvalidCorrelation,
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
}
