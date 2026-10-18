use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tempfile::tempdir;
use wvb_admission::{
    AdmissionEngine, BundleFile, BundleFileKind, Compatibility, FormatVersion, FrozenInputs,
    OperationAdmission, OperatorAdmission,
};
use wvb_authz::{Grant, Registry, Role};
use wvb_integrity::sha256_bytes;
use wvb_state::{ActorRecord, BundleAdmissionRecord, GrantRecord, Store};

#[derive(Deserialize)]
struct Descriptor {
    schema: String,
    contract: Contract,
    dispatcher: Dispatcher,
    target: Target,
    dependencies: Vec<Dependency>,
    operations: Vec<Operation>,
}

#[derive(Deserialize)]
struct Contract {
    format: String,
    path: String,
    canonical_sha256: String,
}

#[derive(Deserialize)]
struct Dispatcher {
    abi: String,
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
struct Target {
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
struct Dependency {
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
struct Operation {
    id: u32,
    request_schema_id: u32,
    response_schema_id: u32,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../external/whiny/v0.3.0/frozen-bundles")
}

fn hash(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}

fn approval(directory: &Path) -> (OperatorAdmission, Vec<u8>, Vec<u8>) {
    let descriptor_bytes = fs::read(directory.join("bundle.json")).unwrap();
    let descriptor: Descriptor = serde_json::from_slice(&descriptor_bytes).unwrap();
    let contract_bytes = fs::read(directory.join(&descriptor.contract.path)).unwrap();
    assert_eq!(
        sha256_bytes(&contract_bytes),
        hash(&descriptor.contract.canonical_sha256)
    );
    let mut files = vec![
        BundleFile {
            kind: BundleFileKind::Dispatcher,
            relative_path: descriptor.dispatcher.path.clone(),
            sha256: hash(&descriptor.dispatcher.sha256),
        },
        BundleFile {
            kind: BundleFileKind::Target,
            relative_path: descriptor.target.path.clone(),
            sha256: hash(&descriptor.target.sha256),
        },
    ];
    files.extend(descriptor.dependencies.iter().map(|dependency| BundleFile {
        kind: BundleFileKind::Dependency,
        relative_path: dependency.path.clone(),
        sha256: hash(&dependency.sha256),
    }));
    let value = OperatorAdmission {
        compatibility: Compatibility {
            contract: FormatVersion {
                identifier: descriptor.contract.format.clone(),
                major: 3,
            },
            bundle: FormatVersion {
                identifier: descriptor.schema.clone(),
                major: 1,
            },
            dispatcher_abi: FormatVersion {
                identifier: descriptor.dispatcher.abi.clone(),
                major: 1,
            },
        },
        contract_sha256: hash(&descriptor.contract.canonical_sha256),
        bundle_descriptor_sha256: sha256_bytes(&descriptor_bytes),
        files,
        operations: descriptor
            .operations
            .iter()
            .map(|operation| OperationAdmission {
                operation_id: operation.id,
                request_schema_id: operation.request_schema_id,
                response_schema_id: operation.response_schema_id,
            })
            .collect(),
    };
    (value, contract_bytes, descriptor_bytes)
}

fn persist_admission(approval: &OperatorAdmission, descriptor_bytes: &[u8], operator: [u8; 16]) {
    let state = tempdir().unwrap();
    let path = state.path().join("state.db");
    let mut store = Store::open(&path).unwrap();
    store
        .commit_pairing(
            &ActorRecord {
                actor_id: operator,
                public_key: [3; 32],
                label: String::from("bundle operator"),
                active: true,
            },
            &[GrantRecord {
                actor_id: operator,
                role: Role::AdapterAdmin as u16,
                adapter_hash: Some(approval.contract_sha256),
                operation_id: None,
                expires_unix_ms: None,
            }],
            b"operator paired",
        )
        .unwrap();
    store
        .commit_bundle_admission(
            &BundleAdmissionRecord {
                bundle_descriptor_hash: approval.bundle_descriptor_sha256,
                contract_hash: approval.contract_sha256,
                contract_format: approval.compatibility.contract.identifier.clone(),
                contract_major: approval.compatibility.contract.major,
                bundle_format: approval.compatibility.bundle.identifier.clone(),
                bundle_major: approval.compatibility.bundle.major,
                dispatcher_abi: approval.compatibility.dispatcher_abi.identifier.clone(),
                dispatcher_abi_major: approval.compatibility.dispatcher_abi.major,
                approval_payload: descriptor_bytes.to_vec(),
                admitted_by: operator,
            },
            b"bundle admitted",
        )
        .unwrap();
    drop(store);
    assert_eq!(
        Store::open(&path)
            .unwrap()
            .active_bundle_admissions()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn frozen_whiny_scalar_bundles_admit_persist_and_keep_invoke_separate() {
    for name in ["native-scalar", "managed-scalar"] {
        let directory = root().join(name);
        let (approval, contract, descriptor_bytes) = approval(&directory);
        let operator = [1; 16];
        let caller = [2; 16];
        let mut registry = Registry::default();
        registry.register(operator, [3; 32]).unwrap();
        registry.register(caller, [4; 32]).unwrap();
        registry
            .grant(
                operator,
                Grant {
                    role: Role::AdapterAdmin,
                    adapter_hash: Some(approval.contract_sha256),
                    operation_id: None,
                    expires_at_unix_ms: None,
                },
            )
            .unwrap();
        let engine = AdmissionEngine::new(&directory).unwrap();
        let admitted = engine
            .admit(
                &registry,
                operator,
                1,
                &approval,
                FrozenInputs {
                    contract: &contract,
                    bundle_descriptor: &descriptor_bytes,
                },
            )
            .unwrap();
        assert!(
            admitted
                .authorize_operation(&registry, caller, 1, 1)
                .is_err()
        );
        registry
            .grant(
                caller,
                Grant {
                    role: Role::Invoke,
                    adapter_hash: Some(approval.contract_sha256),
                    operation_id: Some(1),
                    expires_at_unix_ms: None,
                },
            )
            .unwrap();
        admitted
            .authorize_operation(&registry, caller, 1, 1)
            .unwrap();
        assert_eq!(
            admitted.operation(1).unwrap().request_schema_id,
            approval.operations[0].request_schema_id
        );
        admitted.reverify_files().unwrap();

        persist_admission(&approval, &descriptor_bytes, operator);
    }
}
