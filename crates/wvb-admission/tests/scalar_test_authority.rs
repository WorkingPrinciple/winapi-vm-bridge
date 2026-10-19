use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use tempfile::tempdir;
use wvb_admission::{
    AdmissionEngine, ScalarProfile, ScalarTestAuthorityApproval, ScalarTestAuthorityError,
    WHINY_SCALAR_ARTIFACTS_MANIFEST_SHA256, WHINY_SCALAR_AUTHORITY_REGISTRY_SHA256,
    WHINY_SCALAR_SOURCE_EVIDENCE_SHA256,
};
use wvb_authz::{Grant, Registry, Role};
use wvb_integrity::sha256_file;

const CALLER: [u8; 16] = [7; 16];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../runtime-artifacts/whiny-v0.3.0/acceptance/scalar-test-artifacts")
}

fn bind(path: &Path) -> Result<wvb_admission::BoundScalarTestAuthority, ScalarTestAuthorityError> {
    AdmissionEngine::new(path)
        .unwrap()
        .bind_scalar_test_authority(&approval(path))
}

fn approval(path: &Path) -> ScalarTestAuthorityApproval {
    ScalarTestAuthorityApproval {
        manifest_sha256: sha256_file(&path.join("scalar-test-artifacts.json")).unwrap(),
        registry_sha256: sha256_file(&path.join("authority-registry.json")).unwrap(),
        ..ScalarTestAuthorityApproval::default()
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_jcs::to_vec(value).unwrap()).unwrap();
}

fn update_manifest_hash(root: &Path, profile: &str, field: &str, path: &Path) {
    let manifest_path = root.join("scalar-test-artifacts.json");
    let mut manifest = read_json(&manifest_path);
    let profile = manifest["profiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|value| value["name"] == profile)
        .unwrap();
    profile[field]["sha256"] = json!(hex(sha256_file(path).unwrap()));
    write_json(&manifest_path, &manifest);
}

fn update_manifest_file_hash(root: &Path, field: &str, path: &Path) {
    let manifest_path = root.join("scalar-test-artifacts.json");
    let mut manifest = read_json(&manifest_path);
    manifest[field]["sha256"] = json!(hex(sha256_file(path).unwrap()));
    write_json(&manifest_path, &manifest);
}

fn hex(value: [u8; 32]) -> String {
    use std::fmt::Write;

    value.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").unwrap();
        output
    })
}

#[test]
fn exact_whiny_scalar_authority_binds_without_importing_private_replay_state() {
    let root = root();
    assert_eq!(
        sha256_file(&root.join("scalar-test-artifacts.json")).unwrap(),
        WHINY_SCALAR_ARTIFACTS_MANIFEST_SHA256
    );
    assert_eq!(
        sha256_file(&root.join("authority-registry.json")).unwrap(),
        WHINY_SCALAR_AUTHORITY_REGISTRY_SHA256
    );
    assert!(!root.join("replay-state.json").exists());

    let authority = AdmissionEngine::new(&root)
        .unwrap()
        .bind_scalar_test_authority(&ScalarTestAuthorityApproval::default())
        .unwrap();
    authority.reverify_files().unwrap();
    assert_eq!(
        hex(authority.source_replay_state_sha256()),
        "c6269edc801213a0bdc8ccac590f6e419b7aad6a08671d2d25bc56d59e85b56a"
    );
    assert_eq!(
        authority.source_evidence_sha256(),
        WHINY_SCALAR_SOURCE_EVIDENCE_SHA256
    );
    for profile in [ScalarProfile::Native, ScalarProfile::Managed] {
        let bound = authority.profile(profile).unwrap();
        assert_eq!(bound.qualification(), "development-only");
        assert_eq!(bound.support_claim(), "none");
        assert!(!bound.runtime_support());
        assert_eq!(bound.operation().operation_id, 1);
        assert_eq!(
            bound.replay_state_sha256(),
            authority.source_replay_state_sha256()
        );
    }
}

#[test]
fn exact_external_invoke_is_required_and_only_authorizes_test_execution() {
    let authority = bind(&root()).unwrap();
    for profile in [ScalarProfile::Native, ScalarProfile::Managed] {
        let bound = authority.profile(profile).unwrap();
        let mut registry = Registry::default();
        registry.register(CALLER, [9; 32]).unwrap();
        assert!(matches!(
            bound.authorize_test_execution(&registry, CALLER, 1),
            Err(ScalarTestAuthorityError::Authorization(_))
        ));
        registry
            .grant(
                CALLER,
                Grant {
                    role: Role::Invoke,
                    adapter_hash: Some([0; 32]),
                    operation_id: Some(bound.operation().operation_id),
                    expires_at_unix_ms: None,
                },
            )
            .unwrap();
        assert!(matches!(
            bound.authorize_test_execution(&registry, CALLER, 1),
            Err(ScalarTestAuthorityError::Authorization(_))
        ));

        let mut exact = Registry::default();
        exact.register(CALLER, [9; 32]).unwrap();
        exact
            .grant(
                CALLER,
                Grant {
                    role: Role::Invoke,
                    adapter_hash: Some(bound.contract_sha256()),
                    operation_id: Some(bound.operation().operation_id),
                    expires_at_unix_ms: None,
                },
            )
            .unwrap();
        let authorization = bound.authorize_test_execution(&exact, CALLER, 1).unwrap();
        assert_eq!(
            authorization.authorization_state(),
            "test-execution-authorized"
        );
        assert_eq!(authorization.qualification(), "development-only");
        assert_eq!(authorization.contract_sha256(), bound.contract_sha256());
        assert_eq!(authorization.bundle_sha256(), bound.bundle_sha256());
    }
}

#[test]
fn self_consistent_replacement_chain_cannot_override_frozen_pin() {
    let temporary = tempdir().unwrap();
    copy_tree(&root(), temporary.path());
    let policy_path = temporary.path().join("runtime-trust-policy.json");
    let mut policy = read_json(&policy_path);
    policy["source_policy_sha256"] = json!("44".repeat(32));
    write_json(&policy_path, &policy);
    update_manifest_file_hash(temporary.path(), "trust_policy", &policy_path);
    assert!(matches!(
        bind(temporary.path()),
        Err(ScalarTestAuthorityError::Binding(
            "frozen scalar artifact pin"
        ))
    ));
}

#[test]
fn non_scalar_general_development_authority_is_rejected() {
    let temporary = tempdir().unwrap();
    copy_tree(&root(), temporary.path());
    let registry_path = temporary.path().join("authority-registry.json");
    let mut registry = read_json(&registry_path);
    registry["entries"][0]["profile_id"] = json!("native-cpp-bounded-x64-v1");
    write_json(&registry_path, &registry);
    let manifest_path = temporary.path().join("scalar-test-artifacts.json");
    let mut manifest = read_json(&manifest_path);
    manifest["registry"]["sha256"] = json!(hex(sha256_file(&registry_path).unwrap()));
    write_json(&manifest_path, &manifest);
    assert!(bind(temporary.path()).is_err());
}

#[test]
fn artifact_identity_drift_is_rejected() {
    let temporary = tempdir().unwrap();
    copy_tree(&root(), temporary.path());
    fs::write(
        temporary
            .path()
            .join("native-scalar/target/native_math.dll"),
        b"drift",
    )
    .unwrap();
    assert!(bind(temporary.path()).is_err());
}

#[test]
fn manifest_registry_handoff_expectation_and_admission_drift_are_rejected() {
    let manifest = tempdir().unwrap();
    copy_tree(&root(), manifest.path());
    fs::write(manifest.path().join("scalar-test-artifacts.json"), b"{}").unwrap();
    assert!(
        AdmissionEngine::new(manifest.path())
            .unwrap()
            .bind_scalar_test_authority(&ScalarTestAuthorityApproval::default())
            .is_err()
    );

    let registry = tempdir().unwrap();
    copy_tree(&root(), registry.path());
    let registry_path = registry.path().join("authority-registry.json");
    let mut registry_value = read_json(&registry_path);
    registry_value["entries"][0]["entry_id"] = json!("scalar.drifted");
    write_json(&registry_path, &registry_value);
    assert!(bind(registry.path()).is_err());

    let handoff = tempdir().unwrap();
    copy_tree(&root(), handoff.path());
    let handoff_path = handoff
        .path()
        .join("native-scalar/scalar-frozen-handoff.json");
    let mut handoff_value = read_json(&handoff_path);
    handoff_value["candidate"]["sha256"] = json!("00".repeat(32));
    write_json(&handoff_path, &handoff_value);
    update_manifest_hash(handoff.path(), "native-scalar", "handoff", &handoff_path);
    assert!(bind(handoff.path()).is_err());

    let expectations = tempdir().unwrap();
    copy_tree(&root(), expectations.path());
    let expectations_path = expectations
        .path()
        .join("managed-scalar/correlated-expectations.json");
    let mut expectations_value = read_json(&expectations_path);
    expectations_value["bundle_sha256"] = json!("11".repeat(32));
    write_json(&expectations_path, &expectations_value);
    update_manifest_hash(
        expectations.path(),
        "managed-scalar",
        "expectations",
        &expectations_path,
    );
    assert!(bind(expectations.path()).is_err());

    let admission = tempdir().unwrap();
    copy_tree(&root(), admission.path());
    let admission_path = admission
        .path()
        .join("native-scalar/correlated-admission.json");
    let mut admission_value = read_json(&admission_path);
    admission_value["runtime"]["response_sha256"] = json!("22".repeat(32));
    write_json(&admission_path, &admission_value);
    update_manifest_hash(
        admission.path(),
        "native-scalar",
        "admission",
        &admission_path,
    );
    assert!(bind(admission.path()).is_err());
}

#[test]
fn challenge_sequence_and_replay_mutations_are_rejected() {
    let challenge = tempdir().unwrap();
    copy_tree(&root(), challenge.path());
    let expectations_path = challenge
        .path()
        .join("native-scalar/correlated-expectations.json");
    let mut expectations = read_json(&expectations_path);
    expectations["policy"]["challenge_sequence"]["sequence"] = json!("unsupported");
    write_json(&expectations_path, &expectations);
    update_manifest_hash(
        challenge.path(),
        "native-scalar",
        "expectations",
        &expectations_path,
    );
    assert!(bind(challenge.path()).is_err());

    let replay = tempdir().unwrap();
    copy_tree(&root(), replay.path());
    let admission_path = replay
        .path()
        .join("managed-scalar/correlated-admission.json");
    let mut admission = read_json(&admission_path);
    admission["replay_binding"]["challenge_consumed"] = json!(false);
    write_json(&admission_path, &admission);
    update_manifest_hash(
        replay.path(),
        "managed-scalar",
        "admission",
        &admission_path,
    );
    assert!(bind(replay.path()).is_err());
}

#[test]
fn signed_receipt_and_policy_authentication_mutations_are_rejected() {
    let temporary = tempdir().unwrap();
    copy_tree(&root(), temporary.path());
    let receipt_path = temporary.path().join("native-scalar/runtime-receipt.json");
    let mut receipt = read_json(&receipt_path);
    receipt["authentication"]["signature"] = json!("00".repeat(64));
    write_json(&receipt_path, &receipt);
    update_manifest_hash(
        temporary.path(),
        "native-scalar",
        "runtime_receipt",
        &receipt_path,
    );
    assert!(bind(temporary.path()).is_err());

    let policy = tempdir().unwrap();
    copy_tree(&root(), policy.path());
    let policy_path = policy.path().join("runtime-trust-policy.json");
    let mut policy_value = read_json(&policy_path);
    policy_value["signers"][0]["public_key_hex"] = json!("00".repeat(32));
    write_json(&policy_path, &policy_value);
    update_manifest_file_hash(policy.path(), "trust_policy", &policy_path);
    assert!(bind(policy.path()).is_err());
}

#[test]
fn imported_artifacts_do_not_embed_external_authority_or_private_state() {
    fn inspect(value: &Value) {
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    let key = key.to_ascii_lowercase().replace('-', "_");
                    assert!(
                        ![
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
                            "private_key",
                            "private_state",
                        ]
                        .contains(&key.as_str()),
                        "forbidden authority field {key}"
                    );
                    inspect(child);
                }
            }
            Value::Array(values) => {
                for child in values {
                    inspect(child);
                }
            }
            _ => {}
        }
    }

    for path in [
        root().join("scalar-test-artifacts.json"),
        root().join("authority-registry.json"),
        root().join("native-scalar/scalar-frozen-handoff.json"),
        root().join("native-scalar/correlated-expectations.json"),
        root().join("native-scalar/correlated-admission.json"),
        root().join("managed-scalar/scalar-frozen-handoff.json"),
        root().join("managed-scalar/correlated-expectations.json"),
        root().join("managed-scalar/correlated-admission.json"),
    ] {
        inspect(&read_json(&path));
    }
    assert!(!root().join("replay-state.json").exists());
}
