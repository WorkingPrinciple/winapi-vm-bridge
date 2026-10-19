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
