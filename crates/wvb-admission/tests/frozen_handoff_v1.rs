use std::fs;
use std::path::Path;

use serde_json::{Value, json};
use tempfile::tempdir;
use wvb_admission::{
    AdmissionEngine, BundleFile, BundleFileKind, CorrelatedEvidenceApproval,
    CorrelatedEvidenceError, CorrelatedEvidenceInputs, FrozenHandoffApproval, FrozenHandoffInputs,
    HandoffAdmissionError, OperationAdmission, OperatorAdmission, WHINY_VALIDATOR_REVISION,
    current_compatibility,
};
use wvb_authz::{Grant, Registry, Role};
use wvb_integrity::sha256_bytes;

const OPERATOR: [u8; 16] = [1; 16];
const CALLER: [u8; 16] = [2; 16];
const OPERATION_ID: u32 = 1_879_048_193;
const REQUEST_SCHEMA_ID: u32 = 1_879_048_194;
const RESPONSE_SCHEMA_ID: u32 = 1_879_048_195;

struct Fixture {
    directory: tempfile::TempDir,
    handoff: Value,
    contract: Vec<u8>,
    bundle: Vec<u8>,
    approval: OperatorAdmission,
    registry: Registry,
}

impl Fixture {
    #[allow(clippy::too_many_lines)]
    fn new() -> Self {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::write(root.join("dispatcher.dll"), b"dispatcher").unwrap();
        fs::write(root.join("provider.dll"), b"provider").unwrap();
        fs::write(root.join("candidate.dll"), b"candidate").unwrap();
        fs::write(root.join("dispatcher.generated.c"), b"source").unwrap();
        fs::write(root.join("Makefile.generated"), b"project").unwrap();
        fs::create_dir(root.join("evidence")).unwrap();
        for (name, contents) in [
            ("provider.json", b"provider evidence".as_slice()),
            ("review.json", b"review evidence".as_slice()),
            ("events.json", b"event policy".as_slice()),
            ("absence.json", b"absence window".as_slice()),
            ("windows.json", b"window categories".as_slice()),
        ] {
            fs::write(root.join("evidence").join(name), contents).unwrap();
        }

        let operation = json!({
            "id": OPERATION_ID,
            "request_schema_id": REQUEST_SCHEMA_ID,
            "response_schema_id": RESPONSE_SCHEMA_ID
        });
        let provider = json!({
            "path": "provider.dll",
            "sha256": hex(sha256_bytes(b"provider")),
            "expected_exports": ["ProviderEntry"]
        });
        let candidate = json!({
            "path": "candidate.dll",
            "sha256": hex(sha256_bytes(b"candidate")),
            "expected_exports": ["CandidateEntry"]
        });
        let effects = json!({
            "allowed": ["temporary-windows-objects"],
            "cleanup_required": ["close-owned-handles"],
            "success_requires_cleanup": true
        });
        let challenge = json!({
            "challenge": "unsupported",
            "sequence": "unsupported",
            "correlation": "unsupported"
        });
        let custody = json!({
            "identity": "99".repeat(32),
            "direction": "frozen-bundle-to-vm-bridge",
            "request_boundary": "immutable-package-only",
            "receipt_boundary": "authenticated-correlated-only"
        });
        let entry = json!({
            "scenario_id": "windows.shell_hook.fixture",
            "profile_id": "native-c-scalar-x64-v1",
            "adapter": "shell_hook",
            "provider": provider,
            "candidate": candidate,
            "operation": operation,
            "evidence": {
                "authority": [
                    {
                        "kind": "provider-identity-receipt",
                        "path": "evidence/provider.json",
                        "sha256": file_hash(root, "evidence/provider.json")
                    },
                    {
                        "kind": "review-receipt",
                        "path": "evidence/review.json",
                        "sha256": file_hash(root, "evidence/review.json")
                    }
                ],
                "calibration": [
                    {
                        "kind": "shell-event-policy",
                        "path": "evidence/events.json",
                        "sha256": file_hash(root, "evidence/events.json")
                    },
                    {
                        "kind": "absence-window",
                        "path": "evidence/absence.json",
                        "sha256": file_hash(root, "evidence/absence.json")
                    },
                    {
                        "kind": "window-categories",
                        "path": "evidence/windows.json",
                        "sha256": file_hash(root, "evidence/windows.json")
                    }
                ],
                "helper": [],
                "runtime": []
            },
            "side_effects": effects,
            "challenge_sequence": challenge,
            "qualification": "development-only",
            "source_revision": WHINY_VALIDATOR_REVISION,
            "custody": custody
        });
        let entry_sha256 = canonical_hash(&entry);
        let authority_registry = json!({
            "schema": "whiny.authority-registry.v1",
            "registry_id": "whiny.windows.fixture_authority",
            "entries": [entry]
        });
        let authority_registry_bytes = canonical_bytes(&authority_registry);
        fs::write(
            root.join("authority-registry.json"),
            &authority_registry_bytes,
        )
        .unwrap();

        let contract_value = json!({
            "contract_id": "windows.shell_hook",
            "target": {
                "relative_path": "candidate.dll",
                "sha256": hex(sha256_bytes(b"candidate"))
            },
            "dependencies": [],
            "operations": [operation]
        });
        let contract = canonical_bytes(&contract_value);
        fs::write(root.join("contract.canonical.json"), &contract).unwrap();

        let bundle_value = json!({
            "schema": "whiny.adapter-bundle.v1",
            "bundle_id": "windows.shell_hook",
            "bundle_version": "1.0.0",
            "profile": "native-c-scalar-x64-v1",
            "contract": {
                "format": "whiny.adapter-contract.v3",
                "path": "contract.canonical.json",
                "file_sha256": hex(sha256_bytes(&contract)),
                "canonical_sha256": hex(canonical_hash(&contract_value))
            },
            "dispatcher": {
                "abi": "whiny.dispatch.v1",
                "path": "dispatcher.dll",
                "sha256": hex(sha256_bytes(b"dispatcher"))
            },
            "target": {
                "path": "candidate.dll",
                "sha256": hex(sha256_bytes(b"candidate"))
            },
            "dependencies": [],
            "operations": [operation],
            "artifacts": [
                {
                    "kind": "dispatcher-source",
                    "path": "dispatcher.generated.c",
                    "sha256": hex(sha256_bytes(b"source"))
                },
                {
                    "kind": "project",
                    "path": "Makefile.generated",
                    "sha256": hex(sha256_bytes(b"project"))
                }
            ],
            "provenance": {
                "source_repository": "https://github.com/dragoshont/winapi-vm-bridge",
                "source_commits": ["09cf8a34cf17c6721512f831456ebd1588fe0082"],
                "generator": {
                    "name": "whiny-generate",
                    "version": "0.3.0",
                    "source_sha256": "ab".repeat(32)
                }
            },
            "runtime_requirements": [],
            "hard_stops": ["pointers"]
        });
        let bundle = canonical_bytes(&bundle_value);
        fs::write(root.join("bundle.json"), &bundle).unwrap();

        let build_receipt = json!({
            "schema": "whiny.deterministic-build-receipt.v1",
            "command": ["make", "-f", "Makefile.generated"],
            "output": "dispatcher.dll",
            "source_sha256": hex(sha256_bytes(b"source")),
            "project_sha256": hex(sha256_bytes(b"project")),
            "output_sha256": hex(sha256_bytes(b"dispatcher")),
            "determinism": {
                "pe_timestamp": 0,
                "architecture": "x86-64",
                "build_count": 2,
                "rebuild_comparison": "byte-for-byte"
            }
        });
        let build_receipt_bytes = canonical_bytes(&build_receipt);
        fs::write(root.join("build-receipt.json"), &build_receipt_bytes).unwrap();

        let handoff = json!({
            "schema": "whiny.frozen-adapter-handoff.v1",
            "handoff_id": "windows.shell_hook",
            "qualification": "development-only",
            "registry": {
                "path": "authority-registry.json",
                "sha256": hex(sha256_bytes(&authority_registry_bytes)),
                "registry_id": "whiny.windows.fixture_authority",
                "entry_sha256": hex(entry_sha256)
            },
            "contract": {
                "path": "contract.canonical.json",
                "file_sha256": hex(sha256_bytes(&contract)),
                "canonical_sha256": hex(canonical_hash(&contract_value))
            },
            "bundle": {
                "path": "bundle.json",
                "canonical_sha256": hex(sha256_bytes(&bundle))
            },
            "dispatcher": {
                "abi": "whiny.dispatch.v1",
                "path": "dispatcher.dll",
                "sha256": hex(sha256_bytes(b"dispatcher"))
            },
            "build_receipt": {
                "path": "build-receipt.json",
                "sha256": hex(sha256_bytes(&build_receipt_bytes)),
                "command": ["make", "-f", "Makefile.generated"],
                "output_path": "dispatcher.dll",
                "output_sha256": hex(sha256_bytes(b"dispatcher"))
            },
            "provider": provider,
            "candidate": candidate,
            "operation": operation,
            "side_effects": effects,
            "challenge_sequence": challenge,
            "receipt_policy": {
                "runtime_admission": "required",
                "authentication": "required",
                "correlation": "required",
                "uncorrelated_receipts": "rejected"
            },
            "acceptance_command": [
                "whiny",
                "frozen-adapter-handoff-validate",
                ".",
                "frozen-adapter-handoff.json"
            ],
            "source_revision": WHINY_VALIDATOR_REVISION,
            "custody": custody
        });
        let approval = OperatorAdmission {
            compatibility: current_compatibility(),
            contract_sha256: canonical_hash(&contract_value),
            bundle_descriptor_sha256: sha256_bytes(&bundle),
            files: vec![
                BundleFile {
                    kind: BundleFileKind::Dispatcher,
                    relative_path: String::from("dispatcher.dll"),
                    sha256: sha256_bytes(b"dispatcher"),
                },
                BundleFile {
                    kind: BundleFileKind::Target,
                    relative_path: String::from("candidate.dll"),
                    sha256: sha256_bytes(b"candidate"),
                },
            ],
            operations: vec![OperationAdmission {
                operation_id: OPERATION_ID,
                request_schema_id: REQUEST_SCHEMA_ID,
                response_schema_id: RESPONSE_SCHEMA_ID,
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
        Self {
            directory,
            handoff,
            contract,
            bundle,
            approval,
            registry,
        }
    }

    fn bind(&self) -> Result<wvb_admission::BoundFrozenHandoff, HandoffAdmissionError> {
        self.bind_value(&self.handoff)
    }

    fn bind_value(
        &self,
        handoff: &Value,
    ) -> Result<wvb_admission::BoundFrozenHandoff, HandoffAdmissionError> {
        let handoff_bytes = canonical_bytes(handoff);
        let validator_result = canonical_bytes(&json!({
            "schema": "whiny.frozen-adapter-handoff.v1",
            "sha256": hex(sha256_bytes(&handoff_bytes))
        }));
        AdmissionEngine::new(self.directory.path())
            .unwrap()
            .bind_frozen_handoff(
                &self.registry,
                OPERATOR,
                1,
                &self.approval,
                &FrozenHandoffApproval {
                    validator_revision: String::from(WHINY_VALIDATOR_REVISION),
                    handoff_sha256: sha256_bytes(&handoff_bytes),
                    validator_result_sha256: sha256_bytes(&validator_result),
                },
                FrozenHandoffInputs {
                    validator_result: &validator_result,
                    handoff: &handoff_bytes,
                    contract: &self.contract,
                    bundle_descriptor: &self.bundle,
                },
            )
    }

    fn correlated_values(&self, bound: &wvb_admission::BoundFrozenHandoff) -> (Value, Value) {
        let expectations = json!({
            "schema": "whiny.correlated-runtime-expectations.v1",
            "correlation_id": "receipt-shell-hook-development-1",
            "qualification": "development-only",
            "support_claim": "none",
            "registry": {
                "sha256": hex(bound.registry_sha256()),
                "registry_id": self.handoff["registry"]["registry_id"],
                "entry_sha256": hex(bound.registry_entry_sha256())
            },
            "handoff": {
                "sha256": hex(bound.handoff_sha256()),
                "handoff_id": bound.handoff_id()
            },
            "contract": {
                "file_sha256": self.handoff["contract"]["file_sha256"],
                "canonical_sha256": hex(self.approval.contract_sha256)
            },
            "bundle_sha256": hex(self.approval.bundle_descriptor_sha256),
            "build_receipt_sha256": hex(bound.build_receipt_sha256()),
            "dispatcher": self.handoff["dispatcher"],
            "provider": self.handoff["provider"],
            "candidate": self.handoff["candidate"],
            "operation": self.handoff["operation"],
            "runtime": {
                "policy_sha256": "bb".repeat(32),
                "receipt_id": "receipt-shell-hook-development-1",
                "host_id": "windows-x64-development",
                "key_id": "cc".repeat(32),
                "authorization_receipt_sha256": "dd".repeat(32),
                "challenge_sha256": "ee".repeat(32),
                "sequence": 1,
                "request_sha256": "ff".repeat(32),
                "response_sha256":
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "loaded_files": [{
                    "path": self.handoff["candidate"]["path"],
                    "sha256": self.handoff["candidate"]["sha256"]
                }],
                "cleanup": {
                    "status": "verified",
                    "diagnostics": []
                }
            },
            "source_revision": bound.source_revision(),
            "custody": self.handoff["custody"]
        });
        let expectations_sha256 = canonical_hash(&expectations);
        let admission = json!({
            "schema": "whiny.correlated-runtime-admission.v1",
            "correlation_id": expectations["correlation_id"],
            "expectations_sha256": hex(expectations_sha256),
            "receipt_sha256": "22".repeat(32),
            "registry": expectations["registry"],
            "handoff": expectations["handoff"],
            "runtime": {
                "receipt_id": expectations["runtime"]["receipt_id"],
                "host_id": expectations["runtime"]["host_id"],
                "key_id": expectations["runtime"]["key_id"],
                "challenge_sha256": expectations["runtime"]["challenge_sha256"],
                "sequence": expectations["runtime"]["sequence"],
                "status": "ok",
                "cleanup": expectations["runtime"]["cleanup"]
            },
            "evidence_admitted": true,
            "receipt_eligible": true,
            "qualification": "development-only",
            "runtime_support": false,
            "source_revision": expectations["source_revision"],
            "custody": expectations["custody"]
        });
        (expectations, admission)
    }
}

#[test]
fn exact_public_handoff_binds_but_cannot_create_runtime_authority() {
    let mut fixture = Fixture::new();
    let bound = fixture.bind().unwrap();
    assert_eq!(bound.handoff_id(), "windows.shell_hook");
    assert_eq!(bound.adapter(), "shell_hook");
    assert_eq!(bound.qualification(), "development-only");
    assert_eq!(bound.source_revision(), WHINY_VALIDATOR_REVISION);
    assert_eq!(
        bound.operation(),
        OperationAdmission {
            operation_id: OPERATION_ID,
            request_schema_id: REQUEST_SCHEMA_ID,
            response_schema_id: RESPONSE_SCHEMA_ID,
        }
    );
    assert!(matches!(
        bound.authorize_invocation_grant(&fixture.registry, CALLER, 1),
        Err(HandoffAdmissionError::Admission(_))
    ));
    fixture
        .registry
        .grant(
            CALLER,
            Grant {
                role: Role::Invoke,
                adapter_hash: Some(fixture.approval.contract_sha256),
                operation_id: Some(OPERATION_ID),
                expires_at_unix_ms: None,
            },
        )
        .unwrap();
    bound
        .authorize_invocation_grant(&fixture.registry, CALLER, 1)
        .unwrap();
    assert!(matches!(
        bound.authorize_runtime_operation(&fixture.registry, CALLER, 1),
        Err(HandoffAdmissionError::RuntimeAuthorityUnsupported {
            adapter,
            qualification
        }) if adapter == "shell_hook" && qualification == "development-only"
    ));
}

#[test]
fn public_schema_and_binding_tampering_fail_closed() {
    let cases = [
        (
            "/operation/response_schema_id",
            json!(REQUEST_SCHEMA_ID),
            "schema collision",
        ),
        (
            "/acceptance_command/1",
            json!("adapter-bundle-validate"),
            "command drift",
        ),
        ("/custody/trusted", json!(true), "authority field"),
    ];
    for (pointer, replacement, label) in cases {
        let fixture = Fixture::new();
        let mut handoff = fixture.handoff.clone();
        if pointer == "/custody/trusted" {
            handoff["custody"]["trusted"] = replacement;
        } else {
            *handoff.pointer_mut(pointer).unwrap() = replacement;
        }

        assert!(fixture.bind_value(&handoff).is_err(), "{label}");
    }
}

#[test]
fn public_correlated_evidence_binds_and_remains_non_authoritative() {
    let mut fixture = Fixture::new();
    let handoff = fixture.bind().unwrap();
    let (expectations, admission) = fixture.correlated_values(&handoff);
    let expectations_bytes = canonical_bytes(&expectations);
    let admission_bytes = canonical_bytes(&admission);
    let correlated = handoff
        .bind_correlated_evidence(
            &CorrelatedEvidenceApproval {
                expectations_sha256: sha256_bytes(&expectations_bytes),
                admission_sha256: sha256_bytes(&admission_bytes),
            },
            CorrelatedEvidenceInputs {
                expectations: &expectations_bytes,
                admission: &admission_bytes,
            },
        )
        .unwrap();
    fixture
        .registry
        .grant(
            CALLER,
            Grant {
                role: Role::Invoke,
                adapter_hash: Some(fixture.approval.contract_sha256),
                operation_id: Some(OPERATION_ID),
                expires_at_unix_ms: None,
            },
        )
        .unwrap();
    assert!(matches!(
        correlated.authorize_runtime_operation(&fixture.registry, CALLER, 1),
        Err(CorrelatedEvidenceError::RuntimeAuthorityUnsupported { .. })
    ));

    let mut invalid_admission = admission;
    invalid_admission["runtime_support"] = json!(true);
    let invalid_bytes = canonical_bytes(&invalid_admission);
    assert!(
        handoff
            .bind_correlated_evidence(
                &CorrelatedEvidenceApproval {
                    expectations_sha256: sha256_bytes(&expectations_bytes),
                    admission_sha256: sha256_bytes(&invalid_bytes),
                },
                CorrelatedEvidenceInputs {
                    expectations: &expectations_bytes,
                    admission: &invalid_bytes,
                },
            )
            .is_err()
    );
}

#[test]
fn bound_files_are_reverified_and_historical_receipts_are_not_handoffs() {
    let fixture = Fixture::new();
    let bound = fixture.bind().unwrap();
    fs::write(
        fixture.directory.path().join("evidence/review.json"),
        b"changed",
    )
    .unwrap();
    assert!(bound.reverify_files().is_err());

    let historical = json!({
        "schema": "whiny.runtime-receipt.v1",
        "receipt_id": "historical-posthoc"
    });
    assert!(matches!(
        fixture.bind_value(&historical),
        Err(HandoffAdmissionError::Invalid(_))
    ));
}

#[cfg(unix)]
#[test]
fn hard_linked_transitive_evidence_is_rejected() {
    let mut fixture = Fixture::new();
    let review = fixture.directory.path().join("evidence/review.json");
    fs::remove_file(&review).unwrap();
    fs::hard_link(
        fixture.directory.path().join("evidence/provider.json"),
        &review,
    )
    .unwrap();
    let registry_path = fixture.directory.path().join("authority-registry.json");
    let mut registry: Value = serde_json::from_slice(&fs::read(&registry_path).unwrap()).unwrap();
    registry["entries"][0]["evidence"]["authority"][1]["sha256"] =
        registry["entries"][0]["evidence"]["authority"][0]["sha256"].clone();
    let registry_bytes = canonical_bytes(&registry);
    fs::write(&registry_path, &registry_bytes).unwrap();
    fixture.handoff["registry"]["sha256"] = json!(hex(sha256_bytes(&registry_bytes)));
    fixture.handoff["registry"]["entry_sha256"] =
        json!(hex(canonical_hash(&registry["entries"][0])));
    assert!(matches!(
        fixture.bind(),
        Err(HandoffAdmissionError::Binding(
            "duplicate transitive file identity"
        ))
    ));
}

#[test]
fn validator_revision_is_pinned_to_the_merged_whiny_baseline() {
    let fixture = Fixture::new();
    let handoff_bytes = canonical_bytes(&fixture.handoff);
    let validator_result = canonical_bytes(&json!({
        "schema": "whiny.frozen-adapter-handoff.v1",
        "sha256": hex(sha256_bytes(&handoff_bytes))
    }));
    let result = AdmissionEngine::new(fixture.directory.path())
        .unwrap()
        .bind_frozen_handoff(
            &fixture.registry,
            OPERATOR,
            1,
            &fixture.approval,
            &FrozenHandoffApproval {
                validator_revision: String::from("870da868f3d3d48f1da1a36123a9aaf1a6435e53"),
                handoff_sha256: sha256_bytes(&handoff_bytes),
                validator_result_sha256: sha256_bytes(&validator_result),
            },
            FrozenHandoffInputs {
                validator_result: &validator_result,
                handoff: &handoff_bytes,
                contract: &fixture.contract,
                bundle_descriptor: &fixture.bundle,
            },
        );
    assert!(matches!(
        result,
        Err(HandoffAdmissionError::ValidatorRevisionMismatch)
    ));
}

fn canonical_bytes(value: &Value) -> Vec<u8> {
    serde_jcs::to_vec(value).unwrap()
}

fn canonical_hash(value: &Value) -> [u8; 32] {
    sha256_bytes(&canonical_bytes(value))
}

fn hex(value: [u8; 32]) -> String {
    use std::fmt::Write;

    value.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").unwrap();
        output
    })
}

fn file_hash(root: &Path, path: &str) -> String {
    hex(sha256_bytes(&fs::read(root.join(path)).unwrap()))
}
