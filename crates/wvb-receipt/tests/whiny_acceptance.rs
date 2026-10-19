use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use wvb_receipt::RuntimeReceipt;

fn evidence_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../runtime-artifacts/whiny-v0.3.0/acceptance/runtime-receipts-v1")
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex pair"), 16).expect("valid hex")
        })
        .collect()
}

#[test]
fn corrected_whiny_receipts_are_canonical_authenticated_and_policy_bound() {
    let root = evidence_root();
    let policy_bytes = fs::read(root.join("whiny-trust-policy.json")).expect("policy");
    assert_eq!(
        format!("{:x}", Sha256::digest(&policy_bytes)),
        "fedfc843772405c0dd799ba83e6a108f56e2c98ea06a1935efd61f114fa292e9"
    );
    let policy: Value = serde_json::from_slice(&policy_bytes).expect("policy JSON");
    assert_eq!(
        policy["signing_domain"],
        Value::String(String::from("whiny.runtime-receipt.v1\\u0000"))
    );
    assert_eq!(
        policy["historical_invalid_receipts"],
        serde_json::json!(["native-scalar-receipt.json", "managed-scalar-receipt.json"])
    );

    for (name, expected_hash) in [
        (
            "native-scalar-receipt-jcs.json",
            "eb02139899a73b93f11bd273ee9a27c9d599b7e0723c0a2695eb91d39ce422cd",
        ),
        (
            "managed-scalar-receipt-jcs.json",
            "bcbb3a8086fca5aa705e9577bdc93e875ea51e76aca514314d54867814e458b6",
        ),
    ] {
        let bytes = fs::read(root.join(name)).expect("receipt");
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), expected_hash);
        let receipt: RuntimeReceipt = serde_json::from_slice(&bytes).expect("receipt JSON");
        assert_eq!(receipt.canonical_bytes().expect("canonical receipt"), bytes);

        let signer = policy["signers"]
            .as_array()
            .expect("signers")
            .iter()
            .find(|signer| signer["key_id"] == receipt.authentication.key_id)
            .expect("admitted signer");
        assert_eq!(signer["scope"], "acceptance-only");
        assert_eq!(signer["production_runtime_identity"], false);
        assert_eq!(signer["bundle_sha256"], receipt.bundle_sha256);
        assert!(
            signer["host_ids"]
                .as_array()
                .expect("host ids")
                .iter()
                .any(|host| host == &receipt.runtime_identity.host_id)
        );

        let public_key = decode_hex(signer["public_key_hex"].as_str().expect("public key"));
        assert_eq!(
            format!("{:x}", Sha256::digest(&public_key)),
            receipt.authentication.key_id
        );
        receipt.verify(&public_key).expect("authenticated receipt");
    }
}

#[test]
fn historical_non_jcs_receipts_are_retained_but_rejected() {
    let root = evidence_root();
    for (receipt_name, key_name) in [
        ("native-scalar-receipt.json", "native-scalar-public-key.bin"),
        (
            "managed-scalar-receipt.json",
            "managed-scalar-public-key.bin",
        ),
    ] {
        let receipt: RuntimeReceipt =
            serde_json::from_slice(&fs::read(root.join(receipt_name)).expect("receipt"))
                .expect("receipt JSON");
        let public_key = fs::read(root.join(key_name)).expect("historical public key");
        assert!(receipt.verify(&public_key).is_err());
    }
}
