//! Authenticated `whiny.runtime-receipt.v1` emission and verification.

use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wvb_integrity::validate_portable_relative_path;

pub const RECEIPT_IDENTIFIER: &str = "whiny.runtime-receipt.v1";
pub const DISPATCHER_ABI: &str = "whiny.dispatch.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeIdentity {
    pub host_id: String,
    pub os_build: String,
    pub architecture: String,
    pub bridge_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cleanup {
    pub status: String,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authentication {
    pub scheme: String,
    pub key_id: String,
    pub signed_payload_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub bundle_sha256: String,
    pub contract_sha256: String,
    pub dispatcher_abi: String,
    pub operation_id: u32,
    pub request_sha256: String,
    pub response_sha256: String,
    pub status: String,
    pub runtime_identity: RuntimeIdentity,
    pub loaded_files: Vec<LoadedFile>,
    pub authorization_receipt_sha256: String,
    pub challenge_sha256: String,
    pub sequence: u64,
    pub started_at: String,
    pub completed_at: String,
    pub cleanup: Cleanup,
    pub authentication: Authentication,
}

#[derive(Serialize)]
struct UnsignedReceipt<'a> {
    schema: &'a str,
    receipt_id: &'a str,
    bundle_sha256: &'a str,
    contract_sha256: &'a str,
    dispatcher_abi: &'a str,
    operation_id: u32,
    request_sha256: &'a str,
    response_sha256: &'a str,
    status: &'a str,
    runtime_identity: &'a RuntimeIdentity,
    loaded_files: &'a [LoadedFile],
    authorization_receipt_sha256: &'a str,
    challenge_sha256: &'a str,
    sequence: u64,
    started_at: &'a str,
    completed_at: &'a str,
    cleanup: &'a Cleanup,
}

#[derive(Debug)]
pub enum ReceiptError {
    Invalid(&'static str),
    Canonicalization(String),
    Signing,
    Verification,
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ReceiptError {}

impl RuntimeReceipt {
    pub fn sign(&mut self, seed: &[u8; 32]) -> Result<(), ReceiptError> {
        self.validate_unsigned()?;
        let key = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| ReceiptError::Signing)?;
        let payload = self.unsigned_bytes()?;
        let payload_hash = Sha256::digest(&payload);
        self.authentication = Authentication {
            scheme: String::from("ed25519"),
            key_id: hex(&Sha256::digest(key.public_key().as_ref())),
            signed_payload_sha256: hex(&payload_hash),
            signature: hex(key.sign(&payload).as_ref()),
        };
        Ok(())
    }

    pub fn verify(&self, public_key: &[u8]) -> Result<(), ReceiptError> {
        self.validate()?;
        if self.authentication.key_id != hex(&Sha256::digest(public_key)) {
            return Err(ReceiptError::Verification);
        }
        let payload = self.unsigned_bytes()?;
        if self.authentication.signed_payload_sha256 != hex(&Sha256::digest(&payload)) {
            return Err(ReceiptError::Verification);
        }
        let signature = decode_hex::<64>(&self.authentication.signature)?;
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&payload, &signature)
            .map_err(|_| ReceiptError::Verification)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReceiptError> {
        self.validate()?;
        serde_jcs::to_vec(self).map_err(|error| ReceiptError::Canonicalization(error.to_string()))
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, ReceiptError> {
        serde_jcs::to_vec(&UnsignedReceipt {
            schema: &self.schema,
            receipt_id: &self.receipt_id,
            bundle_sha256: &self.bundle_sha256,
            contract_sha256: &self.contract_sha256,
            dispatcher_abi: &self.dispatcher_abi,
            operation_id: self.operation_id,
            request_sha256: &self.request_sha256,
            response_sha256: &self.response_sha256,
            status: &self.status,
            runtime_identity: &self.runtime_identity,
            loaded_files: &self.loaded_files,
            authorization_receipt_sha256: &self.authorization_receipt_sha256,
            challenge_sha256: &self.challenge_sha256,
            sequence: self.sequence,
            started_at: &self.started_at,
            completed_at: &self.completed_at,
            cleanup: &self.cleanup,
        })
        .map_err(|error| ReceiptError::Canonicalization(error.to_string()))
    }

    fn validate_unsigned(&self) -> Result<(), ReceiptError> {
        if self.schema != RECEIPT_IDENTIFIER
            || self.dispatcher_abi != DISPATCHER_ABI
            || self.receipt_id.is_empty()
            || self.operation_id == 0
            || self.sequence == 0
            || !matches!(
                self.status.as_str(),
                "ok" | "invalid-request"
                    | "operation-unknown"
                    | "target-failure"
                    | "timeout"
                    | "cancelled"
                    | "internal"
            )
            || !matches!(
                self.cleanup.status.as_str(),
                "verified" | "failed" | "not-required" | "unknown"
            )
            || self.loaded_files.is_empty()
            || !timestamp(&self.started_at)
            || !timestamp(&self.completed_at)
        {
            return Err(ReceiptError::Invalid("receipt fields"));
        }
        for value in [
            &self.bundle_sha256,
            &self.contract_sha256,
            &self.request_sha256,
            &self.response_sha256,
            &self.authorization_receipt_sha256,
            &self.challenge_sha256,
        ] {
            validate_hash(value)?;
        }
        for file in &self.loaded_files {
            validate_portable_relative_path(&file.path)
                .map_err(|_| ReceiptError::Invalid("loaded path"))?;
            validate_hash(&file.sha256)?;
        }
        for value in [
            &self.runtime_identity.host_id,
            &self.runtime_identity.os_build,
            &self.runtime_identity.architecture,
            &self.runtime_identity.bridge_version,
        ] {
            if value.is_empty() {
                return Err(ReceiptError::Invalid("runtime identity"));
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ReceiptError> {
        self.validate_unsigned()?;
        if self.authentication.scheme != "ed25519" {
            return Err(ReceiptError::Invalid("authentication scheme"));
        }
        validate_hash(&self.authentication.key_id)?;
        validate_hash(&self.authentication.signed_payload_sha256)?;
        decode_hex::<64>(&self.authentication.signature)?;
        Ok(())
    }
}

pub fn public_key(seed: &[u8; 32]) -> Result<Vec<u8>, ReceiptError> {
    Ok(Ed25519KeyPair::from_seed_unchecked(seed)
        .map_err(|_| ReceiptError::Signing)?
        .public_key()
        .as_ref()
        .to_vec())
}

fn validate_hash(value: &str) -> Result<(), ReceiptError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ReceiptError::Invalid("sha256"))
    }
}

fn timestamp(value: &str) -> bool {
    value.len() == 20
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value.as_bytes().get(10) == Some(&b'T')
        && value.as_bytes().get(13) == Some(&b':')
        && value.as_bytes().get(16) == Some(&b':')
        && value.ends_with('Z')
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], ReceiptError> {
    if value.len() != N * 2 {
        return Err(ReceiptError::Invalid("hex length"));
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ReceiptError::Invalid("hex"))?;
    }
    Ok(output)
}

fn hex(value: &[u8]) -> String {
    use std::fmt::Write;

    value.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
        output
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(cleanup: &str) -> RuntimeReceipt {
        RuntimeReceipt {
            schema: String::from(RECEIPT_IDENTIFIER),
            receipt_id: String::from("receipt-1"),
            bundle_sha256: "1".repeat(64),
            contract_sha256: "2".repeat(64),
            dispatcher_abi: String::from(DISPATCHER_ABI),
            operation_id: 1,
            request_sha256: "3".repeat(64),
            response_sha256: "4".repeat(64),
            status: String::from("ok"),
            runtime_identity: RuntimeIdentity {
                host_id: String::from("host"),
                os_build: String::from("build"),
                architecture: String::from("x86-64"),
                bridge_version: String::from("0.2.0"),
            },
            loaded_files: vec![LoadedFile {
                path: String::from("target/native_math.dll"),
                sha256: "5".repeat(64),
            }],
            authorization_receipt_sha256: "6".repeat(64),
            challenge_sha256: "7".repeat(64),
            sequence: 1,
            started_at: String::from("2026-10-18T00:00:00Z"),
            completed_at: String::from("2026-10-18T00:00:01Z"),
            cleanup: Cleanup {
                status: String::from(cleanup),
                diagnostics: if cleanup == "failed" {
                    vec![String::from("owned child remained active")]
                } else {
                    Vec::new()
                },
            },
            authentication: Authentication {
                scheme: String::new(),
                key_id: String::new(),
                signed_payload_sha256: String::new(),
                signature: String::new(),
            },
        }
    }

    #[test]
    fn receipt_signs_verifies_and_binds_cleanup_truth() {
        let seed = [9; 32];
        for cleanup in ["verified", "failed"] {
            let mut value = receipt(cleanup);
            value.sign(&seed).unwrap();
            value.verify(&public_key(&seed).unwrap()).unwrap();
            let encoded = value.canonical_bytes().unwrap();
            let decoded: RuntimeReceipt = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(decoded.cleanup.status, cleanup);
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn tampering_and_path_escape_fail_closed() {
        let seed = [9; 32];
        let mut value = receipt("verified");
        value.sign(&seed).unwrap();
        value.response_sha256 = "8".repeat(64);
        assert!(matches!(
            value.verify(&public_key(&seed).unwrap()),
            Err(ReceiptError::Verification)
        ));
        value.loaded_files[0].path = String::from("../target.dll");
        assert!(value.canonical_bytes().is_err());
    }
}
