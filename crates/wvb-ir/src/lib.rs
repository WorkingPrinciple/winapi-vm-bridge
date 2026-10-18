//! Canonical adapter contract and dependency graph.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetFamily {
    NativeCDll,
    NativeCppDll,
    Com,
    WinRt,
    DotNetAssembly,
    NativeExe,
    DotNetExe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Architecture {
    X86,
    X86_64,
    Arm64,
    Arm64Ec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Placement {
    MacLocal,
    MacProxy,
    WindowsReal,
    WindowsProxyToMac,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sensitivity {
    Public,
    Internal,
    Personal,
    Credential,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    In,
    Out,
    InOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CallingConvention {
    Cdecl,
    Stdcall,
    Winapi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetIdentity {
    pub relative_path: String,
    pub sha256: String,
    pub architecture: Architecture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub id: String,
    pub relative_path: String,
    pub sha256: String,
    pub architecture: Architecture,
    pub placement: Placement,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub load_order: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub type_id: String,
    pub direction: Direction,
    pub sensitivity: Sensitivity,
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub id: u32,
    pub name: String,
    pub symbol: String,
    pub calling_convention: CallingConvention,
    pub timeout_ms: u32,
    pub request_schema_id: u32,
    pub response_schema_id: u32,
    pub parameters: Vec<Parameter>,
    pub return_type_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterContract {
    pub schema_version: u32,
    pub adapter_id: String,
    pub adapter_version: String,
    pub family: TargetFamily,
    pub target: TargetIdentity,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
    #[serde(default)]
    pub types: BTreeMap<String, serde_json::Value>,
    pub operations: Vec<Operation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    SchemaVersion,
    Identifier(String),
    Version,
    Path(String),
    Hash(String),
    DuplicateDependency(String),
    UnknownDependency {
        dependency: String,
        referenced: String,
    },
    DependencyCycle(String),
    ArchitectureMismatch(String),
    DuplicateOperation(u32),
    Timeout(String),
    Bound(String),
    Canonicalization(String),
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ContractError {}

impl AdapterContract {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractError::SchemaVersion);
        }
        validate_dotted_identifier(&self.adapter_id)?;
        if !valid_semver_triplet(&self.adapter_version) {
            return Err(ContractError::Version);
        }
        validate_relative_path(&self.target.relative_path)?;
        validate_hash(&self.target.sha256)?;

        let mut dependencies = BTreeMap::new();
        for dependency in &self.dependencies {
            validate_identifier(&dependency.id)?;
            validate_relative_path(&dependency.relative_path)?;
            validate_hash(&dependency.sha256)?;
            if dependency.architecture != self.target.architecture {
                return Err(ContractError::ArchitectureMismatch(dependency.id.clone()));
            }
            if dependencies
                .insert(dependency.id.as_str(), dependency)
                .is_some()
            {
                return Err(ContractError::DuplicateDependency(dependency.id.clone()));
            }
        }
        for dependency in &self.dependencies {
            for referenced in &dependency.depends_on {
                if !dependencies.contains_key(referenced.as_str()) {
                    return Err(ContractError::UnknownDependency {
                        dependency: dependency.id.clone(),
                        referenced: referenced.clone(),
                    });
                }
            }
        }
        validate_acyclic(&dependencies)?;

        let mut operation_ids = BTreeSet::new();
        for operation in &self.operations {
            validate_identifier(&operation.name)?;
            if operation.symbol.is_empty() {
                return Err(ContractError::Identifier(operation.name.clone()));
            }
            if !operation_ids.insert(operation.id) {
                return Err(ContractError::DuplicateOperation(operation.id));
            }
            if !(1..=300_000).contains(&operation.timeout_ms) {
                return Err(ContractError::Timeout(operation.name.clone()));
            }
            for parameter in &operation.parameters {
                validate_identifier(&parameter.name)?;
                validate_identifier(&parameter.type_id)?;
                if parameter
                    .max_bytes
                    .is_some_and(|bound| bound == 0 || bound > 16 * 1024 * 1024)
                {
                    return Err(ContractError::Bound(parameter.name.clone()));
                }
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        serde_jcs::to_vec(self).map_err(|error| ContractError::Canonicalization(error.to_string()))
    }

    pub fn contract_hash(&self) -> Result<[u8; 32], ContractError> {
        let digest = Sha256::digest(self.canonical_bytes()?);
        Ok(digest.into())
    }
}

fn validate_acyclic(dependencies: &BTreeMap<&str, &Dependency>) -> Result<(), ContractError> {
    fn visit<'a>(
        id: &'a str,
        dependencies: &BTreeMap<&'a str, &'a Dependency>,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> Result<(), ContractError> {
        if visited.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id) {
            return Err(ContractError::DependencyCycle(id.to_owned()));
        }
        for next in &dependencies[id].depends_on {
            visit(next, dependencies, visiting, visited)?;
        }
        visiting.remove(id);
        visited.insert(id);
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for id in dependencies.keys().copied() {
        visit(id, dependencies, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), ContractError> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ContractError::Path(value.to_owned()));
    }
    Ok(())
}

fn validate_hash(value: &str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::Hash(value.to_owned()));
    }
    Ok(())
}

fn validate_dotted_identifier(value: &str) -> Result<(), ContractError> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() < 2 {
        return Err(ContractError::Identifier(value.to_owned()));
    }
    for part in parts {
        validate_identifier(part)?;
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), ContractError> {
    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(ContractError::Identifier(value.to_owned()));
    }
    Ok(())
}

fn valid_semver_triplet(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> AdapterContract {
        AdapterContract {
            schema_version: 2,
            adapter_id: "example.math".into(),
            adapter_version: "1.0.0".into(),
            family: TargetFamily::NativeCDll,
            target: TargetIdentity {
                relative_path: "bin/vendor.dll".into(),
                sha256: "a".repeat(64),
                architecture: Architecture::X86_64,
            },
            dependencies: vec![
                Dependency {
                    id: "runtime".into(),
                    relative_path: "bin/runtime.dll".into(),
                    sha256: "b".repeat(64),
                    architecture: Architecture::X86_64,
                    placement: Placement::WindowsReal,
                    depends_on: Vec::new(),
                    load_order: 1,
                },
                Dependency {
                    id: "codec".into(),
                    relative_path: "bin/codec.dll".into(),
                    sha256: "c".repeat(64),
                    architecture: Architecture::X86_64,
                    placement: Placement::WindowsReal,
                    depends_on: vec!["runtime".into()],
                    load_order: 2,
                },
            ],
            types: BTreeMap::new(),
            operations: vec![Operation {
                id: 1,
                name: "Add".into(),
                symbol: "VendorAdd".into(),
                calling_convention: CallingConvention::Stdcall,
                timeout_ms: 1_000,
                request_schema_id: 0x3000_0001,
                response_schema_id: 0x3000_0002,
                parameters: vec![Parameter {
                    name: "left".into(),
                    type_id: "i32".into(),
                    direction: Direction::In,
                    sensitivity: Sensitivity::Public,
                    max_bytes: None,
                }],
                return_type_id: "i32".into(),
            }],
        }
    }

    #[test]
    fn canonical_hash_is_stable() {
        let first = contract().contract_hash().unwrap();
        let second = contract().contract_hash().unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn path_escape_cycle_and_duplicates_fail() {
        let mut value = contract();
        value.dependencies[0].relative_path = "../runtime.dll".into();
        assert!(matches!(value.validate(), Err(ContractError::Path(_))));

        let mut value = contract();
        value.dependencies[0].depends_on.push("codec".into());
        assert!(matches!(
            value.validate(),
            Err(ContractError::DependencyCycle(_))
        ));

        let mut value = contract();
        value.operations.push(value.operations[0].clone());
        assert_eq!(value.validate(), Err(ContractError::DuplicateOperation(1)));
    }
}
