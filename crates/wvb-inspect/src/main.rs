use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;
use goblin::pe::{PE, export::Reexport};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    binary: PathBuf,
    #[arg(long)]
    header: Option<PathBuf>,
    #[arg(long, default_value = "clang")]
    clang: String,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InspectionReport {
    schema_version: u32,
    binary: BinaryEvidence,
    header: Option<HeaderEvidence>,
    functions: Vec<FunctionEvidence>,
    limitations: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BinaryEvidence {
    name: String,
    sha256: String,
    format: &'static str,
    architecture: String,
    is_dll: bool,
    is_managed: bool,
    exports: Vec<ExportEvidence>,
    imported_modules: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportEvidence {
    name: Option<String>,
    rva: usize,
    reexport: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HeaderEvidence {
    name: String,
    sha256: String,
    clang: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FunctionEvidence {
    name: String,
    signature: String,
    return_type: String,
    parameters: Vec<ParameterEvidence>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ParameterEvidence {
    name: String,
    spelling: String,
    abi_type: String,
    classification: &'static str,
    generated: bool,
    unresolved: Option<&'static str>,
}

fn main() {
    if let Err(error) = run(Arguments::parse()) {
        eprintln!("wvb-inspect: {error}");
        std::process::exit(2);
    }
}

fn run(arguments: Arguments) -> Result<(), InspectError> {
    let binary = inspect_binary(&arguments.binary)?;
    let (header, functions) = if let Some(path) = arguments.header {
        let functions = inspect_header(&path, &arguments.clang)?;
        (
            Some(HeaderEvidence {
                name: file_name(&path)?,
                sha256: hash_file(&path)?,
                clang: arguments.clang,
            }),
            functions,
        )
    } else {
        (None, Vec::new())
    };
    let report = InspectionReport {
        schema_version: 1,
        binary,
        header,
        functions,
        limitations: vec![
            "Static metadata cannot prove pointer ownership or allocator pairing.",
            "Callback threading, reentrancy, cancellation and rare failures require authorized traces.",
            "Custom COM marshaling and apartment behavior require explicit review.",
        ],
    };
    fs::write(arguments.out, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

#[derive(Debug)]
enum InspectError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Parse(String),
    Command(String),
}

impl std::fmt::Display for InspectError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O: {error}"),
            Self::Json(error) => write!(formatter, "JSON: {error}"),
            Self::Parse(reason) => write!(formatter, "parse: {reason}"),
            Self::Command(reason) => write!(formatter, "command: {reason}"),
        }
    }
}

impl std::error::Error for InspectError {}

impl From<std::io::Error> for InspectError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for InspectError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

fn inspect_binary(path: &Path) -> Result<BinaryEvidence, InspectError> {
    let bytes = fs::read(path)?;
    let pe = PE::parse(&bytes).map_err(|error| InspectError::Parse(error.to_string()))?;
    let mut imported_modules = BTreeSet::new();
    for import in &pe.imports {
        imported_modules.insert(import.dll.to_ascii_lowercase());
    }
    let is_managed = imported_modules.contains("mscoree.dll");
    let exports = pe
        .exports
        .iter()
        .map(|export| ExportEvidence {
            name: export.name.map(str::to_owned),
            rva: export.rva,
            reexport: export.reexport.as_ref().map(|reexport| match reexport {
                Reexport::DLLName { export, lib } => format!("{lib}.{export}"),
                Reexport::DLLOrdinal { ordinal, lib } => format!("{lib}.#{ordinal}"),
            }),
        })
        .collect();
    Ok(BinaryEvidence {
        name: file_name(path)?,
        sha256: hash_bytes(&bytes),
        format: "pe",
        architecture: machine_name(pe.header.coff_header.machine).to_owned(),
        is_dll: pe.is_lib,
        is_managed,
        exports,
        imported_modules: imported_modules.into_iter().collect(),
    })
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "x86",
        0x8664 => "x86_64",
        0xaa64 => "arm64",
        0xa641 => "arm64ec",
        _ => "unknown",
    }
}

fn inspect_header(path: &Path, clang: &str) -> Result<Vec<FunctionEvidence>, InspectError> {
    let output = Command::new(clang)
        .args(["-x", "c", "-fsyntax-only", "-Xclang", "-ast-dump=json"])
        .arg(path)
        .output()?;
    if !output.status.success() {
        return Err(InspectError::Command(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    let ast: Value = serde_json::from_slice(&output.stdout)?;
    let mut functions = Vec::new();
    walk_functions(&ast, path, &mut functions);
    Ok(functions)
}

fn walk_functions(value: &Value, header: &Path, output: &mut Vec<FunctionEvidence>) {
    if value.get("kind").and_then(Value::as_str) == Some("FunctionDecl") {
        let source = value
            .pointer("/loc/file")
            .and_then(Value::as_str)
            .map(Path::new);
        if source.is_none_or(|source| source == header)
            && let (Some(name), Some(signature)) = (
                value.get("name").and_then(Value::as_str),
                value.pointer("/type/qualType").and_then(Value::as_str),
            )
        {
            let return_type = signature.split('(').next().unwrap_or_default().trim();
            let mut parameters = Vec::new();
            if let Some(children) = value.get("inner").and_then(Value::as_array) {
                for child in children {
                    if child.get("kind").and_then(Value::as_str) != Some("ParmVarDecl") {
                        continue;
                    }
                    let spelling = child
                        .pointer("/type/qualType")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let abi_type = child
                        .pointer("/type/desugaredQualType")
                        .and_then(Value::as_str)
                        .unwrap_or(spelling);
                    let (classification, generated, unresolved) = classify(abi_type);
                    parameters.push(ParameterEvidence {
                        name: child
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        spelling: spelling.to_owned(),
                        abi_type: abi_type.to_owned(),
                        classification,
                        generated,
                        unresolved,
                    });
                }
                output.push(FunctionEvidence {
                    name: name.to_owned(),
                    signature: signature.to_owned(),
                    return_type: return_type.to_owned(),
                    parameters,
                });
            }
        }
    }
    if let Some(children) = value.get("inner").and_then(Value::as_array) {
        for child in children {
            walk_functions(child, header, output);
        }
    }
}

fn classify(type_name: &str) -> (&'static str, bool, Option<&'static str>) {
    if type_name.contains("(*") {
        (
            "callback",
            false,
            Some("thread, lifetime, ordering and reentrancy require tracing"),
        )
    } else if type_name.contains('*') {
        (
            "pointer",
            false,
            Some("direction, length, ownership, nullability and aliasing are unresolved"),
        )
    } else if is_scalar(type_name) {
        ("scalar", true, None)
    } else {
        (
            "record-or-named",
            false,
            Some("layout and ABI identity require authoritative metadata"),
        )
    }
}

fn is_scalar(type_name: &str) -> bool {
    matches!(
        type_name.trim(),
        "void"
            | "bool"
            | "char"
            | "signed char"
            | "unsigned char"
            | "short"
            | "unsigned short"
            | "int"
            | "unsigned int"
            | "long"
            | "unsigned long"
            | "long long"
            | "unsigned long long"
            | "float"
            | "double"
    ) || type_name.trim().starts_with("enum ")
}

fn hash_file(path: &Path) -> Result<String, InspectError> {
    Ok(hash_bytes(&fs::read(path)?))
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("write to string");
            output
        })
}

fn file_name(path: &Path) -> Result<String, InspectError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| InspectError::Parse("non-UTF-8 file name".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_and_pointer_semantics_stop_generation() {
        assert_eq!(classify("int"), ("scalar", true, None));
        assert!(!classify("void *").1);
        assert_eq!(classify("void (*)(int) ").0, "callback");
    }
}
