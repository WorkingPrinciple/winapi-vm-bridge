use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use wvb_ir::{
    AdapterContract, Architecture, CallingConvention, ContractError, Direction,
    ManagedTargetFramework, Operation, TargetFamily,
};

#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    contract: PathBuf,
    #[arg(long)]
    out: PathBuf,
}

fn main() {
    if let Err(error) = run(&Arguments::parse()) {
        eprintln!("wvb-generate: {error}");
        std::process::exit(2);
    }
}

fn run(arguments: &Arguments) -> Result<(), GenerateError> {
    let input = fs::read(&arguments.contract)?;
    let contract: AdapterContract = serde_json::from_slice(&input)?;
    contract.validate()?;
    generate(&contract, &arguments.out)
}

#[derive(Debug)]
enum GenerateError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Contract(ContractError),
    Unsupported(String),
}

impl std::fmt::Display for GenerateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O: {error}"),
            Self::Json(error) => write!(formatter, "JSON: {error}"),
            Self::Contract(error) => write!(formatter, "contract: {error}"),
            Self::Unsupported(reason) => write!(formatter, "unsupported: {reason}"),
        }
    }
}

impl From<std::io::Error> for GenerateError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for GenerateError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<ContractError> for GenerateError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

fn generate(contract: &AdapterContract, output: &Path) -> Result<(), GenerateError> {
    match contract.family {
        TargetFamily::NativeCDll => generate_native_c(contract, output),
        TargetFamily::DotNetAssembly => generate_managed_assembly(contract, output),
        _ => Err(GenerateError::Unsupported(format!(
            "target family {:?} generator is not implemented",
            contract.family
        ))),
    }
}

fn generate_native_c(contract: &AdapterContract, output: &Path) -> Result<(), GenerateError> {
    fs::create_dir_all(output)?;
    let hash = contract.contract_hash()?;
    let hash_literal = byte_array(&hash);
    let mut proxy = String::from(PROXY_PREAMBLE);
    writeln!(
        proxy,
        "\nstatic const uint8_t WVB_ADAPTER_HASH[32] = {{{hash_literal}}};"
    )
    .expect("write to string");
    let mut dispatcher = format!(
        "#define WVB_TARGET_RELATIVE L\"{}\"\n{DISPATCHER_PREAMBLE}\n",
        escape_c_wide(&contract.target.relative_path)?
    );
    let mut definitions = format!(
        "LIBRARY {}\nEXPORTS\n",
        contract.adapter_id.replace('.', "_")
    );

    for operation in &contract.operations {
        let generated = generate_operation(operation)?;
        proxy.push_str(&generated.proxy);
        dispatcher.push_str(&generated.dispatcher);
        writeln!(definitions, "  {}", operation.symbol).expect("write to string");
    }
    dispatcher.push_str(DISPATCHER_EPILOGUE);
    fs::write(output.join("proxy.generated.c"), proxy)?;
    fs::write(output.join("proxy.generated.def"), definitions)?;
    fs::write(output.join("dispatcher.generated.cpp"), dispatcher)?;
    fs::write(
        output.join("contract.canonical.json"),
        contract.canonical_bytes()?,
    )?;
    Ok(())
}

fn generate_managed_assembly(
    contract: &AdapterContract,
    output: &Path,
) -> Result<(), GenerateError> {
    fs::create_dir_all(output)?;
    let managed = contract
        .managed
        .as_ref()
        .ok_or_else(|| GenerateError::Unsupported("managed metadata is required".into()))?;
    let target_framework = match managed.target_framework {
        ManagedTargetFramework::Net481 => {
            return Err(GenerateError::Unsupported(
                ".NET Framework 4.8.1 generation is not proven by this slice".into(),
            ));
        }
        ManagedTargetFramework::Net8Windows => "net8.0-windows",
    };
    if managed.requires_strong_name || managed.strong_name_key_file.is_some() {
        return Err(GenerateError::Unsupported(
            "strong-name identity requires an authorized signing and binding proof".into(),
        ));
    }
    if contract.target.architecture != Architecture::X86_64 {
        return Err(GenerateError::Unsupported(
            "managed scalar generation is currently proven only for x86-64".into(),
        ));
    }
    let project = format!(
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n\
             \x20 <PropertyGroup>\n\
             \x20   <TargetFramework>{target_framework}</TargetFramework>\n\
             \x20   <AssemblyName>{}</AssemblyName>\n\
             \x20   <AssemblyVersion>{}</AssemblyVersion>\n\
             \x20   <FileVersion>{}</FileVersion>\n\
             \x20   <RootNamespace>{}</RootNamespace>\n\
             \x20   <PlatformTarget>x64</PlatformTarget>\n\
             \x20   <Prefer32Bit>false</Prefer32Bit>\n\
             \x20   <Nullable>enable</Nullable>\n\
             \x20   <ImplicitUsings>disable</ImplicitUsings>\n\
             \x20   <Deterministic>true</Deterministic>\n\
             \x20 </PropertyGroup>\n\
             </Project>\n",
        escape_xml(&managed.assembly_name),
        escape_xml(&managed.assembly_version),
        escape_xml(&managed.assembly_version),
        escape_xml(&managed.root_namespace),
    );
    let hash = contract.contract_hash()?;
    let hash_literal = hash
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut source = format!(
        "using System;\nusing System.Runtime.InteropServices;\n\n\
             internal static class WvbNative\n{{\n\
             \x20   internal const int Ok = 0;\n\
             \x20   internal static readonly byte[] AdapterHash = new byte[] {{ {hash_literal} }};\n\
             \x20   static WvbNative()\n\
             \x20   {{\n\
             \x20       if (!BitConverter.IsLittleEndian)\n\
             \x20           throw new PlatformNotSupportedException(\"WinAPI VM Bridge scalar encoding requires little-endian Windows\");\n\
             \x20   }}\n\
             \x20   [DllImport(\"wvb_client_ffi\", EntryPoint = \"wvb_client_call\", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl)]\n\
             \x20   internal static extern int wvb_client_call(\n\
             \x20       byte[] adapterHash, uint operationId,\n\
             \x20       byte[] request, UIntPtr requestLength,\n\
             \x20       [Out] byte[] response, UIntPtr responseCapacity,\n\
             \x20       out UIntPtr responseLength);\n\
             }}\n\n",
    );
    for operation in &contract.operations {
        source.push_str(&generate_managed_operation(operation)?);
    }
    source.truncate(source.trim_end_matches('\n').len());
    source.push('\n');
    fs::write(
        output.join(format!("{}.csproj", managed.assembly_name)),
        project,
    )?;
    fs::write(output.join("Proxy.generated.cs"), source)?;
    fs::write(
        output.join("contract.canonical.json"),
        contract.canonical_bytes()?,
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn generate_managed_operation(operation: &Operation) -> Result<String, GenerateError> {
    if operation
        .parameters
        .iter()
        .any(|parameter| parameter.direction != Direction::In || !is_scalar(&parameter.type_id))
        || !is_scalar(&operation.return_type_id)
    {
        return Err(GenerateError::Unsupported(format!(
            "managed operation {} needs custom marshalling",
            operation.name
        )));
    }
    let managed = operation
        .managed
        .as_ref()
        .ok_or_else(|| GenerateError::Unsupported("managed operation metadata".into()))?;
    if !managed.is_static {
        return Err(GenerateError::Unsupported(format!(
            "{} is not static",
            operation.name
        )));
    }
    let (namespace, class_name) = managed.declaring_type.rsplit_once('.').map_or(
        (None, managed.declaring_type.as_str()),
        |(namespace, name)| (Some(namespace), name),
    );
    let parameters = operation
        .parameters
        .iter()
        .map(|parameter| {
            Ok(format!(
                "{} {}",
                csharp_type(&parameter.type_id)?,
                csharp_identifier(&parameter.name)
            ))
        })
        .collect::<Result<Vec<_>, GenerateError>>()?
        .join(", ");
    let request_bytes = operation
        .parameters
        .iter()
        .map(|parameter| scalar_size(&parameter.type_id))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<usize>();
    let response_bytes = scalar_size(&operation.return_type_id)?;
    let mut writes = String::new();
    let mut offset = 0;
    for parameter in &operation.parameters {
        writeln!(
            writes,
            "            {}",
            csharp_write(
                &parameter.type_id,
                &csharp_identifier(&parameter.name),
                offset
            )?
        )
        .expect("write to string");
        offset += scalar_size(&parameter.type_id)?;
    }
    let namespace_open = namespace.map_or_else(String::new, |value| {
        format!(
            "namespace {}\n{{\n",
            value
                .split('.')
                .map(csharp_identifier)
                .collect::<Vec<_>>()
                .join(".")
        )
    });
    let namespace_close = if namespace.is_some() { "}\n\n" } else { "\n" };
    let class_indent = if namespace.is_some() { "    " } else { "" };
    let body_indent = if namespace.is_some() {
        "        "
    } else {
        "    "
    };
    let statement_indent = if namespace.is_some() {
        "            "
    } else {
        "        "
    };
    Ok(format!(
        "{namespace_open}\
             {class_indent}public static partial class {class_name}\n\
             {class_indent}{{\n\
             {body_indent}public static {return_type} {member_name}({parameters})\n\
             {body_indent}{{\n\
             {statement_indent}byte[] request = new byte[{request_bytes}];\n\
             {writes}\
             {statement_indent}byte[] response = new byte[{response_bytes}];\n\
             {statement_indent}UIntPtr responseLength;\n\
             {statement_indent}int status = WvbNative.wvb_client_call(\n\
             {statement_indent}    WvbNative.AdapterHash, {operation_id}u, request, (UIntPtr)request.Length,\n\
             {statement_indent}    response, (UIntPtr)response.Length, out responseLength);\n\
             {statement_indent}if (status != WvbNative.Ok || responseLength.ToUInt64() != (ulong)response.Length)\n\
             {statement_indent}    throw new ExternalException(\"WinAPI VM Bridge call failed\", status);\n\
             {statement_indent}return {read};\n\
             {body_indent}}}\n\
             {class_indent}}}\n\
             {namespace_close}",
        class_name = csharp_identifier(class_name),
        return_type = csharp_type(&operation.return_type_id)?,
        member_name = csharp_identifier(&managed.member_name),
        operation_id = operation.id,
        read = csharp_read(&operation.return_type_id, "response", 0)?,
    ))
}

fn csharp_type(value: &str) -> Result<&'static str, GenerateError> {
    match value {
        "i8" => Ok("sbyte"),
        "u8" => Ok("byte"),
        "i16" => Ok("short"),
        "u16" => Ok("ushort"),
        "i32" | "hresult" => Ok("int"),
        "u32" => Ok("uint"),
        "i64" => Ok("long"),
        "u64" => Ok("ulong"),
        "f32" => Ok("float"),
        "f64" => Ok("double"),
        "bool" => Ok("bool"),
        other => Err(GenerateError::Unsupported(other.to_owned())),
    }
}

fn csharp_write(value: &str, name: &str, offset: usize) -> Result<String, GenerateError> {
    let expression = match value {
        "i8" | "u8" => return Ok(format!("request[{offset}] = unchecked((byte){name});")),
        "bool" => return Ok(format!("request[{offset}] = {name} ? (byte)1 : (byte)0;")),
        "i16" | "u16" | "i32" | "hresult" | "u32" | "i64" | "u64" | "f32" | "f64" => {
            format!("BitConverter.GetBytes({name})")
        }
        other => return Err(GenerateError::Unsupported(other.to_owned())),
    };
    Ok(format!("{expression}.CopyTo(request, {offset});"))
}

fn csharp_read(value: &str, buffer: &str, offset: usize) -> Result<String, GenerateError> {
    match value {
        "i8" => Ok(format!("unchecked((sbyte){buffer}[{offset}])")),
        "u8" => Ok(format!("{buffer}[{offset}]")),
        "bool" => Ok(format!("{buffer}[{offset}] != 0")),
        "i16" => Ok(format!("BitConverter.ToInt16({buffer}, {offset})")),
        "u16" => Ok(format!("BitConverter.ToUInt16({buffer}, {offset})")),
        "i32" | "hresult" => Ok(format!("BitConverter.ToInt32({buffer}, {offset})")),
        "u32" => Ok(format!("BitConverter.ToUInt32({buffer}, {offset})")),
        "i64" => Ok(format!("BitConverter.ToInt64({buffer}, {offset})")),
        "u64" => Ok(format!("BitConverter.ToUInt64({buffer}, {offset})")),
        "f32" => Ok(format!("BitConverter.ToSingle({buffer}, {offset})")),
        "f64" => Ok(format!("BitConverter.ToDouble({buffer}, {offset})")),
        other => Err(GenerateError::Unsupported(other.to_owned())),
    }
}

fn csharp_identifier(value: &str) -> String {
    format!("@{value}")
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
struct GeneratedOperation {
    proxy: String,
    dispatcher: String,
}

#[allow(clippy::too_many_lines)]
fn generate_operation(operation: &Operation) -> Result<GeneratedOperation, GenerateError> {
    if operation
        .parameters
        .iter()
        .any(|parameter| parameter.direction != Direction::In || !is_scalar(&parameter.type_id))
        || !is_scalar(&operation.return_type_id)
    {
        return Err(GenerateError::Unsupported(format!(
            "operation {} needs custom marshalling",
            operation.name
        )));
    }
    let convention = match operation.calling_convention {
        CallingConvention::Cdecl => "__cdecl",
        CallingConvention::Stdcall => "__stdcall",
        CallingConvention::Winapi => "WINAPI",
    };
    let return_type = c_type(&operation.return_type_id)?;
    let params = operation
        .parameters
        .iter()
        .map(|parameter| {
            Ok(format!(
                "{} {}",
                c_type(&parameter.type_id)?,
                parameter.name
            ))
        })
        .collect::<Result<Vec<_>, GenerateError>>()?
        .join(", ");
    let request_bytes: usize = operation
        .parameters
        .iter()
        .map(|parameter| scalar_size(&parameter.type_id))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum();
    let response_bytes = scalar_size(&operation.return_type_id)?;
    let mut writes = String::new();
    let mut offset = 0;
    for parameter in &operation.parameters {
        let size = scalar_size(&parameter.type_id)?;
        writeln!(
            writes,
            "  wvb_store_le(request + {offset}, &{}, {size});",
            parameter.name
        )
        .expect("write to string");
        offset += size;
    }
    let proxy = format!(
        "\nWVB_EXPORT {return_type} {convention} {}({params}) {{\n\
         \x20 uint8_t request[{request_bytes_or_one}] = {{0}};\n\
         {writes}\
         \x20 uint8_t response[{response_bytes}] = {{0}};\n\
         \x20 size_t response_len = 0;\n\
         \x20 WvbStatus status = wvb_client_call(WVB_ADAPTER_HASH, {}, request, {request_bytes}, response, sizeof(response), &response_len);\n\
         \x20 if (status != WVB_STATUS_OK || response_len != sizeof(response)) {{ SetLastError(ERROR_GEN_FAILURE); return ({return_type})0; }}\n\
         \x20 {return_type} result = ({return_type})0;\n\
         \x20 wvb_load_le(&result, response, sizeof(result));\n\
         \x20 return result;\n\
         }}\n",
        operation.symbol,
        operation.id,
        request_bytes_or_one = request_bytes.max(1),
    );

    let parameter_types = operation
        .parameters
        .iter()
        .map(|parameter| c_type(&parameter.type_id))
        .collect::<Result<Vec<_>, _>>()?;
    let function_parameters = parameter_types.join(", ");
    let mut reads = String::new();
    let mut arguments = Vec::new();
    let mut offset = 0;
    for (index, parameter) in operation.parameters.iter().enumerate() {
        let ty = c_type(&parameter.type_id)?;
        let size = scalar_size(&parameter.type_id)?;
        writeln!(
            reads,
            "      {ty} arg{index} = ({ty})0; wvb_load_le(&arg{index}, request + {offset}, {size});"
        )
        .expect("write to string");
        arguments.push(format!("arg{index}"));
        offset += size;
    }
    let dispatcher = format!(
        "\n    case {}: {{\n\
         \x20     if (request_len != {request_bytes} || response_cap < {response_bytes}) return WVB_DISPATCH_INVALID_BUFFER;\n\
         {reads}\
         \x20     using Function = {return_type} ({convention}*)({function_parameters});\n\
         \x20     Function function = reinterpret_cast<Function>(wvb_resolve(\"{}\"));\n\
         \x20     if (!function) return WVB_DISPATCH_EXPORT_NOT_FOUND;\n\
         \x20     {return_type} result = function({arguments});\n\
         \x20     wvb_store_le(response, &result, sizeof(result));\n\
         \x20     *response_len = sizeof(result);\n\
         \x20     return WVB_DISPATCH_OK;\n\
         \x20   }}\n",
        operation.id,
        operation.symbol,
        arguments = arguments.join(", "),
    );
    Ok(GeneratedOperation { proxy, dispatcher })
}

fn is_scalar(value: &str) -> bool {
    matches!(
        value,
        "i8" | "u8"
            | "i16"
            | "u16"
            | "i32"
            | "u32"
            | "i64"
            | "u64"
            | "f32"
            | "f64"
            | "bool"
            | "hresult"
    )
}

fn c_type(value: &str) -> Result<&'static str, GenerateError> {
    match value {
        "i8" => Ok("int8_t"),
        "u8" | "bool" => Ok("uint8_t"),
        "i16" => Ok("int16_t"),
        "u16" => Ok("uint16_t"),
        "i32" | "hresult" => Ok("int32_t"),
        "u32" => Ok("uint32_t"),
        "i64" => Ok("int64_t"),
        "u64" => Ok("uint64_t"),
        "f32" => Ok("float"),
        "f64" => Ok("double"),
        other => Err(GenerateError::Unsupported(other.to_owned())),
    }
}

fn scalar_size(value: &str) -> Result<usize, GenerateError> {
    match value {
        "i8" | "u8" | "bool" => Ok(1),
        "i16" | "u16" => Ok(2),
        "i32" | "u32" | "f32" | "hresult" => Ok(4),
        "i64" | "u64" | "f64" => Ok(8),
        other => Err(GenerateError::Unsupported(other.to_owned())),
    }
}

fn byte_array(value: &[u8]) -> String {
    value
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn escape_c_wide(value: &str) -> Result<String, GenerateError> {
    if value.contains(['\0', '"']) {
        return Err(GenerateError::Unsupported("unsafe target path".into()));
    }
    Ok(value.replace('\\', "\\\\"))
}

const PROXY_PREAMBLE: &str = r#"#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "wvb_client.h"
#define WVB_EXPORT __declspec(dllexport)
static void wvb_store_le(uint8_t *out, const void *value, size_t size) { memcpy(out, value, size); }
static void wvb_load_le(void *out, const uint8_t *value, size_t size) { memcpy(out, value, size); }
"#;

const DISPATCHER_PREAMBLE: &str = r#"#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
enum { WVB_DISPATCH_OK=0, WVB_DISPATCH_INVALID_BUFFER=1, WVB_DISPATCH_EXPORT_NOT_FOUND=2, WVB_DISPATCH_OPERATION_UNKNOWN=3, WVB_DISPATCH_LOAD_FAILED=4 };
static HMODULE WVB_TARGET = NULL;
static HMODULE WVB_SELF = NULL;
static void wvb_store_le(uint8_t *out, const void *value, size_t size) { memcpy(out, value, size); }
static void wvb_load_le(void *out, const uint8_t *value, size_t size) { memcpy(out, value, size); }
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) WVB_SELF = instance;
  return TRUE;
}
static FARPROC wvb_resolve(const char *name) {
  if (!WVB_TARGET) {
    wchar_t path[32768];
    DWORD length = GetModuleFileNameW(WVB_SELF, path, 32768);
    if (!length || length >= 32768) return NULL;
    while (length && path[length - 1] != L'\\' && path[length - 1] != L'/') --length;
    if (!length || wcslen(WVB_TARGET_RELATIVE) >= 32768 - length) return NULL;
    wcscpy(path + length, WVB_TARGET_RELATIVE);
    WVB_TARGET = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
  }
  return WVB_TARGET ? GetProcAddress(WVB_TARGET, name) : NULL;
}
extern "C" __declspec(dllexport) int32_t __stdcall wvb_dispatch(uint32_t operation_id, const uint8_t *request, size_t request_len, uint8_t *response, size_t response_cap, size_t *response_len) {
  if ((!request && request_len) || !response || !response_len) return WVB_DISPATCH_INVALID_BUFFER;
  switch (operation_id) {
"#;

const DISPATCHER_EPILOGUE: &str = r"
    default: return WVB_DISPATCH_OPERATION_UNKNOWN;
  }
}
";

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::tempdir;
    use wvb_ir::{
        Architecture, CallingConvention, Direction, ManagedOperation, ManagedTarget,
        ManagedTargetFramework, Operation, Parameter, Sensitivity, TargetFamily, TargetIdentity,
    };

    fn contract() -> AdapterContract {
        AdapterContract {
            schema_version: 2,
            adapter_id: "example.math".into(),
            adapter_version: "1.0.0".into(),
            family: TargetFamily::NativeCDll,
            target: TargetIdentity {
                relative_path: "example-math.dll".into(),
                sha256: "a".repeat(64),
                architecture: Architecture::X86_64,
            },
            managed: None,
            dependencies: Vec::new(),
            types: BTreeMap::new(),
            operations: vec![Operation {
                id: 1,
                name: "Add".into(),
                symbol: "ExampleAdd".into(),
                calling_convention: CallingConvention::Stdcall,
                timeout_ms: 1_000,
                request_schema_id: 0x3000_0001,
                response_schema_id: 0x3000_0002,
                parameters: vec![
                    Parameter {
                        name: "left".into(),
                        type_id: "i32".into(),
                        direction: Direction::In,
                        sensitivity: Sensitivity::Public,
                        max_bytes: None,
                    },
                    Parameter {
                        name: "right".into(),
                        type_id: "i32".into(),
                        direction: Direction::In,
                        sensitivity: Sensitivity::Public,
                        max_bytes: None,
                    },
                ],
                return_type_id: "i32".into(),
                managed: None,
            }],
        }
    }

    #[test]
    fn scalar_proxy_and_dispatcher_are_concrete() {
        let directory = tempdir().unwrap();
        generate(&contract(), directory.path()).unwrap();
        let proxy = fs::read_to_string(directory.path().join("proxy.generated.c")).unwrap();
        let dispatcher =
            fs::read_to_string(directory.path().join("dispatcher.generated.cpp")).unwrap();
        assert!(proxy.contains("ExampleAdd"));
        assert!(proxy.contains("wvb_client_call"));
        assert!(dispatcher.contains("LoadLibraryExW"));
        assert!(dispatcher.contains("GetProcAddress"));
        assert!(dispatcher.contains("case 1"));
    }

    fn managed_contract() -> AdapterContract {
        let mut value = contract();
        value.family = TargetFamily::DotNetAssembly;
        value.target.relative_path = "lib/Example.Math.dll".into();
        value.managed = Some(ManagedTarget {
            assembly_name: "Example.Math".into(),
            assembly_version: "1.0.0.0".into(),
            root_namespace: "Example.Math".into(),
            target_framework: ManagedTargetFramework::Net8Windows,
            requires_strong_name: false,
            strong_name_key_file: None,
        });
        value.operations[0].managed = Some(ManagedOperation {
            declaring_type: "Example.Math.Calculator".into(),
            declaring_type_is_static: true,
            member_name: "Add".into(),
            is_public: true,
            is_static: true,
        });
        value
    }

    #[test]
    fn managed_scalar_static_proxy_is_deterministic() {
        let first = tempdir().unwrap();
        let second = tempdir().unwrap();
        let mut contract = managed_contract();
        let mut second_operation = contract.operations[0].clone();
        second_operation.id = 2;
        second_operation.name = "Subtract".into();
        second_operation.symbol = "Example.ManagedMath.Calculator.Subtract".into();
        second_operation.managed.as_mut().unwrap().member_name = "Subtract".into();
        contract.operations.push(second_operation);
        contract.validate().unwrap();

        generate(&contract, first.path()).unwrap();
        generate(&contract, second.path()).unwrap();

        for file in [
            "Example.Math.csproj",
            "Proxy.generated.cs",
            "contract.canonical.json",
        ] {
            assert_eq!(
                fs::read(first.path().join(file)).unwrap(),
                fs::read(second.path().join(file)).unwrap()
            );
        }
        let source = fs::read_to_string(first.path().join("Proxy.generated.cs")).unwrap();
        assert!(source.contains("namespace @Example.@Math"));
        assert!(source.contains("public static partial class @Calculator"));
        assert!(source.contains("public static int @Add(int @left, int @right)"));
        assert!(source.contains("public static int @Subtract(int @left, int @right)"));
        assert!(source.contains("EntryPoint = \"wvb_client_call\""));
        assert_eq!(source.matches("AdapterHash = new byte[]").count(), 1);
        assert!(source.contains("BitConverter.GetBytes(@left).CopyTo(request, 0);"));
        assert!(source.contains("BitConverter.ToInt32(response, 0)"));
        let project = fs::read_to_string(first.path().join("Example.Math.csproj")).unwrap();
        assert!(project.contains("<AssemblyVersion>1.0.0.0</AssemblyVersion>"));
        assert!(project.contains("<PlatformTarget>x64</PlatformTarget>"));
    }

    #[test]
    fn managed_generation_stops_on_instance_and_non_scalar_members() {
        let directory = tempdir().unwrap();
        let mut contract = managed_contract();
        contract.operations[0].managed.as_mut().unwrap().is_static = false;
        assert!(matches!(
            generate(&contract, directory.path()),
            Err(GenerateError::Contract(ContractError::Managed(reason)))
                if reason.contains("instance-state semantics")
        ));

        let directory = tempdir().unwrap();
        let mut contract = managed_contract();
        contract.operations[0].parameters[0].type_id = "utf16".into();
        assert!(matches!(
            generate(&contract, directory.path()),
            Err(GenerateError::Unsupported(reason))
                if reason.contains("custom marshalling")
        ));

        let directory = tempdir().unwrap();
        let mut contract = managed_contract();
        let managed = contract.managed.as_mut().unwrap();
        managed.requires_strong_name = true;
        managed.strong_name_key_file = Some("signing/authorized.snk".into());
        assert!(matches!(
            generate(&contract, directory.path()),
            Err(GenerateError::Unsupported(reason))
                if reason.contains("strong-name identity")
        ));

        let directory = tempdir().unwrap();
        let mut contract = managed_contract();
        contract.managed.as_mut().unwrap().target_framework = ManagedTargetFramework::Net481;
        assert!(matches!(
            generate(&contract, directory.path()),
            Err(GenerateError::Unsupported(reason))
                if reason.contains(".NET Framework 4.8.1")
        ));
    }
}
