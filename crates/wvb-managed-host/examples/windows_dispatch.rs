#[cfg(windows)]
use std::path::PathBuf;

#[cfg(windows)]
use wvb_broker::TypedDispatchModule;
#[cfg(windows)]
use wvb_managed_host::{ManagedHostConfig, NativeManagedDispatcher};

#[cfg(windows)]
fn main() {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 13 {
        std::process::exit(64);
    }
    let config = ManagedHostConfig {
        host_dll: PathBuf::from(&arguments[1]),
        host_dll_sha256: hash(&arguments[2]),
        dotnet_root: PathBuf::from(&arguments[3]),
        nethost_path: PathBuf::from(&arguments[4]),
        nethost_sha256: hash(&arguments[5]),
        hostfxr_sha256: hash(&arguments[6]),
        runtime_config_path: PathBuf::from(&arguments[7]),
        runtime_config_sha256: hash(&arguments[8]),
        dispatcher_assembly_path: PathBuf::from(&arguments[9]),
        dispatcher_assembly_sha256: hash(&arguments[10]),
        target_assembly_path: PathBuf::from(&arguments[11]),
        target_assembly_sha256: hash(&arguments[12]),
        dispatcher_type_name: String::from(
            "Whiny.Generated.ManagedDispatcher, ExampleManagedMath.WhinyDispatcher",
        ),
        dispatcher_method_name: String::from("DispatchUnmanaged"),
    };
    let dispatcher = NativeManagedDispatcher::load(&config).unwrap_or_else(|_| {
        std::process::exit(70);
    });
    let mut request = Vec::new();
    request.extend_from_slice(&20_i32.to_le_bytes());
    request.extend_from_slice(&22_i32.to_le_bytes());
    let result = dispatcher.dispatch(1, &request);
    if result.status != 0
        || result.body.len() != 4
        || i32::from_le_bytes(result.body.try_into().unwrap()) != 42
    {
        std::process::exit(71);
    }
}

#[cfg(windows)]
fn hash(value: &str) -> [u8; 32] {
    if value.len() != 64 {
        std::process::exit(65);
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap_or_else(|_| {
            std::process::exit(65);
        });
    }
    output
}

#[cfg(not(windows))]
fn main() {
    std::process::exit(2);
}
