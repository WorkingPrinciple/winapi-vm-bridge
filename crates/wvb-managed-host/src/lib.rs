//! Windows CLR-host adapter for the canonical typed-dispatch broker seam.
#![allow(unsafe_code)]

use std::path::PathBuf;

#[cfg(not(windows))]
use wvb_broker::{DispatchOutcome, TypedDispatchModule};

pub struct ManagedHostConfig {
    pub host_dll: PathBuf,
    pub host_dll_sha256: [u8; 32],
    pub dotnet_root: PathBuf,
    pub nethost_path: PathBuf,
    pub nethost_sha256: [u8; 32],
    pub hostfxr_sha256: [u8; 32],
    pub runtime_config_path: PathBuf,
    pub runtime_config_sha256: [u8; 32],
    pub dispatcher_assembly_path: PathBuf,
    pub dispatcher_assembly_sha256: [u8; 32],
    pub target_assembly_path: PathBuf,
    pub target_assembly_sha256: [u8; 32],
    pub dispatcher_type_name: String,
    pub dispatcher_method_name: String,
}

#[derive(Debug)]
pub enum ManagedHostError {
    UnsupportedPlatform,
    Io(std::io::Error),
    HashMismatch,
    InvalidPath,
    LoadFailed,
    CreateFailed(i32),
}

impl std::fmt::Display for ManagedHostError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ManagedHostError {}

impl From<std::io::Error> for ManagedHostError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[cfg(windows)]
mod windows {
    use super::{ManagedHostConfig, ManagedHostError};
    use sha2::{Digest, Sha256};
    use std::ffi::{c_char, c_void};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;
    use wvb_broker::{DispatchOutcome, TypedDispatchModule};

    const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
    const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;
    const WVB_MANAGED_HOST_OK: i32 = 0;
    const RESPONSE_CAPACITY: usize = 8;

    type Module = *mut c_void;
    type Host = *mut c_void;
    type CreateFn = unsafe extern "C" fn(*const NativeConfig, *mut Host) -> i32;
    type DispatchFn =
        unsafe extern "C" fn(Host, u32, *const u8, usize, *mut u8, usize, *mut usize) -> i32;
    type DestroyFn = unsafe extern "C" fn(Host);

    #[repr(C)]
    struct NativeConfig {
        struct_size: u32,
        dotnet_root: *const u16,
        nethost_path: *const u16,
        nethost_sha256: [u8; 32],
        hostfxr_sha256: [u8; 32],
        runtime_config_path: *const u16,
        runtime_config_sha256: [u8; 32],
        dispatcher_assembly_path: *const u16,
        dispatcher_assembly_sha256: [u8; 32],
        target_assembly_path: *const u16,
        target_assembly_sha256: [u8; 32],
        dispatcher_type_name: *const u16,
        dispatcher_method_name: *const u16,
    }

    unsafe extern "system" {
        fn LoadLibraryExW(path: *const u16, file: *mut c_void, flags: u32) -> Module;
        fn GetProcAddress(module: Module, name: *const c_char) -> *mut c_void;
        fn FreeLibrary(module: Module) -> i32;
    }

    pub struct NativeManagedDispatcher {
        module: usize,
        host: usize,
        dispatch: DispatchFn,
        destroy: DestroyFn,
    }

    impl NativeManagedDispatcher {
        pub fn load(config: &ManagedHostConfig) -> Result<Self, ManagedHostError> {
            verify_hash(&config.host_dll, &config.host_dll_sha256)?;
            let host_dll = wide_path(&config.host_dll)?;
            let dotnet_root = wide_path(&config.dotnet_root)?;
            let nethost_path = wide_path(&config.nethost_path)?;
            let runtime_config_path = wide_path(&config.runtime_config_path)?;
            let dispatcher_assembly_path = wide_path(&config.dispatcher_assembly_path)?;
            let target_assembly_path = wide_path(&config.target_assembly_path)?;
            let dispatcher_type_name = wide_text(&config.dispatcher_type_name)?;
            let dispatcher_method_name = wide_text(&config.dispatcher_method_name)?;
            let struct_size = u32::try_from(std::mem::size_of::<NativeConfig>())
                .map_err(|_| ManagedHostError::InvalidPath)?;
            let module = unsafe {
                LoadLibraryExW(
                    host_dll.as_ptr(),
                    ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
                )
            };
            if module.is_null() {
                return Err(ManagedHostError::LoadFailed);
            }
            let create = unsafe { load_symbol::<CreateFn>(module, b"wvb_managed_host_create\0") };
            let dispatch =
                unsafe { load_symbol::<DispatchFn>(module, b"wvb_managed_host_dispatch\0") };
            let destroy =
                unsafe { load_symbol::<DestroyFn>(module, b"wvb_managed_host_destroy\0") };
            let (Some(create), Some(dispatch), Some(destroy)) = (create, dispatch, destroy) else {
                unsafe {
                    FreeLibrary(module);
                }
                return Err(ManagedHostError::LoadFailed);
            };
            let native = NativeConfig {
                struct_size,
                dotnet_root: dotnet_root.as_ptr(),
                nethost_path: nethost_path.as_ptr(),
                nethost_sha256: config.nethost_sha256,
                hostfxr_sha256: config.hostfxr_sha256,
                runtime_config_path: runtime_config_path.as_ptr(),
                runtime_config_sha256: config.runtime_config_sha256,
                dispatcher_assembly_path: dispatcher_assembly_path.as_ptr(),
                dispatcher_assembly_sha256: config.dispatcher_assembly_sha256,
                target_assembly_path: target_assembly_path.as_ptr(),
                target_assembly_sha256: config.target_assembly_sha256,
                dispatcher_type_name: dispatcher_type_name.as_ptr(),
                dispatcher_method_name: dispatcher_method_name.as_ptr(),
            };
            let mut host = ptr::null_mut();
            let status = unsafe { create(&raw const native, &raw mut host) };
            if status != WVB_MANAGED_HOST_OK || host.is_null() {
                unsafe {
                    FreeLibrary(module);
                }
                return Err(ManagedHostError::CreateFailed(status));
            }
            Ok(Self {
                module: module as usize,
                host: host as usize,
                dispatch,
                destroy,
            })
        }
    }

    impl TypedDispatchModule for NativeManagedDispatcher {
        fn dispatch(&self, operation_id: u32, request: &[u8]) -> DispatchOutcome {
            let mut response = vec![0_u8; RESPONSE_CAPACITY];
            let mut response_length = 0_usize;
            let status = unsafe {
                (self.dispatch)(
                    self.host as Host,
                    operation_id,
                    request.as_ptr(),
                    request.len(),
                    response.as_mut_ptr(),
                    response.len(),
                    &raw mut response_length,
                )
            };
            if response_length > response.len() {
                return DispatchOutcome {
                    status: -5,
                    body: Vec::new(),
                };
            }
            response.truncate(response_length);
            DispatchOutcome {
                status,
                body: response,
            }
        }
    }

    impl Drop for NativeManagedDispatcher {
        fn drop(&mut self) {
            unsafe {
                (self.destroy)(self.host as Host);
                FreeLibrary(self.module as Module);
            }
        }
    }

    fn verify_hash(path: &Path, expected: &[u8; 32]) -> Result<(), ManagedHostError> {
        let observed = Sha256::digest(std::fs::read(path)?);
        if observed.as_slice() != expected {
            return Err(ManagedHostError::HashMismatch);
        }
        Ok(())
    }

    fn wide_path(path: &Path) -> Result<Vec<u16>, ManagedHostError> {
        let value = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        if value.len() <= 1 || value[..value.len() - 1].contains(&0) {
            return Err(ManagedHostError::InvalidPath);
        }
        Ok(value)
    }

    fn wide_text(value: &str) -> Result<Vec<u16>, ManagedHostError> {
        let value = value
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        if value.len() <= 1 || value[..value.len() - 1].contains(&0) {
            return Err(ManagedHostError::InvalidPath);
        }
        Ok(value)
    }

    unsafe fn load_symbol<Function>(module: Module, name: &[u8]) -> Option<Function>
    where
        Function: Copy,
    {
        let symbol = unsafe { GetProcAddress(module, name.as_ptr().cast()) };
        if symbol.is_null() {
            return None;
        }
        assert_eq!(
            std::mem::size_of::<Function>(),
            std::mem::size_of_val(&symbol)
        );
        Some(unsafe { std::mem::transmute_copy(&symbol) })
    }

    pub use NativeManagedDispatcher as PlatformDispatcher;
}

#[cfg(windows)]
pub use windows::PlatformDispatcher as NativeManagedDispatcher;

#[cfg(not(windows))]
pub struct NativeManagedDispatcher;

#[cfg(not(windows))]
impl NativeManagedDispatcher {
    pub fn load(_config: &ManagedHostConfig) -> Result<Self, ManagedHostError> {
        Err(ManagedHostError::UnsupportedPlatform)
    }
}

#[cfg(not(windows))]
impl TypedDispatchModule for NativeManagedDispatcher {
    fn dispatch(&self, _operation_id: u32, _request: &[u8]) -> DispatchOutcome {
        DispatchOutcome {
            status: -4,
            body: Vec::new(),
        }
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn non_windows_loader_fails_closed() {
        #[cfg(not(windows))]
        {
            let config = ManagedHostConfig {
                host_dll: PathBuf::new(),
                host_dll_sha256: [0; 32],
                dotnet_root: PathBuf::new(),
                nethost_path: PathBuf::new(),
                nethost_sha256: [0; 32],
                hostfxr_sha256: [0; 32],
                runtime_config_path: PathBuf::new(),
                runtime_config_sha256: [0; 32],
                dispatcher_assembly_path: PathBuf::new(),
                dispatcher_assembly_sha256: [0; 32],
                target_assembly_path: PathBuf::new(),
                target_assembly_sha256: [0; 32],
                dispatcher_type_name: String::new(),
                dispatcher_method_name: String::new(),
            };
            assert!(matches!(
                NativeManagedDispatcher::load(&config),
                Err(ManagedHostError::UnsupportedPlatform)
            ));
        }
    }
}
