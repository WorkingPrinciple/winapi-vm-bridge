//! Generic Windows loader for the frozen `whiny.dispatch.v1` native ABI.
#![allow(unsafe_code)]

use std::path::PathBuf;

#[cfg(not(windows))]
use wvb_broker::{DispatchOutcome, TypedDispatchModule};

pub const DISPATCHER_ABI_IDENTIFIER: &str = "whiny.dispatch.v1";

pub struct NativeHostConfig {
    pub dispatcher_path: PathBuf,
    pub dispatcher_sha256: [u8; 32],
    pub response_capacity: usize,
}

#[derive(Debug)]
pub enum NativeHostError {
    UnsupportedPlatform,
    Integrity(wvb_integrity::IntegrityError),
    InvalidPath,
    LoadFailed,
    ExportMissing,
}

impl std::fmt::Display for NativeHostError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for NativeHostError {}

impl From<wvb_integrity::IntegrityError> for NativeHostError {
    fn from(value: wvb_integrity::IntegrityError) -> Self {
        Self::Integrity(value)
    }
}

#[cfg(windows)]
mod windows {
    use super::{NativeHostConfig, NativeHostError};
    use std::ffi::{c_char, c_void};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use wvb_broker::{DispatchOutcome, TypedDispatchModule};
    use wvb_integrity::sha256_file;

    const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
    const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;

    type Module = *mut c_void;
    type DispatchFn =
        unsafe extern "system" fn(u32, *const u8, usize, *mut u8, usize, *mut usize) -> i32;

    unsafe extern "system" {
        fn LoadLibraryExW(path: *const u16, file: *mut c_void, flags: u32) -> Module;
        fn GetProcAddress(module: Module, name: *const c_char) -> *mut c_void;
        fn FreeLibrary(module: Module) -> i32;
    }

    pub struct NativeDispatcher {
        module: usize,
        dispatch: DispatchFn,
        response_capacity: usize,
    }

    impl NativeDispatcher {
        pub fn load(config: &NativeHostConfig) -> Result<Self, NativeHostError> {
            if config.response_capacity == 0
                || sha256_file(&config.dispatcher_path)? != config.dispatcher_sha256
            {
                return Err(NativeHostError::LoadFailed);
            }
            let path = wide_path(&config.dispatcher_path)?;
            let module = unsafe {
                LoadLibraryExW(
                    path.as_ptr(),
                    ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
                )
            };
            if module.is_null() {
                return Err(NativeHostError::LoadFailed);
            }
            let dispatch = unsafe { load_symbol::<DispatchFn>(module, b"whiny_dispatch_v1\0") };
            let Some(dispatch) = dispatch else {
                unsafe {
                    FreeLibrary(module);
                }
                return Err(NativeHostError::ExportMissing);
            };
            Ok(Self {
                module: module as usize,
                dispatch,
                response_capacity: config.response_capacity,
            })
        }
    }

    impl TypedDispatchModule for NativeDispatcher {
        fn dispatch(&self, operation_id: u32, request: &[u8]) -> DispatchOutcome {
            let mut response = vec![0_u8; self.response_capacity];
            let mut response_length = 0_usize;
            let status = unsafe {
                (self.dispatch)(
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
                    status: -1,
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

    impl Drop for NativeDispatcher {
        fn drop(&mut self) {
            unsafe {
                FreeLibrary(self.module as Module);
            }
        }
    }

    fn wide_path(path: &std::path::Path) -> Result<Vec<u16>, NativeHostError> {
        let value = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        if value.len() <= 1 || value[..value.len() - 1].contains(&0) {
            return Err(NativeHostError::InvalidPath);
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

    pub use NativeDispatcher as PlatformDispatcher;
}

#[cfg(windows)]
pub use windows::PlatformDispatcher as NativeDispatcher;

#[cfg(not(windows))]
pub struct NativeDispatcher;

#[cfg(not(windows))]
impl NativeDispatcher {
    pub fn load(_config: &NativeHostConfig) -> Result<Self, NativeHostError> {
        Err(NativeHostError::UnsupportedPlatform)
    }
}

#[cfg(not(windows))]
impl TypedDispatchModule for NativeDispatcher {
    fn dispatch(&self, _operation_id: u32, _request: &[u8]) -> DispatchOutcome {
        DispatchOutcome {
            status: -1,
            body: Vec::new(),
        }
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn non_windows_loader_fails_closed() {
        assert!(matches!(
            NativeDispatcher::load(&NativeHostConfig {
                dispatcher_path: PathBuf::new(),
                dispatcher_sha256: [0; 32],
                response_capacity: 1024,
            }),
            Err(NativeHostError::UnsupportedPlatform)
        ));
    }
}
