//! Generic Windows loader for the frozen `whiny.dispatch.v1` native ABI.
#![allow(unsafe_code)]

use std::path::PathBuf;

use wvb_broker::DispatchOutcome;
#[cfg(not(windows))]
use wvb_broker::TypedDispatchModule;
use wvb_call::LOGICAL_MAX;

pub const DISPATCHER_ABI_IDENTIFIER: &str = "whiny.dispatch.v1";

#[cfg(all(feature = "source-fixture", target_os = "macos"))]
pub mod source_fixture;

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
    InvalidResponseCapacity,
    #[cfg(all(feature = "source-fixture", target_os = "macos"))]
    SourceFixtureLoad(String),
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

fn validate_response_capacity(capacity: usize) -> Result<(), NativeHostError> {
    if capacity == 0 || capacity > LOGICAL_MAX {
        return Err(NativeHostError::InvalidResponseCapacity);
    }
    Ok(())
}

#[cfg(any(windows, test, all(feature = "source-fixture", target_os = "macos")))]
type DispatchFn =
    unsafe extern "system" fn(u32, *const u8, usize, *mut u8, usize, *mut usize) -> i32;

#[cfg(any(windows, test, all(feature = "source-fixture", target_os = "macos")))]
unsafe fn invoke_dispatch(
    dispatch: DispatchFn,
    response_capacity: usize,
    operation_id: u32,
    request: &[u8],
) -> DispatchOutcome {
    if validate_response_capacity(response_capacity).is_err() || request.len() > LOGICAL_MAX {
        return DispatchOutcome {
            status: -1,
            body: Vec::new(),
        };
    }
    let mut response = vec![0_u8; response_capacity];
    let mut response_length = 0_usize;
    let status = unsafe {
        dispatch(
            operation_id,
            request.as_ptr(),
            request.len(),
            response.as_mut_ptr(),
            response.len(),
            &raw mut response_length,
        )
    };
    bounded_dispatch_outcome(status, response, response_length)
}

#[cfg(any(windows, test, all(feature = "source-fixture", target_os = "macos")))]
fn bounded_dispatch_outcome(
    status: i32,
    mut response: Vec<u8>,
    response_length: usize,
) -> DispatchOutcome {
    if response.len() > LOGICAL_MAX || response_length > response.len() {
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

#[cfg(windows)]
mod windows {
    use super::{
        DispatchFn, NativeHostConfig, NativeHostError, invoke_dispatch, validate_response_capacity,
    };
    use std::ffi::{c_char, c_void};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use wvb_broker::{DispatchOutcome, TypedDispatchModule};
    use wvb_integrity::sha256_file;

    const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
    const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;

    type Module = *mut c_void;
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
            validate_response_capacity(config.response_capacity)?;
            if sha256_file(&config.dispatcher_path)? != config.dispatcher_sha256 {
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
            unsafe { invoke_dispatch(self.dispatch, self.response_capacity, operation_id, request) }
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
    pub fn load(config: &NativeHostConfig) -> Result<Self, NativeHostError> {
        validate_response_capacity(config.response_capacity)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(windows))]
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

    #[test]
    fn response_capacity_must_fit_the_actual_call_body_bound() {
        for capacity in [0, LOGICAL_MAX + 1, usize::MAX] {
            assert!(matches!(
                NativeDispatcher::load(&NativeHostConfig {
                    dispatcher_path: PathBuf::from("must-not-be-loaded.dll"),
                    dispatcher_sha256: [0; 32],
                    response_capacity: capacity,
                }),
                Err(NativeHostError::InvalidResponseCapacity)
            ));
        }
        assert!(validate_response_capacity(1).is_ok());
        assert!(validate_response_capacity(LOGICAL_MAX).is_ok());
    }

    #[test]
    fn dispatcher_cannot_publish_bytes_beyond_its_capacity() {
        for length in [5, usize::MAX] {
            let outcome = bounded_dispatch_outcome(0, vec![0xa5; 4], length);
            assert_eq!(outcome.status, -1);
            assert!(outcome.body.is_empty());
        }
        let maximum = bounded_dispatch_outcome(0, vec![0xa5; LOGICAL_MAX], LOGICAL_MAX);
        assert_eq!(maximum.body.len(), LOGICAL_MAX);
        let oversized = bounded_dispatch_outcome(0, vec![0xa5; LOGICAL_MAX + 1], 4);
        assert_eq!(oversized.status, -1);
        assert!(oversized.body.is_empty());
    }

    #[test]
    fn host_preserves_dispatch_status_and_only_the_reported_typed_bytes() {
        let outcome =
            bounded_dispatch_outcome(0, [0x8000_4005_u32.to_le_bytes(), [0xa5; 4]].concat(), 4);
        assert_eq!(outcome.status, 0);
        assert_eq!(outcome.body, 0x8000_4005_u32.to_le_bytes());
        let failed = bounded_dispatch_outcome(-17, vec![42; 4], 4);
        assert_eq!(failed.status, -17);
        assert_eq!(failed.body, vec![42; 4]);
    }

    #[test]
    fn shared_invocation_checks_bounds_before_the_single_export_call() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "system" fn export(
            operation: u32,
            _: *const u8,
            _: usize,
            response: *mut u8,
            capacity: usize,
            length: *mut usize,
        ) -> i32 {
            CALLS.fetch_add(1, Ordering::SeqCst);
            assert_eq!(capacity, 4);
            unsafe {
                std::ptr::copy_nonoverlapping(0x8000_4005_u32.to_le_bytes().as_ptr(), response, 4);
                length.write(if operation == 3 { usize::MAX } else { 4 });
            }
            if operation == 2 { -17 } else { 0 }
        }

        for capacity in [0, LOGICAL_MAX + 1] {
            let outcome = unsafe { invoke_dispatch(export, capacity, 1, &[]) };
            assert_eq!(outcome.status, -1);
            assert!(outcome.body.is_empty());
        }
        let oversized = unsafe { invoke_dispatch(export, 4, 1, &vec![0; LOGICAL_MAX + 1]) };
        assert_eq!(oversized.status, -1);
        assert_eq!(CALLS.load(Ordering::SeqCst), 0);
        for (operation, status) in [(1, 0), (2, -17), (3, -1)] {
            let outcome = unsafe { invoke_dispatch(export, 4, operation, &[]) };
            assert_eq!(outcome.status, status);
            if operation == 3 {
                assert!(outcome.body.is_empty());
            } else {
                assert_eq!(outcome.body, 0x8000_4005_u32.to_le_bytes());
            }
            assert_eq!(CALLS.load(Ordering::SeqCst), operation as usize);
        }
    }
}
