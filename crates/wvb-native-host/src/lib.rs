//! Generic Windows loader for the frozen `whiny.dispatch.v1` native ABI.
#![allow(unsafe_code)]

use std::path::PathBuf;

use wvb_broker::DispatchOutcome;
#[cfg(not(windows))]
use wvb_broker::TypedDispatchModule;
use wvb_call::LOGICAL_MAX;

pub mod object;

pub const DISPATCHER_ABI_IDENTIFIER: &str = "whiny.dispatch.v1";

#[cfg(all(feature = "source-fixture", target_os = "macos"))]
pub mod source_fixture;

pub struct NativeHostConfig {
    pub dispatcher_path: PathBuf,
    pub dispatcher_sha256: [u8; 32],
    pub response_capacity: usize,
}

pub struct ComTargetConfig {
    pub clsid: String,
    pub path: PathBuf,
    pub sha256: [u8; 32],
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

    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoInitializeEx(reserved: *mut c_void, model: u32) -> i32;
        fn CoUninitialize();
    }

    type ActivateObject = unsafe extern "system" fn(*mut *mut c_void) -> i32;
    type InvokeObject = unsafe extern "system" fn(*mut c_void, u32, *mut u32) -> i32;
    type ReleaseObject = unsafe extern "system" fn(*mut c_void) -> u32;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegGetValueW(
            key: *mut c_void,
            subkey: *const u16,
            value: *const u16,
            flags: u32,
            kind: *mut u32,
            data: *mut c_void,
            bytes: *mut u32,
        ) -> i32;
    }

    fn verify_com_registration(target: &super::ComTargetConfig) -> Result<(), String> {
        let key = format!(
            "Software\\Classes\\CLSID\\{{{}}}\\LocalServer32",
            target.clsid
        )
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
        let mut buffer = vec![0_u16; 16_384];
        let mut size = u32::try_from(buffer.len() * 2).map_err(|error| error.to_string())?;
        // Windows predefined HKEY_CURRENT_USER is a sign-extended LONG.
        let current_user = (-2_147_483_647_isize) as *mut c_void;
        let status = unsafe {
            RegGetValueW(
                current_user,
                key.as_ptr(),
                ptr::null(),
                2,
                ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &raw mut size,
            )
        };
        if status != 0 {
            return Err(format!("current-user LocalServer32 read status={status}"));
        }
        let length = usize::try_from(size).map_err(|error| error.to_string())? / 2;
        if length == 0 || length > buffer.len() || buffer[length - 1] != 0 {
            return Err("invalid LocalServer32 string".into());
        }
        let command =
            String::from_utf16(&buffer[..length - 1]).map_err(|error| error.to_string())?;
        let rest = command
            .strip_prefix('"')
            .ok_or("LocalServer32 executable must be quoted")?;
        let (executable, _) = rest
            .split_once('"')
            .ok_or("LocalServer32 closing quote missing")?;
        let actual = std::fs::canonicalize(executable).map_err(|error| error.to_string())?;
        let expected = std::fs::canonicalize(&target.path).map_err(|error| error.to_string())?;
        if actual != expected
            || sha256_file(&actual).map_err(|error| error.to_string())? != target.sha256
        {
            return Err("LocalServer32 does not resolve to the admitted target".into());
        }
        Ok(())
    }

    struct ComBackend {
        module: Module,
        activate: ActivateObject,
        invoke: InvokeObject,
        release: ReleaseObject,
        target: super::ComTargetConfig,
    }

    impl super::object::ObjectBackend for ComBackend {
        fn activate(&mut self) -> (i32, Option<usize>) {
            if let Err(error) = verify_com_registration(&self.target) {
                eprintln!("wvb: COM registration rejected before activation: {error}");
                return (i32::from_le_bytes(0x8007_0005_u32.to_le_bytes()), None);
            }
            let mut object = ptr::null_mut();
            let hr = unsafe { (self.activate)(&raw mut object) };
            (hr, (!object.is_null()).then_some(object as usize))
        }

        fn invoke(&mut self, object: usize, input: u32) -> (i32, u32) {
            let mut output = 0;
            let hr = unsafe { (self.invoke)(object as *mut c_void, input, &raw mut output) };
            (hr, output)
        }

        fn release(&mut self, object: usize) {
            unsafe {
                (self.release)(object as *mut c_void);
            }
        }
    }

    impl Drop for ComBackend {
        fn drop(&mut self) {
            unsafe {
                FreeLibrary(self.module);
                CoUninitialize();
            }
        }
    }

    pub fn load_com_backend(
        config: &NativeHostConfig,
        target: super::ComTargetConfig,
    ) -> Result<Box<dyn super::object::ObjectBackend>, wvb_broker::BrokerError> {
        let error = |reason: &str| wvb_broker::BrokerError::Handler(reason.into());
        if unsafe { CoInitializeEx(ptr::null_mut(), 0) } < 0 {
            return Err(error("MTA initialization failed"));
        }
        let loaded = (|| {
            if sha256_file(&config.dispatcher_path).map_err(|e| error(&e.to_string()))?
                != config.dispatcher_sha256
            {
                return Err(error("object dispatcher hash mismatch"));
            }
            let path = wide_path(&config.dispatcher_path).map_err(|e| error(&e.to_string()))?;
            let module = unsafe {
                LoadLibraryExW(
                    path.as_ptr(),
                    ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
                )
            };
            if module.is_null() {
                return Err(error("object dispatcher load failed"));
            }
            let exports = unsafe {
                (
                    load_symbol::<ActivateObject>(module, b"whiny_object_activate_v1\0"),
                    load_symbol::<InvokeObject>(module, b"whiny_object_invoke_v1\0"),
                    load_symbol::<ReleaseObject>(module, b"whiny_object_release_v1\0"),
                )
            };
            if let (Some(activate), Some(invoke), Some(release)) = exports {
                Ok(Box::new(ComBackend {
                    module,
                    activate,
                    invoke,
                    release,
                    target,
                }) as Box<dyn super::object::ObjectBackend>)
            } else {
                unsafe {
                    FreeLibrary(module);
                }
                Err(error("object dispatcher missing generated ABI export"))
            }
        })();
        if loaded.is_err() {
            unsafe {
                CoUninitialize();
            }
        }
        loaded
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

#[cfg(windows)]
pub use windows::load_com_backend;

#[cfg(not(windows))]
pub fn load_com_backend(
    _config: &NativeHostConfig,
    _target: ComTargetConfig,
) -> Result<Box<dyn object::ObjectBackend>, wvb_broker::BrokerError> {
    Err(wvb_broker::BrokerError::Handler(
        "COM object backend requires Windows".into(),
    ))
}

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
