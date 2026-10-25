//! Opt-in macOS source-fixture loader, not Windows runtime support.

use std::ffi::{CStr, CString, c_char, c_void};
use std::os::unix::ffi::OsStrExt;

use wvb_broker::{DispatchOutcome, TypedDispatchModule};
use wvb_integrity::sha256_file;

use crate::{
    DispatchFn, NativeHostConfig, NativeHostError, invoke_dispatch, validate_response_capacity,
};

const RTLD_NOW: i32 = 0x2;
const RTLD_LOCAL: i32 = 0x4;
const RTLD_FIRST: i32 = 0x100;

unsafe extern "C" {
    fn dlopen(path: *const c_char, mode: i32) -> *mut c_void;
    fn dlsym(module: *mut c_void, name: *const c_char) -> *mut c_void;
    fn dlclose(module: *mut c_void) -> i32;
    fn dlerror() -> *const c_char;
}

pub struct SourceFixtureDispatcher {
    module: usize,
    dispatch: DispatchFn,
    response_capacity: usize,
}

impl SourceFixtureDispatcher {
    /// Loads a trusted local source-test dylib only.
    ///
    /// # Safety
    /// The library and its initializers must be trusted, expose the exact
    /// `whiny.dispatch.v1` ABI, honor buffer capacities and support concurrent
    /// invocation. Hash matching is identity, not authorization or safety.
    pub unsafe fn load(config: &NativeHostConfig) -> Result<Self, NativeHostError> {
        validate_response_capacity(config.response_capacity)?;
        if !config.dispatcher_path.is_absolute() {
            return Err(NativeHostError::InvalidPath);
        }
        let path = CString::new(config.dispatcher_path.as_os_str().as_bytes())
            .map_err(|_| NativeHostError::InvalidPath)?;
        if sha256_file(&config.dispatcher_path)? != config.dispatcher_sha256 {
            return Err(NativeHostError::LoadFailed);
        }
        let module = unsafe { dlopen(path.as_ptr(), RTLD_NOW | RTLD_LOCAL | RTLD_FIRST) };
        if module.is_null() {
            return Err(NativeHostError::SourceFixtureLoad(dynamic_error()));
        }
        let symbol = unsafe { dlsym(module, c"whiny_dispatch_v1".as_ptr()) };
        if symbol.is_null() {
            close(module);
            return Err(NativeHostError::ExportMissing);
        }
        let dispatch = unsafe { std::mem::transmute::<*mut c_void, DispatchFn>(symbol) };
        Ok(Self {
            module: module as usize,
            dispatch,
            response_capacity: config.response_capacity,
        })
    }
}

impl TypedDispatchModule for SourceFixtureDispatcher {
    fn dispatch(&self, operation_id: u32, request: &[u8]) -> DispatchOutcome {
        unsafe { invoke_dispatch(self.dispatch, self.response_capacity, operation_id, request) }
    }
}

impl Drop for SourceFixtureDispatcher {
    fn drop(&mut self) {
        close(self.module as *mut c_void);
    }
}

fn close(module: *mut c_void) {
    if unsafe { dlclose(module) } != 0 {
        eprintln!("source-fixture unload failed: {}", dynamic_error());
    }
}

fn dynamic_error() -> String {
    let error = unsafe { dlerror() };
    if error.is_null() {
        return "dynamic loader failed without a diagnostic".into();
    }
    unsafe { CStr::from_ptr(error) }
        .to_string_lossy()
        .into_owned()
}
