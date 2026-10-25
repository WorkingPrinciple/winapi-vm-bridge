use std::ffi::{OsString, c_void};
use std::os::windows::ffi::OsStringExt;
use std::ptr;

use wvb_broker::BrokerError;
use wvb_integrity::sha256_file;

use crate::object::ObjectBackend;
use crate::windows::{load_symbol, wide_path};
use crate::{NativeHostConfig, WinrtTargetConfig};

type Module = *mut c_void;
type Factory = unsafe extern "system" fn(*mut *mut c_void) -> i32;
type Create = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
type Invoke = unsafe extern "system" fn(*mut c_void, u32, *mut u32) -> i32;
type Release = unsafe extern "system" fn(*mut c_void) -> u32;

#[repr(C)]
struct ActCtx {
    size: u32,
    flags: u32,
    source: *const u16,
    architecture: u16,
    language: u16,
    assembly_directory: *const u16,
    resource_name: *const u16,
    application_name: *const u16,
    module: Module,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateActCtxW(context: *const ActCtx) -> Module;
    fn ActivateActCtx(context: Module, cookie: *mut usize) -> i32;
    fn DeactivateActCtx(flags: u32, cookie: usize) -> i32;
    fn ReleaseActCtx(context: Module);
    fn GetLastError() -> u32;
    fn LoadLibraryExW(path: *const u16, file: Module, flags: u32) -> Module;
    fn FreeLibrary(module: Module) -> i32;
    fn GetModuleHandleExW(flags: u32, address: *const u16, module: *mut Module) -> i32;
    fn GetModuleFileNameW(module: Module, path: *mut u16, capacity: u32) -> u32;
}

#[link(name = "runtimeobject")]
unsafe extern "system" {
    fn RoInitialize(model: u32) -> i32;
    fn RoUninitialize();
}

struct ActivationContext {
    handle: Module,
    cookie: Option<usize>,
}

impl ActivationContext {
    fn activate(target: &WinrtTargetConfig) -> Result<Self, BrokerError> {
        let source = wide_path(&target.manifest_path).map_err(failure)?;
        let directory = wide_path(
            target
                .path
                .parent()
                .ok_or_else(|| failure("target has no directory"))?,
        )
        .map_err(failure)?;
        // RO_INIT_MULTITHREADED is 1, unlike COINIT_MULTITHREADED (0).
        let hr = unsafe { RoInitialize(1) };
        if hr < 0 {
            return Err(failure(format!("RoInitialize(MTA) HRESULT={hr:#010x}")));
        }
        let mut context = Self {
            handle: ptr::null_mut(),
            cookie: None,
        };
        let definition = ActCtx {
            size: u32::try_from(std::mem::size_of::<ActCtx>()).map_err(failure)?,
            flags: 4, // ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID; never process-default.
            source: source.as_ptr(),
            architecture: 0,
            language: 0,
            assembly_directory: directory.as_ptr(),
            resource_name: ptr::null(),
            application_name: ptr::null(),
            module: ptr::null_mut(),
        };
        let handle = unsafe { CreateActCtxW(&raw const definition) };
        if handle == (-1_isize) as Module {
            return Err(failure(format!("CreateActCtxW error={}", unsafe {
                GetLastError()
            })));
        }
        context.handle = handle;
        let mut cookie = 0;
        if unsafe { ActivateActCtx(handle, &raw mut cookie) } == 0 {
            return Err(failure(format!("ActivateActCtx error={}", unsafe {
                GetLastError()
            })));
        }
        context.cookie = Some(cookie);
        Ok(context)
    }
}

impl Drop for ActivationContext {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
        if let Some(cookie) = self.cookie
            && unsafe { DeactivateActCtx(0, cookie) } == 0
        {
            eprintln!(
                "wvb: WinRT activation-context cleanup failed: error={}",
                unsafe { GetLastError() }
            );
        }
        if !self.handle.is_null() {
            unsafe { ReleaseActCtx(self.handle) };
        }
    }
}

struct WinrtBackend {
    module: Module,
    factory: Factory,
    create: Create,
    invoke: Invoke,
    release: Release,
    target: WinrtTargetConfig,
    _context: ActivationContext,
}

impl WinrtBackend {
    fn verify_object(&self, object: usize) -> Result<(), BrokerError> {
        let address = unsafe { **(object as *const *const *const c_void) };
        let mut module = ptr::null_mut();
        // FROM_ADDRESS | UNCHANGED_REFCOUNT; the live object keeps its code loaded.
        if unsafe { GetModuleHandleExW(6, address.cast(), &raw mut module) } == 0 {
            return Err(failure(format!(
                "WinRT object module lookup error={}",
                unsafe { GetLastError() }
            )));
        }
        let mut path = vec![0_u16; 32_768];
        let length = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), 32_768) } as usize;
        if length == 0 || length >= path.len() {
            return Err(failure(format!(
                "WinRT object module path error={}",
                unsafe { GetLastError() }
            )));
        }
        let actual =
            std::fs::canonicalize(OsString::from_wide(&path[..length])).map_err(failure)?;
        let expected = std::fs::canonicalize(&self.target.path).map_err(failure)?;
        if actual != expected || sha256_file(&actual).map_err(failure)? != self.target.sha256 {
            return Err(failure(
                "WinRT object vtable is not in the admitted native target",
            ));
        }
        Ok(())
    }
}

impl ObjectBackend for WinrtBackend {
    fn activate(&mut self) -> (i32, Option<usize>) {
        if let Err(error) = verify_target(&self.target) {
            eprintln!("wvb: WinRT activation pins rejected: {error}");
            return (-2_147_024_891, None); // E_ACCESSDENIED.
        }
        let mut object = ptr::null_mut();
        let hr = unsafe { (self.factory)(&raw mut object) };
        if !object.is_null()
            && let Err(error) = self.verify_object(object as usize)
        {
            self.release(object as usize);
            eprintln!("wvb: WinRT native factory identity rejected: {error}");
            return (-2_147_024_891, None);
        }
        (hr, (!object.is_null()).then_some(object as usize))
    }

    fn create(&mut self, factory: usize) -> Result<(i32, Option<usize>), BrokerError> {
        let mut instance = ptr::null_mut();
        let hr = unsafe { (self.create)(factory as *mut c_void, &raw mut instance) };
        if !instance.is_null()
            && let Err(error) = self.verify_object(instance as usize)
        {
            self.release(instance as usize);
            return Err(error);
        }
        Ok((hr, (!instance.is_null()).then_some(instance as usize)))
    }

    fn invoke(&mut self, instance: usize, input: u32) -> (i32, u32) {
        let mut output = 0;
        let hr = unsafe { (self.invoke)(instance as *mut c_void, input, &raw mut output) };
        (hr, output)
    }

    fn release(&mut self, object: usize) {
        unsafe { (self.release)(object as *mut c_void) };
    }
}

impl Drop for WinrtBackend {
    fn drop(&mut self) {
        if unsafe { FreeLibrary(self.module) } == 0 {
            eprintln!("wvb: WinRT dispatcher unload failed: error={}", unsafe {
                GetLastError()
            });
        }
    }
}

fn verify_target(target: &WinrtTargetConfig) -> Result<(), BrokerError> {
    for (path, hash) in [
        (&target.path, target.sha256),
        (&target.manifest_path, target.manifest_sha256),
        (&target.winmd_path, target.winmd_sha256),
    ] {
        if !path.is_absolute() || sha256_file(path).map_err(failure)? != hash {
            return Err(failure(format!(
                "WinRT native input pin rejected: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

pub fn load_winrt_backend(
    config: &NativeHostConfig,
    target: WinrtTargetConfig,
) -> Result<Box<dyn ObjectBackend>, BrokerError> {
    verify_target(&target)?;
    if sha256_file(&config.dispatcher_path).map_err(failure)? != config.dispatcher_sha256 {
        return Err(failure("WinRT dispatcher hash mismatch"));
    }
    let path = wide_path(&config.dispatcher_path).map_err(failure)?;
    let context = ActivationContext::activate(&target)?;
    let module = unsafe { LoadLibraryExW(path.as_ptr(), ptr::null_mut(), 0x1100) };
    if module.is_null() {
        return Err(failure(format!("WinRT dispatcher load error={}", unsafe {
            GetLastError()
        })));
    }
    let exports = unsafe {
        (
            load_symbol::<Factory>(module, b"whiny_winrt_factory_v1\0"),
            load_symbol::<Create>(module, b"whiny_winrt_create_v1\0"),
            load_symbol::<Invoke>(module, b"whiny_object_invoke_v1\0"),
            load_symbol::<Release>(module, b"whiny_object_release_v1\0"),
        )
    };
    if let (Some(factory), Some(create), Some(invoke), Some(release)) = exports {
        Ok(Box::new(WinrtBackend {
            module,
            factory,
            create,
            invoke,
            release,
            target,
            _context: context,
        }))
    } else {
        if unsafe { FreeLibrary(module) } == 0 {
            eprintln!(
                "wvb: rejected WinRT dispatcher unload failed: error={}",
                unsafe { GetLastError() }
            );
        }
        Err(failure(
            "WinRT dispatcher missing a generated factory/create/invoke/release export",
        ))
    }
}

fn failure(reason: impl std::fmt::Display) -> BrokerError {
    BrokerError::Handler(reason.to_string())
}
