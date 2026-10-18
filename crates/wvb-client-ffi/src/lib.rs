//! Windows-loadable C ABI for the canonical bridge client runtime.
#![allow(unsafe_code)]

use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;
use std::str;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use tokio::runtime::Runtime;
use wvb_call::CallRequest;
use wvb_crypto::StaticPrivateKey;
use wvb_runtime::{ClientConfig, RuntimeClient};
use wvb_session::{Hello, Platform};

pub const WVB_STATUS_OK: i32 = 0;
pub const WVB_STATUS_INVALID_ARGUMENT: i32 = -1;
pub const WVB_STATUS_NOT_CONFIGURED: i32 = -2;
pub const WVB_STATUS_RUNTIME_ERROR: i32 = -3;
pub const WVB_STATUS_INSUFFICIENT_BUFFER: i32 = -4;
pub const WVB_STATUS_PANIC: i32 = -5;

#[repr(C)]
pub struct WvbClientConfig {
    pub struct_size: u32,
    pub broker_address: *const u8,
    pub broker_address_len: usize,
    pub client_private_key: [u8; 32],
    pub broker_public_key: [u8; 32],
    pub actor_id: [u8; 16],
    pub client_instance: [u8; 16],
    pub build_fingerprint: [u8; 32],
    pub connect_timeout_ms: u32,
    pub call_timeout_ms: u32,
}

struct Configured {
    runtime: Arc<Runtime>,
    client: RuntimeClient,
    call_timeout: Duration,
}

static CONFIGURED: OnceLock<RwLock<Option<Configured>>> = OnceLock::new();

fn configured() -> &'static RwLock<Option<Configured>> {
    CONFIGURED.get_or_init(|| RwLock::new(None))
}

#[unsafe(no_mangle)]
/// Configures and connects the process-wide bridge client.
///
/// # Safety
///
/// `config` must point to a readable `WvbClientConfig`. Its address pointer
/// must remain readable for `broker_address_len` bytes for the duration of the
/// call. All fixed-size byte arrays must contain initialized bytes.
pub unsafe extern "C" fn wvb_client_configure(config: *const WvbClientConfig) -> i32 {
    ffi_status(|| {
        let config = unsafe { config.as_ref() }.ok_or(WVB_STATUS_INVALID_ARGUMENT)?;
        if usize::try_from(config.struct_size).ok() != Some(size_of::<WvbClientConfig>())
            || config.broker_address.is_null()
            || config.broker_address_len == 0
            || config.connect_timeout_ms == 0
            || config.call_timeout_ms == 0
        {
            return Err(WVB_STATUS_INVALID_ARGUMENT);
        }
        let address_bytes =
            unsafe { slice::from_raw_parts(config.broker_address, config.broker_address_len) };
        let address = str::from_utf8(address_bytes)
            .map_err(|_| WVB_STATUS_INVALID_ARGUMENT)?
            .parse::<SocketAddr>()
            .map_err(|_| WVB_STATUS_INVALID_ARGUMENT)?;
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|_| WVB_STATUS_RUNTIME_ERROR)?,
        );
        let client = runtime
            .block_on(RuntimeClient::connect(ClientConfig {
                address,
                local_private_key: StaticPrivateKey::from_bytes(config.client_private_key),
                broker_public_key: config.broker_public_key,
                expected_actor: config.actor_id,
                hello: Hello {
                    peer_kind: 1,
                    min_minor: 0,
                    max_minor: 0,
                    features: 0,
                    max_logical_payload: 1_048_576,
                    max_streams: 64,
                    initial_connection_credit: 4_194_304,
                    client_instance: config.client_instance,
                    platform: Platform {
                        os: 1,
                        os_version: String::from("Windows"),
                        architecture: 2,
                        wine_version: None,
                        runtime_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                        build_fingerprint: config.build_fingerprint.to_vec(),
                    },
                    client_wall_unix_ms: unix_time_ms(),
                },
                hello_message_id: config.client_instance,
                message_nonce: config.client_instance[..8]
                    .try_into()
                    .map_err(|_| WVB_STATUS_INVALID_ARGUMENT)?,
                queue_capacity: 256,
                connect_timeout: Duration::from_millis(u64::from(config.connect_timeout_ms)),
            }))
            .map_err(|_| WVB_STATUS_RUNTIME_ERROR)?;
        *configured().write().map_err(|_| WVB_STATUS_RUNTIME_ERROR)? = Some(Configured {
            runtime,
            client,
            call_timeout: Duration::from_millis(u64::from(config.call_timeout_ms)),
        });
        Ok(WVB_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
/// Performs one canonical bridge call through the configured runtime.
///
/// # Safety
///
/// `adapter_hash` must reference 32 readable bytes. A nonzero `request_len`
/// requires `request` to reference that many readable bytes. `response_len`
/// must be writable. A nonzero `response_cap` requires `response` to reference
/// that many writable bytes. Input and output regions must not overlap.
pub unsafe extern "C" fn wvb_client_call(
    adapter_hash: *const u8,
    operation_id: u32,
    request: *const u8,
    request_len: usize,
    response: *mut u8,
    response_cap: usize,
    response_len: *mut usize,
) -> i32 {
    ffi_status(|| {
        if adapter_hash.is_null()
            || response_len.is_null()
            || request_len != 0 && request.is_null()
            || response_cap != 0 && response.is_null()
        {
            return Err(WVB_STATUS_INVALID_ARGUMENT);
        }
        let adapter_hash: [u8; 32] = unsafe { slice::from_raw_parts(adapter_hash, 32) }
            .try_into()
            .map_err(|_| WVB_STATUS_INVALID_ARGUMENT)?;
        let request = if request_len == 0 {
            Vec::new()
        } else {
            unsafe { slice::from_raw_parts(request, request_len) }.to_vec()
        };
        let guard = configured().read().map_err(|_| WVB_STATUS_RUNTIME_ERROR)?;
        let configured = guard.as_ref().ok_or(WVB_STATUS_NOT_CONFIGURED)?;
        let result = configured
            .runtime
            .block_on(configured.client.call(
                &CallRequest {
                    adapter_hash,
                    operation_id,
                    request_schema_id: 0x3000_0000 | operation_id,
                    deduplication_mode: 0,
                    idempotency_key: None,
                    disconnect_policy: 0,
                    sensitivity: 0,
                    body: request,
                },
                configured.call_timeout,
            ))
            .map_err(|_| WVB_STATUS_RUNTIME_ERROR)?;
        unsafe { response_len.write(result.body.len()) };
        if response_cap < result.body.len() {
            return Err(WVB_STATUS_INSUFFICIENT_BUFFER);
        }
        if !result.body.is_empty() {
            unsafe {
                response.copy_from_nonoverlapping(result.body.as_ptr(), result.body.len());
            }
        }
        Ok(WVB_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn wvb_client_reset() -> i32 {
    ffi_status(|| {
        *configured().write().map_err(|_| WVB_STATUS_RUNTIME_ERROR)? = None;
        Ok(WVB_STATUS_OK)
    })
}

fn ffi_status(operation: impl FnOnce() -> Result<i32, i32>) -> i32 {
    catch_unwind(AssertUnwindSafe(operation))
        .unwrap_or(Err(WVB_STATUS_PANIC))
        .unwrap_or_else(|status| status)
}

fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_rejects_invalid_arguments_and_reports_unconfigured_state() {
        assert_eq!(
            unsafe {
                wvb_client_call(
                    std::ptr::null(),
                    1,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                )
            },
            WVB_STATUS_INVALID_ARGUMENT
        );
        let adapter = [1_u8; 32];
        let mut response_length = 0_usize;
        assert_eq!(
            unsafe {
                wvb_client_call(
                    adapter.as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    0,
                    &raw mut response_length,
                )
            },
            WVB_STATUS_NOT_CONFIGURED
        );
    }
}
