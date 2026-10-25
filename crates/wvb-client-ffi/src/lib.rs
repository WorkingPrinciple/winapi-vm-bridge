//! Windows-loadable C ABI for the canonical bridge client runtime.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;
use std::str;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use tokio::runtime::Runtime;
use wvb_call::{CallRequest, CallResult};
use wvb_crypto::StaticPrivateKey;
use wvb_runtime::{ClientConfig, RuntimeClient};
use wvb_session::{Hello, Platform};

pub const WVB_STATUS_OK: i32 = 0;
pub const WVB_STATUS_INVALID_ARGUMENT: i32 = -1;
pub const WVB_STATUS_NOT_CONFIGURED: i32 = -2;
pub const WVB_STATUS_RUNTIME_ERROR: i32 = -3;
pub const WVB_STATUS_INSUFFICIENT_BUFFER: i32 = -4;
pub const WVB_STATUS_PANIC: i32 = -5;
pub const WVB_STATUS_DISPATCH_ERROR: i32 = -6;
pub const WVB_STATUS_PROTOCOL_ERROR: i32 = -7;
pub const WVB_STATUS_OPERATION_NOT_BOUND: i32 = -8;

#[derive(Clone, Copy, PartialEq, Eq)]
struct OperationSchema {
    request: u32,
    response: u32,
}

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
    operations: BTreeMap<([u8; 32], u32), OperationSchema>,
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
                .map_err(|error| {
                    eprintln!("wvb: configure runtime initialization failed: {error}");
                    WVB_STATUS_RUNTIME_ERROR
                })?,
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
            .map_err(|error| {
                eprintln!("wvb: configure connection failed: {error}");
                WVB_STATUS_RUNTIME_ERROR
            })?;
        *configured().write().map_err(|_| WVB_STATUS_RUNTIME_ERROR)? = Some(Configured {
            runtime,
            client,
            call_timeout: Duration::from_millis(u64::from(config.call_timeout_ms)),
            operations: BTreeMap::new(),
        });
        Ok(WVB_STATUS_OK)
    })
}

#[unsafe(no_mangle)]
/// Binds the exact schema IDs from the frozen operation consumed by admission.
/// This is connection-local client configuration, not an invocation grant.
/// Conflicting bindings are rejected; reset or reconfigure clears all bindings.
///
/// # Safety
///
/// `adapter_hash` must reference 32 readable bytes.
pub unsafe extern "C" fn wvb_client_bind_operation(
    adapter_hash: *const u8,
    operation_id: u32,
    request_schema_id: u32,
    response_schema_id: u32,
) -> i32 {
    ffi_status(|| {
        if adapter_hash.is_null()
            || operation_id == 0
            || request_schema_id == 0
            || response_schema_id == 0
        {
            return Err(WVB_STATUS_INVALID_ARGUMENT);
        }
        let adapter_hash: [u8; 32] = unsafe { slice::from_raw_parts(adapter_hash, 32) }
            .try_into()
            .map_err(|_| WVB_STATUS_INVALID_ARGUMENT)?;
        let mut guard = configured().write().map_err(|_| WVB_STATUS_RUNTIME_ERROR)?;
        let configured = guard.as_mut().ok_or(WVB_STATUS_NOT_CONFIGURED)?;
        let key = (adapter_hash, operation_id);
        let schema = OperationSchema {
            request: request_schema_id,
            response: response_schema_id,
        };
        if let Some(existing) = configured.operations.get(&key) {
            if *existing != schema {
                return Err(WVB_STATUS_INVALID_ARGUMENT);
            }
        } else {
            if configured.operations.len() >= 65_536 {
                return Err(WVB_STATUS_INVALID_ARGUMENT);
            }
            configured.operations.insert(key, schema);
        }
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
    let mut dispatch_status = 0;
    unsafe {
        wvb_client_call_ex(
            adapter_hash,
            operation_id,
            request,
            request_len,
            response,
            response_cap,
            response_len,
            &raw mut dispatch_status,
        )
    }
}

#[unsafe(no_mangle)]
/// Calls the configured runtime, preserving the dispatcher execution status.
///
/// A nonzero `whiny.dispatch.v1` status returns `WVB_STATUS_DISPATCH_ERROR`
/// without copying a body. A target API HRESULT or last-error is not a
/// dispatcher status: typed target results travel unchanged in a successful
/// dispatch body. Schema and status framing are checked before any body write.
/// `response_len` is zero on failure except insufficient response capacity.
/// `dispatch_status` is meaningful on OK, `INSUFFICIENT_BUFFER` or `DISPATCH_ERROR`.
/// The caller must validate the operation-specific body shape before use.
///
/// # Safety
///
/// The pointer requirements of `wvb_client_call` apply. `dispatch_status` must
/// also reference a writable i32, disjoint from all other input/output regions.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn wvb_client_call_ex(
    adapter_hash: *const u8,
    operation_id: u32,
    request: *const u8,
    request_len: usize,
    response: *mut u8,
    response_cap: usize,
    response_len: *mut usize,
    dispatch_status: *mut i32,
) -> i32 {
    ffi_status(|| {
        if adapter_hash.is_null()
            || response_len.is_null()
            || dispatch_status.is_null()
            || request_len != 0 && request.is_null()
            || response_cap != 0 && response.is_null()
        {
            return Err(WVB_STATUS_INVALID_ARGUMENT);
        }
        unsafe {
            response_len.write(0);
            dispatch_status.write(0);
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
        let schema = configured
            .operations
            .get(&(adapter_hash, operation_id))
            .ok_or(WVB_STATUS_OPERATION_NOT_BOUND)?;
        let result = configured
            .runtime
            .block_on(configured.client.call(
                &CallRequest {
                    adapter_hash,
                    operation_id,
                    request_schema_id: schema.request,
                    deduplication_mode: 0,
                    idempotency_key: None,
                    disconnect_policy: 0,
                    sensitivity: 0,
                    body: request,
                },
                configured.call_timeout,
            ))
            .map_err(|_| WVB_STATUS_RUNTIME_ERROR)?;
        let status = validate_result(&result, *schema)?;
        unsafe { dispatch_status.write(status) };
        if status != 0 {
            return Err(WVB_STATUS_DISPATCH_ERROR);
        }
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

fn validate_result(result: &CallResult, schema: OperationSchema) -> Result<i32, i32> {
    if result.response_schema_id != schema.response {
        return Err(WVB_STATUS_PROTOCOL_ERROR);
    }
    let status = result
        .native_status
        .as_slice()
        .try_into()
        .map_err(|_| WVB_STATUS_PROTOCOL_ERROR)?;
    Ok(i32::from_le_bytes(status))
}

#[unsafe(no_mangle)]
/// Closes a connection-owned remote object without retrying.
///
/// # Safety
///
/// `token` references 28 readable bytes and `native_status` references a
/// disjoint writable i32. Neither pointer may be null.
pub unsafe extern "C" fn wvb_client_handle_close(token: *const u8, native_status: *mut i32) -> i32 {
    ffi_status(|| {
        if token.is_null() || native_status.is_null() {
            return Err(WVB_STATUS_INVALID_ARGUMENT);
        }
        unsafe { native_status.write(0) };
        let bytes = unsafe { slice::from_raw_parts(token, 28) };
        let guard = configured().read().map_err(|_| WVB_STATUS_RUNTIME_ERROR)?;
        let configured = guard.as_ref().ok_or(WVB_STATUS_NOT_CONFIGURED)?;
        let request = wvb_control::HandleClose {
            broker_epoch: bytes[..16]
                .try_into()
                .map_err(|_| WVB_STATUS_INVALID_ARGUMENT)?,
            owner_actor_id: configured.client.actor_id(),
            slot: u32::from_le_bytes(
                bytes[16..20]
                    .try_into()
                    .map_err(|_| WVB_STATUS_INVALID_ARGUMENT)?,
            ),
            generation: u32::from_le_bytes(
                bytes[20..24]
                    .try_into()
                    .map_err(|_| WVB_STATUS_INVALID_ARGUMENT)?,
            ),
            handle_type: u32::from_le_bytes(
                bytes[24..28]
                    .try_into()
                    .map_err(|_| WVB_STATUS_INVALID_ARGUMENT)?,
            ),
        };
        let status = configured
            .runtime
            .block_on(
                configured
                    .client
                    .close_handle(request, configured.call_timeout),
            )
            .map_err(|_| WVB_STATUS_RUNTIME_ERROR)?;
        let native = status.native_status.ok_or(WVB_STATUS_PROTOCOL_ERROR)?;
        let native = i32::from_le_bytes(native.try_into().map_err(|_| WVB_STATUS_PROTOCOL_ERROR)?);
        unsafe { native_status.write(native) };
        if status.disposition != 0 {
            return Err(WVB_STATUS_DISPATCH_ERROR);
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
    use async_trait::async_trait;
    use std::sync::{Barrier, Mutex, TryLockError, mpsc};
    use tokio::net::TcpListener;
    use tokio::sync::Notify;
    use wvb_broker::{
        BrokerError, CallHandler, DispatchOutcome, DispatcherCallHandler,
        OperationSchema as BrokerSchema, TypedDispatchModule, serve_calls,
    };
    use wvb_call::CallResult;
    use wvb_session::{HelloAck, Readiness, activate_broker};
    use wvb_transport::session_responder;

    static FFI_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct NativeScalar;

    impl TypedDispatchModule for NativeScalar {
        fn dispatch(&self, _operation_id: u32, request: &[u8]) -> DispatchOutcome {
            DispatchOutcome {
                status: if request == [1] { -17 } else { 0 },
                body: if request == [4] {
                    0x8000_4005_u32.to_le_bytes().to_vec()
                } else {
                    42_i32.to_le_bytes().to_vec()
                },
            }
        }
    }

    struct CallGate {
        entered: mpsc::SyncSender<()>,
        release: Notify,
    }

    struct TestHandler {
        inner: DispatcherCallHandler,
        gate: Option<Arc<CallGate>>,
    }

    #[async_trait]
    impl CallHandler for TestHandler {
        async fn handle_call(&self, request: CallRequest) -> Result<CallResult, BrokerError> {
            let selector = request.body.first().copied();
            if selector == Some(5) {
                let gate = self.gate.as_ref().expect("gated call needs a gate");
                gate.entered.send(()).unwrap();
                gate.release.notified().await;
            }
            let mut result = self.inner.handle_call(request).await?;
            if selector == Some(2) {
                result.native_status = vec![0];
            }
            if selector == Some(3) {
                result.response_schema_id = 99;
            }
            Ok(result)
        }

        async fn handle_close(
            &self,
            request: wvb_control::HandleClose,
        ) -> Result<wvb_control::HandleStatus, BrokerError> {
            assert_eq!(request.owner_actor_id, [8; 16]);
            assert_eq!(request.broker_epoch, [7; 16]);
            assert_eq!(request.generation, 3);
            assert_eq!(request.handle_type, 9);
            Ok(wvb_control::HandleStatus {
                disposition: u16::from(request.slot != 17),
                native_status: Some(
                    (if request.slot == 17 { 0_i32 } else { -7_i32 })
                        .to_le_bytes()
                        .to_vec(),
                ),
                receipt: None,
            })
        }
    }

    fn connect_fixture() -> (Runtime, tokio::task::JoinHandle<Result<(), BrokerError>>) {
        connect_fixture_with_gate(None)
    }

    #[test]
    fn exported_handle_close_uses_existing_control_and_authenticated_actor() {
        let _serial = FFI_TEST_LOCK.lock().unwrap();
        let (runtime, server) = connect_fixture();
        let mut native = 999;
        assert_eq!(
            unsafe { wvb_client_handle_close(std::ptr::null(), &raw mut native) },
            WVB_STATUS_INVALID_ARGUMENT
        );
        let mut token = [7; 28];
        token[16..20].copy_from_slice(&17_u32.to_le_bytes());
        token[20..24].copy_from_slice(&3_u32.to_le_bytes());
        token[24..28].copy_from_slice(&9_u32.to_le_bytes());
        assert_eq!(
            unsafe { wvb_client_handle_close(token.as_ptr(), &raw mut native) },
            WVB_STATUS_OK
        );
        assert_eq!(native, 0);
        token[16..20].copy_from_slice(&18_u32.to_le_bytes());
        assert_eq!(
            unsafe { wvb_client_handle_close(token.as_ptr(), &raw mut native) },
            WVB_STATUS_DISPATCH_ERROR
        );
        assert_eq!(native, -7);
        assert_eq!(wvb_client_reset(), WVB_STATUS_OK);
        assert!(runtime.block_on(server).unwrap().is_ok());
    }

    fn connect_fixture_with_gate(
        gate: Option<Arc<CallGate>>,
    ) -> (Runtime, tokio::task::JoinHandle<Result<(), BrokerError>>) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (broker_key, broker_public) = StaticPrivateKey::generate().unwrap();
        let server = runtime.spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (_, provisional) = session_responder(stream, &broker_key).await.unwrap();
            let ack = HelloAck {
                selected_minor: 0,
                features: 0,
                max_logical_payload: 1_048_576,
                max_streams: 8,
                initial_connection_credit: 2_097_152,
                connection_epoch: 42,
                broker_epoch: [7; 16],
                actor_id: [8; 16],
                readiness: Readiness {
                    overall_status: 1,
                    generated_at_unix_ms: 2,
                    source_version: String::from("ffi-test"),
                },
                broker_wall_unix_ms: 2,
            };
            let (_, active) = activate_broker(provisional, &ack, [6; 16]).await.unwrap();
            let handler = TestHandler {
                inner: DispatcherCallHandler::new(
                    [1; 32],
                    [1, 2]
                        .into_iter()
                        .map(|operation_id| {
                            (
                                operation_id,
                                BrokerSchema {
                                    request_schema_id: 0x1000_0001,
                                    response_schema_id: 0x1000_0002,
                                },
                            )
                        })
                        .collect(),
                    Arc::new(NativeScalar),
                ),
                gate,
            };
            serve_calls(active, Arc::new(handler), 4).await
        });
        let config = WvbClientConfig {
            struct_size: u32::try_from(size_of::<WvbClientConfig>()).unwrap(),
            broker_address: address.as_ptr(),
            broker_address_len: address.len(),
            client_private_key: [3; 32],
            broker_public_key: broker_public,
            actor_id: [8; 16],
            client_instance: [4; 16],
            build_fingerprint: [5; 32],
            connect_timeout_ms: 2000,
            call_timeout_ms: 2000,
        };
        assert_eq!(
            unsafe { wvb_client_configure(&raw const config) },
            WVB_STATUS_OK
        );
        (runtime, server)
    }

    #[test]
    fn exported_ffi_uses_bound_schemas_and_preserves_failure_domains() {
        let _serial = FFI_TEST_LOCK.lock().unwrap();
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

        // Exercise the exported entrypoint, not a hand-built Rust CallRequest.
        let (_runtime, server) = connect_fixture();
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
            WVB_STATUS_OPERATION_NOT_BOUND
        );
        assert_eq!(response_length, 0);
        assert_eq!(
            unsafe { wvb_client_bind_operation(adapter.as_ptr(), 1, 0x1000_0001, 0x1000_0002) },
            WVB_STATUS_OK
        );
        assert_eq!(
            unsafe { wvb_client_bind_operation(adapter.as_ptr(), 1, 0x1000_0001, 0x1000_0002) },
            WVB_STATUS_OK
        );
        assert_eq!(
            unsafe { wvb_client_bind_operation(adapter.as_ptr(), 1, 0x3000_0001, 0x1000_0002) },
            WVB_STATUS_INVALID_ARGUMENT
        );
        let mut response = [0xa5_u8; 4];
        let status = unsafe {
            wvb_client_call(
                adapter.as_ptr(),
                1,
                std::ptr::null(),
                0,
                response.as_mut_ptr(),
                response.len(),
                &raw mut response_length,
            )
        };
        assert_eq!(status, WVB_STATUS_OK);
        assert_eq!(response, 42_i32.to_le_bytes());
        assert_eq!(response_length, 4);

        assert_response_outcomes(&adapter);
        assert_eq!(wvb_client_reset(), WVB_STATUS_OK);
        assert!(configured().read().unwrap().is_none());
        assert_eq!(
            unsafe { wvb_client_bind_operation(adapter.as_ptr(), 1, 0x1000_0001, 0x1000_0002) },
            WVB_STATUS_NOT_CONFIGURED
        );
        server.abort();
    }

    fn assert_response_outcomes(adapter: &[u8; 32]) {
        let mut response = [0xa5; 4];
        for (selector, expected, expected_dispatch) in [
            (1, WVB_STATUS_DISPATCH_ERROR, -17),
            (2, WVB_STATUS_PROTOCOL_ERROR, 0),
            (3, WVB_STATUS_PROTOCOL_ERROR, 0),
            (4, WVB_STATUS_OK, 0),
        ] {
            let mut dispatch_status = 999;
            response.fill(0xa5);
            let mut response_length = 999;
            let status = unsafe {
                wvb_client_call_ex(
                    adapter.as_ptr(),
                    1,
                    &raw const selector,
                    1,
                    response.as_mut_ptr(),
                    response.len(),
                    &raw mut response_length,
                    &raw mut dispatch_status,
                )
            };
            assert_eq!(status, expected);
            assert_eq!(dispatch_status, expected_dispatch);
            if expected == WVB_STATUS_OK {
                // A failing target HRESULT is still a successful dispatch.
                assert_eq!(response, 0x8000_4005_u32.to_le_bytes());
                assert_eq!(response_length, 4);
            } else {
                assert_eq!(response, [0xa5; 4]);
                assert_eq!(response_length, 0);
            }
        }
        response.fill(0xa5);
        let mut response_length = 0;
        assert_eq!(
            unsafe {
                wvb_client_call(
                    adapter.as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    response.as_mut_ptr(),
                    3,
                    &raw mut response_length,
                )
            },
            WVB_STATUS_INSUFFICIENT_BUFFER
        );
        assert_eq!(response, [0xa5; 4]);
        assert_eq!(response_length, 4);
        assert_eq!(
            unsafe { wvb_client_bind_operation(adapter.as_ptr(), 2, 0x3000_0002, 0x1000_0002) },
            WVB_STATUS_OK
        );
        assert_eq!(
            unsafe {
                wvb_client_call(
                    adapter.as_ptr(),
                    2,
                    std::ptr::null(),
                    0,
                    response.as_mut_ptr(),
                    response.len(),
                    &raw mut response_length,
                )
            },
            WVB_STATUS_RUNTIME_ERROR
        );
        assert_eq!(response, [0xa5; 4]);
        assert_eq!(response_length, 0);
    }

    #[test]
    fn only_an_exact_i32_dispatch_status_and_bound_response_schema_are_valid() {
        let schema = OperationSchema {
            request: 1,
            response: 2,
        };
        for status in [vec![], vec![0], vec![0; 3], vec![0; 5], vec![0; 8]] {
            assert_eq!(
                validate_result(
                    &CallResult {
                        response_schema_id: 2,
                        operation_uuid: None,
                        native_status: status,
                        body: vec![],
                    },
                    schema
                ),
                Err(WVB_STATUS_PROTOCOL_ERROR)
            );
        }
    }

    fn bind_scalar() -> i32 {
        unsafe { wvb_client_bind_operation([1; 32].as_ptr(), 1, 0x1000_0001, 0x1000_0002) }
    }

    fn scalar_call(selector: u8) -> (i32, [u8; 4], usize) {
        let mut response = [0xa5; 4];
        let mut length = 999;
        let status = unsafe {
            wvb_client_call(
                [1; 32].as_ptr(),
                1,
                &raw const selector,
                1,
                response.as_mut_ptr(),
                response.len(),
                &raw mut length,
            )
        };
        (status, response, length)
    }

    #[test]
    fn successful_reconfiguration_discards_previous_operation_bindings() {
        let _serial = FFI_TEST_LOCK.lock().unwrap();
        let (_old_runtime, old_server) = connect_fixture();
        assert_eq!(bind_scalar(), WVB_STATUS_OK);
        assert_eq!(scalar_call(0), (WVB_STATUS_OK, 42_i32.to_le_bytes(), 4));

        let (_new_runtime, new_server) = connect_fixture();
        assert_eq!(
            scalar_call(0),
            (WVB_STATUS_OPERATION_NOT_BOUND, [0xa5; 4], 0)
        );
        assert_eq!(bind_scalar(), WVB_STATUS_OK);
        assert_eq!(scalar_call(0), (WVB_STATUS_OK, 42_i32.to_le_bytes(), 4));
        assert_eq!(wvb_client_reset(), WVB_STATUS_OK);
        old_server.abort();
        new_server.abort();
    }

    #[test]
    fn concurrent_bind_reset_and_reconfigure_wait_for_inflight_call() {
        let _serial = FFI_TEST_LOCK.lock().unwrap();
        let (entered, entered_rx) = mpsc::sync_channel(1);
        let gate = Arc::new(CallGate {
            entered,
            release: Notify::new(),
        });
        let (_old_runtime, old_server) = connect_fixture_with_gate(Some(gate.clone()));
        assert_eq!(bind_scalar(), WVB_STATUS_OK);
        let call = std::thread::spawn(|| scalar_call(5));
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            configured().try_write(),
            Err(TryLockError::WouldBlock)
        ));

        let ready = Arc::new(Barrier::new(4));
        let (completed, completed_rx) = mpsc::channel();
        let bind = {
            let ready = ready.clone();
            let completed = completed.clone();
            std::thread::spawn(move || {
                ready.wait();
                let result = bind_scalar();
                completed.send("bind").unwrap();
                result
            })
        };
        let reset = {
            let ready = ready.clone();
            let completed = completed.clone();
            std::thread::spawn(move || {
                ready.wait();
                let result = wvb_client_reset();
                completed.send("reset").unwrap();
                result
            })
        };
        let reconfigure = {
            let ready = ready.clone();
            std::thread::spawn(move || {
                ready.wait();
                let fixture = connect_fixture();
                completed.send("reconfigure").unwrap();
                fixture
            })
        };
        ready.wait();
        let while_blocked = completed_rx.recv_timeout(Duration::from_millis(50));
        gate.release.notify_one();
        assert!(matches!(
            while_blocked,
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert_eq!(
            call.join().unwrap(),
            (WVB_STATUS_OK, 42_i32.to_le_bytes(), 4)
        );
        let mut completions = Vec::new();
        for _ in 0..3 {
            completions.push(completed_rx.recv_timeout(Duration::from_secs(5)).unwrap());
        }
        completions.sort_unstable();
        assert_eq!(completions, ["bind", "reconfigure", "reset"]);
        assert!(matches!(
            bind.join().unwrap(),
            WVB_STATUS_OK | WVB_STATUS_NOT_CONFIGURED
        ));
        assert_eq!(reset.join().unwrap(), WVB_STATUS_OK);
        let (_new_runtime, new_server) = reconfigure.join().unwrap();
        // The racing writers may linearize in any order; establish a clean
        // terminal state explicitly rather than assuming which writer wins.
        assert_eq!(wvb_client_reset(), WVB_STATUS_OK);
        assert!(configured().read().unwrap().is_none());
        old_server.abort();
        new_server.abort();
    }
}
