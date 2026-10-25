#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::json;
use wvb_admission::{AdmissionEngine, BundleFileKind, FrozenInputs, OperatorAdmission};
use wvb_authz::{Grant, Registry};
use wvb_broker::{
    AuthorizedCallHandler, CallHandler, DispatcherCallHandler, OperationSchema,
    actor_for_session_key, serve_calls,
};
use wvb_call::LOGICAL_MAX;
use wvb_client_ffi::{
    WVB_STATUS_OK, WvbClientConfig, wvb_client_bind_operation, wvb_client_call_ex,
    wvb_client_configure, wvb_client_reset,
};
use wvb_crypto::StaticPrivateKey;
use wvb_integrity::{canonical_root, resolve_regular_file, sha256_bytes};
use wvb_native_host::object::{ObjectSession, ObjectSlice};
use wvb_native_host::{ComRegistrationScope, ComTargetConfig, NativeDispatcher, NativeHostConfig};
use wvb_session::{HelloAck, Readiness, activate_broker};
use wvb_transport::session_responder;
use zeroize::{Zeroize, Zeroizing};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const CONFIG_MAX: usize = 1_048_576;

#[derive(Parser)]
#[command(about = "One authenticated, generated Windows call. No automatic retry.")]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve one authenticated connection, then exit after its completed calls drain.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Invoke one frozen operation. Writes its typed result body to a new file.
    Call {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        response: PathBuf,
    },
}

#[derive(Deserialize)]
struct ActorConfig {
    id: [u8; 16],
    public_key: [u8; 32],
    grants: Vec<Grant>,
}

#[derive(Deserialize)]
struct ServeConfig {
    listen: SocketAddr,
    private_key_path: PathBuf,
    actors: Vec<ActorConfig>,
    operator_actor: [u8; 16],
    bundle_root: PathBuf,
    contract_path: String,
    descriptor_path: String,
    approval: OperatorAdmission,
    response_capacity: usize,
    lifetime_ms: u64,
    #[serde(default)]
    com_registration_scope: ComRegistrationScope,
}

#[derive(Deserialize)]
struct ContractSlice {
    object_slice: Option<ObjectSlice>,
    #[serde(default)]
    operations: Vec<ContractOperation>,
}

#[derive(Deserialize)]
struct ContractOperation {
    id: u32,
    request_schema_id: u32,
    response_schema_id: u32,
    native_error: Option<NativeErrorRule>,
}

#[derive(Deserialize)]
struct NativeErrorRule {
    output_validity: String,
}

impl ContractSlice {
    fn validated_object(
        self,
        operations: &BTreeMap<u32, OperationSchema>,
    ) -> Result<Option<ObjectSlice>> {
        let Some(slice) = self.object_slice else {
            return Ok(None);
        };
        slice.validate(operations)?;
        let mut seen = std::collections::BTreeSet::new();
        if self.operations.len() != operations.len() {
            return Err("object contract/admission operation count mismatch".into());
        }
        for operation in self.operations {
            let schema = operations
                .get(&operation.id)
                .ok_or("unadmitted object operation")?;
            let expected = if operation.id == slice.method_operation_id {
                "zero-on-failure"
            } else {
                "success-only"
            };
            if !seen.insert(operation.id)
                || operation.request_schema_id != schema.request_schema_id
                || operation.response_schema_id != schema.response_schema_id
                || operation
                    .native_error
                    .as_ref()
                    .map(|rule| rule.output_validity.as_str())
                    != Some(expected)
            {
                return Err("object contract schema/output rule does not match admission".into());
            }
        }
        Ok(Some(slice))
    }
}

#[derive(Deserialize)]
struct CallConfig {
    address: SocketAddr,
    private_key_path: PathBuf,
    broker_public_key: [u8; 32],
    actor_id: [u8; 16],
    client_instance: [u8; 16],
    build_fingerprint: [u8; 32],
    contract_path: PathBuf,
    contract_sha256: [u8; 32],
    operation: wvb_admission::OperationAdmission,
    response_capacity: usize,
    connect_timeout_ms: u32,
    call_timeout_ms: u32,
}

fn bounded_read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("input must be a regular, nonsymlink file".into());
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(u64::try_from(maximum)? + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("input exceeds size bound".into());
    }
    Ok(bytes)
}

fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            return Err("private key file must have owner-only permissions".into());
        }
    }
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("private key must be a regular, nonsymlink file".into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(path)?.take(33).read_to_end(&mut bytes)?;
    if bytes.len() != 32 {
        return Err("private key file must contain exactly 32 binary bytes".into());
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn validate_bounds(capacity: usize, lifetime_ms: u64) -> Result<()> {
    if capacity == 0 || capacity > LOGICAL_MAX || !(1..=600_000).contains(&lifetime_ms) {
        return Err("response capacity or finite time budget is outside bounds".into());
    }
    Ok(())
}

fn registry(actors: &[ActorConfig]) -> Result<Registry> {
    if actors.is_empty() || actors.len() > 64 {
        return Err("configure between one and 64 explicit actors".into());
    }
    let mut registry = Registry::default();
    for actor in actors {
        registry
            .register(actor.id, actor.public_key)
            .map_err(|error| format!("register actor: {error:?}"))?;
        if actor.grants.len() > 256 {
            return Err("too many actor grants".into());
        }
        for grant in &actor.grants {
            registry
                .grant(actor.id, grant.clone())
                .map_err(|error| format!("register grant: {error:?}"))?;
        }
    }
    Ok(registry)
}

#[allow(clippy::too_many_lines)]
async fn serve(config: ServeConfig) -> Result<()> {
    validate_bounds(config.response_capacity, config.lifetime_ms)?;
    if config.listen.port() == 0 || config.listen.ip().is_unspecified() {
        return Err("listen must select a specific interface and nonzero port".into());
    }
    let registry = registry(&config.actors)?;
    let root = canonical_root(&config.bundle_root)?;
    let contract = bounded_read(
        &resolve_regular_file(&root, &config.contract_path)?,
        CONFIG_MAX,
    )?;
    let descriptor = bounded_read(
        &resolve_regular_file(&root, &config.descriptor_path)?,
        CONFIG_MAX,
    )?;
    let admitted = AdmissionEngine::new(&root)?.admit(
        &registry,
        config.operator_actor,
        now_ms()?,
        &config.approval,
        FrozenInputs {
            contract: &contract,
            bundle_descriptor: &descriptor,
        },
    )?;
    admitted.reverify_files()?;
    let dispatcher = admitted
        .files()
        .iter()
        .find(|file| file.kind == BundleFileKind::Dispatcher)
        .ok_or("admitted bundle has no dispatcher")?;
    let native_config = NativeHostConfig {
        dispatcher_path: dispatcher.canonical_path.clone(),
        dispatcher_sha256: dispatcher.sha256,
        response_capacity: config.response_capacity,
    };
    let operations = config
        .approval
        .operations
        .iter()
        .map(|operation| {
            (
                operation.operation_id,
                OperationSchema {
                    request_schema_id: operation.request_schema_id,
                    response_schema_id: operation.response_schema_id,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let object_slice =
        serde_json::from_slice::<ContractSlice>(&contract)?.validated_object(&operations)?;
    let scalar: Option<Arc<dyn CallHandler>> = if object_slice.is_none() {
        Some(Arc::new(DispatcherCallHandler::new(
            admitted.contract_sha256(),
            operations.clone(),
            Arc::new(NativeDispatcher::load(&native_config)?),
        )))
    } else {
        None
    };
    let key = read_key(&config.private_key_path)?;
    let broker_key = StaticPrivateKey::from_bytes(*key);
    drop(key);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let registry = Arc::new(RwLock::new(registry));
    let mut nonce = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "session nonce generation failed")?;
    let epoch = u64::from_le_bytes(nonce[..8].try_into()?);
    let ready = json!({"event":"ready", "pid": std::process::id(),
        "listen": listener.local_addr()?.to_string(), "lifetime_ms":config.lifetime_ms});
    println!("{ready}");
    std::io::stdout().flush()?;
    let mut session_handler: Option<Arc<dyn CallHandler>> = None;
    let work = async {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let (remote, provisional) = session_responder(stream, &broker_key).await?;
        let actor = actor_for_session_key(&registry, &remote)?;
        admitted.reverify_files()?;
        let typed: Arc<dyn CallHandler> = if let Some(slice) = &object_slice {
            let target = admitted
                .files()
                .iter()
                .find(|file| file.kind == BundleFileKind::Target)
                .ok_or("object contract has no admitted target")?;
            let target = ComTargetConfig {
                clsid: slice.activation.clsid.clone(),
                path: target.canonical_path.clone(),
                sha256: target.sha256,
                registration_scope: config.com_registration_scope,
            };
            Arc::new(ObjectSession::start(
                actor,
                nonce,
                admitted.contract_sha256(),
                slice.clone(),
                operations.clone(),
                move || wvb_native_host::load_com_backend(&native_config, target),
            )?)
        } else {
            scalar.clone().ok_or("missing scalar dispatcher")?
        };
        let mut authorized = AuthorizedCallHandler::new(actor, registry.clone(), typed);
        if let Some(slice) = &object_slice {
            authorized = authorized
                .with_close_operation(admitted.contract_sha256(), slice.close_operation_id);
        }
        let authorized: Arc<dyn CallHandler> = Arc::new(authorized);
        session_handler = Some(authorized.clone());
        let ack = HelloAck {
            selected_minor: 0,
            features: 0,
            max_logical_payload: u32::try_from(LOGICAL_MAX)?,
            max_streams: 1,
            initial_connection_credit: 4_194_304,
            connection_epoch: epoch,
            broker_epoch: nonce,
            actor_id: actor,
            readiness: Readiness {
                overall_status: 1,
                generated_at_unix_ms: now_ms()?,
                source_version: env!("CARGO_PKG_VERSION").into(),
            },
            broker_wall_unix_ms: now_ms()?,
        };
        let (_, active) = activate_broker(provisional, &ack, nonce).await?;
        serve_calls(active, authorized, 1).await?;
        Ok::<_, Box<dyn Error>>(())
    };
    let result = tokio::time::timeout(Duration::from_millis(config.lifetime_ms), work).await;
    if let Some(handler) = session_handler {
        handler.disconnect().await?;
    }
    result
        .map_err(|_| "serve lifetime expired; native completion/quiescence unknown; no replay")??;
    println!("{}", json!({"event":"completed", "pid":std::process::id()}));
    Ok(())
}

fn call(config: &CallConfig, request_path: &Path, response_path: &Path) -> Result<()> {
    validate_bounds(config.response_capacity, u64::from(config.call_timeout_ms))?;
    validate_bounds(
        config.response_capacity,
        u64::from(config.connect_timeout_ms),
    )?;
    if sha256_bytes(&bounded_read(&config.contract_path, CONFIG_MAX)?) != config.contract_sha256 {
        return Err("contract hash mismatch".into());
    }
    let request = Zeroizing::new(bounded_read(request_path, LOGICAL_MAX)?);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(response_path)?;
    let key = read_key(&config.private_key_path)?;
    let address = config.address.to_string();
    let mut client = WvbClientConfig {
        struct_size: u32::try_from(std::mem::size_of::<WvbClientConfig>())?,
        broker_address: address.as_ptr(),
        broker_address_len: address.len(),
        client_private_key: *key,
        broker_public_key: config.broker_public_key,
        actor_id: config.actor_id,
        client_instance: config.client_instance,
        build_fingerprint: config.build_fingerprint,
        connect_timeout_ms: config.connect_timeout_ms,
        call_timeout_ms: config.call_timeout_ms,
    };
    let configured = unsafe { wvb_client_configure(&raw const client) };
    client.client_private_key.zeroize();
    drop(key);
    if configured != WVB_STATUS_OK {
        return Err(format!("configure failed status={configured}; no call sent").into());
    }
    let result: Result<()> = (|| {
        let operation = config.operation;
        let bound = unsafe {
            wvb_client_bind_operation(
                config.contract_sha256.as_ptr(),
                operation.operation_id,
                operation.request_schema_id,
                operation.response_schema_id,
            )
        };
        if bound != WVB_STATUS_OK {
            return Err(format!("bind failed status={bound}; no call sent").into());
        }
        let mut body = Zeroizing::new(vec![0_u8; config.response_capacity]);
        let mut length = 0;
        let mut dispatch = 0;
        let status = unsafe {
            wvb_client_call_ex(
                config.contract_sha256.as_ptr(),
                operation.operation_id,
                request.as_ptr(),
                request.len(),
                body.as_mut_ptr(),
                body.len(),
                &raw mut length,
                &raw mut dispatch,
            )
        };
        if status != WVB_STATUS_OK {
            return Err(format!("call failed status={status} dispatch_status={dispatch}; completion may be unknown; no retry").into());
        }
        output
            .write_all(&body[..length])
            .and_then(|()| output.flush())
            .map_err(|error| format!("call returned but result write failed: {error}; no retry"))?;
        println!(
            "{}",
            json!({"event":"result", "dispatch_status":dispatch, "response_bytes":length})
        );
        Ok(())
    })();
    let reset = wvb_client_reset();
    result?;
    if reset != WVB_STATUS_OK {
        return Err(format!("reset failed status={reset}; call already returned, no retry").into());
    }
    Ok(())
}

fn run() -> Result<()> {
    match Arguments::parse().command {
        Command::Serve { config } => {
            let config = serde_json::from_slice(&bounded_read(&config, CONFIG_MAX)?)?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(serve(config))
        }
        Command::Call {
            config,
            request,
            response,
        } => {
            let config = serde_json::from_slice(&bounded_read(&config, CONFIG_MAX)?)?;
            call(&config, &request, &response)
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("wvb: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wvb_authz::Role;
    use wvb_broker::{DispatchOutcome, TypedDispatchModule};

    #[test]
    fn object_output_rule_and_schemas_must_match_the_frozen_operation_admission() {
        let operations = (1..=3)
            .map(|id| {
                (
                    id,
                    OperationSchema {
                        request_schema_id: id * 2,
                        response_schema_id: id * 2 + 1,
                    },
                )
            })
            .collect();
        let contract = json!({
            "object_slice": {
                "abi":"com-u32-v1",
                "activation":{"kind":"com-local-server","clsid":"BA9A4DA2-79FE-4B31-8DB4-201AF0266C11"},
                "interface_iid":"BA9A4DA2-79FE-4B31-8DB4-201AF0266C12",
                "interface_kind":"iunknown", "handle_type":7, "method_slot":3,
                "activation_operation_id":1, "method_operation_id":2, "close_operation_id":3,
                "max_objects":8
            },
            "operations": (1..=3).map(|id| json!({
                "id":id, "request_schema_id":id*2, "response_schema_id":id*2+1,
                "native_error":{"output_validity":if id == 2 {"zero-on-failure"} else {"success-only"}}
            })).collect::<Vec<_>>()
        });
        let validate = |value| {
            serde_json::from_value::<ContractSlice>(value)
                .unwrap()
                .validated_object(&operations)
        };
        assert!(validate(contract.clone()).unwrap().is_some());
        for bad in ["success-only", "unchanged", "unknown"] {
            let mut changed = contract.clone();
            changed["operations"][1]["native_error"]["output_validity"] = json!(bad);
            assert!(validate(changed).is_err());
        }
        for index in [0, 2] {
            let mut changed = contract.clone();
            changed["operations"][index]["native_error"]["output_validity"] =
                json!("zero-on-failure");
            assert!(validate(changed).is_err());
        }
        let mut changed = contract.clone();
        changed["operations"][1]["native_error"] = serde_json::Value::Null;
        assert!(validate(changed).is_err());
        let mut changed = contract.clone();
        changed["operations"][1]["request_schema_id"] = json!(99);
        assert!(validate(changed).is_err());
        let mut changed = contract.clone();
        changed["operations"][1]["response_schema_id"] = json!(99);
        assert!(validate(changed).is_err());
        let mut changed = contract.clone();
        changed["operations"][1] = changed["operations"][0].clone();
        assert!(validate(changed).is_err());
        let mut changed = contract;
        changed["operations"].as_array_mut().unwrap().remove(1);
        assert!(validate(changed).is_err());
        assert!(validate(json!({})).unwrap().is_none());
    }

    #[test]
    fn bounds_keys_and_policy_fail_closed() {
        assert!(validate_bounds(0, 1).is_err());
        assert!(validate_bounds(LOGICAL_MAX + 1, 1).is_err());
        assert!(validate_bounds(4, 0).is_err());
        assert!(validate_bounds(4, 600_001).is_err());
        assert!(validate_bounds(4, 1000).is_ok());
        let root = tempfile::tempdir().unwrap();
        let key = root.path().join("key");
        std::fs::write(&key, [3; 33]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(read_key(&key).is_err());
        std::fs::write(&key, [3; 32]).unwrap();
        assert_eq!(*read_key(&key).unwrap(), [3; 32]);
        assert!(registry(&[]).is_err());
        let actors = vec![ActorConfig {
            id: [1; 16],
            public_key: [2; 32],
            grants: vec![],
        }];
        assert!(
            registry(&actors)
                .unwrap()
                .authorize_invoke([1; 16], [3; 32], 7, 0)
                .is_err()
        );
        assert!(registry(&actors).unwrap().actor_for_key(&[4; 32]).is_err());
        std::fs::write(&key, [0; 2]).unwrap();
        assert!(bounded_read(&key, 1).is_err());
    }

    struct Value;
    impl TypedDispatchModule for Value {
        fn dispatch(&self, operation: u32, request: &[u8]) -> DispatchOutcome {
            assert_eq!(operation, 7);
            assert!(request.is_empty());
            DispatchOutcome {
                status: 0,
                body: 1234_u32.to_le_bytes().to_vec(),
            }
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn product_call_uses_authenticated_ffi_binding_and_preserves_typed_bytes() {
        let root = tempfile::tempdir().unwrap();
        let key_path = root.path().join("client.key");
        // RFC 7748 Alice test key; never a product identity.
        let key: Vec<u8> = (0..64)
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(
                    &"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"[i..i + 2],
                    16,
                )
                .unwrap()
            })
            .collect();
        let public: Vec<u8> = (0..64)
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(
                    &"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"[i..i + 2],
                    16,
                )
                .unwrap()
            })
            .collect();
        std::fs::write(&key_path, key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let contract_path = root.path().join("contract");
        std::fs::write(&contract_path, b"test-only-contract").unwrap();
        let hash = sha256_bytes(b"test-only-contract");
        let request = root.path().join("request");
        let response = root.path().join("response");
        std::fs::write(&request, []).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (server_key, server_public) = StaticPrivateKey::generate().unwrap();
        let server = runtime.spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (remote, provisional) = session_responder(stream, &server_key).await.unwrap();
            assert_eq!(remote.as_slice(), public.as_slice());
            let actor = [8; 16];
            let actors = vec![ActorConfig {
                id: actor,
                public_key: remote,
                grants: vec![Grant {
                    role: Role::Invoke,
                    adapter_hash: Some(hash),
                    operation_id: Some(7),
                    expires_at_unix_ms: None,
                }],
            }];
            let registry = Arc::new(RwLock::new(registry(&actors).unwrap()));
            assert_eq!(actor_for_session_key(&registry, &remote).unwrap(), actor);
            let ack = HelloAck {
                selected_minor: 0,
                features: 0,
                max_logical_payload: u32::try_from(LOGICAL_MAX).unwrap(),
                max_streams: 1,
                initial_connection_credit: 4_194_304,
                connection_epoch: 99,
                broker_epoch: [7; 16],
                actor_id: actor,
                readiness: Readiness {
                    overall_status: 1,
                    generated_at_unix_ms: 1,
                    source_version: "test".into(),
                },
                broker_wall_unix_ms: 1,
            };
            let (_, active) = activate_broker(provisional, &ack, [6; 16]).await.unwrap();
            let typed = Arc::new(DispatcherCallHandler::new(
                hash,
                BTreeMap::from([(
                    7,
                    OperationSchema {
                        request_schema_id: 11,
                        response_schema_id: 12,
                    },
                )]),
                Arc::new(Value),
            ));
            serve_calls(
                active,
                Arc::new(AuthorizedCallHandler::new(actor, registry, typed)),
                1,
            )
            .await
            .unwrap();
        });
        call(
            &CallConfig {
                address,
                private_key_path: key_path,
                broker_public_key: server_public,
                actor_id: [8; 16],
                client_instance: [4; 16],
                build_fingerprint: [5; 32],
                contract_path,
                contract_sha256: hash,
                operation: wvb_admission::OperationAdmission {
                    operation_id: 7,
                    request_schema_id: 11,
                    response_schema_id: 12,
                },
                response_capacity: 4,
                connect_timeout_ms: 2000,
                call_timeout_ms: 2000,
            },
            &request,
            &response,
        )
        .unwrap();
        assert_eq!(std::fs::read(response).unwrap(), 1234_u32.to_le_bytes());
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .unwrap()
                .unwrap();
        });
    }
}
