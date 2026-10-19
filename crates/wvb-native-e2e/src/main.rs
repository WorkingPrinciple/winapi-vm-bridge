use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use wvb_authz::{Grant, Registry, Role};
use wvb_broker::{
    AuthorizedCallHandler, BrokerError, CallHandler, DispatcherCallHandler, OperationSchema,
    serve_calls,
};
use wvb_call::{CallRequest, CallResult};
use wvb_crypto::StaticPrivateKey;
use wvb_native_host::{NativeDispatcher, NativeHostConfig};
use wvb_runtime::{ClientConfig, RuntimeClient};
use wvb_session::{Hello, HelloAck, Platform, Readiness, activate_broker};
use wvb_transport::{SecureConnection, session_responder};

const ACTOR_ID: [u8; 16] = [0x41; 16];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcceptanceConfig {
    address: SocketAddr,
    adapter_hash: String,
    dispatcher_path: PathBuf,
    dispatcher_sha256: String,
}

struct OneShot {
    inner: Arc<dyn CallHandler>,
    completed: Arc<Notify>,
}

#[async_trait]
impl CallHandler for OneShot {
    async fn handle_call(&self, request: CallRequest) -> Result<CallResult, BrokerError> {
        let result = self.inner.handle_call(request).await;
        self.completed.notify_one();
        result
    }
}

async fn accept_authorized(
    listener: &TcpListener,
    broker_key: &StaticPrivateKey,
    client_public: [u8; 32],
) -> Result<SecureConnection<TcpStream>, Box<dyn std::error::Error>> {
    Ok(tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            if stream.set_nodelay(true).is_err() {
                continue;
            }
            let Ok((remote, provisional)) = session_responder(stream, broker_key).await else {
                continue;
            };
            if remote == client_public {
                break provisional;
            }
        }
    })
    .await?)
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("wvb-native-e2e: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err("usage: wvb-native-e2e <server|client> CONFIG.json".into());
    }
    let config = load_config(Path::new(&arguments[2]))?;
    match arguments[1].as_str() {
        "server" => run_server(config).await,
        "client" => run_client(config, false).await,
        "client-schema-negative" => run_client(config, true).await,
        _ => Err("mode must be server or client".into()),
    }
}

async fn run_server(config: AcceptanceConfig) -> Result<(), Box<dyn std::error::Error>> {
    let adapter_hash = hash(&config.adapter_hash)?;
    let broker_private = environment_key("WVB_TEST_BROKER_PRIVATE")?;
    let client_public = environment_key("WVB_TEST_CLIENT_PUBLIC")?;
    let dispatcher = NativeDispatcher::load(&NativeHostConfig {
        dispatcher_path: config.dispatcher_path,
        dispatcher_sha256: hash(&config.dispatcher_sha256)?,
        response_capacity: 4,
    })?;
    let typed = Arc::new(DispatcherCallHandler::new(
        adapter_hash,
        BTreeMap::from([(
            1,
            OperationSchema {
                request_schema_id: 0x1000_0001,
                response_schema_id: 0x1000_0002,
            },
        )]),
        Arc::new(dispatcher),
    ));
    let mut registry = Registry::default();
    registry
        .register(ACTOR_ID, client_public)
        .map_err(|error| format!("register actor: {error:?}"))?;
    registry
        .grant(
            ACTOR_ID,
            Grant {
                role: Role::Invoke,
                adapter_hash: Some(adapter_hash),
                operation_id: Some(1),
                expires_at_unix_ms: None,
            },
        )
        .map_err(|error| format!("grant invoke: {error:?}"))?;
    let authorized: Arc<dyn CallHandler> = Arc::new(AuthorizedCallHandler::new(
        ACTOR_ID,
        Arc::new(RwLock::new(registry)),
        typed,
    ));
    let completed = Arc::new(Notify::new());
    let handler = Arc::new(OneShot {
        inner: authorized,
        completed: completed.clone(),
    });

    let listener = TcpListener::bind(config.address).await?;
    println!("native-broker-ready={}", listener.local_addr()?);
    let broker_key = StaticPrivateKey::from_bytes(broker_private);
    let provisional = accept_authorized(&listener, &broker_key, client_public).await?;
    let ack = HelloAck {
        selected_minor: 0,
        features: 0,
        max_logical_payload: 1_048_576,
        max_streams: 8,
        initial_connection_credit: 2_097_152,
        connection_epoch: 83,
        broker_epoch: [0x23; 16],
        actor_id: ACTOR_ID,
        readiness: Readiness {
            overall_status: 1,
            generated_at_unix_ms: 1,
            source_version: String::from("native-e2e"),
        },
        broker_wall_unix_ms: 1,
    };
    let (_, active) = activate_broker(provisional, &ack, [0x30; 16]).await?;
    let server = tokio::spawn(serve_calls(active, handler, 1));
    tokio::time::timeout(Duration::from_secs(20), completed.notified()).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    server.abort();
    Ok(())
}

async fn run_client(
    config: AcceptanceConfig,
    invalid_schema: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter_hash = hash(&config.adapter_hash)?;
    let client_private = environment_key("WVB_TEST_CLIENT_PRIVATE")?;
    let broker_public = environment_key("WVB_TEST_BROKER_PUBLIC")?;
    let client = RuntimeClient::connect(ClientConfig {
        address: config.address,
        local_private_key: StaticPrivateKey::from_bytes(client_private),
        broker_public_key: broker_public,
        expected_actor: ACTOR_ID,
        hello: Hello {
            peer_kind: 1,
            min_minor: 0,
            max_minor: 0,
            features: 0,
            max_logical_payload: 1_048_576,
            max_streams: 8,
            initial_connection_credit: 2_097_152,
            client_instance: [0x16; 16],
            platform: Platform {
                os: 2,
                os_version: String::from("macOS"),
                architecture: 3,
                wine_version: None,
                runtime_version: Some(String::from("0.2.0")),
                build_fingerprint: vec![0x50; 32],
            },
            client_wall_unix_ms: 1,
        },
        hello_message_id: [0x60; 16],
        message_nonce: [0x70; 8],
        queue_capacity: 8,
        connect_timeout: Duration::from_secs(10),
    })
    .await?;
    let mut body = Vec::new();
    body.extend_from_slice(&20_i32.to_le_bytes());
    body.extend_from_slice(&22_i32.to_le_bytes());
    let result = client
        .call(
            &CallRequest {
                adapter_hash,
                operation_id: 1,
                request_schema_id: if invalid_schema {
                    0x1000_ffff
                } else {
                    0x1000_0001
                },
                deduplication_mode: 0,
                idempotency_key: None,
                disconnect_policy: 0,
                sensitivity: 0,
                body,
            },
            Duration::from_secs(10),
        )
        .await;
    if invalid_schema {
        if result.is_ok() {
            return Err("native invalid schema unexpectedly dispatched".into());
        }
        println!("native-schema-negative=ok");
        return Ok(());
    }
    let result = result?;
    if result.native_status != 0_i32.to_le_bytes()
        || result.body.len() != 4
        || i32::from_le_bytes(result.body.try_into().map_err(|_| "response size")?) != 42
    {
        return Err("native encrypted result mismatch".into());
    }
    println!("native-encrypted-roundtrip=ok result=42");
    Ok(())
}

fn load_config(path: &Path) -> Result<AcceptanceConfig, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn hash(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if value.len() != 64 {
        return Err("hash length".into());
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(output)
}

fn environment_key(name: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    hash(&std::env::var(name).map_err(|_| format!("missing {name}"))?)
}
