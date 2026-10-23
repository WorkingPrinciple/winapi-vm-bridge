//! Opt-in source-test broker for an explicitly selected generated Mach-O export.
//! This does not load Windows PE code or confer runtime authority.

#[cfg(target_os = "macos")]
mod fixture {
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::json;
    use tokio::net::{TcpListener, TcpStream};
    use wvb_broker::{DispatcherCallHandler, OperationSchema, serve_calls};
    use wvb_call::LOGICAL_MAX;
    use wvb_crypto::StaticPrivateKey;
    use wvb_native_host::{NativeHostConfig, source_fixture::SourceFixtureDispatcher};
    use wvb_session::{HelloAck, Readiness, activate_broker};
    use wvb_transport::session_responder;

    const SCOPE: &str = "generated-byte-export-source-fixture-not-windows-loader-guest-or-app";

    struct Fixture {
        dispatcher: NativeHostConfig,
        contract: [u8; 32],
        operation: u32,
        request_schema: u32,
        response_schema: u32,
    }

    fn hash(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        if value.len() != 64 {
            return Err("SHA-256 must contain exactly 64 hex characters".into());
        }
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(
                value
                    .get(index * 2..index * 2 + 2)
                    .ok_or("invalid hex encoding")?,
                16,
            )?;
        }
        Ok(bytes)
    }

    fn arguments(args: &[String]) -> Result<Fixture, Box<dyn std::error::Error>> {
        if args.len() != 7 {
            return Err("usage: source_fixture_broker ABSOLUTE_DISPATCHER_DYLIB DISPATCHER_SHA256_HEX CONTRACT_SHA256_HEX OP REQUEST_SCHEMA RESPONSE_SCHEMA".into());
        }
        let operation = args[4].parse()?;
        let request_schema = args[5].parse()?;
        let response_schema = args[6].parse()?;
        if operation == 0 || request_schema == 0 || response_schema == 0 {
            return Err("operation and schema IDs must be nonzero".into());
        }
        let dispatcher_path = PathBuf::from(&args[1]);
        if !dispatcher_path.is_absolute() {
            return Err("source fixture dispatcher must have an absolute path".into());
        }
        Ok(Fixture {
            dispatcher: NativeHostConfig {
                dispatcher_path,
                dispatcher_sha256: hash(&args[2])?,
                response_capacity: LOGICAL_MAX,
            },
            contract: hash(&args[3])?,
            operation,
            request_schema,
            response_schema,
        })
    }

    async fn connection(
        stream: TcpStream,
        key: Arc<StaticPrivateKey>,
        handler: Arc<DispatcherCallHandler>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        stream.set_nodelay(true)?;
        let (_, provisional) = session_responder(stream, &key).await?;
        let ack = HelloAck {
            selected_minor: 0,
            features: 0,
            max_logical_payload: u32::try_from(LOGICAL_MAX)?,
            max_streams: 64,
            initial_connection_credit: 4_194_304,
            connection_epoch: 42,
            broker_epoch: [7; 16],
            actor_id: [8; 16],
            readiness: Readiness {
                overall_status: 1,
                generated_at_unix_ms: 1,
                source_version: SCOPE.into(),
            },
            broker_wall_unix_ms: 1,
        };
        let (_, active) = activate_broker(provisional, &ack, [6; 16]).await?;
        serve_calls(active, handler, 4).await?;
        Ok(())
    }

    pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = arguments(&std::env::args().collect::<Vec<_>>())?;
        // The source-test driver selects trusted generated code and its exact hash.
        #[allow(unsafe_code)]
        let module = unsafe { SourceFixtureDispatcher::load(&fixture.dispatcher)? };
        let handler = Arc::new(DispatcherCallHandler::new(
            fixture.contract,
            BTreeMap::from([(
                fixture.operation,
                OperationSchema {
                    request_schema_id: fixture.request_schema,
                    response_schema_id: fixture.response_schema,
                },
            )]),
            Arc::new(module),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let (key, public) = StaticPrivateKey::generate()?;
        let key = Arc::new(key);
        println!(
            "{}",
            json!({
                "scope": SCOPE,
                "address": listener.local_addr()?.to_string(),
                "brokerPublicKey": public,
                "clientPrivateKey": ([3_u8; 32]),
                "actorId": ([8_u8; 16]),
                "clientInstance": ([4_u8; 16]),
                "buildFingerprint": ([5_u8; 32]),
                "contractSha256": fixture.contract,
                "operationId": fixture.operation,
                "requestSchemaId": fixture.request_schema,
                "responseSchemaId": fixture.response_schema,
                "dispatcherPath": fixture.dispatcher.dispatcher_path,
                "dispatcherSha256": fixture.dispatcher.dispatcher_sha256,
                "responseCapacity": LOGICAL_MAX,
                "lifetimeSeconds": 60
            })
        );
        std::io::stdout().flush()?;
        let deadline = tokio::time::sleep(Duration::from_secs(60));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                () = &mut deadline => return Ok(()),
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let key = key.clone();
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        match tokio::time::timeout(Duration::from_secs(10), connection(stream, key, handler)).await {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => eprintln!("source-fixture connection ended: {error}"),
                            Err(_) => eprintln!("source-fixture connection ended: bounded connection timeout"),
                        }
                    });
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn explicit_path_hash_and_operation_metadata_are_required() {
            let args = [
                "source_fixture_broker".into(),
                "/tmp/generated.dylib".into(),
                "01".repeat(32),
                "02".repeat(32),
                "7".into(),
                "305419896".into(),
                "878082193".into(),
            ];
            let fixture = arguments(&args).unwrap();
            assert_eq!(fixture.dispatcher.response_capacity, LOGICAL_MAX);
            assert_eq!(fixture.request_schema, 0x1234_5678);
            assert!(arguments(&args[..6]).is_err());
            for (index, value) in [
                (1, "relative.dylib"),
                (2, "bad-hash"),
                (3, "bad-hash"),
                (4, "0"),
                (5, "0"),
                (6, "0"),
            ] {
                let mut invalid = args.clone();
                invalid[index] = value.into();
                assert!(arguments(&invalid).is_err());
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    {
        fixture::run().await
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("source_fixture_broker requires the opt-in macOS source-fixture loader".into())
    }
}
