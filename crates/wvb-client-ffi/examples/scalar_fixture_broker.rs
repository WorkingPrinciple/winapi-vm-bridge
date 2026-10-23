//! Source-test-only loopback broker for generated scalar/actual FFI composition.
//! The synthetic identity and dispatcher confer no production authority.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use wvb_broker::{
    BrokerError, CallHandler, DispatchOutcome, DispatcherCallHandler, OperationSchema,
    TypedDispatchModule, serve_calls,
};
use wvb_call::{CallRequest, CallResult};
use wvb_crypto::StaticPrivateKey;
use wvb_session::{HelloAck, Readiness, activate_broker};
use wvb_transport::session_responder;

struct SyntheticScalar;

impl TypedDispatchModule for SyntheticScalar {
    fn dispatch(&self, _operation_id: u32, request: &[u8]) -> DispatchOutcome {
        let Ok(bytes) = <[u8; 8]>::try_from(request) else {
            return DispatchOutcome {
                status: -1,
                body: Vec::new(),
            };
        };
        let left = i32::from_le_bytes(bytes[..4].try_into().expect("four bytes"));
        let right = i32::from_le_bytes(bytes[4..].try_into().expect("four bytes"));
        let (status, value) = match left {
            -1001 => (0, i32::from_le_bytes(0x8000_4005_u32.to_le_bytes())),
            -1002 => (-17, 42),
            _ => match left.checked_add(right) {
                Some(value) => (0, value),
                None => (-1, 0),
            },
        };
        DispatchOutcome {
            status,
            body: value.to_le_bytes().to_vec(),
        }
    }
}

struct FaultFixture(DispatcherCallHandler);

#[async_trait]
impl CallHandler for FaultFixture {
    async fn handle_call(&self, request: CallRequest) -> Result<CallResult, BrokerError> {
        let selector = request
            .body
            .get(..4)
            .map(|bytes| i32::from_le_bytes(bytes.try_into().expect("four bytes")));
        let mut result = self.0.handle_call(request).await?;
        match selector {
            Some(-1003) => result.response_schema_id ^= 1,
            Some(-1004) => result.body.truncate(3),
            Some(-1005) => result.native_status = vec![0],
            Some(-1006) => result.body.clear(),
            Some(-1007) => {
                return Err(BrokerError::Handler(
                    "synthetic disconnect after dispatch".into(),
                ));
            }
            Some(-1008) => result.body.push(0),
            _ => {}
        }
        Ok(result)
    }
}

struct FixtureOperation {
    hash: [u8; 32],
    id: u32,
    request_schema: u32,
    response_schema: u32,
}

fn operation(arguments: &[String]) -> Result<FixtureOperation, Box<dyn std::error::Error>> {
    if arguments.len() != 5 || arguments[1].len() != 64 {
        return Err(
            "usage: scalar_fixture_broker CONTRACT_SHA256_HEX OP REQUEST_SCHEMA RESPONSE_SCHEMA"
                .into(),
        );
    }
    let mut hash = [0_u8; 32];
    for (index, value) in hash.iter_mut().enumerate() {
        *value = u8::from_str_radix(
            arguments[1]
                .get(index * 2..index * 2 + 2)
                .ok_or("invalid hash encoding")?,
            16,
        )?;
    }
    let id = arguments[2].parse()?;
    let request_schema = arguments[3].parse()?;
    let response_schema = arguments[4].parse()?;
    if id == 0 || request_schema == 0 || response_schema == 0 {
        return Err("operation and schema IDs must be nonzero".into());
    }
    Ok(FixtureOperation {
        hash,
        id,
        request_schema,
        response_schema,
    })
}

async fn connection(
    stream: TcpStream,
    key: Arc<StaticPrivateKey>,
    handler: Arc<FaultFixture>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    stream.set_nodelay(true)?;
    let (_, provisional) = session_responder(stream, &key).await?;
    let ack = HelloAck {
        selected_minor: 0,
        features: 0,
        max_logical_payload: 1_048_576,
        max_streams: 64,
        initial_connection_credit: 4_194_304,
        connection_epoch: 42,
        broker_epoch: [7; 16],
        actor_id: [8; 16],
        readiness: Readiness {
            overall_status: 1,
            generated_at_unix_ms: 1,
            source_version: String::from("synthetic-scalar-source-test-only"),
        },
        broker_wall_unix_ms: 1,
    };
    let (_, active) = activate_broker(provisional, &ack, [6; 16]).await?;
    serve_calls(active, handler, 4).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let operation = operation(&std::env::args().collect::<Vec<_>>())?;
    let handler = Arc::new(FaultFixture(DispatcherCallHandler::new(
        operation.hash,
        BTreeMap::from([(
            operation.id,
            OperationSchema {
                request_schema_id: operation.request_schema,
                response_schema_id: operation.response_schema,
            },
        )]),
        Arc::new(SyntheticScalar),
    )));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let (key, public) = StaticPrivateKey::generate()?;
    let key = Arc::new(key);
    println!(
        "{}",
        json!({
            "scope": "synthetic-scalar-source-test-only",
            "address": listener.local_addr()?.to_string(),
            "brokerPublicKey": public,
            "clientPrivateKey": ([3_u8; 32]),
            "actorId": ([8_u8; 16]),
            "clientInstance": ([4_u8; 16]),
            "buildFingerprint": ([5_u8; 32]),
            "contractSha256": operation.hash,
            "operationId": operation.id,
            "requestSchemaId": operation.request_schema,
            "responseSchemaId": operation.response_schema,
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
                        Ok(Err(error)) => eprintln!("fixture-connection-ended: {error}"),
                        Err(_) => eprintln!("fixture-connection-ended: bounded connection timeout"),
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
    fn typed_target_keeps_api_failure_separate_from_dispatch_failure() {
        for (left, status, result) in [
            (20_i32, 0, 42_i32),
            (-1001, 0, -2_147_467_259),
            (-1002, -17, 42),
        ] {
            let body = [left.to_le_bytes(), 22_i32.to_le_bytes()].concat();
            let outcome = SyntheticScalar.dispatch(7, &body);
            assert_eq!(outcome.status, status);
            assert_eq!(outcome.body, result.to_le_bytes());
        }
        assert_eq!(SyntheticScalar.dispatch(7, &[0; 7]).status, -1);
    }
}
