//! Production TCP client composition for the canonical bridge protocol.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use wvb_call::{CallRequest, CallResult};
use wvb_client::{Client, ClientError};
use wvb_control::{ControlMessage, HandleClose, HandleStatus};
use wvb_crypto::StaticPrivateKey;
use wvb_session::{Hello, HelloAck, SessionError, activate_client};
use wvb_transport::{TransportError, session_initiator};

#[derive(Debug)]
pub enum RuntimeError {
    Io(std::io::Error),
    Transport(TransportError),
    Session(SessionError),
    Client(ClientError),
    ActorMismatch,
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RuntimeError {}

impl From<std::io::Error> for RuntimeError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<TransportError> for RuntimeError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<SessionError> for RuntimeError {
    fn from(value: SessionError) -> Self {
        Self::Session(value)
    }
}

impl From<ClientError> for RuntimeError {
    fn from(value: ClientError) -> Self {
        Self::Client(value)
    }
}

pub struct ClientConfig {
    pub address: SocketAddr,
    pub local_private_key: StaticPrivateKey,
    pub broker_public_key: [u8; 32],
    pub expected_actor: [u8; 16],
    pub hello: Hello,
    pub hello_message_id: [u8; 16],
    pub message_nonce: [u8; 8],
    pub queue_capacity: usize,
    pub connect_timeout: Duration,
}

#[derive(Clone)]
pub struct RuntimeClient {
    client: Client,
    actor_id: [u8; 16],
    negotiated: HelloAck,
}

impl RuntimeClient {
    pub async fn connect(config: ClientConfig) -> Result<Self, RuntimeError> {
        tokio::time::timeout(config.connect_timeout, async {
            let stream = TcpStream::connect(config.address).await?;
            stream.set_nodelay(true)?;
            let provisional =
                session_initiator(stream, &config.local_private_key, &config.broker_public_key)
                    .await?;
            let (ack, connection) =
                activate_client(provisional, &config.hello, config.hello_message_id).await?;
            if ack.actor_id != config.expected_actor {
                return Err(RuntimeError::ActorMismatch);
            }
            let client = Client::spawn(
                connection,
                ack.connection_epoch,
                config.message_nonce,
                config.queue_capacity,
            );
            Ok(Self {
                client,
                actor_id: ack.actor_id,
                negotiated: ack,
            })
        })
        .await
        .map_err(|_| {
            RuntimeError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "broker connection timed out",
            ))
        })?
    }

    pub async fn call(
        &self,
        request: &CallRequest,
        timeout: Duration,
    ) -> Result<CallResult, RuntimeError> {
        Ok(self.client.call(request, timeout).await?)
    }

    pub async fn close_handle(
        &self,
        request: HandleClose,
        timeout: Duration,
    ) -> Result<HandleStatus, RuntimeError> {
        let (kind, payload) = ControlMessage::HandleClose(request)
            .encode()
            .map_err(|_| ClientError::Protocol)?;
        let response = self.client.request(kind as u16, payload, timeout).await?;
        if response.envelope.message_type != wvb_protocol::MessageType::HandleStatus as u16
            || response.envelope.flags
                != (wvb_protocol::EnvelopeFlags::RESPONSE | wvb_protocol::EnvelopeFlags::END_STREAM)
            || response.envelope.stream_sequence != 0
        {
            return Err(ClientError::Protocol.into());
        }
        match ControlMessage::decode(wvb_protocol::MessageType::HandleStatus, &response.payload)
            .map_err(|_| ClientError::Protocol)?
        {
            ControlMessage::HandleStatus(status) => Ok(status),
            _ => Err(ClientError::Protocol.into()),
        }
    }

    #[must_use]
    pub fn actor_id(&self) -> [u8; 16] {
        self.actor_id
    }

    #[must_use]
    pub fn negotiated(&self) -> &HelloAck {
        &self.negotiated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::net::TcpListener;
    use wvb_broker::{BrokerError, CallHandler, serve_calls};
    use wvb_crypto::StaticPrivateKey;
    use wvb_session::{HelloAck, Platform, Readiness, activate_broker};
    use wvb_transport::session_responder;

    struct Echo;

    #[async_trait]
    impl CallHandler for Echo {
        async fn handle_call(&self, request: CallRequest) -> Result<CallResult, BrokerError> {
            Ok(CallResult {
                response_schema_id: request.request_schema_id + 1,
                operation_uuid: None,
                native_status: vec![1],
                body: request.body,
            })
        }
    }

    fn hello() -> Hello {
        Hello {
            peer_kind: 1,
            min_minor: 0,
            max_minor: 0,
            features: 0,
            max_logical_payload: 1_048_576,
            max_streams: 16,
            initial_connection_credit: 2_097_152,
            client_instance: [3; 16],
            platform: Platform {
                os: 1,
                os_version: String::from("Windows"),
                architecture: 2,
                wine_version: Some(String::from("CrossOver")),
                runtime_version: Some(String::from("0.2.0")),
                build_fingerprint: vec![4; 32],
            },
            client_wall_unix_ms: 1,
        }
    }

    async fn assert_connect_deadline(stall_activation: bool) {
        let (client_key, _) = StaticPrivateKey::generate().unwrap();
        let (broker_key, broker_public) = StaticPrivateKey::generate().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let broker = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            if stall_activation {
                let (_, connection) = session_responder(stream, &broker_key).await.unwrap();
                let _ = released.await;
                drop(connection);
            } else {
                let _ = released.await;
                drop(stream);
            }
        });
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            RuntimeClient::connect(ClientConfig {
                address,
                local_private_key: client_key,
                broker_public_key: broker_public,
                expected_actor: [8; 16],
                hello: hello(),
                hello_message_id: [5; 16],
                message_nonce: [9; 8],
                queue_capacity: 16,
                connect_timeout: Duration::from_millis(50),
            }),
        )
        .await;
        release.send(()).unwrap();
        broker.await.unwrap();
        assert!(
            matches!(result, Ok(Err(RuntimeError::Io(ref error)))
                    if error.kind() == std::io::ErrorKind::TimedOut),
            "whole connect must time out while activation={stall_activation} is stalled"
        );
    }

    #[tokio::test]
    async fn connect_deadline_includes_stalled_noise() {
        assert_connect_deadline(false).await;
    }

    #[tokio::test]
    async fn connect_deadline_includes_stalled_activation() {
        assert_connect_deadline(true).await;
    }

    #[tokio::test]
    async fn real_tcp_session_authenticates_activates_and_calls() {
        let (client_key, _) = StaticPrivateKey::generate().unwrap();
        let (broker_key, broker_public) = StaticPrivateKey::generate().unwrap();
        let actor_id = [8; 16];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let broker = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            let (_, provisional) = session_responder(stream, &broker_key).await.unwrap();
            let ack = HelloAck {
                selected_minor: 0,
                features: 0,
                max_logical_payload: 1_048_576,
                max_streams: 16,
                initial_connection_credit: 2_097_152,
                connection_epoch: 42,
                broker_epoch: [7; 16],
                actor_id,
                readiness: Readiness {
                    overall_status: 1,
                    generated_at_unix_ms: 2,
                    source_version: String::from("test"),
                },
                broker_wall_unix_ms: 2,
            };
            let (_, active) = activate_broker(provisional, &ack, [6; 16]).await.unwrap();
            serve_calls(active, Arc::new(Echo), 4).await.unwrap();
        });
        let client = RuntimeClient::connect(ClientConfig {
            address,
            local_private_key: client_key,
            broker_public_key: broker_public,
            expected_actor: actor_id,
            hello: hello(),
            hello_message_id: [5; 16],
            message_nonce: [9; 8],
            queue_capacity: 16,
            connect_timeout: Duration::from_secs(2),
        })
        .await
        .unwrap();
        assert_eq!(client.actor_id(), actor_id);
        assert_eq!(client.negotiated().connection_epoch, 42);
        let result = client
            .call(
                &CallRequest {
                    adapter_hash: [1; 32],
                    operation_id: 7,
                    request_schema_id: 0x3000_0007,
                    deduplication_mode: 0,
                    idempotency_key: None,
                    disconnect_policy: 0,
                    sensitivity: 0,
                    body: vec![0xa5; 100_000],
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(result.response_schema_id, 0x3000_0008);
        assert_eq!(result.body, vec![0xa5; 100_000]);
        broker.abort();
    }
}
