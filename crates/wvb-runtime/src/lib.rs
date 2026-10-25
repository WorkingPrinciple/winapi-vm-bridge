//! Production TCP client composition for the canonical bridge protocol.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use wvb_call::{CallRequest, CallResult};
use wvb_client::{Client, ClientError};
use wvb_control::{ControlMessage, HandleClose, HandleStatus};
use wvb_crypto::StaticPrivateKey;
use wvb_session::{Hello, HelloAck, READINESS_READY, SessionError, activate_client};
use wvb_transport::{TransportError, session_initiator};

#[derive(Debug)]
pub enum RuntimeError {
    Io(std::io::Error),
    Transport(TransportError),
    Session(SessionError),
    Client(ClientError),
    ActorMismatch,
    NotReady(u16),
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
    /// One budget for TCP, Noise and authenticated backend readiness; never reset per stage.
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
        // Backend initialization and HELLO_ACK consume the same setup budget as TCP/Noise.
        let deadline = tokio::time::Instant::now() + config.connect_timeout;
        let stream = tokio::time::timeout_at(deadline, TcpStream::connect(config.address))
            .await
            .map_err(|_| Self::setup_timeout("TCP connection"))??;
        stream.set_nodelay(true)?;
        let provisional = tokio::time::timeout_at(
            deadline,
            session_initiator(stream, &config.local_private_key, &config.broker_public_key),
        )
        .await
        .map_err(|_| Self::setup_timeout("Noise authentication"))??;
        let (ack, connection) = tokio::time::timeout_at(
            deadline,
            activate_client(provisional, &config.hello, config.hello_message_id),
        )
        .await
        .map_err(|_| Self::setup_timeout("HELLO_ACK readiness"))??;
        if ack.actor_id != config.expected_actor {
            return Err(RuntimeError::ActorMismatch);
        }
        if ack.readiness.overall_status != READINESS_READY {
            return Err(RuntimeError::NotReady(ack.readiness.overall_status));
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
    }

    fn setup_timeout(stage: &str) -> RuntimeError {
        RuntimeError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("broker setup timed out during {stage}"),
        ))
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
        let error = result.unwrap().err().unwrap().to_string();
        assert!(
            error.contains(if stall_activation {
                "HELLO_ACK readiness"
            } else {
                "Noise authentication"
            }),
            "setup timeout must identify the pending stage: {error}"
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

    async fn connect_with_readiness(
        status: u16,
        noise_delay: Duration,
        readiness_delay: Duration,
        budget: Duration,
    ) -> Result<RuntimeClient, RuntimeError> {
        let (client_key, _) = StaticPrivateKey::generate().unwrap();
        let (broker_key, broker_public) = StaticPrivateKey::generate().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let broker = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(noise_delay).await;
            let (_, provisional) = session_responder(stream, &broker_key).await.unwrap();
            tokio::time::sleep(readiness_delay).await;
            let ack = HelloAck {
                selected_minor: 0,
                features: 0,
                max_logical_payload: 1_048_576,
                max_streams: 16,
                initial_connection_credit: 2_097_152,
                connection_epoch: 42,
                broker_epoch: [7; 16],
                actor_id: [8; 16],
                readiness: Readiness {
                    overall_status: status,
                    generated_at_unix_ms: 2,
                    source_version: String::from("delayed-backend-fixture"),
                },
                broker_wall_unix_ms: 2,
            };
            if let Ok((_, active)) = activate_broker(provisional, &ack, [6; 16]).await {
                let _ = serve_calls(active, Arc::new(Echo), 4).await;
            }
        });
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            RuntimeClient::connect(ClientConfig {
                address,
                local_private_key: client_key,
                broker_public_key: broker_public,
                expected_actor: [8; 16],
                hello: hello(),
                hello_message_id: [5; 16],
                message_nonce: [9; 8],
                queue_capacity: 16,
                connect_timeout: budget,
            }),
        )
        .await
        .expect("bounded readiness fixture must not hang");
        broker.abort();
        result
    }

    #[tokio::test]
    async fn authenticated_ack_must_report_ready_before_configuration_succeeds() {
        for status in [0, 2, 3, u16::MAX] {
            let result = connect_with_readiness(
                status,
                Duration::ZERO,
                Duration::ZERO,
                Duration::from_secs(1),
            )
            .await;
            assert!(matches!(result, Err(RuntimeError::NotReady(actual)) if actual == status));
        }
    }

    #[tokio::test]
    async fn listening_and_noise_completion_do_not_bypass_backend_readiness_deadline() {
        let result = connect_with_readiness(
            READINESS_READY,
            Duration::ZERO,
            Duration::from_millis(150),
            Duration::from_millis(50),
        )
        .await;
        assert!(matches!(result, Err(RuntimeError::Io(ref error))
            if error.kind() == std::io::ErrorKind::TimedOut
                && error.to_string().contains("HELLO_ACK readiness")));
        assert!(
            connect_with_readiness(
                READINESS_READY,
                Duration::ZERO,
                Duration::from_millis(150),
                Duration::from_secs(1)
            )
            .await
            .is_ok(),
            "an explicitly sufficient setup budget must admit a delayed ready backend"
        );
    }

    #[tokio::test]
    async fn readiness_does_not_restart_the_shared_setup_budget_after_noise() {
        let result = connect_with_readiness(
            READINESS_READY,
            Duration::from_millis(300),
            Duration::from_millis(300),
            Duration::from_millis(500),
        )
        .await;
        assert!(matches!(result, Err(RuntimeError::Io(ref error))
            if error.kind() == std::io::ErrorKind::TimedOut
                && error.to_string().contains("HELLO_ACK readiness")));
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
