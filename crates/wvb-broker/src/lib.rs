//! Concurrent canonical broker session driver.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Semaphore, mpsc};
use wvb_protocol::{Envelope, EnvelopeFlags};
use wvb_transport::{SecureConnection, TransportError};

#[derive(Debug)]
pub struct BrokerRequest {
    pub envelope: Envelope,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct BrokerResponse {
    pub message_type: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum BrokerError {
    Transport(TransportError),
    Handler(String),
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for BrokerError {}

impl From<TransportError> for BrokerError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

#[async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle(&self, request: BrokerRequest) -> Result<BrokerResponse, BrokerError>;
}

struct Completed {
    request: Envelope,
    response: Result<BrokerResponse, BrokerError>,
}

pub async fn serve_session<S>(
    mut connection: SecureConnection<S>,
    handler: Arc<dyn Handler>,
    max_concurrent: usize,
) -> Result<(), BrokerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let permits = Arc::new(Semaphore::new(max_concurrent));
    let (completed_sender, mut completed_receiver) = mpsc::channel(max_concurrent);
    loop {
        tokio::select! {
            received = connection.receive() => {
                let (envelope, payload) = received?;
                if !envelope.flags.contains(EnvelopeFlags::REQUEST) {
                    continue;
                }
                let permit = permits.clone().acquire_owned().await.map_err(|error| {
                    BrokerError::Handler(format!("semaphore closed: {error}"))
                })?;
                let sender = completed_sender.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    let response = handler.handle(BrokerRequest {
                        envelope: envelope.clone(),
                        payload,
                    }).await;
                    let _ = sender.send(Completed { request: envelope, response }).await;
                    drop(permit);
                });
            }
            completed = completed_receiver.recv() => {
                let Some(completed) = completed else { return Ok(()); };
                let response = completed.response?;
                let payload_length = u32::try_from(response.payload.len())
                    .map_err(|_| BrokerError::Handler("response too large".into()))?;
                let envelope = Envelope {
                    minor: completed.request.minor,
                    message_type: response.message_type,
                    flags: EnvelopeFlags::RESPONSE | EnvelopeFlags::END_STREAM,
                    connection_epoch: completed.request.connection_epoch,
                    stream_id: completed.request.stream_id,
                    stream_sequence: 0,
                    message_id: response_message_id(completed.request.message_id),
                    correlation_id: completed.request.message_id,
                    remaining_budget_ms: completed.request.remaining_budget_ms,
                    payload_length,
                };
                connection.send(&envelope, &response.payload).await?;
            }
        }
    }
}

fn response_message_id(request: [u8; 16]) -> [u8; 16] {
    let mut response = request;
    response[0] ^= 0x80;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use tokio::io::duplex;
    use wvb_client::Client;
    use wvb_crypto::{Handshake, PairingPsk, StaticPrivateKey, Transport};

    struct Echo;

    #[async_trait]
    impl Handler for Echo {
        async fn handle(&self, request: BrokerRequest) -> Result<BrokerResponse, BrokerError> {
            Ok(BrokerResponse {
                message_type: request.envelope.message_type + 1,
                payload: request.payload,
            })
        }
    }

    fn paired_transports() -> (Transport, Transport) {
        let (client_key, _) = StaticPrivateKey::generate().unwrap();
        let (broker_key, _) = StaticPrivateKey::generate().unwrap();
        let mut client =
            Handshake::pairing_initiator(&client_key, &PairingPsk::from_bytes([5; 32])).unwrap();
        let mut broker =
            Handshake::pairing_responder(&broker_key, &PairingPsk::from_bytes([5; 32])).unwrap();
        let mut message = [0_u8; 256];
        let mut payload = [0_u8; 256];
        let size = client.write(&[], &mut message).unwrap();
        broker.read(&message[..size], &mut payload).unwrap();
        let size = broker.write(&[], &mut message).unwrap();
        client.read(&message[..size], &mut payload).unwrap();
        let size = client.write(&[], &mut message).unwrap();
        broker.read(&message[..size], &mut payload).unwrap();
        (
            client.into_transport().unwrap(),
            broker.into_transport().unwrap(),
        )
    }

    #[tokio::test]
    async fn multiplexed_request_returns_correlated_result() {
        let (client_crypto, broker_crypto) = paired_transports();
        let (client_io, broker_io) = duplex(1 << 20);
        let client_connection = SecureConnection::new(client_io, client_crypto, 99);
        let broker_connection = SecureConnection::new(broker_io, broker_crypto, 99);
        let server = tokio::spawn(serve_session(broker_connection, Arc::new(Echo), 8));
        let client = Client::spawn(client_connection, 99, [7; 8], 16);
        let response = client
            .request(0x100, b"real".to_vec(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(response.envelope.message_type, 0x101);
        assert_eq!(response.payload, b"real");
        server.abort();
    }
}
