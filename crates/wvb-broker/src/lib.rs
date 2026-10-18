//! Concurrent canonical broker session driver.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Semaphore, mpsc};
use wvb_call::{CallAssembler, CallRequest, CallResult};
use wvb_protocol::{Envelope, EnvelopeFlags, MessageType};
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

#[async_trait]
pub trait CallHandler: Send + Sync + 'static {
    async fn handle_call(&self, request: CallRequest) -> Result<CallResult, BrokerError>;
}

struct Completed {
    request: Envelope,
    response: Result<BrokerResponse, BrokerError>,
}

struct IncomingCall {
    assembler: CallAssembler,
    root_message_id: [u8; 16],
    next_sequence: u32,
}

struct CompletedCall {
    stream_id: u32,
    root_message_id: [u8; 16],
    remaining_budget_ms: u64,
    response: Result<CallResult, BrokerError>,
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

pub async fn serve_calls<S>(
    mut connection: SecureConnection<S>,
    handler: Arc<dyn CallHandler>,
    max_concurrent: usize,
) -> Result<(), BrokerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let permits = Arc::new(Semaphore::new(max_concurrent));
    let (completed_sender, mut completed_receiver) = mpsc::channel(max_concurrent);
    let mut incoming = BTreeMap::<u32, IncomingCall>::new();
    loop {
        tokio::select! {
            received = connection.receive() => {
                let (envelope, payload) = received?;
                let request = receive_call_frame(&mut incoming, &envelope, &payload)?;
                if let Some(request) = request {
                    let completed = incoming.remove(&envelope.stream_id)
                        .ok_or_else(|| BrokerError::Handler("call stream disappeared".into()))?;
                    let permit = permits.clone().acquire_owned().await.map_err(|error| {
                        BrokerError::Handler(format!("semaphore closed: {error}"))
                    })?;
                    let sender = completed_sender.clone();
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        let response = handler.handle_call(request).await;
                        let _ = sender.send(CompletedCall {
                            stream_id: envelope.stream_id,
                            root_message_id: completed.root_message_id,
                            remaining_budget_ms: envelope.remaining_budget_ms,
                            response,
                        }).await;
                        drop(permit);
                    });
                }
            }
            completed = completed_receiver.recv() => {
                let Some(completed) = completed else { return Ok(()); };
                send_call_result(&mut connection, completed).await?;
            }
        }
    }
}

fn receive_call_frame(
    incoming: &mut BTreeMap<u32, IncomingCall>,
    envelope: &Envelope,
    payload: &[u8],
) -> Result<Option<CallRequest>, BrokerError> {
    if !envelope.flags.contains(EnvelopeFlags::REQUEST)
        || envelope.stream_id == 0
        || envelope.stream_id.is_multiple_of(2)
    {
        return Err(BrokerError::Handler("invalid call stream envelope".into()));
    }
    let message_type = MessageType::try_from(envelope.message_type)
        .map_err(|_| BrokerError::Handler("unknown call message".into()))?;
    let entry = incoming
        .entry(envelope.stream_id)
        .or_insert_with(|| IncomingCall {
            assembler: CallAssembler::default(),
            root_message_id: envelope.message_id,
            next_sequence: 0,
        });
    if envelope.stream_sequence != entry.next_sequence {
        return Err(BrokerError::Handler("call stream sequence gap".into()));
    }
    entry.next_sequence = entry
        .next_sequence
        .checked_add(1)
        .ok_or_else(|| BrokerError::Handler("call stream sequence exhausted".into()))?;
    let request = entry
        .assembler
        .push(message_type, payload)
        .map_err(|error| BrokerError::Handler(format!("invalid call stream: {error}")))?;
    if request.is_some() && !envelope.flags.contains(EnvelopeFlags::END_STREAM) {
        return Err(BrokerError::Handler("CALL_END missing END_STREAM".into()));
    }
    if request.is_none() && envelope.flags.contains(EnvelopeFlags::END_STREAM) {
        return Err(BrokerError::Handler("premature END_STREAM".into()));
    }
    Ok(request)
}

async fn send_call_result<S>(
    connection: &mut SecureConnection<S>,
    completed: CompletedCall,
) -> Result<(), BrokerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let messages = completed
        .response?
        .messages()
        .map_err(|error| BrokerError::Handler(format!("invalid result stream: {error}")))?;
    let message_count = messages.len();
    for (index, message) in messages.into_iter().enumerate() {
        let mut flags = EnvelopeFlags::RESPONSE;
        if index + 1 == message_count {
            flags = flags | EnvelopeFlags::END_STREAM;
        }
        let payload_length = u32::try_from(message.payload.len())
            .map_err(|_| BrokerError::Handler("response too large".into()))?;
        let envelope = Envelope {
            minor: 0,
            message_type: message.message_type as u16,
            flags,
            connection_epoch: connection.connection_epoch(),
            stream_id: completed.stream_id,
            stream_sequence: u32::try_from(index)
                .map_err(|_| BrokerError::Handler("result sequence exhausted".into()))?,
            message_id: response_stream_message_id(completed.root_message_id, index)?,
            correlation_id: completed.root_message_id,
            remaining_budget_ms: completed.remaining_budget_ms,
            payload_length,
        };
        connection.send(&envelope, &message.payload).await?;
    }
    Ok(())
}

fn response_message_id(request: [u8; 16]) -> [u8; 16] {
    let mut response = request;
    response[0] ^= 0x80;
    response
}

fn response_stream_message_id(request: [u8; 16], index: usize) -> Result<[u8; 16], BrokerError> {
    let mut response = request;
    response[0] ^= 0x80;
    let index = u64::try_from(index)
        .map_err(|_| BrokerError::Handler("result message index exceeds u64".into()))?;
    let tail = u64::from_be_bytes(
        response[8..]
            .try_into()
            .map_err(|_| BrokerError::Handler("message id tail".into()))?,
    )
    .checked_add(index)
    .ok_or_else(|| BrokerError::Handler("result message id exhausted".into()))?;
    response[8..].copy_from_slice(&tail.to_be_bytes());
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use tokio::io::duplex;
    use wvb_client::Client;
    use wvb_crypto::{Handshake, PairingPsk, StaticPrivateKey, Transport};

    struct Echo;
    struct EchoCall;

    #[async_trait]
    impl Handler for Echo {
        async fn handle(&self, request: BrokerRequest) -> Result<BrokerResponse, BrokerError> {
            Ok(BrokerResponse {
                message_type: request.envelope.message_type + 1,
                payload: request.payload,
            })
        }
    }

    #[async_trait]
    impl CallHandler for EchoCall {
        async fn handle_call(&self, request: CallRequest) -> Result<CallResult, BrokerError> {
            Ok(CallResult {
                response_schema_id: request.request_schema_id + 1,
                operation_uuid: Some([9; 16]),
                native_status: vec![1],
                body: request.body,
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

    #[tokio::test]
    async fn concurrent_canonical_calls_round_trip_on_independent_streams() {
        let (client_crypto, broker_crypto) = paired_transports();
        let (client_io, broker_io) = duplex(4 << 20);
        let client_connection = SecureConnection::new(client_io, client_crypto, 99);
        let broker_connection = SecureConnection::new(broker_io, broker_crypto, 99);
        let server = tokio::spawn(serve_calls(broker_connection, Arc::new(EchoCall), 8));
        let client = Client::spawn(client_connection, 99, [7; 8], 16);
        let request = |operation_id, body| CallRequest {
            adapter_hash: [3; 32],
            operation_id,
            request_schema_id: 0x3000_0000 | operation_id,
            deduplication_mode: 0,
            idempotency_key: None,
            disconnect_policy: 0,
            sensitivity: 0,
            body,
        };
        let first_request = request(1, vec![1; 70_000]);
        let second_request = request(2, vec![2; 80_000]);
        let first = client.call(&first_request, Duration::from_secs(2));
        let second = client.call(&second_request, Duration::from_secs(2));
        let (first, second) = tokio::try_join!(first, second).unwrap();
        assert_eq!(first.response_schema_id, 0x3000_0002);
        assert_eq!(first.body, vec![1; 70_000]);
        assert_eq!(second.response_schema_id, 0x3000_0003);
        assert_eq!(second.body, vec![2; 80_000]);
        server.abort();
    }
}
