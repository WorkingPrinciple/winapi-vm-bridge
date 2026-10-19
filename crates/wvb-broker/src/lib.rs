//! Concurrent canonical broker session driver.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Semaphore, mpsc};
use wvb_authz::{ActorId, AuthorizationError, Registry};
use wvb_call::{CallAssembler, CallRequest, CallResult};
use wvb_protocol::{Envelope, EnvelopeFlags, MessageType};
use wvb_transfer::{
    ActorId as TransferActorId, TransferCancelAck, TransferLimits, TransferMessage,
    TransferReceipt, TransferReceiptMessage, TransferRegistry,
};
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

pub trait TypedDispatchModule: Send + Sync + 'static {
    fn dispatch(&self, operation_id: u32, request: &[u8]) -> DispatchOutcome;
}

pub trait TransferSink: Send + Sync + 'static {
    fn completed(&self, receipt: &TransferReceipt, path: &Path) -> Result<Vec<u8>, String>;

    fn cancelled(&self, _receipt: &TransferReceipt) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
}

pub struct DispatchOutcome {
    pub status: i32,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy)]
pub struct OperationSchema {
    pub request_schema_id: u32,
    pub response_schema_id: u32,
}

pub struct DispatcherCallHandler {
    adapter_hash: [u8; 32],
    operations: BTreeMap<u32, OperationSchema>,
    dispatcher: Arc<dyn TypedDispatchModule>,
}

impl DispatcherCallHandler {
    #[must_use]
    pub fn new(
        adapter_hash: [u8; 32],
        operations: BTreeMap<u32, OperationSchema>,
        dispatcher: Arc<dyn TypedDispatchModule>,
    ) -> Self {
        Self {
            adapter_hash,
            operations,
            dispatcher,
        }
    }
}

#[async_trait]
impl CallHandler for DispatcherCallHandler {
    async fn handle_call(&self, request: CallRequest) -> Result<CallResult, BrokerError> {
        if request.adapter_hash != self.adapter_hash {
            return Err(BrokerError::Handler("adapter hash mismatch".into()));
        }
        let schema = self.operations.get(&request.operation_id).ok_or_else(|| {
            BrokerError::Handler("operation is not in dispatcher contract".into())
        })?;
        if request.request_schema_id != schema.request_schema_id {
            return Err(BrokerError::Handler("request schema mismatch".into()));
        }
        let outcome = self
            .dispatcher
            .dispatch(request.operation_id, &request.body);
        Ok(CallResult {
            response_schema_id: schema.response_schema_id,
            operation_uuid: None,
            native_status: outcome.status.to_le_bytes().to_vec(),
            body: outcome.body,
        })
    }
}

pub fn actor_for_session_key(
    registry: &RwLock<Registry>,
    remote_public_key: &[u8; 32],
) -> Result<ActorId, BrokerError> {
    registry
        .read()
        .map_err(|_| BrokerError::Handler("authorization registry poisoned".into()))?
        .actor_for_key(remote_public_key)
        .map_err(authorization_error)
}

pub struct AuthorizedCallHandler {
    actor_id: ActorId,
    registry: Arc<RwLock<Registry>>,
    inner: Arc<dyn CallHandler>,
}

impl AuthorizedCallHandler {
    #[must_use]
    pub fn new(
        actor_id: ActorId,
        registry: Arc<RwLock<Registry>>,
        inner: Arc<dyn CallHandler>,
    ) -> Self {
        Self {
            actor_id,
            registry,
            inner,
        }
    }
}

#[async_trait]
impl CallHandler for AuthorizedCallHandler {
    async fn handle_call(&self, request: CallRequest) -> Result<CallResult, BrokerError> {
        let now = unix_time_ms();
        self.registry
            .read()
            .map_err(|_| BrokerError::Handler("authorization registry poisoned".into()))?
            .authorize_invoke(
                self.actor_id,
                request.adapter_hash,
                request.operation_id,
                now,
            )
            .map_err(authorization_error)?;
        self.inner.handle_call(request).await
    }
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

pub async fn serve_transfers<S>(
    mut connection: SecureConnection<S>,
    actor_id: TransferActorId,
    limits: TransferLimits,
    sink: Arc<dyn TransferSink>,
) -> Result<(), BrokerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut registry = TransferRegistry::new(limits);
    let mut streams = BTreeMap::<u32, ([u8; 16], u32)>::new();
    loop {
        let (envelope, payload) = connection.receive().await?;
        if !envelope.flags.contains(EnvelopeFlags::REQUEST)
            || envelope.stream_id == 0
            || envelope.stream_id.is_multiple_of(2)
        {
            return Err(BrokerError::Handler(
                "invalid transfer stream envelope".into(),
            ));
        }
        let message_type = MessageType::try_from(envelope.message_type)
            .map_err(|_| BrokerError::Handler("unknown transfer message".into()))?;
        let message = TransferMessage::decode(message_type, &payload)
            .map_err(|error| BrokerError::Handler(format!("invalid transfer: {error}")))?;
        let response = match message {
            TransferMessage::Begin(begin) => {
                if envelope.stream_sequence != 0 {
                    return Err(BrokerError::Handler("transfer sequence mismatch".into()));
                }
                if streams
                    .insert(envelope.stream_id, (begin.transfer_id, 1))
                    .is_some()
                {
                    return Err(BrokerError::Handler("duplicate transfer stream".into()));
                }
                registry
                    .begin(actor_id, begin)
                    .map_err(|error| BrokerError::Handler(format!("transfer begin: {error}")))?;
                None
            }
            TransferMessage::Data(data) => {
                let (transfer_id, next_sequence) = streams
                    .get_mut(&envelope.stream_id)
                    .ok_or_else(|| BrokerError::Handler("unknown transfer stream".into()))?;
                if *transfer_id != data.transfer_id || envelope.stream_sequence != *next_sequence {
                    return Err(BrokerError::Handler("transfer stream mismatch".into()));
                }
                *next_sequence = next_sequence
                    .checked_add(1)
                    .ok_or_else(|| BrokerError::Handler("transfer sequence exhausted".into()))?;
                registry
                    .data(actor_id, &data)
                    .map_err(|error| BrokerError::Handler(format!("transfer data: {error}")))?;
                None
            }
            TransferMessage::End(end) => {
                verify_transfer_terminal(&mut streams, &envelope, end.transfer_id)?;
                let completed = registry
                    .finish(actor_id, &end)
                    .map_err(|error| BrokerError::Handler(format!("transfer end: {error}")))?;
                let receipt_bytes = sink
                    .completed(&completed.receipt, completed.path())
                    .map_err(BrokerError::Handler)?;
                Some(TransferMessage::Receipt(TransferReceiptMessage {
                    transfer_id: completed.receipt.transfer_id,
                    receipt: receipt_bytes,
                }))
            }
            TransferMessage::Cancel(cancel) => {
                verify_transfer_terminal(&mut streams, &envelope, cancel.transfer_id)?;
                let receipt = registry
                    .cancel(actor_id, cancel)
                    .map_err(|error| BrokerError::Handler(format!("transfer cancel: {error}")))?;
                Some(TransferMessage::CancelAck(TransferCancelAck {
                    transfer_id: receipt.transfer_id,
                    disposition: 1,
                    receipt: sink.cancelled(&receipt).map_err(BrokerError::Handler)?,
                }))
            }
            TransferMessage::CancelAck(_) | TransferMessage::Receipt(_) => {
                return Err(BrokerError::Handler(
                    "client transfer response is invalid".into(),
                ));
            }
        };
        if let Some(response) = response {
            send_transfer_response(&mut connection, &envelope, response).await?;
        } else if envelope.flags.contains(EnvelopeFlags::END_STREAM) {
            return Err(BrokerError::Handler(
                "transfer stream ended before terminal message".into(),
            ));
        }
    }
}

fn verify_transfer_terminal(
    streams: &mut BTreeMap<u32, ([u8; 16], u32)>,
    envelope: &Envelope,
    transfer_id: [u8; 16],
) -> Result<(), BrokerError> {
    let (expected_id, expected_sequence) = streams
        .remove(&envelope.stream_id)
        .ok_or_else(|| BrokerError::Handler("unknown transfer stream".into()))?;
    if expected_id != transfer_id
        || envelope.stream_sequence != expected_sequence
        || !envelope.flags.contains(EnvelopeFlags::END_STREAM)
    {
        return Err(BrokerError::Handler(
            "invalid transfer terminal frame".into(),
        ));
    }
    Ok(())
}

async fn send_transfer_response<S>(
    connection: &mut SecureConnection<S>,
    request: &Envelope,
    response: TransferMessage,
) -> Result<(), BrokerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (message_type, payload) = response
        .encode()
        .map_err(|error| BrokerError::Handler(format!("transfer receipt: {error}")))?;
    let payload_length = u32::try_from(payload.len())
        .map_err(|_| BrokerError::Handler("transfer receipt too large".into()))?;
    let envelope = Envelope {
        minor: request.minor,
        message_type: message_type as u16,
        flags: EnvelopeFlags::RESPONSE | EnvelopeFlags::END_STREAM,
        connection_epoch: request.connection_epoch,
        stream_id: request.stream_id,
        stream_sequence: 0,
        message_id: response_message_id(request.message_id),
        correlation_id: request.message_id,
        remaining_budget_ms: request.remaining_budget_ms,
        payload_length,
    };
    connection.send(&envelope, &payload).await?;
    Ok(())
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

fn authorization_error(error: AuthorizationError) -> BrokerError {
    BrokerError::Handler(format!("authorization denied: {error:?}"))
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
    use sha2::Digest;
    use std::sync::Mutex;
    use std::time::Duration;

    use tokio::io::duplex;
    use wvb_authz::{Grant, Role};
    use wvb_client::Client;
    use wvb_crypto::{Handshake, PairingPsk, StaticPrivateKey, Transport};
    use wvb_exe::{Limits, ProcessRequest, ProcessResult};
    use wvb_transfer::{
        TransferBegin, TransferData, TransferEnd, TransferKind, TransferMessage,
        TransferReceiptMessage,
    };

    struct Echo;
    struct EchoCall;
    struct ScalarAdd;
    struct ProcessFixture {
        limits: Limits,
    }
    #[derive(Default)]
    struct CaptureTransfer(Mutex<Vec<u8>>);

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

    impl TypedDispatchModule for ScalarAdd {
        fn dispatch(&self, operation_id: u32, request: &[u8]) -> DispatchOutcome {
            if operation_id != 1 || request.len() != 8 {
                return DispatchOutcome {
                    status: 1,
                    body: Vec::new(),
                };
            }
            let left = i32::from_le_bytes(request[..4].try_into().unwrap());
            let right = i32::from_le_bytes(request[4..].try_into().unwrap());
            match left.checked_add(right) {
                Some(result) => DispatchOutcome {
                    status: 0,
                    body: result.to_le_bytes().to_vec(),
                },
                None => DispatchOutcome {
                    status: 3,
                    body: Vec::new(),
                },
            }
        }
    }

    impl TransferSink for CaptureTransfer {
        fn completed(&self, _receipt: &TransferReceipt, path: &Path) -> Result<Vec<u8>, String> {
            *self
                .0
                .lock()
                .map_err(|_| String::from("capture poisoned"))? =
                std::fs::read(path).map_err(|error| error.to_string())?;
            Ok(b"runtime-receipt".to_vec())
        }
    }

    impl TypedDispatchModule for ProcessFixture {
        fn dispatch(&self, operation_id: u32, request: &[u8]) -> DispatchOutcome {
            let Ok(request) = ProcessRequest::decode(request, &self.limits) else {
                return DispatchOutcome {
                    status: 1,
                    body: Vec::new(),
                };
            };
            if operation_id != 1 || request.arguments != ["alpha", "two words"] {
                return DispatchOutcome {
                    status: 1,
                    body: Vec::new(),
                };
            }

            let result = ProcessResult {
                exit_code: 17,
                timed_out: false,
                cancelled: false,
                stdout: b"fixture-stdout".to_vec(),
                stderr: b"fixture-stderr".to_vec(),
            };
            DispatchOutcome {
                status: 0,
                body: result.encode(&self.limits).unwrap(),
            }
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

    #[tokio::test]
    async fn typed_dispatcher_runs_scalar_call_through_canonical_runtime() {
        let (client_crypto, broker_crypto) = paired_transports();
        let (client_io, broker_io) = duplex(1 << 20);
        let client_connection = SecureConnection::new(client_io, client_crypto, 99);
        let broker_connection = SecureConnection::new(broker_io, broker_crypto, 99);
        let handler = DispatcherCallHandler::new(
            [3; 32],
            BTreeMap::from([(
                1,
                OperationSchema {
                    request_schema_id: 0x3000_0001,
                    response_schema_id: 0x3000_0002,
                },
            )]),
            Arc::new(ScalarAdd),
        );
        let server = tokio::spawn(serve_calls(broker_connection, Arc::new(handler), 4));
        let client = Client::spawn(client_connection, 99, [7; 8], 8);
        let mut body = Vec::new();
        body.extend_from_slice(&20_i32.to_le_bytes());
        body.extend_from_slice(&22_i32.to_le_bytes());
        let result = client
            .call(
                &CallRequest {
                    adapter_hash: [3; 32],
                    operation_id: 1,
                    request_schema_id: 0x3000_0001,
                    deduplication_mode: 0,
                    idempotency_key: None,
                    disconnect_policy: 0,
                    sensitivity: 0,
                    body,
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(result.response_schema_id, 0x3000_0002);
        assert_eq!(result.native_status, 0_i32.to_le_bytes());
        assert_eq!(i32::from_le_bytes(result.body.try_into().unwrap()), 42);
        server.abort();
    }

    #[tokio::test]
    async fn native_exe_contract_runs_through_canonical_runtime() {
        let limits = Limits {
            max_arguments: 8,
            max_argument_bytes: 128,
            max_stdin_bytes: 1024,
            max_stdout_bytes: 1024,
            max_stderr_bytes: 1024,
            environment_allowlist: std::collections::BTreeSet::from([String::from("WVB_MODE")]),
        };
        let request_body = ProcessRequest {
            invocation_id: [0x33; 16],
            arguments: vec![String::from("alpha"), String::from("two words")],
            environment: BTreeMap::from([(String::from("WVB_MODE"), String::from("oracle"))]),
            stdin: b"fixture-input".to_vec(),
        }
        .encode(&limits)
        .unwrap();
        let (client_crypto, broker_crypto) = paired_transports();
        let (client_io, broker_io) = duplex(1 << 20);
        let client_connection = SecureConnection::new(client_io, client_crypto, 99);
        let broker_connection = SecureConnection::new(broker_io, broker_crypto, 99);
        let handler = DispatcherCallHandler::new(
            [4; 32],
            BTreeMap::from([(
                1,
                OperationSchema {
                    request_schema_id: 0x3000_0101,
                    response_schema_id: 0x3000_0102,
                },
            )]),
            Arc::new(ProcessFixture {
                limits: limits.clone(),
            }),
        );
        let server = tokio::spawn(serve_calls(broker_connection, Arc::new(handler), 1));
        let client = Client::spawn(client_connection, 99, [7; 8], 8);
        let result = client
            .call(
                &CallRequest {
                    adapter_hash: [4; 32],
                    operation_id: 1,
                    request_schema_id: 0x3000_0101,
                    deduplication_mode: 0,
                    idempotency_key: None,
                    disconnect_policy: 0,
                    sensitivity: 0,
                    body: request_body,
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        let process = ProcessResult::decode(&result.body, &limits).unwrap();
        assert_eq!(process.exit_code, 17);
        assert_eq!(process.stdout, b"fixture-stdout");
        assert_eq!(process.stderr, b"fixture-stderr");
        server.abort();
    }

    #[tokio::test]
    async fn compound_transfer_runs_through_canonical_broker() {
        let (client_crypto, broker_crypto) = paired_transports();
        let (client_io, broker_io) = duplex(1 << 20);
        let mut client_connection = SecureConnection::new(client_io, client_crypto, 99);
        let broker_connection = SecureConnection::new(broker_io, broker_crypto, 99);
        let actor = [5; 16];
        let transfer_id = [6; 16];
        let body = b"content-addressed-transfer".to_vec();
        let sink = Arc::new(CaptureTransfer::default());
        let server_sink = sink.clone();
        let server = tokio::spawn(serve_transfers(
            broker_connection,
            actor,
            TransferLimits {
                maximum_bytes: 1024,
                maximum_chunk_bytes: 1024,
                maximum_active: 2,
                maximum_metadata_bytes: 256,
                maximum_receipt_bytes: 4096,
            },
            server_sink,
        ));
        let messages = [
            TransferMessage::Begin(TransferBegin {
                transfer_id,
                kind: TransferKind::CallInput,
                parent_message_id: None,
                parent_operation_id: None,
                declared_length: body.len(),
                content_hash: sha2::Sha256::digest(&body).into(),
                media_type: None,
                file_name: None,
                sensitivity: 1,
            }),
            TransferMessage::Data(TransferData {
                transfer_id,
                chunk_index: 0,
                offset: 0,
                chunk_hash: sha2::Sha256::digest(&body).into(),
                bytes: body.clone(),
            }),
            TransferMessage::End(TransferEnd {
                transfer_id,
                chunk_count: 1,
                total_length: body.len(),
                total_hash: sha2::Sha256::digest(&body).into(),
                terminal_status: 1,
                receipt: b"sender-receipt".to_vec(),
            }),
        ];
        for (index, message) in messages.into_iter().enumerate() {
            let (message_type, payload) = message.encode().unwrap();
            let terminal = index == 2;
            let envelope = Envelope {
                minor: 0,
                message_type: message_type as u16,
                flags: if terminal {
                    EnvelopeFlags::REQUEST | EnvelopeFlags::END_STREAM
                } else {
                    EnvelopeFlags::REQUEST
                },
                connection_epoch: 99,
                stream_id: 1,
                stream_sequence: u32::try_from(index).unwrap(),
                message_id: [u8::try_from(index + 1).unwrap(); 16],
                correlation_id: [0; 16],
                remaining_budget_ms: 1_000,
                payload_length: u32::try_from(payload.len()).unwrap(),
            };
            client_connection.send(&envelope, &payload).await.unwrap();
        }
        let (envelope, payload) = client_connection.receive().await.unwrap();
        assert_eq!(envelope.message_type, MessageType::TransferReceipt as u16);
        let TransferMessage::Receipt(TransferReceiptMessage {
            transfer_id: receipt_transfer_id,
            receipt,
        }) = TransferMessage::decode(MessageType::TransferReceipt, &payload).unwrap()
        else {
            panic!("expected receipt");
        };
        assert_eq!(receipt_transfer_id, transfer_id);
        assert_eq!(receipt, b"runtime-receipt");
        assert_eq!(*sink.0.lock().unwrap(), body);
        server.abort();
    }

    #[tokio::test]
    async fn authenticated_actor_is_still_default_denied_without_exact_grant() {
        let actor = [1; 16];
        let key = [2; 32];
        let adapter = [3; 32];
        let mut registry = Registry::default();
        registry.register(actor, key).unwrap();
        assert_eq!(
            actor_for_session_key(&RwLock::new(registry), &key).unwrap(),
            actor
        );

        let mut registry = Registry::default();
        registry.register(actor, key).unwrap();
        let registry = Arc::new(RwLock::new(registry));
        let authorized = AuthorizedCallHandler::new(actor, registry.clone(), Arc::new(EchoCall));
        let request = CallRequest {
            adapter_hash: adapter,
            operation_id: 7,
            request_schema_id: 1,
            deduplication_mode: 0,
            idempotency_key: None,
            disconnect_policy: 0,
            sensitivity: 0,
            body: vec![1],
        };
        assert!(authorized.handle_call(request.clone()).await.is_err());
        registry
            .write()
            .unwrap()
            .grant(
                actor,
                Grant {
                    role: Role::Invoke,
                    adapter_hash: Some(adapter),
                    operation_id: Some(7),
                    expires_at_unix_ms: None,
                },
            )
            .unwrap();
        assert_eq!(authorized.handle_call(request).await.unwrap().body, vec![1]);
    }
}
