//! Multiplexed canonical bridge client.

use std::collections::BTreeMap;
use std::sync::{
    Arc,
    atomic::{AtomicU32, AtomicU64, Ordering},
};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use wvb_call::{CallRequest, CallResult, ResultAssembler};
use wvb_protocol::{Envelope, EnvelopeFlags, MessageType};
use wvb_transport::{SecureConnection, TransportError};

#[derive(Debug)]
pub enum ClientError {
    DriverClosed,
    Transport(TransportError),
    Timeout,
    StreamExhausted,
    Protocol,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ClientError {}

impl From<TransportError> for ClientError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

#[derive(Debug)]
pub struct Response {
    pub envelope: Envelope,
    pub payload: Vec<u8>,
}

struct Command {
    frames: Vec<(Envelope, Vec<u8>)>,
    completion: CompletionKind,
    response: oneshot::Sender<Result<Completion, ClientError>>,
}

enum CompletionKind {
    Single([u8; 16]),
    Call(u32),
}

enum Completion {
    Single(Response),
    Call(CallResult),
}

struct PendingCall {
    assembler: ResultAssembler,
    response: oneshot::Sender<Result<Completion, ClientError>>,
}

#[derive(Clone)]
pub struct Client {
    commands: mpsc::Sender<Command>,
    connection_epoch: u64,
    nonce: [u8; 8],
    message_counter: Arc<AtomicU64>,
    stream_counter: Arc<AtomicU32>,
}

impl Client {
    pub fn spawn<S>(
        connection: SecureConnection<S>,
        connection_epoch: u64,
        nonce: [u8; 8],
        queue_capacity: usize,
    ) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (commands, receiver) = mpsc::channel(queue_capacity);
        tokio::spawn(driver(connection, receiver));
        Self {
            commands,
            connection_epoch,
            nonce,
            message_counter: Arc::new(AtomicU64::new(1)),
            stream_counter: Arc::new(AtomicU32::new(1)),
        }
    }

    pub async fn request(
        &self,
        message_type: u16,
        payload: Vec<u8>,
        timeout: Duration,
    ) -> Result<Response, ClientError> {
        let stream_id = self.stream_counter.fetch_add(2, Ordering::Relaxed);
        if stream_id == 0 || stream_id.is_multiple_of(2) {
            return Err(ClientError::StreamExhausted);
        }
        let message_id = self.next_message_id();
        let payload_length =
            u32::try_from(payload.len()).map_err(|_| ClientError::StreamExhausted)?;
        let remaining_budget_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let envelope = Envelope {
            minor: 0,
            message_type,
            flags: EnvelopeFlags::REQUEST | EnvelopeFlags::END_STREAM,
            connection_epoch: self.connection_epoch,
            stream_id,
            stream_sequence: 0,
            message_id,
            correlation_id: [0; 16],
            remaining_budget_ms,
            payload_length,
        };
        let (sender, receiver) = oneshot::channel();
        self.commands
            .send(Command {
                frames: vec![(envelope, payload)],
                completion: CompletionKind::Single(message_id),
                response: sender,
            })
            .await
            .map_err(|_| ClientError::DriverClosed)?;
        tokio::time::timeout(timeout, receiver)
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|_| ClientError::DriverClosed)?
            .and_then(|completion| match completion {
                Completion::Single(response) => Ok(response),
                Completion::Call(_) => Err(ClientError::Protocol),
            })
    }

    pub async fn call(
        &self,
        request: &CallRequest,
        timeout: Duration,
    ) -> Result<CallResult, ClientError> {
        let stream_id = self.stream_counter.fetch_add(2, Ordering::Relaxed);
        if stream_id == 0 || stream_id.is_multiple_of(2) {
            return Err(ClientError::StreamExhausted);
        }
        let messages = request.messages().map_err(|_| ClientError::Protocol)?;
        let message_count =
            u32::try_from(messages.len()).map_err(|_| ClientError::StreamExhausted)?;
        let remaining_budget_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let frames = messages
            .into_iter()
            .enumerate()
            .map(|(index, message)| {
                let payload_length = u32::try_from(message.payload.len())
                    .map_err(|_| ClientError::StreamExhausted)?;
                let mut flags = EnvelopeFlags::REQUEST;
                if u32::try_from(index + 1).ok() == Some(message_count) {
                    flags = flags | EnvelopeFlags::END_STREAM;
                }
                Ok((
                    Envelope {
                        minor: 0,
                        message_type: message.message_type as u16,
                        flags,
                        connection_epoch: self.connection_epoch,
                        stream_id,
                        stream_sequence: u32::try_from(index)
                            .map_err(|_| ClientError::StreamExhausted)?,
                        message_id: self.next_message_id(),
                        correlation_id: [0; 16],
                        remaining_budget_ms,
                        payload_length,
                    },
                    message.payload,
                ))
            })
            .collect::<Result<Vec<_>, ClientError>>()?;
        let (sender, receiver) = oneshot::channel();
        tokio::time::timeout(timeout, async {
            self.commands
                .send(Command {
                    frames,
                    completion: CompletionKind::Call(stream_id),
                    response: sender,
                })
                .await
                .map_err(|_| ClientError::DriverClosed)?;
            receiver.await.map_err(|_| ClientError::DriverClosed)?
        })
        .await
        .map_err(|_| ClientError::Timeout)?
        .and_then(|completion| match completion {
            Completion::Call(result) => Ok(result),
            Completion::Single(_) => Err(ClientError::Protocol),
        })
    }

    fn next_message_id(&self) -> [u8; 16] {
        let mut value = [0_u8; 16];
        value[..8].copy_from_slice(&self.nonce);
        value[8..].copy_from_slice(
            &self
                .message_counter
                .fetch_add(1, Ordering::Relaxed)
                .to_be_bytes(),
        );
        value
    }
}

async fn driver<S>(mut connection: SecureConnection<S>, mut commands: mpsc::Receiver<Command>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut pending_single =
        BTreeMap::<[u8; 16], oneshot::Sender<Result<Completion, ClientError>>>::new();
    let mut pending_calls = BTreeMap::<u32, PendingCall>::new();
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break; };
                let mut failed = false;
                for (envelope, payload) in command.frames {
                    if connection.send(&envelope, &payload).await.is_err() {
                        failed = true;
                        break;
                    }
                }
                if failed {
                    let _ = command.response.send(Err(ClientError::DriverClosed));
                    break;
                }
                match command.completion {
                    CompletionKind::Single(message_id) => {
                        pending_single.insert(message_id, command.response);
                    }
                    CompletionKind::Call(stream_id) => {
                        pending_calls.insert(stream_id, PendingCall {
                            assembler: ResultAssembler::default(),
                            response: command.response,
                        });
                    }
                }
            }
            received = connection.receive(), if !pending_single.is_empty() || !pending_calls.is_empty() => {
                match received {
                    Ok((envelope, payload)) => {
                        if let Some(sender) = pending_single.remove(&envelope.correlation_id) {
                            let _ = sender.send(Ok(Completion::Single(Response { envelope, payload })));
                        } else if let Some(pending) = pending_calls.get_mut(&envelope.stream_id) {
                            let result = MessageType::try_from(envelope.message_type)
                                .map_err(|_| ClientError::Protocol)
                                .and_then(|message_type| pending.assembler
                                    .push(message_type, &payload)
                                    .map_err(|_| ClientError::Protocol));
                            match result {
                                Ok(Some(result)) => {
                                    if let Some(pending) = pending_calls.remove(&envelope.stream_id) {
                                        let _ = pending.response.send(Ok(Completion::Call(result)));
                                    }
                                }
                                Ok(None) => {}
                                Err(error) => {
                                    if let Some(pending) = pending_calls.remove(&envelope.stream_id) {
                                        let _ = pending.response.send(Err(error));
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    for (_, sender) in pending_single {
        let _ = sender.send(Err(ClientError::DriverClosed));
    }
    for (_, pending) in pending_calls {
        let _ = pending.response.send(Err(ClientError::DriverClosed));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn call_deadline_includes_wait_for_full_command_queue() {
        let (commands, _receiver) = mpsc::channel(1);
        let (response, _response_receiver) = oneshot::channel();
        commands
            .send(Command {
                frames: Vec::new(),
                completion: CompletionKind::Call(1),
                response,
            })
            .await
            .unwrap();
        let client = Client {
            commands,
            connection_epoch: 42,
            nonce: [1; 8],
            message_counter: Arc::new(AtomicU64::new(1)),
            stream_counter: Arc::new(AtomicU32::new(1)),
        };
        let request = CallRequest {
            adapter_hash: [2; 32],
            operation_id: 1,
            request_schema_id: 1,
            deduplication_mode: 0,
            idempotency_key: None,
            disconnect_policy: 0,
            sensitivity: 0,
            body: vec![42],
        };
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            client.call(&request, Duration::from_millis(20)),
        )
        .await
        .expect("configured call deadline must expire while the queue stays full");
        assert!(matches!(result, Err(ClientError::Timeout)), "{result:?}");
    }
}
