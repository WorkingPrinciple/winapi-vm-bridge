//! Multiplexed canonical bridge client.

use std::collections::BTreeMap;
use std::sync::{
    Arc,
    atomic::{AtomicU32, AtomicU64, Ordering},
};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use wvb_protocol::{Envelope, EnvelopeFlags};
use wvb_transport::{SecureConnection, TransportError};

#[derive(Debug)]
pub enum ClientError {
    DriverClosed,
    Transport(TransportError),
    Timeout,
    StreamExhausted,
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
    envelope: Envelope,
    payload: Vec<u8>,
    response: oneshot::Sender<Result<Response, ClientError>>,
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
                envelope,
                payload,
                response: sender,
            })
            .await
            .map_err(|_| ClientError::DriverClosed)?;
        tokio::time::timeout(timeout, receiver)
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|_| ClientError::DriverClosed)?
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
    let mut pending = BTreeMap::<[u8; 16], oneshot::Sender<Result<Response, ClientError>>>::new();
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break; };
                let message_id = command.envelope.message_id;
                if connection.send(&command.envelope, &command.payload).await.is_err() {
                    let _ = command.response.send(Err(ClientError::DriverClosed));
                    break;
                }
                pending.insert(message_id, command.response);
            }
            received = connection.receive(), if !pending.is_empty() => {
                match received {
                    Ok((envelope, payload)) => {
                        if let Some(sender) = pending.remove(&envelope.correlation_id) {
                            let _ = sender.send(Ok(Response { envelope, payload }));
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    for (_, sender) in pending {
        let _ = sender.send(Err(ClientError::DriverClosed));
    }
}
