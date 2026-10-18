//! Encrypted persistent framed transport over an asynchronous byte stream.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use wvb_crypto::{CryptoError, NOISE_MESSAGE_MAX, Transport};
use wvb_protocol::{ENVELOPE_BYTES, Envelope, ProtocolError, Reassembler, fragment_logical_frame};

#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    Crypto(CryptoError),
    Protocol(ProtocolError),
    Closed,
    PayloadLength,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<CryptoError> for TransportError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<ProtocolError> for TransportError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

pub struct SecureConnection<S> {
    io: S,
    crypto: Transport,
    connection_epoch: u64,
    next_physical_sequence: u64,
    next_logical_frame_id: u64,
    reassembler: Reassembler,
}

impl<S> SecureConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[must_use]
    pub fn new(io: S, crypto: Transport, connection_epoch: u64) -> Self {
        Self {
            io,
            crypto,
            connection_epoch,
            next_physical_sequence: 0,
            next_logical_frame_id: 1,
            reassembler: Reassembler::new(0),
        }
    }

    pub async fn send(
        &mut self,
        envelope: &Envelope,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        if usize::try_from(envelope.payload_length).map_err(|_| TransportError::PayloadLength)?
            != payload.len()
            || envelope.connection_epoch != self.connection_epoch
        {
            return Err(TransportError::PayloadLength);
        }
        let mut logical = Vec::with_capacity(ENVELOPE_BYTES + payload.len());
        logical.extend_from_slice(&envelope.encode()?);
        logical.extend_from_slice(payload);
        let fragments = fragment_logical_frame(
            &logical,
            self.connection_epoch,
            self.next_physical_sequence,
            self.next_logical_frame_id,
        )?;
        for plaintext in fragments {
            let mut ciphertext = vec![0_u8; plaintext.len() + 16];
            let length = self.crypto.encrypt(&plaintext, &mut ciphertext)?;
            let length_u16 = u16::try_from(length).map_err(|_| TransportError::PayloadLength)?;
            self.io.write_all(&length_u16.to_be_bytes()).await?;
            self.io.write_all(&ciphertext[..length]).await?;
            self.next_physical_sequence = self
                .next_physical_sequence
                .checked_add(1)
                .ok_or(ProtocolError::SequenceExhausted)?;
        }
        self.io.flush().await?;
        self.next_logical_frame_id = self
            .next_logical_frame_id
            .checked_add(1)
            .ok_or(ProtocolError::SequenceExhausted)?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<(Envelope, Vec<u8>), TransportError> {
        loop {
            let mut length_bytes = [0_u8; 2];
            self.io.read_exact(&mut length_bytes).await?;
            let length = usize::from(u16::from_be_bytes(length_bytes));
            if length == 0 || length > NOISE_MESSAGE_MAX {
                return Err(TransportError::Protocol(
                    ProtocolError::PhysicalLengthInvalid,
                ));
            }
            let mut ciphertext = vec![0_u8; length];
            self.io.read_exact(&mut ciphertext).await?;
            let mut plaintext = vec![0_u8; length];
            let plaintext_length = self.crypto.decrypt(&ciphertext, &mut plaintext)?;
            if let Some(logical) = self
                .reassembler
                .push(&plaintext[..plaintext_length], self.connection_epoch)?
            {
                if logical.len() < ENVELOPE_BYTES {
                    return Err(TransportError::Protocol(ProtocolError::EnvelopeInvalid));
                }
                let envelope = Envelope::decode(&logical[..ENVELOPE_BYTES])?;
                let payload = logical[ENVELOPE_BYTES..].to_vec();
                if usize::try_from(envelope.payload_length)
                    .map_err(|_| TransportError::PayloadLength)?
                    != payload.len()
                {
                    return Err(TransportError::PayloadLength);
                }
                return Ok((envelope, payload));
            }
        }
    }

    pub async fn close(mut self) -> Result<(), TransportError> {
        self.io.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use wvb_crypto::{Handshake, PairingPsk, StaticPrivateKey};
    use wvb_protocol::EnvelopeFlags;

    fn paired_transports() -> (Transport, Transport) {
        let (client_key, _) = StaticPrivateKey::generate().unwrap();
        let (broker_key, _) = StaticPrivateKey::generate().unwrap();
        let mut client =
            Handshake::pairing_initiator(&client_key, &PairingPsk::from_bytes([9; 32])).unwrap();
        let mut broker =
            Handshake::pairing_responder(&broker_key, &PairingPsk::from_bytes([9; 32])).unwrap();
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
    async fn encrypted_logical_round_trip() {
        let (client_crypto, broker_crypto) = paired_transports();
        let (client_io, broker_io) = duplex(2 * 1024 * 1024);
        let mut client = SecureConnection::new(client_io, client_crypto, 77);
        let mut broker = SecureConnection::new(broker_io, broker_crypto, 77);
        let payload = vec![0xa5; 1_048_576];
        let envelope = Envelope {
            minor: 0,
            message_type: 0x0101,
            flags: EnvelopeFlags::REQUEST,
            connection_epoch: 77,
            stream_id: 1,
            stream_sequence: 0,
            message_id: [1; 16],
            correlation_id: [0; 16],
            remaining_budget_ms: 15_000,
            payload_length: u32::try_from(payload.len()).unwrap(),
        };
        let send_envelope = envelope.clone();
        let sender = tokio::spawn(async move {
            client.send(&send_envelope, &payload).await.unwrap();
            payload
        });
        let (received_envelope, received_payload) = broker.receive().await.unwrap();
        let original = sender.await.unwrap();
        assert_eq!(received_envelope, envelope);
        assert_eq!(received_payload, original);
    }
}
