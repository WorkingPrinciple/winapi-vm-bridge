//! Encrypted persistent framed transport over an asynchronous byte stream.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use wvb_crypto::{
    CryptoError, Handshake, NOISE_MESSAGE_MAX, PairingPsk, StaticPrivateKey, Transport,
};
use wvb_protocol::{ENVELOPE_BYTES, Envelope, ProtocolError, Reassembler, fragment_logical_frame};

#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    Crypto(CryptoError),
    Protocol(ProtocolError),
    Closed,
    PayloadLength,
    Bootstrap,
}

const PREFACE_MAGIC: [u8; 4] = *b"WVBN";
const PREFACE_MAJOR: u8 = 2;
const PREFACE_MINOR: u8 = 0;
const PREFACE_BYTES: usize = 12;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapMode {
    Pair = 1,
    Session = 2,
}

impl TryFrom<u8> for BootstrapMode {
    type Error = TransportError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Pair),
            2 => Ok(Self::Session),
            _ => Err(TransportError::Bootstrap),
        }
    }
}

pub async fn pairing_initiator<S>(
    mut io: S,
    local_private: &StaticPrivateKey,
    psk: &PairingPsk,
) -> Result<([u8; 32], SecureConnection<S>), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_preface(&mut io, BootstrapMode::Pair).await?;
    let mut handshake = Handshake::pairing_initiator(local_private, psk)?;
    write_handshake(&mut io, &mut handshake).await?;
    read_handshake(&mut io, &mut handshake).await?;
    write_handshake(&mut io, &mut handshake).await?;
    let remote = handshake.remote_static()?;
    Ok((
        remote,
        SecureConnection::new(io, handshake.into_transport()?, 0),
    ))
}

pub async fn pairing_responder<S>(
    mut io: S,
    local_private: &StaticPrivateKey,
    psk: &PairingPsk,
) -> Result<([u8; 32], SecureConnection<S>), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    expect_preface(&mut io, BootstrapMode::Pair).await?;
    let mut handshake = Handshake::pairing_responder(local_private, psk)?;
    read_handshake(&mut io, &mut handshake).await?;
    write_handshake(&mut io, &mut handshake).await?;
    read_handshake(&mut io, &mut handshake).await?;
    let remote = handshake.remote_static()?;
    Ok((
        remote,
        SecureConnection::new(io, handshake.into_transport()?, 0),
    ))
}

pub async fn session_initiator<S>(
    mut io: S,
    local_private: &StaticPrivateKey,
    remote_public: &[u8; 32],
) -> Result<SecureConnection<S>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_preface(&mut io, BootstrapMode::Session).await?;
    let mut handshake = Handshake::session_initiator(local_private, remote_public)?;
    write_handshake(&mut io, &mut handshake).await?;
    read_handshake(&mut io, &mut handshake).await?;
    if handshake.remote_static()? != *remote_public {
        return Err(TransportError::Bootstrap);
    }
    Ok(SecureConnection::new(io, handshake.into_transport()?, 0))
}

pub async fn session_responder<S>(
    mut io: S,
    local_private: &StaticPrivateKey,
) -> Result<([u8; 32], SecureConnection<S>), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    expect_preface(&mut io, BootstrapMode::Session).await?;
    let mut handshake = Handshake::session_responder(local_private)?;
    read_handshake(&mut io, &mut handshake).await?;
    write_handshake(&mut io, &mut handshake).await?;
    let remote = handshake.remote_static()?;
    Ok((
        remote,
        SecureConnection::new(io, handshake.into_transport()?, 0),
    ))
}

async fn write_preface<S>(io: &mut S, mode: BootstrapMode) -> Result<(), TransportError>
where
    S: AsyncWrite + Unpin,
{
    let mut preface = [0_u8; PREFACE_BYTES];
    preface[..4].copy_from_slice(&PREFACE_MAGIC);
    preface[4] = PREFACE_MAJOR;
    preface[5] = PREFACE_MINOR;
    preface[6] = mode as u8;
    io.write_all(&preface).await?;
    io.flush().await?;
    Ok(())
}

async fn expect_preface<S>(io: &mut S, expected: BootstrapMode) -> Result<(), TransportError>
where
    S: AsyncRead + Unpin,
{
    let mut preface = [0_u8; PREFACE_BYTES];
    io.read_exact(&mut preface).await?;
    if preface[..4] != PREFACE_MAGIC
        || preface[4] != PREFACE_MAJOR
        || preface[5] != PREFACE_MINOR
        || BootstrapMode::try_from(preface[6])? != expected
        || preface[7..] != [0; 5]
    {
        return Err(TransportError::Bootstrap);
    }
    Ok(())
}

async fn write_handshake<S>(io: &mut S, handshake: &mut Handshake) -> Result<(), TransportError>
where
    S: AsyncWrite + Unpin,
{
    let mut message = [0_u8; 512];
    let length = handshake.write(&[], &mut message)?;
    let encoded = u16::try_from(length).map_err(|_| TransportError::Bootstrap)?;
    io.write_all(&encoded.to_be_bytes()).await?;
    io.write_all(&message[..length]).await?;
    io.flush().await?;
    Ok(())
}

async fn read_handshake<S>(io: &mut S, handshake: &mut Handshake) -> Result<(), TransportError>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0_u8; 2];
    io.read_exact(&mut length).await?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > NOISE_MESSAGE_MAX {
        return Err(TransportError::Bootstrap);
    }
    let mut message = vec![0_u8; length];
    io.read_exact(&mut message).await?;
    let mut payload = [0_u8; 512];
    let payload_length = handshake.read(&message, &mut payload)?;
    if payload_length != 0 {
        return Err(TransportError::Bootstrap);
    }
    Ok(())
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

    pub fn activate_epoch(&mut self, epoch: u64) -> Result<(), TransportError> {
        if self.connection_epoch != 0 || epoch == 0 {
            return Err(TransportError::Bootstrap);
        }
        self.connection_epoch = epoch;
        Ok(())
    }

    #[must_use]
    pub fn connection_epoch(&self) -> u64 {
        self.connection_epoch
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

    #[tokio::test]
    async fn tcp_bootstrap_runs_pairing_then_pinned_session_handshakes() {
        let (client_key, client_public) = StaticPrivateKey::generate().unwrap();
        let (broker_key, broker_public) = StaticPrivateKey::generate().unwrap();
        let (client_io, broker_io) = duplex(4_096);
        let client_psk = PairingPsk::from_bytes([7; 32]);
        let broker_psk = PairingPsk::from_bytes([7; 32]);
        let client_pair = pairing_initiator(client_io, &client_key, &client_psk);
        let broker_pair = pairing_responder(broker_io, &broker_key, &broker_psk);
        let ((observed_broker, _), (observed_client, _)) =
            tokio::try_join!(client_pair, broker_pair).unwrap();
        assert_eq!(observed_broker, broker_public);
        assert_eq!(observed_client, client_public);

        let (client_io, broker_io) = duplex(4_096);
        let client_session = session_initiator(client_io, &client_key, &broker_public);
        let broker_session = session_responder(broker_io, &broker_key);
        let (_, (observed_client, _)) = tokio::try_join!(client_session, broker_session).unwrap();
        assert_eq!(observed_client, client_public);
    }

    #[tokio::test]
    async fn tcp_bootstrap_rejects_wrong_mode_without_oracle_detail() {
        let (mut client_io, mut broker_io) = duplex(64);
        let writer = tokio::spawn(async move {
            write_preface(&mut client_io, BootstrapMode::Pair)
                .await
                .unwrap();
        });
        assert!(matches!(
            expect_preface(&mut broker_io, BootstrapMode::Session).await,
            Err(TransportError::Bootstrap)
        ));
        writer.await.unwrap();
    }
}
