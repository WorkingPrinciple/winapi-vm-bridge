//! Canonical `HELLO/HELLO_ACK` negotiation and epoch activation.

use wvb_protocol::{
    Envelope, EnvelopeFlags, MessageType, PackedDecoder, PackedEncoder, ProtocolError, WireType,
    top_level_schema_id,
};
use wvb_transport::{SecureConnection, TransportError};

const REQUIRED: u8 = 0x01;
const PLATFORM_SCHEMA: u32 = 0x1002;
const READINESS_SCHEMA: u32 = 0x1004;
pub const READINESS_READY: u16 = 1;

#[derive(Debug)]
pub enum SessionError {
    Transport(TransportError),
    Protocol(ProtocolError),
    Invalid(&'static str),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SessionError {}

impl From<TransportError> for SessionError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<ProtocolError> for SessionError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub os: u16,
    pub os_version: String,
    pub architecture: u16,
    pub wine_version: Option<String>,
    pub runtime_version: Option<String>,
    pub build_fingerprint: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub peer_kind: u16,
    pub min_minor: u16,
    pub max_minor: u16,
    pub features: u64,
    pub max_logical_payload: u32,
    pub max_streams: u32,
    pub initial_connection_credit: u64,
    pub client_instance: [u8; 16],
    pub platform: Platform,
    pub client_wall_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    pub overall_status: u16,
    pub generated_at_unix_ms: u64,
    pub source_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAck {
    pub selected_minor: u16,
    pub features: u64,
    pub max_logical_payload: u32,
    pub max_streams: u32,
    pub initial_connection_credit: u64,
    pub connection_epoch: u64,
    pub broker_epoch: [u8; 16],
    pub actor_id: [u8; 16],
    pub readiness: Readiness,
    pub broker_wall_unix_ms: u64,
}

pub async fn activate_client<S>(
    mut connection: SecureConnection<S>,
    hello: &Hello,
    message_id: [u8; 16],
) -> Result<(HelloAck, SecureConnection<S>), SessionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if connection.connection_epoch() != 0 {
        return Err(SessionError::Invalid("client session already active"));
    }
    let payload = encode_hello(hello)?;
    let envelope = control_envelope(
        MessageType::Hello,
        EnvelopeFlags::REQUEST | EnvelopeFlags::END_STREAM,
        message_id,
        [0; 16],
        payload.len(),
    )?;
    connection.send(&envelope, &payload).await?;
    let (response, payload) = connection.receive().await?;
    if response.message_type != MessageType::HelloAck as u16
        || !response.flags.contains(EnvelopeFlags::RESPONSE)
        || response.stream_id != 0
        || response.correlation_id != message_id
        || response.connection_epoch != 0
    {
        return Err(SessionError::Invalid("invalid HELLO_ACK envelope"));
    }
    let ack = decode_hello_ack(&payload)?;
    connection.activate_epoch(ack.connection_epoch)?;
    Ok((ack, connection))
}

pub async fn activate_broker<S>(
    mut connection: SecureConnection<S>,
    ack: &HelloAck,
    response_message_id: [u8; 16],
) -> Result<(Hello, SecureConnection<S>), SessionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if connection.connection_epoch() != 0 || ack.connection_epoch == 0 {
        return Err(SessionError::Invalid("invalid provisional broker session"));
    }
    let (request, payload) = connection.receive().await?;
    if request.message_type != MessageType::Hello as u16
        || !request.flags.contains(EnvelopeFlags::REQUEST)
        || request.stream_id != 0
        || request.connection_epoch != 0
    {
        return Err(SessionError::Invalid("invalid HELLO envelope"));
    }
    let hello = decode_hello(&payload)?;
    if hello.min_minor > ack.selected_minor || hello.max_minor < ack.selected_minor {
        return Err(SessionError::Invalid("minor version mismatch"));
    }
    let payload = encode_hello_ack(ack)?;
    let envelope = control_envelope(
        MessageType::HelloAck,
        EnvelopeFlags::RESPONSE | EnvelopeFlags::END_STREAM,
        response_message_id,
        request.message_id,
        payload.len(),
    )?;
    connection.send(&envelope, &payload).await?;
    connection.activate_epoch(ack.connection_epoch)?;
    Ok((hello, connection))
}

fn control_envelope(
    message_type: MessageType,
    flags: EnvelopeFlags,
    message_id: [u8; 16],
    correlation_id: [u8; 16],
    payload_length: usize,
) -> Result<Envelope, SessionError> {
    Ok(Envelope {
        minor: 0,
        message_type: message_type as u16,
        flags,
        connection_epoch: 0,
        stream_id: 0,
        stream_sequence: 0,
        message_id,
        correlation_id,
        remaining_budget_ms: 15_000,
        payload_length: u32::try_from(payload_length)
            .map_err(|_| SessionError::Invalid("payload too large"))?,
    })
}

fn encode_platform(value: &Platform) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = PackedEncoder::new(PLATFORM_SCHEMA, 1)
        .field(1, WireType::U16, REQUIRED, value.os.to_le_bytes())?
        .field(
            2,
            WireType::Utf8,
            REQUIRED,
            value.os_version.as_bytes().to_vec(),
        )?
        .field(3, WireType::U16, REQUIRED, value.architecture.to_le_bytes())?
        .field(
            6,
            WireType::Bytes,
            REQUIRED,
            value.build_fingerprint.clone(),
        )?;
    if let Some(wine) = &value.wine_version {
        encoder = encoder.field(4, WireType::Utf8, 0, wine.as_bytes().to_vec())?;
    }
    if let Some(runtime) = &value.runtime_version {
        encoder = encoder.field(5, WireType::Utf8, 0, runtime.as_bytes().to_vec())?;
    }
    encoder.encode()
}

fn decode_platform(input: &[u8]) -> Result<Platform, SessionError> {
    let decoder = PackedDecoder::decode(input)?;
    require_schema(&decoder, PLATFORM_SCHEMA)?;
    Ok(Platform {
        os: required_u16(&decoder, 1)?,
        os_version: required_utf8(&decoder, 2)?,
        architecture: required_u16(&decoder, 3)?,
        wine_version: optional_utf8(&decoder, 4)?,
        runtime_version: optional_utf8(&decoder, 5)?,
        build_fingerprint: required_bytes(&decoder, 6)?,
    })
}

fn encode_hello(value: &Hello) -> Result<Vec<u8>, ProtocolError> {
    PackedEncoder::new(top_level_schema_id(MessageType::Hello), 1)
        .field(1, WireType::U16, REQUIRED, value.peer_kind.to_le_bytes())?
        .field(2, WireType::U16, REQUIRED, value.min_minor.to_le_bytes())?
        .field(3, WireType::U16, REQUIRED, value.max_minor.to_le_bytes())?
        .field(4, WireType::U64, REQUIRED, value.features.to_le_bytes())?
        .field(
            5,
            WireType::U32,
            REQUIRED,
            value.max_logical_payload.to_le_bytes(),
        )?
        .field(6, WireType::U32, REQUIRED, value.max_streams.to_le_bytes())?
        .field(
            7,
            WireType::U64,
            REQUIRED,
            value.initial_connection_credit.to_le_bytes(),
        )?
        .field(8, WireType::Uuid128, REQUIRED, value.client_instance)?
        .field(
            9,
            WireType::Nested,
            REQUIRED,
            encode_platform(&value.platform)?,
        )?
        .field(
            10,
            WireType::U64,
            REQUIRED,
            value.client_wall_unix_ms.to_le_bytes(),
        )?
        .encode()
}

fn decode_hello(input: &[u8]) -> Result<Hello, SessionError> {
    let decoder = PackedDecoder::decode(input)?;
    require_schema(&decoder, top_level_schema_id(MessageType::Hello))?;
    Ok(Hello {
        peer_kind: required_u16(&decoder, 1)?,
        min_minor: required_u16(&decoder, 2)?,
        max_minor: required_u16(&decoder, 3)?,
        features: required_u64(&decoder, 4)?,
        max_logical_payload: required_u32(&decoder, 5)?,
        max_streams: required_u32(&decoder, 6)?,
        initial_connection_credit: required_u64(&decoder, 7)?,
        client_instance: required_uuid(&decoder, 8)?,
        platform: decode_platform(required_field(&decoder, 9, WireType::Nested)?)?,
        client_wall_unix_ms: required_u64(&decoder, 10)?,
    })
}

fn encode_readiness(value: &Readiness) -> Result<Vec<u8>, ProtocolError> {
    PackedEncoder::new(READINESS_SCHEMA, 1)
        .field(
            1,
            WireType::U16,
            REQUIRED,
            value.overall_status.to_le_bytes(),
        )?
        .field(2, WireType::RepeatedNested, REQUIRED, Vec::new())?
        .field(
            3,
            WireType::U64,
            REQUIRED,
            value.generated_at_unix_ms.to_le_bytes(),
        )?
        .field(
            4,
            WireType::Utf8,
            REQUIRED,
            value.source_version.as_bytes().to_vec(),
        )?
        .encode()
}

fn decode_readiness(input: &[u8]) -> Result<Readiness, SessionError> {
    let decoder = PackedDecoder::decode(input)?;
    require_schema(&decoder, READINESS_SCHEMA)?;
    let _checks = required_field(&decoder, 2, WireType::RepeatedNested)?;
    Ok(Readiness {
        overall_status: required_u16(&decoder, 1)?,
        generated_at_unix_ms: required_u64(&decoder, 3)?,
        source_version: required_utf8(&decoder, 4)?,
    })
}

fn encode_hello_ack(value: &HelloAck) -> Result<Vec<u8>, ProtocolError> {
    PackedEncoder::new(top_level_schema_id(MessageType::HelloAck), 1)
        .field(
            1,
            WireType::U16,
            REQUIRED,
            value.selected_minor.to_le_bytes(),
        )?
        .field(2, WireType::U64, REQUIRED, value.features.to_le_bytes())?
        .field(
            3,
            WireType::U32,
            REQUIRED,
            value.max_logical_payload.to_le_bytes(),
        )?
        .field(4, WireType::U32, REQUIRED, value.max_streams.to_le_bytes())?
        .field(
            5,
            WireType::U64,
            REQUIRED,
            value.initial_connection_credit.to_le_bytes(),
        )?
        .field(
            6,
            WireType::U64,
            REQUIRED,
            value.connection_epoch.to_le_bytes(),
        )?
        .field(7, WireType::Uuid128, REQUIRED, value.broker_epoch)?
        .field(8, WireType::Uuid128, REQUIRED, value.actor_id)?
        .field(
            9,
            WireType::Nested,
            REQUIRED,
            encode_readiness(&value.readiness)?,
        )?
        .field(
            10,
            WireType::U64,
            REQUIRED,
            value.broker_wall_unix_ms.to_le_bytes(),
        )?
        .encode()
}

fn decode_hello_ack(input: &[u8]) -> Result<HelloAck, SessionError> {
    let decoder = PackedDecoder::decode(input)?;
    require_schema(&decoder, top_level_schema_id(MessageType::HelloAck))?;
    let connection_epoch = required_u64(&decoder, 6)?;
    if connection_epoch == 0 {
        return Err(SessionError::Invalid("zero active epoch"));
    }
    Ok(HelloAck {
        selected_minor: required_u16(&decoder, 1)?,
        features: required_u64(&decoder, 2)?,
        max_logical_payload: required_u32(&decoder, 3)?,
        max_streams: required_u32(&decoder, 4)?,
        initial_connection_credit: required_u64(&decoder, 5)?,
        connection_epoch,
        broker_epoch: required_uuid(&decoder, 7)?,
        actor_id: required_uuid(&decoder, 8)?,
        readiness: decode_readiness(required_field(&decoder, 9, WireType::Nested)?)?,
        broker_wall_unix_ms: required_u64(&decoder, 10)?,
    })
}

fn require_schema(decoder: &PackedDecoder<'_>, schema: u32) -> Result<(), SessionError> {
    if decoder.schema_id != schema || decoder.schema_version != 1 {
        return Err(SessionError::Invalid("schema mismatch"));
    }
    Ok(())
}

fn required_field<'a>(
    decoder: &'a PackedDecoder<'a>,
    tag: u16,
    wire_type: WireType,
) -> Result<&'a [u8], SessionError> {
    let field = decoder
        .field(tag)
        .ok_or(SessionError::Invalid("required field missing"))?;
    if field.wire_type != wire_type || field.flags & REQUIRED == 0 {
        return Err(SessionError::Invalid("required field type or flag"));
    }
    Ok(field.value)
}

fn required_u16(decoder: &PackedDecoder<'_>, tag: u16) -> Result<u16, SessionError> {
    let value = required_field(decoder, tag, WireType::U16)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn required_u32(decoder: &PackedDecoder<'_>, tag: u16) -> Result<u32, SessionError> {
    let value = required_field(decoder, tag, WireType::U32)?;
    Ok(u32::from_le_bytes(
        value.try_into().map_err(|_| SessionError::Invalid("u32"))?,
    ))
}

fn required_u64(decoder: &PackedDecoder<'_>, tag: u16) -> Result<u64, SessionError> {
    let value = required_field(decoder, tag, WireType::U64)?;
    Ok(u64::from_le_bytes(
        value.try_into().map_err(|_| SessionError::Invalid("u64"))?,
    ))
}

fn required_uuid(decoder: &PackedDecoder<'_>, tag: u16) -> Result<[u8; 16], SessionError> {
    required_field(decoder, tag, WireType::Uuid128)?
        .try_into()
        .map_err(|_| SessionError::Invalid("uuid"))
}

fn required_utf8(decoder: &PackedDecoder<'_>, tag: u16) -> Result<String, SessionError> {
    let value = required_field(decoder, tag, WireType::Utf8)?;
    String::from_utf8(value.to_vec()).map_err(|_| SessionError::Invalid("utf8"))
}

fn optional_utf8(decoder: &PackedDecoder<'_>, tag: u16) -> Result<Option<String>, SessionError> {
    decoder
        .field(tag)
        .map(|field| {
            if field.wire_type != WireType::Utf8 || field.flags & REQUIRED != 0 {
                return Err(SessionError::Invalid("optional utf8"));
            }
            String::from_utf8(field.value.to_vec()).map_err(|_| SessionError::Invalid("utf8"))
        })
        .transpose()
}

fn required_bytes(decoder: &PackedDecoder<'_>, tag: u16) -> Result<Vec<u8>, SessionError> {
    Ok(required_field(decoder, tag, WireType::Bytes)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use wvb_crypto::StaticPrivateKey;
    use wvb_transport::{session_initiator, session_responder};

    fn hello() -> Hello {
        Hello {
            peer_kind: 1,
            min_minor: 0,
            max_minor: 0,
            features: 0x55,
            max_logical_payload: 1_048_576,
            max_streams: 64,
            initial_connection_credit: 2_097_152,
            client_instance: [3; 16],
            platform: Platform {
                os: 1,
                os_version: String::from("Windows 11"),
                architecture: 2,
                wine_version: Some(String::from("CrossOver")),
                runtime_version: Some(String::from("0.2.0")),
                build_fingerprint: vec![4; 32],
            },
            client_wall_unix_ms: 10,
        }
    }

    fn ack() -> HelloAck {
        HelloAck {
            selected_minor: 0,
            features: 0x11,
            max_logical_payload: 1_048_576,
            max_streams: 32,
            initial_connection_credit: 1_048_576,
            connection_epoch: 77,
            broker_epoch: [5; 16],
            actor_id: [6; 16],
            readiness: Readiness {
                overall_status: 1,
                generated_at_unix_ms: 11,
                source_version: String::from("broker-0.2.0"),
            },
            broker_wall_unix_ms: 12,
        }
    }

    #[tokio::test]
    async fn provisional_session_activates_only_after_hello_ack() {
        let (client_key, _) = StaticPrivateKey::generate().unwrap();
        let (broker_key, broker_public) = StaticPrivateKey::generate().unwrap();
        let (client_io, broker_io) = duplex(64 * 1024);
        let client_handshake = session_initiator(client_io, &client_key, &broker_public);
        let broker_handshake = session_responder(broker_io, &broker_key);
        let (client, (_, broker)) = tokio::try_join!(client_handshake, broker_handshake).unwrap();
        let expected_hello = hello();
        let expected_ack = ack();
        let client_activation = activate_client(client, &expected_hello, [7; 16]);
        let broker_activation = activate_broker(broker, &expected_ack, [8; 16]);
        let ((observed_ack, client), (observed_hello, broker)) =
            tokio::try_join!(client_activation, broker_activation).unwrap();
        assert_eq!(observed_ack, expected_ack);
        assert_eq!(observed_hello, expected_hello);
        assert_eq!(client.connection_epoch(), 77);
        assert_eq!(broker.connection_epoch(), 77);
    }
}
