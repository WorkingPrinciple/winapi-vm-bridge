//! Cancellation, handle, operation, receipt and audit protocol controls.

use wvb_protocol::{
    MessageType, PackedDecoder, PackedEncoder, ProtocolError, WireType, top_level_schema_id,
};

const REQUIRED: u8 = 0x01;
const REPEATED: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelTarget {
    Message([u8; 16]),
    Operation([u8; 16]),
    Transfer([u8; 16]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelRequest {
    pub target: CancelTarget,
    pub reason: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelAck {
    pub disposition: u16,
    pub native_cancel_invoked: bool,
    pub operation_status: Option<u16>,
    pub receipt: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleClose {
    pub broker_epoch: [u8; 16],
    pub owner_actor_id: [u8; 16],
    pub slot: u32,
    pub generation: u32,
    pub handle_type: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleStatus {
    pub disposition: u16,
    pub native_status: Option<Vec<u8>>,
    pub receipt: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationQuery {
    pub operation_id: [u8; 16],
    pub after_event_sequence: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationStateMessage {
    pub operation: Vec<u8>,
    pub events: Vec<Vec<u8>>,
    pub next_event_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptQuery {
    pub idempotency_key: [u8; 16],
    pub adapter_hash: [u8; 32],
    pub operation_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptResult {
    pub disposition: u16,
    pub operation_id: Option<[u8; 16]>,
    pub receipt: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCheckpoint {
    pub checkpoint_sequence: u64,
    pub event_sequence: u64,
    pub event_hash: [u8; 32],
    pub database_generation: u64,
    pub signature_algorithm: u16,
    pub signing_key_generation: u64,
    pub signature: Vec<u8>,
    pub signer_fingerprint: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    Cancel(CancelRequest),
    CancelAck(CancelAck),
    HandleClose(HandleClose),
    HandleStatus(HandleStatus),
    OperationQuery(OperationQuery),
    OperationState(OperationStateMessage),
    ReceiptQuery(ReceiptQuery),
    ReceiptResult(ReceiptResult),
    AuditCheckpoint(AuditCheckpoint),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    Protocol,
    BoundExceeded,
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ControlError {}

impl From<ProtocolError> for ControlError {
    fn from(_value: ProtocolError) -> Self {
        Self::Protocol
    }
}

impl ControlMessage {
    pub fn encode(&self) -> Result<(MessageType, Vec<u8>), ControlError> {
        match self {
            Self::Cancel(value) => encode_cancel(*value),
            Self::CancelAck(value) => encode_cancel_ack(value),
            Self::HandleClose(value) => encode_handle_close(*value),
            Self::HandleStatus(value) => encode_handle_status(value),
            Self::OperationQuery(value) => encode_operation_query(*value),
            Self::OperationState(value) => encode_operation_state(value),
            Self::ReceiptQuery(value) => encode_receipt_query(*value),
            Self::ReceiptResult(value) => encode_receipt_result(value),
            Self::AuditCheckpoint(value) => encode_audit_checkpoint(value),
        }
    }

    pub fn decode(message_type: MessageType, payload: &[u8]) -> Result<Self, ControlError> {
        let decoder = PackedDecoder::decode(payload)?;
        if decoder.schema_id != top_level_schema_id(message_type) || decoder.schema_version != 1 {
            return Err(ControlError::Protocol);
        }
        match message_type {
            MessageType::Cancel => decode_cancel(&decoder).map(Self::Cancel),
            MessageType::CancelAck => decode_cancel_ack(&decoder).map(Self::CancelAck),
            MessageType::HandleClose => decode_handle_close(&decoder).map(Self::HandleClose),
            MessageType::HandleStatus => decode_handle_status(&decoder).map(Self::HandleStatus),
            MessageType::OperationQuery => {
                decode_operation_query(&decoder).map(Self::OperationQuery)
            }
            MessageType::OperationState => {
                decode_operation_state(&decoder).map(Self::OperationState)
            }
            MessageType::ReceiptQuery => decode_receipt_query(&decoder).map(Self::ReceiptQuery),
            MessageType::ReceiptResult => decode_receipt_result(&decoder).map(Self::ReceiptResult),
            MessageType::AuditCheckpoint => {
                decode_audit_checkpoint(&decoder).map(Self::AuditCheckpoint)
            }
            _ => Err(ControlError::Protocol),
        }
    }
}

fn encode_cancel(value: CancelRequest) -> Result<(MessageType, Vec<u8>), ControlError> {
    let mut encoder = PackedEncoder::new(top_level_schema_id(MessageType::Cancel), 1).field(
        4,
        WireType::U16,
        REQUIRED,
        value.reason.to_le_bytes(),
    )?;
    encoder = match value.target {
        CancelTarget::Message(id) => encoder.field(1, WireType::Uuid128, 0, id)?,
        CancelTarget::Operation(id) => encoder.field(2, WireType::Uuid128, 0, id)?,
        CancelTarget::Transfer(id) => encoder.field(3, WireType::Uuid128, 0, id)?,
    };
    Ok((MessageType::Cancel, encoder.encode()?))
}

fn decode_cancel(decoder: &PackedDecoder<'_>) -> Result<CancelRequest, ControlError> {
    let targets = [
        optional_uuid(decoder, 1)?.map(CancelTarget::Message),
        optional_uuid(decoder, 2)?.map(CancelTarget::Operation),
        optional_uuid(decoder, 3)?.map(CancelTarget::Transfer),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if targets.len() != 1 {
        return Err(ControlError::Protocol);
    }
    Ok(CancelRequest {
        target: targets[0],
        reason: u16_value(decoder, 4)?,
    })
}

fn encode_cancel_ack(value: &CancelAck) -> Result<(MessageType, Vec<u8>), ControlError> {
    let mut encoder = PackedEncoder::new(top_level_schema_id(MessageType::CancelAck), 1)
        .field(1, WireType::U16, REQUIRED, value.disposition.to_le_bytes())?
        .field(
            2,
            WireType::Bool,
            REQUIRED,
            [u8::from(value.native_cancel_invoked)],
        )?;
    if let Some(status) = value.operation_status {
        encoder = encoder.field(3, WireType::U16, 0, status.to_le_bytes())?;
    }
    if let Some(receipt) = &value.receipt {
        encoder = encoder.field(4, WireType::Nested, 0, receipt.clone())?;
    }
    Ok((MessageType::CancelAck, encoder.encode()?))
}

fn decode_cancel_ack(decoder: &PackedDecoder<'_>) -> Result<CancelAck, ControlError> {
    Ok(CancelAck {
        disposition: u16_value(decoder, 1)?,
        native_cancel_invoked: bool_value(decoder, 2)?,
        operation_status: optional_u16(decoder, 3)?,
        receipt: optional(decoder, 4, WireType::Nested)?.map(<[u8]>::to_vec),
    })
}

fn encode_handle_close(value: HandleClose) -> Result<(MessageType, Vec<u8>), ControlError> {
    Ok((
        MessageType::HandleClose,
        PackedEncoder::new(top_level_schema_id(MessageType::HandleClose), 1)
            .field(1, WireType::Uuid128, REQUIRED, value.broker_epoch)?
            .field(2, WireType::Uuid128, REQUIRED, value.owner_actor_id)?
            .field(3, WireType::U32, REQUIRED, value.slot.to_le_bytes())?
            .field(4, WireType::U32, REQUIRED, value.generation.to_le_bytes())?
            .field(5, WireType::U32, REQUIRED, value.handle_type.to_le_bytes())?
            .encode()?,
    ))
}

fn decode_handle_close(decoder: &PackedDecoder<'_>) -> Result<HandleClose, ControlError> {
    Ok(HandleClose {
        broker_epoch: uuid(decoder, 1)?,
        owner_actor_id: uuid(decoder, 2)?,
        slot: u32_value(decoder, 3)?,
        generation: u32_value(decoder, 4)?,
        handle_type: u32_value(decoder, 5)?,
    })
}

fn encode_handle_status(value: &HandleStatus) -> Result<(MessageType, Vec<u8>), ControlError> {
    let mut encoder = PackedEncoder::new(top_level_schema_id(MessageType::HandleStatus), 1).field(
        1,
        WireType::U16,
        REQUIRED,
        value.disposition.to_le_bytes(),
    )?;
    if let Some(status) = &value.native_status {
        encoder = encoder.field(2, WireType::Nested, 0, status.clone())?;
    }
    if let Some(receipt) = &value.receipt {
        encoder = encoder.field(3, WireType::Nested, 0, receipt.clone())?;
    }
    Ok((MessageType::HandleStatus, encoder.encode()?))
}

fn decode_handle_status(decoder: &PackedDecoder<'_>) -> Result<HandleStatus, ControlError> {
    Ok(HandleStatus {
        disposition: u16_value(decoder, 1)?,
        native_status: optional(decoder, 2, WireType::Nested)?.map(<[u8]>::to_vec),
        receipt: optional(decoder, 3, WireType::Nested)?.map(<[u8]>::to_vec),
    })
}

fn encode_operation_query(value: OperationQuery) -> Result<(MessageType, Vec<u8>), ControlError> {
    let mut encoder = PackedEncoder::new(top_level_schema_id(MessageType::OperationQuery), 1)
        .field(1, WireType::Uuid128, REQUIRED, value.operation_id)?;
    if let Some(sequence) = value.after_event_sequence {
        encoder = encoder.field(2, WireType::U64, 0, sequence.to_le_bytes())?;
    }
    Ok((MessageType::OperationQuery, encoder.encode()?))
}

fn decode_operation_query(decoder: &PackedDecoder<'_>) -> Result<OperationQuery, ControlError> {
    Ok(OperationQuery {
        operation_id: uuid(decoder, 1)?,
        after_event_sequence: optional_u64(decoder, 2)?,
    })
}

fn encode_operation_state(
    value: &OperationStateMessage,
) -> Result<(MessageType, Vec<u8>), ControlError> {
    let mut encoder = PackedEncoder::new(top_level_schema_id(MessageType::OperationState), 1)
        .field(1, WireType::Nested, REQUIRED, value.operation.clone())?;
    for event in &value.events {
        encoder = encoder.field(2, WireType::RepeatedNested, REPEATED, event.clone())?;
    }
    Ok((
        MessageType::OperationState,
        encoder
            .field(
                3,
                WireType::U64,
                REQUIRED,
                value.next_event_sequence.to_le_bytes(),
            )?
            .encode()?,
    ))
}

fn decode_operation_state(
    decoder: &PackedDecoder<'_>,
) -> Result<OperationStateMessage, ControlError> {
    let events = decoder
        .fields()
        .iter()
        .filter(|field| field.tag == 2)
        .map(|field| {
            if field.wire_type != WireType::RepeatedNested || field.flags & REPEATED == 0 {
                return Err(ControlError::Protocol);
            }
            Ok(field.value.to_vec())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(OperationStateMessage {
        operation: required(decoder, 1, WireType::Nested)?.to_vec(),
        events,
        next_event_sequence: u64_value(decoder, 3)?,
    })
}

fn encode_receipt_query(value: ReceiptQuery) -> Result<(MessageType, Vec<u8>), ControlError> {
    Ok((
        MessageType::ReceiptQuery,
        PackedEncoder::new(top_level_schema_id(MessageType::ReceiptQuery), 1)
            .field(1, WireType::Uuid128, REQUIRED, value.idempotency_key)?
            .field(2, WireType::Bytes, REQUIRED, value.adapter_hash)?
            .field(3, WireType::U32, REQUIRED, value.operation_id.to_le_bytes())?
            .encode()?,
    ))
}

fn decode_receipt_query(decoder: &PackedDecoder<'_>) -> Result<ReceiptQuery, ControlError> {
    Ok(ReceiptQuery {
        idempotency_key: uuid(decoder, 1)?,
        adapter_hash: hash(decoder, 2)?,
        operation_id: u32_value(decoder, 3)?,
    })
}

fn encode_receipt_result(value: &ReceiptResult) -> Result<(MessageType, Vec<u8>), ControlError> {
    let mut encoder = PackedEncoder::new(top_level_schema_id(MessageType::ReceiptResult), 1)
        .field(1, WireType::U16, REQUIRED, value.disposition.to_le_bytes())?;
    if let Some(operation) = value.operation_id {
        encoder = encoder.field(2, WireType::Uuid128, 0, operation)?;
    }
    if let Some(receipt) = &value.receipt {
        encoder = encoder.field(3, WireType::Nested, 0, receipt.clone())?;
    }
    Ok((MessageType::ReceiptResult, encoder.encode()?))
}

fn decode_receipt_result(decoder: &PackedDecoder<'_>) -> Result<ReceiptResult, ControlError> {
    Ok(ReceiptResult {
        disposition: u16_value(decoder, 1)?,
        operation_id: optional_uuid(decoder, 2)?,
        receipt: optional(decoder, 3, WireType::Nested)?.map(<[u8]>::to_vec),
    })
}

fn encode_audit_checkpoint(
    value: &AuditCheckpoint,
) -> Result<(MessageType, Vec<u8>), ControlError> {
    Ok((
        MessageType::AuditCheckpoint,
        PackedEncoder::new(top_level_schema_id(MessageType::AuditCheckpoint), 1)
            .field(
                1,
                WireType::U64,
                REQUIRED,
                value.checkpoint_sequence.to_le_bytes(),
            )?
            .field(
                2,
                WireType::U64,
                REQUIRED,
                value.event_sequence.to_le_bytes(),
            )?
            .field(3, WireType::Bytes, REQUIRED, value.event_hash)?
            .field(
                4,
                WireType::U64,
                REQUIRED,
                value.database_generation.to_le_bytes(),
            )?
            .field(
                5,
                WireType::U16,
                REQUIRED,
                value.signature_algorithm.to_le_bytes(),
            )?
            .field(
                6,
                WireType::U64,
                REQUIRED,
                value.signing_key_generation.to_le_bytes(),
            )?
            .field(7, WireType::Bytes, REQUIRED, value.signature.clone())?
            .field(
                8,
                WireType::Bytes,
                REQUIRED,
                value.signer_fingerprint.clone(),
            )?
            .encode()?,
    ))
}

fn decode_audit_checkpoint(decoder: &PackedDecoder<'_>) -> Result<AuditCheckpoint, ControlError> {
    Ok(AuditCheckpoint {
        checkpoint_sequence: u64_value(decoder, 1)?,
        event_sequence: u64_value(decoder, 2)?,
        event_hash: hash(decoder, 3)?,
        database_generation: u64_value(decoder, 4)?,
        signature_algorithm: u16_value(decoder, 5)?,
        signing_key_generation: u64_value(decoder, 6)?,
        signature: required(decoder, 7, WireType::Bytes)?.to_vec(),
        signer_fingerprint: required(decoder, 8, WireType::Bytes)?.to_vec(),
    })
}

fn required<'a>(
    decoder: &'a PackedDecoder<'a>,
    tag: u16,
    wire_type: WireType,
) -> Result<&'a [u8], ControlError> {
    let field = decoder.field(tag).ok_or(ControlError::Protocol)?;
    if field.wire_type != wire_type || field.flags & REQUIRED == 0 {
        return Err(ControlError::Protocol);
    }
    Ok(field.value)
}

fn optional<'a>(
    decoder: &'a PackedDecoder<'a>,
    tag: u16,
    wire_type: WireType,
) -> Result<Option<&'a [u8]>, ControlError> {
    decoder
        .field(tag)
        .map(|field| {
            if field.wire_type != wire_type || field.flags & REQUIRED != 0 {
                return Err(ControlError::Protocol);
            }
            Ok(field.value)
        })
        .transpose()
}

fn uuid(decoder: &PackedDecoder<'_>, tag: u16) -> Result<[u8; 16], ControlError> {
    required(decoder, tag, WireType::Uuid128)?
        .try_into()
        .map_err(|_| ControlError::Protocol)
}

fn optional_uuid(decoder: &PackedDecoder<'_>, tag: u16) -> Result<Option<[u8; 16]>, ControlError> {
    optional(decoder, tag, WireType::Uuid128)?
        .map(|value| value.try_into().map_err(|_| ControlError::Protocol))
        .transpose()
}

fn hash(decoder: &PackedDecoder<'_>, tag: u16) -> Result<[u8; 32], ControlError> {
    required(decoder, tag, WireType::Bytes)?
        .try_into()
        .map_err(|_| ControlError::Protocol)
}

fn bool_value(decoder: &PackedDecoder<'_>, tag: u16) -> Result<bool, ControlError> {
    match required(decoder, tag, WireType::Bool)? {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(ControlError::Protocol),
    }
}

fn u16_value(decoder: &PackedDecoder<'_>, tag: u16) -> Result<u16, ControlError> {
    Ok(u16::from_le_bytes(
        required(decoder, tag, WireType::U16)?
            .try_into()
            .map_err(|_| ControlError::Protocol)?,
    ))
}

fn optional_u16(decoder: &PackedDecoder<'_>, tag: u16) -> Result<Option<u16>, ControlError> {
    optional(decoder, tag, WireType::U16)?
        .map(|value| {
            Ok(u16::from_le_bytes(
                value.try_into().map_err(|_| ControlError::Protocol)?,
            ))
        })
        .transpose()
}

fn u32_value(decoder: &PackedDecoder<'_>, tag: u16) -> Result<u32, ControlError> {
    Ok(u32::from_le_bytes(
        required(decoder, tag, WireType::U32)?
            .try_into()
            .map_err(|_| ControlError::Protocol)?,
    ))
}

fn u64_value(decoder: &PackedDecoder<'_>, tag: u16) -> Result<u64, ControlError> {
    Ok(u64::from_le_bytes(
        required(decoder, tag, WireType::U64)?
            .try_into()
            .map_err(|_| ControlError::Protocol)?,
    ))
}

fn optional_u64(decoder: &PackedDecoder<'_>, tag: u16) -> Result<Option<u64>, ControlError> {
    optional(decoder, tag, WireType::U64)?
        .map(|value| {
            Ok(u64::from_le_bytes(
                value.try_into().map_err(|_| ControlError::Protocol)?,
            ))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_messages_round_trip_exact_protocol_shapes() {
        let messages = [
            ControlMessage::Cancel(CancelRequest {
                target: CancelTarget::Operation([1; 16]),
                reason: 2,
            }),
            ControlMessage::CancelAck(CancelAck {
                disposition: 1,
                native_cancel_invoked: true,
                operation_status: Some(5),
                receipt: Some(b"receipt".to_vec()),
            }),
            ControlMessage::HandleClose(HandleClose {
                broker_epoch: [2; 16],
                owner_actor_id: [3; 16],
                slot: 4,
                generation: 5,
                handle_type: 6,
            }),
            ControlMessage::HandleStatus(HandleStatus {
                disposition: 1,
                native_status: Some(b"status".to_vec()),
                receipt: Some(b"receipt".to_vec()),
            }),
            ControlMessage::OperationQuery(OperationQuery {
                operation_id: [4; 16],
                after_event_sequence: Some(7),
            }),
            ControlMessage::OperationState(OperationStateMessage {
                operation: b"operation".to_vec(),
                events: vec![b"one".to_vec(), b"two".to_vec()],
                next_event_sequence: 9,
            }),
            ControlMessage::ReceiptQuery(ReceiptQuery {
                idempotency_key: [5; 16],
                adapter_hash: [6; 32],
                operation_id: 7,
            }),
            ControlMessage::ReceiptResult(ReceiptResult {
                disposition: 1,
                operation_id: Some([8; 16]),
                receipt: Some(b"receipt".to_vec()),
            }),
            ControlMessage::AuditCheckpoint(AuditCheckpoint {
                checkpoint_sequence: 1,
                event_sequence: 2,
                event_hash: [9; 32],
                database_generation: 3,
                signature_algorithm: 1,
                signing_key_generation: 4,
                signature: b"signature".to_vec(),
                signer_fingerprint: b"fingerprint".to_vec(),
            }),
        ];
        for message in messages {
            let (message_type, payload) = message.encode().unwrap();
            assert_eq!(
                ControlMessage::decode(message_type, &payload).unwrap(),
                message
            );
        }
    }

    #[test]
    fn cancel_requires_exactly_one_target() {
        let payload = PackedEncoder::new(top_level_schema_id(MessageType::Cancel), 1)
            .field(1, WireType::Uuid128, 0, [1; 16])
            .unwrap()
            .field(2, WireType::Uuid128, 0, [2; 16])
            .unwrap()
            .field(4, WireType::U16, REQUIRED, 1_u16.to_le_bytes())
            .unwrap()
            .encode()
            .unwrap();
        assert_eq!(
            ControlMessage::decode(MessageType::Cancel, &payload),
            Err(ControlError::Protocol)
        );
    }
}
