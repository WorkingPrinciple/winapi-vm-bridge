//! Bounded content-addressed transfer lifecycle and protocol messages.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use wvb_protocol::{
    MessageType, PackedDecoder, PackedEncoder, ProtocolError, WireType, top_level_schema_id,
};
pub use wvb_registry::{TransferKind, TransferTerminal};

const REQUIRED: u8 = 0x01;

pub type TransferId = [u8; 16];
pub type ActorId = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferLimits {
    pub maximum_bytes: usize,
    pub maximum_chunk_bytes: usize,
    pub maximum_active: usize,
    pub maximum_metadata_bytes: usize,
    pub maximum_receipt_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferBegin {
    pub transfer_id: TransferId,
    pub kind: TransferKind,
    pub parent_message_id: Option<[u8; 16]>,
    pub parent_operation_id: Option<[u8; 16]>,
    pub declared_length: usize,
    pub content_hash: [u8; 32],
    pub media_type: Option<String>,
    pub file_name: Option<String>,
    pub sensitivity: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferData {
    pub transfer_id: TransferId,
    pub chunk_index: u32,
    pub offset: usize,
    pub chunk_hash: [u8; 32],
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferEnd {
    pub transfer_id: TransferId,
    pub chunk_count: u32,
    pub total_length: usize,
    pub total_hash: [u8; 32],
    pub terminal_status: u16,
    pub receipt: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferCancel {
    pub transfer_id: TransferId,
    pub reason: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferCancelAck {
    pub transfer_id: TransferId,
    pub disposition: u16,
    pub receipt: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferReceiptMessage {
    pub transfer_id: TransferId,
    pub receipt: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferMessage {
    Begin(TransferBegin),
    Data(TransferData),
    End(TransferEnd),
    Cancel(TransferCancel),
    CancelAck(TransferCancelAck),
    Receipt(TransferReceiptMessage),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferReceipt {
    pub transfer_id: TransferId,
    pub actor_id: ActorId,
    pub kind: TransferKind,
    pub total_bytes: usize,
    pub sha256: [u8; 32],
    pub terminal: TransferTerminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    Capacity,
    Replay,
    Unknown,
    WrongActor,
    BoundExceeded,
    InvalidOrder,
    HashMismatch,
    Terminal,
    Protocol,
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for TransferError {}

impl From<ProtocolError> for TransferError {
    fn from(_value: ProtocolError) -> Self {
        Self::Protocol
    }
}

#[derive(Debug)]
struct ActiveTransfer {
    actor_id: ActorId,
    begin: TransferBegin,
    next_chunk: u32,
    bytes_written: usize,
    hasher: Sha256,
    chunks: BTreeMap<u32, (usize, usize, [u8; 32])>,
    file: NamedTempFile,
}

#[derive(Debug)]
pub struct CompletedTransfer {
    pub receipt: TransferReceipt,
    file: NamedTempFile,
}

impl CompletedTransfer {
    #[must_use]
    pub fn path(&self) -> &Path {
        self.file.path()
    }
}

#[derive(Debug)]
pub struct TransferRegistry {
    limits: TransferLimits,
    active: BTreeMap<TransferId, ActiveTransfer>,
    terminal: BTreeSet<TransferId>,
}

impl TransferRegistry {
    #[must_use]
    pub fn new(limits: TransferLimits) -> Self {
        Self {
            limits,
            active: BTreeMap::new(),
            terminal: BTreeSet::new(),
        }
    }

    pub fn begin(&mut self, actor_id: ActorId, begin: TransferBegin) -> Result<(), TransferError> {
        if self.active.len() >= self.limits.maximum_active {
            return Err(TransferError::Capacity);
        }
        if self.active.contains_key(&begin.transfer_id)
            || self.terminal.contains(&begin.transfer_id)
        {
            return Err(TransferError::Replay);
        }
        if begin.declared_length > self.limits.maximum_bytes {
            return Err(TransferError::BoundExceeded);
        }
        validate_optional_text(
            begin.media_type.as_deref(),
            self.limits.maximum_metadata_bytes,
        )?;
        validate_optional_text(
            begin.file_name.as_deref(),
            self.limits.maximum_metadata_bytes,
        )?;
        self.active.insert(
            begin.transfer_id,
            ActiveTransfer {
                actor_id,
                begin,
                next_chunk: 0,
                bytes_written: 0,
                hasher: Sha256::new(),
                chunks: BTreeMap::new(),
                file: NamedTempFile::new().map_err(|_| TransferError::Capacity)?,
            },
        );
        Ok(())
    }

    pub fn data(&mut self, actor_id: ActorId, data: &TransferData) -> Result<(), TransferError> {
        let active = self
            .active
            .get_mut(&data.transfer_id)
            .ok_or(TransferError::Unknown)?;
        if active.actor_id != actor_id {
            return Err(TransferError::WrongActor);
        }
        if data.chunk_index < active.next_chunk {
            return if active.chunks.get(&data.chunk_index)
                == Some(&(data.offset, data.bytes.len(), data.chunk_hash))
            {
                Ok(())
            } else {
                Err(TransferError::Replay)
            };
        }
        if data.chunk_index != active.next_chunk || data.offset != active.bytes_written {
            return Err(TransferError::InvalidOrder);
        }
        if data.bytes.len() > self.limits.maximum_chunk_bytes
            || hash(&data.bytes) != data.chunk_hash
        {
            return Err(TransferError::HashMismatch);
        }
        let new_length = active
            .bytes_written
            .checked_add(data.bytes.len())
            .ok_or(TransferError::BoundExceeded)?;
        if new_length > active.begin.declared_length || new_length > self.limits.maximum_bytes {
            return Err(TransferError::BoundExceeded);
        }
        active
            .file
            .write_all(&data.bytes)
            .map_err(|_| TransferError::Capacity)?;
        active.hasher.update(&data.bytes);
        active.chunks.insert(
            data.chunk_index,
            (data.offset, data.bytes.len(), data.chunk_hash),
        );
        active.bytes_written = new_length;
        active.next_chunk = active
            .next_chunk
            .checked_add(1)
            .ok_or(TransferError::BoundExceeded)?;
        Ok(())
    }

    pub fn finish(
        &mut self,
        actor_id: ActorId,
        end: &TransferEnd,
    ) -> Result<CompletedTransfer, TransferError> {
        let mut active = self
            .active
            .remove(&end.transfer_id)
            .ok_or(TransferError::Unknown)?;
        if active.actor_id != actor_id {
            self.active.insert(end.transfer_id, active);
            return Err(TransferError::WrongActor);
        }
        self.terminal.insert(end.transfer_id);
        if end.receipt.len() > self.limits.maximum_receipt_bytes {
            return Err(TransferError::BoundExceeded);
        }
        active.file.flush().map_err(|_| TransferError::Capacity)?;
        let observed_hash: [u8; 32] = active.hasher.clone().finalize().into();
        if active.bytes_written != active.begin.declared_length
            || active.next_chunk != end.chunk_count
            || active.bytes_written != end.total_length
            || active.begin.content_hash != observed_hash
            || end.total_hash != observed_hash
        {
            return Err(TransferError::HashMismatch);
        }
        let terminal =
            TransferTerminal::try_from(end.terminal_status).map_err(|_| TransferError::Terminal)?;
        Ok(CompletedTransfer {
            receipt: TransferReceipt {
                transfer_id: end.transfer_id,
                actor_id,
                kind: active.begin.kind,
                total_bytes: end.total_length,
                sha256: observed_hash,
                terminal,
            },
            file: active.file,
        })
    }

    pub fn cancel(
        &mut self,
        actor_id: ActorId,
        cancel: TransferCancel,
    ) -> Result<TransferReceipt, TransferError> {
        let active = self
            .active
            .remove(&cancel.transfer_id)
            .ok_or(TransferError::Unknown)?;
        if active.actor_id != actor_id {
            self.active.insert(cancel.transfer_id, active);
            return Err(TransferError::WrongActor);
        }
        self.terminal.insert(cancel.transfer_id);
        Ok(TransferReceipt {
            transfer_id: cancel.transfer_id,
            actor_id,
            kind: active.begin.kind,
            total_bytes: active.bytes_written,
            sha256: active.hasher.finalize().into(),
            terminal: TransferTerminal::Canceled,
        })
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }
}

impl TransferMessage {
    pub fn encode(&self) -> Result<(MessageType, Vec<u8>), TransferError> {
        match self {
            Self::Begin(begin) => encode_begin(begin),
            Self::Data(data) => encode_data(data),
            Self::End(end) => encode_end(end),
            Self::Cancel(cancel) => encode_cancel(*cancel),
            Self::CancelAck(ack) => encode_cancel_ack(ack),
            Self::Receipt(receipt) => encode_receipt(receipt),
        }
    }

    pub fn decode(message_type: MessageType, payload: &[u8]) -> Result<Self, TransferError> {
        let decoder = PackedDecoder::decode(payload)?;
        if decoder.schema_id != top_level_schema_id(message_type) || decoder.schema_version != 1 {
            return Err(TransferError::Protocol);
        }
        match message_type {
            MessageType::TransferBegin => Ok(Self::Begin(TransferBegin {
                transfer_id: uuid(&decoder, 1)?,
                kind: TransferKind::try_from(u16_value(&decoder, 2)?)
                    .map_err(|_| TransferError::Protocol)?,
                parent_message_id: optional_uuid(&decoder, 3)?,
                parent_operation_id: optional_uuid(&decoder, 4)?,
                declared_length: usize_value(&decoder, 5)?,
                content_hash: hash_value(&decoder, 6)?,
                media_type: optional_text(&decoder, 7)?,
                file_name: optional_text(&decoder, 8)?,
                sensitivity: u16_value(&decoder, 9)?,
            })),
            MessageType::TransferData => Ok(Self::Data(TransferData {
                transfer_id: uuid(&decoder, 1)?,
                chunk_index: u32_value(&decoder, 2)?,
                offset: usize_value(&decoder, 3)?,
                chunk_hash: hash_value(&decoder, 4)?,
                bytes: bytes(&decoder, 5)?.to_vec(),
            })),
            MessageType::TransferEnd => Ok(Self::End(TransferEnd {
                transfer_id: uuid(&decoder, 1)?,
                chunk_count: u32_value(&decoder, 2)?,
                total_length: usize_value(&decoder, 3)?,
                total_hash: hash_value(&decoder, 4)?,
                terminal_status: u16_value(&decoder, 5)?,
                receipt: nested(&decoder, 6)?.to_vec(),
            })),
            MessageType::TransferCancel => Ok(Self::Cancel(TransferCancel {
                transfer_id: uuid(&decoder, 1)?,
                reason: u16_value(&decoder, 2)?,
            })),
            MessageType::TransferCancelAck => Ok(Self::CancelAck(TransferCancelAck {
                transfer_id: uuid(&decoder, 1)?,
                disposition: u16_value(&decoder, 2)?,
                receipt: optional_nested(&decoder, 3)?.map(<[u8]>::to_vec),
            })),
            MessageType::TransferReceipt => Ok(Self::Receipt(TransferReceiptMessage {
                transfer_id: uuid(&decoder, 1)?,
                receipt: nested(&decoder, 2)?.to_vec(),
            })),
            _ => Err(TransferError::Protocol),
        }
    }
}

fn encode_begin(begin: &TransferBegin) -> Result<(MessageType, Vec<u8>), TransferError> {
    let mut encoder = PackedEncoder::new(top_level_schema_id(MessageType::TransferBegin), 1)
        .field(1, WireType::Uuid128, REQUIRED, begin.transfer_id)?
        .field(
            2,
            WireType::U16,
            REQUIRED,
            u16::from(begin.kind).to_le_bytes(),
        )?
        .field(
            5,
            WireType::U64,
            REQUIRED,
            u64::try_from(begin.declared_length)
                .map_err(|_| TransferError::BoundExceeded)?
                .to_le_bytes(),
        )?
        .field(6, WireType::Bytes, REQUIRED, begin.content_hash)?
        .field(9, WireType::U16, REQUIRED, begin.sensitivity.to_le_bytes())?;
    if let Some(value) = begin.parent_message_id {
        encoder = encoder.field(3, WireType::Uuid128, 0, value)?;
    }
    if let Some(value) = begin.parent_operation_id {
        encoder = encoder.field(4, WireType::Uuid128, 0, value)?;
    }
    if let Some(value) = &begin.media_type {
        encoder = encoder.field(7, WireType::Utf8, 0, value.as_bytes())?;
    }
    if let Some(value) = &begin.file_name {
        encoder = encoder.field(8, WireType::Utf8, 0, value.as_bytes())?;
    }
    Ok((MessageType::TransferBegin, encoder.encode()?))
}

fn encode_data(data: &TransferData) -> Result<(MessageType, Vec<u8>), TransferError> {
    Ok((
        MessageType::TransferData,
        PackedEncoder::new(top_level_schema_id(MessageType::TransferData), 1)
            .field(1, WireType::Uuid128, REQUIRED, data.transfer_id)?
            .field(2, WireType::U32, REQUIRED, data.chunk_index.to_le_bytes())?
            .field(
                3,
                WireType::U64,
                REQUIRED,
                u64::try_from(data.offset)
                    .map_err(|_| TransferError::BoundExceeded)?
                    .to_le_bytes(),
            )?
            .field(4, WireType::Bytes, REQUIRED, data.chunk_hash)?
            .field(5, WireType::Bytes, REQUIRED, data.bytes.clone())?
            .encode()?,
    ))
}

fn encode_end(end: &TransferEnd) -> Result<(MessageType, Vec<u8>), TransferError> {
    Ok((
        MessageType::TransferEnd,
        PackedEncoder::new(top_level_schema_id(MessageType::TransferEnd), 1)
            .field(1, WireType::Uuid128, REQUIRED, end.transfer_id)?
            .field(2, WireType::U32, REQUIRED, end.chunk_count.to_le_bytes())?
            .field(
                3,
                WireType::U64,
                REQUIRED,
                u64::try_from(end.total_length)
                    .map_err(|_| TransferError::BoundExceeded)?
                    .to_le_bytes(),
            )?
            .field(4, WireType::Bytes, REQUIRED, end.total_hash)?
            .field(
                5,
                WireType::U16,
                REQUIRED,
                end.terminal_status.to_le_bytes(),
            )?
            .field(6, WireType::Nested, REQUIRED, end.receipt.clone())?
            .encode()?,
    ))
}

fn encode_cancel(cancel: TransferCancel) -> Result<(MessageType, Vec<u8>), TransferError> {
    Ok((
        MessageType::TransferCancel,
        PackedEncoder::new(top_level_schema_id(MessageType::TransferCancel), 1)
            .field(1, WireType::Uuid128, REQUIRED, cancel.transfer_id)?
            .field(2, WireType::U16, REQUIRED, cancel.reason.to_le_bytes())?
            .encode()?,
    ))
}

fn encode_cancel_ack(ack: &TransferCancelAck) -> Result<(MessageType, Vec<u8>), TransferError> {
    let mut encoder = PackedEncoder::new(top_level_schema_id(MessageType::TransferCancelAck), 1)
        .field(1, WireType::Uuid128, REQUIRED, ack.transfer_id)?
        .field(2, WireType::U16, REQUIRED, ack.disposition.to_le_bytes())?;
    if let Some(receipt) = &ack.receipt {
        encoder = encoder.field(3, WireType::Nested, 0, receipt.clone())?;
    }
    Ok((MessageType::TransferCancelAck, encoder.encode()?))
}

fn encode_receipt(
    receipt: &TransferReceiptMessage,
) -> Result<(MessageType, Vec<u8>), TransferError> {
    Ok((
        MessageType::TransferReceipt,
        PackedEncoder::new(top_level_schema_id(MessageType::TransferReceipt), 1)
            .field(1, WireType::Uuid128, REQUIRED, receipt.transfer_id)?
            .field(2, WireType::Nested, REQUIRED, receipt.receipt.clone())?
            .encode()?,
    ))
}

fn validate_optional_text(value: Option<&str>, maximum: usize) -> Result<(), TransferError> {
    if value.is_some_and(|value| value.len() > maximum || value.as_bytes().contains(&0)) {
        return Err(TransferError::BoundExceeded);
    }
    Ok(())
}

fn required<'a>(
    decoder: &'a PackedDecoder<'a>,
    tag: u16,
    wire_type: WireType,
) -> Result<&'a [u8], TransferError> {
    let field = decoder.field(tag).ok_or(TransferError::Protocol)?;
    if field.wire_type != wire_type || field.flags & REQUIRED == 0 {
        return Err(TransferError::Protocol);
    }
    Ok(field.value)
}

fn optional<'a>(
    decoder: &'a PackedDecoder<'a>,
    tag: u16,
    wire_type: WireType,
) -> Result<Option<&'a [u8]>, TransferError> {
    decoder
        .field(tag)
        .map(|field| {
            if field.wire_type != wire_type || field.flags & REQUIRED != 0 {
                return Err(TransferError::Protocol);
            }
            Ok(field.value)
        })
        .transpose()
}

fn uuid(decoder: &PackedDecoder<'_>, tag: u16) -> Result<[u8; 16], TransferError> {
    required(decoder, tag, WireType::Uuid128)?
        .try_into()
        .map_err(|_| TransferError::Protocol)
}

fn optional_uuid(decoder: &PackedDecoder<'_>, tag: u16) -> Result<Option<[u8; 16]>, TransferError> {
    optional(decoder, tag, WireType::Uuid128)?
        .map(|value| value.try_into().map_err(|_| TransferError::Protocol))
        .transpose()
}

fn bytes<'a>(decoder: &'a PackedDecoder<'a>, tag: u16) -> Result<&'a [u8], TransferError> {
    required(decoder, tag, WireType::Bytes)
}

fn nested<'a>(decoder: &'a PackedDecoder<'a>, tag: u16) -> Result<&'a [u8], TransferError> {
    required(decoder, tag, WireType::Nested)
}

fn optional_nested<'a>(
    decoder: &'a PackedDecoder<'a>,
    tag: u16,
) -> Result<Option<&'a [u8]>, TransferError> {
    optional(decoder, tag, WireType::Nested)
}

fn optional_text(decoder: &PackedDecoder<'_>, tag: u16) -> Result<Option<String>, TransferError> {
    optional(decoder, tag, WireType::Utf8)?
        .map(|value| {
            std::str::from_utf8(value)
                .map(str::to_owned)
                .map_err(|_| TransferError::Protocol)
        })
        .transpose()
}

fn hash_value(decoder: &PackedDecoder<'_>, tag: u16) -> Result<[u8; 32], TransferError> {
    bytes(decoder, tag)?
        .try_into()
        .map_err(|_| TransferError::Protocol)
}

fn u16_value(decoder: &PackedDecoder<'_>, tag: u16) -> Result<u16, TransferError> {
    Ok(u16::from_le_bytes(
        required(decoder, tag, WireType::U16)?
            .try_into()
            .map_err(|_| TransferError::Protocol)?,
    ))
}

fn u32_value(decoder: &PackedDecoder<'_>, tag: u16) -> Result<u32, TransferError> {
    Ok(u32::from_le_bytes(
        required(decoder, tag, WireType::U32)?
            .try_into()
            .map_err(|_| TransferError::Protocol)?,
    ))
}

fn usize_value(decoder: &PackedDecoder<'_>, tag: u16) -> Result<usize, TransferError> {
    usize::try_from(u64::from_le_bytes(
        required(decoder, tag, WireType::U64)?
            .try_into()
            .map_err(|_| TransferError::Protocol)?,
    ))
    .map_err(|_| TransferError::BoundExceeded)
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> TransferLimits {
        TransferLimits {
            maximum_bytes: 1024 * 1024,
            maximum_chunk_bytes: 64 * 1024,
            maximum_active: 2,
            maximum_metadata_bytes: 256,
            maximum_receipt_bytes: 4096,
        }
    }

    fn begin(id: TransferId, body: &[u8]) -> TransferBegin {
        TransferBegin {
            transfer_id: id,
            kind: TransferKind::CallInput,
            parent_message_id: Some([8; 16]),
            parent_operation_id: None,
            declared_length: body.len(),
            content_hash: hash(body),
            media_type: Some(String::from("application/octet-stream")),
            file_name: None,
            sensitivity: 1,
        }
    }

    #[test]
    fn bounded_transfer_requires_order_hash_and_receipt() {
        let actor = [1; 16];
        let id = [2; 16];
        let body = vec![0xa5; 70_000];
        let mut transfers = TransferRegistry::new(limits());
        transfers.begin(actor, begin(id, &body)).unwrap();
        let first = TransferData {
            transfer_id: id,
            chunk_index: 0,
            offset: 0,
            chunk_hash: hash(&body[..64 * 1024]),
            bytes: body[..64 * 1024].to_vec(),
        };
        let second = TransferData {
            transfer_id: id,
            chunk_index: 1,
            offset: 64 * 1024,
            chunk_hash: hash(&body[64 * 1024..]),
            bytes: body[64 * 1024..].to_vec(),
        };
        transfers.data(actor, &first).unwrap();
        transfers.data(actor, &second).unwrap();
        let end = TransferEnd {
            transfer_id: id,
            chunk_count: 2,
            total_length: body.len(),
            total_hash: hash(&body),
            terminal_status: 1,
            receipt: b"sender-receipt".to_vec(),
        };
        let completed = transfers.finish(actor, &end).unwrap();
        assert_eq!(std::fs::read(completed.path()).unwrap(), body);
        assert_eq!(completed.receipt.terminal, TransferTerminal::Complete);
        assert_eq!(
            transfers.begin(actor, begin(id, &[])),
            Err(TransferError::Replay)
        );
    }

    #[test]
    fn transfer_rejects_order_actor_hash_and_bounds() {
        let actor = [1; 16];
        let id = [2; 16];
        let body = b"data";
        let mut transfers = TransferRegistry::new(limits());
        transfers.begin(actor, begin(id, body)).unwrap();
        let mut data = TransferData {
            transfer_id: id,
            chunk_index: 0,
            offset: 0,
            chunk_hash: hash(body),
            bytes: body.to_vec(),
        };
        assert_eq!(
            transfers.data([9; 16], &data),
            Err(TransferError::WrongActor)
        );
        data.chunk_index = 1;
        assert_eq!(
            transfers.data(actor, &data),
            Err(TransferError::InvalidOrder)
        );
        data.chunk_index = 0;
        data.chunk_hash = [0; 32];
        assert_eq!(
            transfers.data(actor, &data),
            Err(TransferError::HashMismatch)
        );
        let mut transfers = TransferRegistry::new(limits());
        let mut oversized = begin(id, &[]);
        oversized.declared_length = limits().maximum_bytes + 1;
        assert_eq!(
            transfers.begin(actor, oversized),
            Err(TransferError::BoundExceeded)
        );
    }

    #[test]
    fn cancellation_is_terminal_and_capacity_is_bounded() {
        let actor = [1; 16];
        let mut transfers = TransferRegistry::new(limits());
        for value in [1_u8, 2] {
            transfers.begin(actor, begin([value; 16], &[])).unwrap();
        }
        assert_eq!(
            transfers.begin(actor, begin([3; 16], &[])),
            Err(TransferError::Capacity)
        );
        let receipt = transfers
            .cancel(
                actor,
                TransferCancel {
                    transfer_id: [1; 16],
                    reason: 1,
                },
            )
            .unwrap();
        assert_eq!(receipt.terminal, TransferTerminal::Canceled);
        assert_eq!(
            transfers.cancel(
                actor,
                TransferCancel {
                    transfer_id: [1; 16],
                    reason: 1,
                },
            ),
            Err(TransferError::Unknown)
        );
    }

    #[test]
    fn transfer_messages_match_the_frozen_protocol_shapes() {
        let body = b"data";
        let messages = [
            TransferMessage::Begin(begin([1; 16], body)),
            TransferMessage::Data(TransferData {
                transfer_id: [1; 16],
                chunk_index: 2,
                offset: 4,
                chunk_hash: hash(body),
                bytes: body.to_vec(),
            }),
            TransferMessage::End(TransferEnd {
                transfer_id: [1; 16],
                chunk_count: 1,
                total_length: 4,
                total_hash: hash(body),
                terminal_status: 1,
                receipt: b"receipt".to_vec(),
            }),
            TransferMessage::Cancel(TransferCancel {
                transfer_id: [1; 16],
                reason: 2,
            }),
            TransferMessage::CancelAck(TransferCancelAck {
                transfer_id: [1; 16],
                disposition: 1,
                receipt: Some(b"receipt".to_vec()),
            }),
            TransferMessage::Receipt(TransferReceiptMessage {
                transfer_id: [1; 16],
                receipt: b"receipt".to_vec(),
            }),
        ];
        for message in messages {
            let (message_type, payload) = message.encode().unwrap();
            assert_eq!(
                TransferMessage::decode(message_type, &payload).unwrap(),
                message
            );
        }
    }

    #[test]
    fn malformed_transfer_corpus_never_panics_or_allocates_unboundedly() {
        let mut state = 0x4d59_5df4_d0f3_3173_u64;
        for length in 0..512 {
            let mut input = vec![0_u8; length];
            for byte in &mut input {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                *byte = state.to_le_bytes()[4];
            }
            for message_type in [
                MessageType::TransferBegin,
                MessageType::TransferData,
                MessageType::TransferEnd,
                MessageType::TransferCancel,
                MessageType::TransferCancelAck,
                MessageType::TransferReceipt,
            ] {
                let _ = TransferMessage::decode(message_type, &input);
            }
        }
    }
}
