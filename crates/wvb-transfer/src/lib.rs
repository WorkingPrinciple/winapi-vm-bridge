//! Bounded content-addressed transfer lifecycle for the runtime plane.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use wvb_protocol::{
    MessageType, PackedDecoder, PackedEncoder, ProtocolError, WireType, top_level_schema_id,
};

const REQUIRED: u8 = 0x01;

pub type TransferId = [u8; 16];
pub type ActorId = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferLimits {
    pub maximum_bytes: usize,
    pub maximum_chunk_bytes: usize,
    pub maximum_active: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKind {
    RequestInput,
    ResponseOutput,
    ProcessStdin,
    ProcessStdout,
    ProcessStderr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferBegin {
    pub transfer_id: TransferId,
    pub actor_id: ActorId,
    pub kind: TransferKind,
    pub total_bytes: usize,
    pub sha256: [u8; 32],
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
pub struct TransferData {
    pub transfer_id: TransferId,
    pub sequence: u32,
    pub offset: usize,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferMessage {
    Begin(TransferBegin),
    Data(TransferData),
    End(TransferId),
    Cancel(TransferId),
    Receipt(TransferReceipt),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferTerminal {
    Completed,
    Cancelled,
    Failed,
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
    Cancelled,
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

impl TransferMessage {
    pub fn encode(&self) -> Result<(MessageType, Vec<u8>), TransferError> {
        match self {
            Self::Begin(begin) => Ok((
                MessageType::TransferBegin,
                PackedEncoder::new(top_level_schema_id(MessageType::TransferBegin), 1)
                    .field(1, WireType::Uuid128, REQUIRED, begin.transfer_id)?
                    .field(2, WireType::Uuid128, REQUIRED, begin.actor_id)?
                    .field(
                        3,
                        WireType::U16,
                        REQUIRED,
                        kind_value(begin.kind).to_le_bytes(),
                    )?
                    .field(
                        4,
                        WireType::U64,
                        REQUIRED,
                        u64::try_from(begin.total_bytes)
                            .map_err(|_| TransferError::BoundExceeded)?
                            .to_le_bytes(),
                    )?
                    .field(5, WireType::Bytes, REQUIRED, begin.sha256)?
                    .encode()?,
            )),
            Self::Data(data) => Ok((
                MessageType::TransferData,
                PackedEncoder::new(top_level_schema_id(MessageType::TransferData), 1)
                    .field(1, WireType::Uuid128, REQUIRED, data.transfer_id)?
                    .field(2, WireType::U32, REQUIRED, data.sequence.to_le_bytes())?
                    .field(
                        3,
                        WireType::U64,
                        REQUIRED,
                        u64::try_from(data.offset)
                            .map_err(|_| TransferError::BoundExceeded)?
                            .to_le_bytes(),
                    )?
                    .field(4, WireType::Bytes, REQUIRED, data.bytes.clone())?
                    .encode()?,
            )),
            Self::End(transfer_id) => encode_id(MessageType::TransferEnd, *transfer_id),
            Self::Cancel(transfer_id) => encode_id(MessageType::TransferCancel, *transfer_id),
            Self::Receipt(receipt) => Ok((
                MessageType::TransferReceipt,
                PackedEncoder::new(top_level_schema_id(MessageType::TransferReceipt), 1)
                    .field(1, WireType::Uuid128, REQUIRED, receipt.transfer_id)?
                    .field(2, WireType::Uuid128, REQUIRED, receipt.actor_id)?
                    .field(
                        3,
                        WireType::U16,
                        REQUIRED,
                        kind_value(receipt.kind).to_le_bytes(),
                    )?
                    .field(
                        4,
                        WireType::U64,
                        REQUIRED,
                        u64::try_from(receipt.total_bytes)
                            .map_err(|_| TransferError::BoundExceeded)?
                            .to_le_bytes(),
                    )?
                    .field(5, WireType::Bytes, REQUIRED, receipt.sha256)?
                    .field(
                        6,
                        WireType::U16,
                        REQUIRED,
                        terminal_value(receipt.terminal).to_le_bytes(),
                    )?
                    .encode()?,
            )),
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
                actor_id: uuid(&decoder, 2)?,
                kind: decode_kind(u16_value(&decoder, 3)?)?,
                total_bytes: usize::try_from(u64_value(&decoder, 4)?)
                    .map_err(|_| TransferError::BoundExceeded)?,
                sha256: bytes(&decoder, 5)?
                    .try_into()
                    .map_err(|_| TransferError::Protocol)?,
            })),
            MessageType::TransferData => Ok(Self::Data(TransferData {
                transfer_id: uuid(&decoder, 1)?,
                sequence: u32_value(&decoder, 2)?,
                offset: usize::try_from(u64_value(&decoder, 3)?)
                    .map_err(|_| TransferError::BoundExceeded)?,
                bytes: bytes(&decoder, 4)?.to_vec(),
            })),
            MessageType::TransferEnd => Ok(Self::End(uuid(&decoder, 1)?)),
            MessageType::TransferCancel => Ok(Self::Cancel(uuid(&decoder, 1)?)),
            MessageType::TransferReceipt => Ok(Self::Receipt(TransferReceipt {
                transfer_id: uuid(&decoder, 1)?,
                actor_id: uuid(&decoder, 2)?,
                kind: decode_kind(u16_value(&decoder, 3)?)?,
                total_bytes: usize::try_from(u64_value(&decoder, 4)?)
                    .map_err(|_| TransferError::BoundExceeded)?,
                sha256: bytes(&decoder, 5)?
                    .try_into()
                    .map_err(|_| TransferError::Protocol)?,
                terminal: decode_terminal(u16_value(&decoder, 6)?)?,
            })),
            _ => Err(TransferError::Protocol),
        }
    }
}

fn encode_id(
    message_type: MessageType,
    transfer_id: TransferId,
) -> Result<(MessageType, Vec<u8>), TransferError> {
    Ok((
        message_type,
        PackedEncoder::new(top_level_schema_id(message_type), 1)
            .field(1, WireType::Uuid128, REQUIRED, transfer_id)?
            .encode()?,
    ))
}

const fn kind_value(kind: TransferKind) -> u16 {
    match kind {
        TransferKind::RequestInput => 1,
        TransferKind::ResponseOutput => 2,
        TransferKind::ProcessStdin => 3,
        TransferKind::ProcessStdout => 4,
        TransferKind::ProcessStderr => 5,
    }
}

fn decode_kind(value: u16) -> Result<TransferKind, TransferError> {
    match value {
        1 => Ok(TransferKind::RequestInput),
        2 => Ok(TransferKind::ResponseOutput),
        3 => Ok(TransferKind::ProcessStdin),
        4 => Ok(TransferKind::ProcessStdout),
        5 => Ok(TransferKind::ProcessStderr),
        _ => Err(TransferError::Protocol),
    }
}

const fn terminal_value(terminal: TransferTerminal) -> u16 {
    match terminal {
        TransferTerminal::Completed => 1,
        TransferTerminal::Cancelled => 2,
        TransferTerminal::Failed => 3,
    }
}

fn decode_terminal(value: u16) -> Result<TransferTerminal, TransferError> {
    match value {
        1 => Ok(TransferTerminal::Completed),
        2 => Ok(TransferTerminal::Cancelled),
        3 => Ok(TransferTerminal::Failed),
        _ => Err(TransferError::Protocol),
    }
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

fn uuid(decoder: &PackedDecoder<'_>, tag: u16) -> Result<[u8; 16], TransferError> {
    required(decoder, tag, WireType::Uuid128)?
        .try_into()
        .map_err(|_| TransferError::Protocol)
}

fn bytes<'a>(decoder: &'a PackedDecoder<'a>, tag: u16) -> Result<&'a [u8], TransferError> {
    required(decoder, tag, WireType::Bytes)
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

fn u64_value(decoder: &PackedDecoder<'_>, tag: u16) -> Result<u64, TransferError> {
    Ok(u64::from_le_bytes(
        required(decoder, tag, WireType::U64)?
            .try_into()
            .map_err(|_| TransferError::Protocol)?,
    ))
}

#[derive(Debug)]
struct ActiveTransfer {
    begin: TransferBegin,
    next_sequence: u32,
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct TransferRegistry {
    limits: TransferLimits,
    active: std::collections::BTreeMap<TransferId, ActiveTransfer>,
    terminal: BTreeSet<TransferId>,
}

impl TransferRegistry {
    #[must_use]
    pub fn new(limits: TransferLimits) -> Self {
        Self {
            limits,
            active: std::collections::BTreeMap::new(),
            terminal: BTreeSet::new(),
        }
    }

    pub fn begin(&mut self, begin: TransferBegin) -> Result<(), TransferError> {
        if self.active.len() >= self.limits.maximum_active {
            return Err(TransferError::Capacity);
        }
        if self.active.contains_key(&begin.transfer_id)
            || self.terminal.contains(&begin.transfer_id)
        {
            return Err(TransferError::Replay);
        }
        if begin.total_bytes > self.limits.maximum_bytes {
            return Err(TransferError::BoundExceeded);
        }
        self.active.insert(
            begin.transfer_id,
            ActiveTransfer {
                bytes: Vec::with_capacity(begin.total_bytes),
                begin,
                next_sequence: 0,
            },
        );
        Ok(())
    }

    pub fn data(
        &mut self,
        actor_id: ActorId,
        transfer_id: TransferId,
        sequence: u32,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), TransferError> {
        let active = self
            .active
            .get_mut(&transfer_id)
            .ok_or(TransferError::Unknown)?;
        if active.begin.actor_id != actor_id {
            return Err(TransferError::WrongActor);
        }
        if sequence != active.next_sequence || offset != active.bytes.len() {
            return Err(TransferError::InvalidOrder);
        }
        if bytes.len() > self.limits.maximum_chunk_bytes {
            return Err(TransferError::BoundExceeded);
        }
        let new_length = active
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(TransferError::BoundExceeded)?;
        if new_length > active.begin.total_bytes || new_length > self.limits.maximum_bytes {
            return Err(TransferError::BoundExceeded);
        }
        active.bytes.extend_from_slice(bytes);
        active.next_sequence = active
            .next_sequence
            .checked_add(1)
            .ok_or(TransferError::BoundExceeded)?;
        Ok(())
    }

    pub fn finish(
        &mut self,
        actor_id: ActorId,
        transfer_id: TransferId,
    ) -> Result<(Vec<u8>, TransferReceipt), TransferError> {
        let active = self
            .active
            .remove(&transfer_id)
            .ok_or(TransferError::Unknown)?;
        if active.begin.actor_id != actor_id {
            self.active.insert(transfer_id, active);
            return Err(TransferError::WrongActor);
        }
        self.terminal.insert(transfer_id);
        if active.bytes.len() != active.begin.total_bytes
            || hash(&active.bytes) != active.begin.sha256
        {
            return Err(TransferError::HashMismatch);
        }
        let receipt = TransferReceipt {
            transfer_id,
            actor_id,
            kind: active.begin.kind,
            total_bytes: active.bytes.len(),
            sha256: active.begin.sha256,
            terminal: TransferTerminal::Completed,
        };
        Ok((active.bytes, receipt))
    }

    pub fn cancel(
        &mut self,
        actor_id: ActorId,
        transfer_id: TransferId,
    ) -> Result<TransferReceipt, TransferError> {
        let active = self
            .active
            .remove(&transfer_id)
            .ok_or(TransferError::Unknown)?;
        if active.begin.actor_id != actor_id {
            self.active.insert(transfer_id, active);
            return Err(TransferError::WrongActor);
        }
        self.terminal.insert(transfer_id);
        Ok(TransferReceipt {
            transfer_id,
            actor_id,
            kind: active.begin.kind,
            total_bytes: active.bytes.len(),
            sha256: hash(&active.bytes),
            terminal: TransferTerminal::Cancelled,
        })
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }
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
        }
    }

    #[test]
    fn bounded_transfer_requires_order_hash_and_receipt() {
        let actor = [1; 16];
        let id = [2; 16];
        let body = vec![0xa5; 70_000];
        let mut transfers = TransferRegistry::new(limits());
        transfers
            .begin(TransferBegin {
                transfer_id: id,
                actor_id: actor,
                kind: TransferKind::RequestInput,
                total_bytes: body.len(),
                sha256: hash(&body),
            })
            .unwrap();
        transfers.data(actor, id, 0, 0, &body[..64 * 1024]).unwrap();
        transfers
            .data(actor, id, 1, 64 * 1024, &body[64 * 1024..])
            .unwrap();
        let (completed, receipt) = transfers.finish(actor, id).unwrap();
        assert_eq!(completed, body);
        assert_eq!(receipt.terminal, TransferTerminal::Completed);
        assert_eq!(
            transfers.begin(TransferBegin {
                transfer_id: id,
                actor_id: actor,
                kind: TransferKind::RequestInput,
                total_bytes: 0,
                sha256: hash(&[]),
            }),
            Err(TransferError::Replay)
        );
    }

    #[test]
    fn transfer_rejects_order_actor_hash_and_bounds() {
        let actor = [1; 16];
        let id = [2; 16];
        let mut transfers = TransferRegistry::new(limits());
        transfers
            .begin(TransferBegin {
                transfer_id: id,
                actor_id: actor,
                kind: TransferKind::ResponseOutput,
                total_bytes: 4,
                sha256: [0; 32],
            })
            .unwrap();
        assert_eq!(
            transfers.data([9; 16], id, 0, 0, b"data"),
            Err(TransferError::WrongActor)
        );
        assert_eq!(
            transfers.data(actor, id, 1, 0, b"data"),
            Err(TransferError::InvalidOrder)
        );
        transfers.data(actor, id, 0, 0, b"data").unwrap();
        assert_eq!(
            transfers.finish(actor, id),
            Err(TransferError::HashMismatch)
        );
        let mut transfers = TransferRegistry::new(limits());
        assert_eq!(
            transfers.begin(TransferBegin {
                transfer_id: id,
                actor_id: actor,
                kind: TransferKind::ResponseOutput,
                total_bytes: limits().maximum_bytes + 1,
                sha256: [0; 32],
            }),
            Err(TransferError::BoundExceeded)
        );
    }

    #[test]
    fn cancellation_is_terminal_and_capacity_is_bounded() {
        let actor = [1; 16];
        let mut transfers = TransferRegistry::new(limits());
        for value in [1_u8, 2] {
            transfers
                .begin(TransferBegin {
                    transfer_id: [value; 16],
                    actor_id: actor,
                    kind: TransferKind::ProcessStdout,
                    total_bytes: 0,
                    sha256: hash(&[]),
                })
                .unwrap();
        }
        assert_eq!(
            transfers.begin(TransferBegin {
                transfer_id: [3; 16],
                actor_id: actor,
                kind: TransferKind::ProcessStdout,
                total_bytes: 0,
                sha256: hash(&[]),
            }),
            Err(TransferError::Capacity)
        );
        let receipt = transfers.cancel(actor, [1; 16]).unwrap();
        assert_eq!(receipt.terminal, TransferTerminal::Cancelled);
        assert_eq!(
            transfers.cancel(actor, [1; 16]),
            Err(TransferError::Unknown)
        );
    }

    #[test]
    fn transfer_messages_round_trip_and_reject_wrong_schema() {
        let messages = [
            TransferMessage::Begin(TransferBegin {
                transfer_id: [1; 16],
                actor_id: [2; 16],
                kind: TransferKind::ProcessStdin,
                total_bytes: 4,
                sha256: [3; 32],
            }),
            TransferMessage::Data(TransferData {
                transfer_id: [1; 16],
                sequence: 2,
                offset: 4,
                bytes: b"data".to_vec(),
            }),
            TransferMessage::End([1; 16]),
            TransferMessage::Cancel([1; 16]),
            TransferMessage::Receipt(TransferReceipt {
                transfer_id: [1; 16],
                actor_id: [2; 16],
                kind: TransferKind::ProcessStdout,
                total_bytes: 4,
                sha256: [3; 32],
                terminal: TransferTerminal::Completed,
            }),
        ];
        for message in messages {
            let (message_type, payload) = message.encode().unwrap();
            assert_eq!(
                TransferMessage::decode(message_type, &payload).unwrap(),
                message
            );
        }
        let (_, payload) = TransferMessage::End([1; 16]).encode().unwrap();
        assert_eq!(
            TransferMessage::decode(MessageType::TransferCancel, &payload),
            Err(TransferError::Protocol)
        );
    }
}
