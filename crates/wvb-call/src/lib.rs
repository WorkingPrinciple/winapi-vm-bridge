//! Canonical chunked call and result message encoding and assembly.

use sha2::{Digest, Sha256};
use wvb_protocol::{
    MessageType, PackedDecoder, PackedEncoder, ProtocolError, WireType, top_level_schema_id,
};

const REQUIRED: u8 = 0x01;
pub const LOGICAL_MAX: usize = 1_048_576;
pub const CHUNK_MAX: usize = 64 * 1024;

#[derive(Debug)]
pub enum CallError {
    Protocol(ProtocolError),
    Invalid(&'static str),
    BoundExceeded,
    HashMismatch,
}

impl std::fmt::Display for CallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CallError {}

impl From<ProtocolError> for CallError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRequest {
    pub adapter_hash: [u8; 32],
    pub operation_id: u32,
    pub request_schema_id: u32,
    pub deduplication_mode: u16,
    pub idempotency_key: Option<[u8; 16]>,
    pub disconnect_policy: u16,
    pub sensitivity: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallResult {
    pub response_schema_id: u32,
    pub operation_uuid: Option<[u8; 16]>,
    pub native_status: Vec<u8>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

impl CallRequest {
    pub fn messages(&self) -> Result<Vec<Message>, CallError> {
        if self.body.len() > LOGICAL_MAX {
            return Err(CallError::BoundExceeded);
        }
        let request_hash = hash(&self.body);
        let mut begin = PackedEncoder::new(top_level_schema_id(MessageType::CallBegin), 1)
            .field(1, WireType::Bytes, REQUIRED, self.adapter_hash.to_vec())?
            .field(2, WireType::U32, REQUIRED, self.operation_id.to_le_bytes())?
            .field(
                3,
                WireType::U32,
                REQUIRED,
                self.request_schema_id.to_le_bytes(),
            )?
            .field(
                4,
                WireType::U16,
                REQUIRED,
                self.deduplication_mode.to_le_bytes(),
            )?
            .field(6, WireType::Bytes, REQUIRED, request_hash.to_vec())?
            .field(
                7,
                WireType::U16,
                REQUIRED,
                self.disconnect_policy.to_le_bytes(),
            )?
            .field(8, WireType::U16, REQUIRED, self.sensitivity.to_le_bytes())?;
        if let Some(key) = self.idempotency_key {
            begin = begin.field(5, WireType::Uuid128, 0, key)?;
        }
        let mut messages = vec![Message {
            message_type: MessageType::CallBegin,
            payload: begin.encode()?,
        }];
        append_chunks(&mut messages, MessageType::CallData, &self.body)?;
        messages.push(Message {
            message_type: MessageType::CallEnd,
            payload: encode_end(MessageType::CallEnd, &self.body)?,
        });
        Ok(messages)
    }
}

impl CallResult {
    pub fn messages(&self) -> Result<Vec<Message>, CallError> {
        if self.body.len() > LOGICAL_MAX {
            return Err(CallError::BoundExceeded);
        }
        let mut begin = PackedEncoder::new(top_level_schema_id(MessageType::ResultBegin), 1)
            .field(
                1,
                WireType::U32,
                REQUIRED,
                self.response_schema_id.to_le_bytes(),
            )?
            .field(3, WireType::Nested, REQUIRED, self.native_status.clone())?
            .field(
                4,
                WireType::U64,
                REQUIRED,
                u64::try_from(self.body.len())
                    .map_err(|_| CallError::BoundExceeded)?
                    .to_le_bytes(),
            )?;
        if let Some(operation) = self.operation_uuid {
            begin = begin.field(2, WireType::Uuid128, 0, operation)?;
        }
        let mut messages = vec![Message {
            message_type: MessageType::ResultBegin,
            payload: begin.encode()?,
        }];
        append_chunks(&mut messages, MessageType::ResultData, &self.body)?;
        messages.push(Message {
            message_type: MessageType::ResultEnd,
            payload: encode_end(MessageType::ResultEnd, &self.body)?,
        });
        Ok(messages)
    }
}

#[derive(Debug, Default)]
pub struct CallAssembler {
    begin: Option<CallRequest>,
    expected_hash: Option<[u8; 32]>,
    expected_chunk: u32,
    expected_offset: u64,
    expected_total: Option<u64>,
    body: Vec<u8>,
}

impl CallAssembler {
    pub fn push(
        &mut self,
        message_type: MessageType,
        payload: &[u8],
    ) -> Result<Option<CallRequest>, CallError> {
        match message_type {
            MessageType::CallBegin => {
                if self.begin.is_some() {
                    return Err(CallError::Invalid("duplicate CALL_BEGIN"));
                }
                let (begin, expected_hash) = decode_call_begin(payload)?;
                self.begin = Some(begin);
                self.expected_hash = Some(expected_hash);
                Ok(None)
            }
            MessageType::CallData => {
                if self.begin.is_none() {
                    return Err(CallError::Invalid("CALL_DATA before CALL_BEGIN"));
                }
                append_decoded_chunk(
                    payload,
                    MessageType::CallData,
                    self.expected_chunk,
                    self.expected_offset,
                    &mut self.expected_total,
                    &mut self.body,
                )?;
                self.expected_chunk = self
                    .expected_chunk
                    .checked_add(1)
                    .ok_or(CallError::BoundExceeded)?;
                self.expected_offset =
                    u64::try_from(self.body.len()).map_err(|_| CallError::BoundExceeded)?;
                Ok(None)
            }
            MessageType::CallEnd => {
                let mut request = self
                    .begin
                    .take()
                    .ok_or(CallError::Invalid("CALL_END before CALL_BEGIN"))?;
                validate_end(
                    payload,
                    MessageType::CallEnd,
                    self.expected_chunk,
                    &self.body,
                )?;
                if self.expected_hash.take() != Some(hash(&self.body)) {
                    return Err(CallError::HashMismatch);
                }
                if self
                    .expected_total
                    .is_some_and(|total| total != self.expected_offset)
                {
                    return Err(CallError::Invalid("logical total mismatch"));
                }
                request.body = std::mem::take(&mut self.body);
                self.expected_chunk = 0;
                self.expected_offset = 0;
                self.expected_total = None;
                Ok(Some(request))
            }
            _ => Err(CallError::Invalid("unexpected call message")),
        }
    }
}

fn decode_call_begin(payload: &[u8]) -> Result<(CallRequest, [u8; 32]), CallError> {
    let decoder = PackedDecoder::decode(payload)?;
    require_schema(&decoder, MessageType::CallBegin)?;
    let adapter_hash = required(&decoder, 1, WireType::Bytes)?
        .try_into()
        .map_err(|_| CallError::Invalid("adapter hash length"))?;
    let request_hash = required(&decoder, 6, WireType::Bytes)?
        .try_into()
        .map_err(|_| CallError::Invalid("request hash length"))?;
    Ok((
        CallRequest {
            adapter_hash,
            operation_id: read_u32(required(&decoder, 2, WireType::U32)?)?,
            request_schema_id: read_u32(required(&decoder, 3, WireType::U32)?)?,
            deduplication_mode: read_u16(required(&decoder, 4, WireType::U16)?)?,
            idempotency_key: optional_uuid(&decoder, 5)?,
            disconnect_policy: read_u16(required(&decoder, 7, WireType::U16)?)?,
            sensitivity: read_u16(required(&decoder, 8, WireType::U16)?)?,
            body: Vec::new(),
        },
        request_hash,
    ))
}

#[derive(Debug, Default)]
pub struct ResultAssembler {
    begin: Option<CallResult>,
    expected_chunk: u32,
    expected_offset: u64,
    expected_total: Option<u64>,
    body: Vec<u8>,
}

impl ResultAssembler {
    pub fn push(
        &mut self,
        message_type: MessageType,
        payload: &[u8],
    ) -> Result<Option<CallResult>, CallError> {
        match message_type {
            MessageType::ResultBegin => {
                if self.begin.is_some() {
                    return Err(CallError::Invalid("duplicate RESULT_BEGIN"));
                }
                let (begin, expected_total) = decode_result_begin(payload)?;
                self.begin = Some(begin);
                self.expected_total = Some(expected_total);
                Ok(None)
            }
            MessageType::ResultData => {
                if self.begin.is_none() {
                    return Err(CallError::Invalid("RESULT_DATA before RESULT_BEGIN"));
                }
                append_decoded_chunk(
                    payload,
                    MessageType::ResultData,
                    self.expected_chunk,
                    self.expected_offset,
                    &mut self.expected_total,
                    &mut self.body,
                )?;
                self.expected_chunk = self
                    .expected_chunk
                    .checked_add(1)
                    .ok_or(CallError::BoundExceeded)?;
                self.expected_offset =
                    u64::try_from(self.body.len()).map_err(|_| CallError::BoundExceeded)?;
                Ok(None)
            }
            MessageType::ResultEnd => {
                let mut result = self
                    .begin
                    .take()
                    .ok_or(CallError::Invalid("RESULT_END before RESULT_BEGIN"))?;
                validate_end(
                    payload,
                    MessageType::ResultEnd,
                    self.expected_chunk,
                    &self.body,
                )?;
                if self.expected_total != Some(self.expected_offset) {
                    return Err(CallError::Invalid("result logical total mismatch"));
                }
                result.body = std::mem::take(&mut self.body);
                self.expected_chunk = 0;
                self.expected_offset = 0;
                self.expected_total = None;
                Ok(Some(result))
            }
            _ => Err(CallError::Invalid("unexpected result message")),
        }
    }
}

fn decode_result_begin(payload: &[u8]) -> Result<(CallResult, u64), CallError> {
    let decoder = PackedDecoder::decode(payload)?;
    require_schema(&decoder, MessageType::ResultBegin)?;
    let total = read_u64(required(&decoder, 4, WireType::U64)?)?;
    if total > LOGICAL_MAX as u64 {
        return Err(CallError::BoundExceeded);
    }
    Ok((
        CallResult {
            response_schema_id: read_u32(required(&decoder, 1, WireType::U32)?)?,
            operation_uuid: optional_uuid(&decoder, 2)?,
            native_status: required(&decoder, 3, WireType::Nested)?.to_vec(),
            body: Vec::new(),
        },
        total,
    ))
}

fn append_chunks(
    output: &mut Vec<Message>,
    message_type: MessageType,
    body: &[u8],
) -> Result<(), CallError> {
    let total = u64::try_from(body.len()).map_err(|_| CallError::BoundExceeded)?;
    for (index, chunk) in body.chunks(CHUNK_MAX).enumerate() {
        let offset = index
            .checked_mul(CHUNK_MAX)
            .ok_or(CallError::BoundExceeded)?;
        output.push(Message {
            message_type,
            payload: PackedEncoder::new(top_level_schema_id(message_type), 1)
                .field(
                    1,
                    WireType::U32,
                    REQUIRED,
                    u32::try_from(index)
                        .map_err(|_| CallError::BoundExceeded)?
                        .to_le_bytes(),
                )?
                .field(
                    2,
                    WireType::U64,
                    REQUIRED,
                    u64::try_from(offset)
                        .map_err(|_| CallError::BoundExceeded)?
                        .to_le_bytes(),
                )?
                .field(3, WireType::U64, REQUIRED, total.to_le_bytes())?
                .field(4, WireType::Bytes, REQUIRED, hash(chunk).to_vec())?
                .field(5, WireType::Bytes, REQUIRED, chunk.to_vec())?
                .encode()?,
        });
    }
    Ok(())
}

fn append_decoded_chunk(
    payload: &[u8],
    message_type: MessageType,
    expected_chunk: u32,
    expected_offset: u64,
    expected_total: &mut Option<u64>,
    body: &mut Vec<u8>,
) -> Result<(), CallError> {
    let decoder = PackedDecoder::decode(payload)?;
    require_schema(&decoder, message_type)?;
    if read_u32(required(&decoder, 1, WireType::U32)?)? != expected_chunk
        || read_u64(required(&decoder, 2, WireType::U64)?)? != expected_offset
    {
        return Err(CallError::Invalid("chunk order"));
    }
    let total = read_u64(required(&decoder, 3, WireType::U64)?)?;
    if total > LOGICAL_MAX as u64 || expected_total.is_some_and(|value| value != total) {
        return Err(CallError::BoundExceeded);
    }
    *expected_total = Some(total);
    let expected_hash = required(&decoder, 4, WireType::Bytes)?;
    let data = required(&decoder, 5, WireType::Bytes)?;
    if data.len() > CHUNK_MAX || expected_hash != hash(data) {
        return Err(CallError::HashMismatch);
    }
    let new_length = body
        .len()
        .checked_add(data.len())
        .ok_or(CallError::BoundExceeded)?;
    if new_length > LOGICAL_MAX || u64::try_from(new_length).unwrap_or(u64::MAX) > total {
        return Err(CallError::BoundExceeded);
    }
    body.extend_from_slice(data);
    Ok(())
}

fn encode_end(message_type: MessageType, body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let chunk_count = body.len().div_ceil(CHUNK_MAX);
    PackedEncoder::new(top_level_schema_id(message_type), 1)
        .field(
            1,
            WireType::U32,
            REQUIRED,
            u32::try_from(chunk_count)
                .map_err(|_| ProtocolError::FieldBoundsExceeded)?
                .to_le_bytes(),
        )?
        .field(2, WireType::Bytes, REQUIRED, hash(body).to_vec())?
        .encode()
}

fn validate_end(
    payload: &[u8],
    message_type: MessageType,
    expected_chunks: u32,
    body: &[u8],
) -> Result<(), CallError> {
    let decoder = PackedDecoder::decode(payload)?;
    require_schema(&decoder, message_type)?;
    if read_u32(required(&decoder, 1, WireType::U32)?)? != expected_chunks {
        return Err(CallError::Invalid("chunk count"));
    }
    if required(&decoder, 2, WireType::Bytes)? != hash(body) {
        return Err(CallError::HashMismatch);
    }
    Ok(())
}

fn require_schema(decoder: &PackedDecoder<'_>, message_type: MessageType) -> Result<(), CallError> {
    if decoder.schema_id != top_level_schema_id(message_type) || decoder.schema_version != 1 {
        return Err(CallError::Invalid("schema mismatch"));
    }
    Ok(())
}

fn required<'a>(
    decoder: &'a PackedDecoder<'a>,
    tag: u16,
    wire_type: WireType,
) -> Result<&'a [u8], CallError> {
    let field = decoder
        .field(tag)
        .ok_or(CallError::Invalid("required field missing"))?;
    if field.wire_type != wire_type || field.flags & REQUIRED == 0 {
        return Err(CallError::Invalid("field type or required flag"));
    }
    Ok(field.value)
}

fn optional_uuid(decoder: &PackedDecoder<'_>, tag: u16) -> Result<Option<[u8; 16]>, CallError> {
    decoder
        .field(tag)
        .map(|field| {
            if field.wire_type != WireType::Uuid128 || field.flags & REQUIRED != 0 {
                return Err(CallError::Invalid("optional uuid"));
            }
            field
                .value
                .try_into()
                .map_err(|_| CallError::Invalid("uuid length"))
        })
        .transpose()
}

fn read_u16(value: &[u8]) -> Result<u16, CallError> {
    Ok(u16::from_le_bytes(
        value
            .try_into()
            .map_err(|_| CallError::Invalid("u16 length"))?,
    ))
}

fn read_u32(value: &[u8]) -> Result<u32, CallError> {
    Ok(u32::from_le_bytes(
        value
            .try_into()
            .map_err(|_| CallError::Invalid("u32 length"))?,
    ))
}

fn read_u64(value: &[u8]) -> Result<u64, CallError> {
    Ok(u64::from_le_bytes(
        value
            .try_into()
            .map_err(|_| CallError::Invalid("u64 length"))?,
    ))
}

fn hash(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(body: Vec<u8>) -> CallRequest {
        CallRequest {
            adapter_hash: [1; 32],
            operation_id: 7,
            request_schema_id: 0x3000_0007,
            deduplication_mode: 1,
            idempotency_key: Some([2; 16]),
            disconnect_policy: 1,
            sensitivity: 0,
            body,
        }
    }

    #[test]
    fn one_mebibyte_call_round_trips_through_canonical_messages() {
        let expected = request(vec![0xa5; LOGICAL_MAX]);
        let messages = expected.messages().unwrap();
        assert_eq!(messages.len(), 18);
        let mut assembler = CallAssembler::default();
        let mut observed = None;
        for message in messages {
            observed = assembler
                .push(message.message_type, &message.payload)
                .unwrap()
                .or(observed);
        }
        assert_eq!(observed, Some(expected));
    }

    #[test]
    fn reordered_or_corrupt_chunks_fail_closed() {
        let expected = request(vec![3; CHUNK_MAX + 1]);
        let mut messages = expected.messages().unwrap();
        messages.swap(1, 2);
        let mut assembler = CallAssembler::default();
        assembler
            .push(messages[0].message_type, &messages[0].payload)
            .unwrap();
        assert!(matches!(
            assembler.push(messages[1].message_type, &messages[1].payload),
            Err(CallError::Invalid("chunk order"))
        ));

        let mut messages = expected.messages().unwrap();
        let last = messages[1].payload.len() - 1;
        messages[1].payload[last] ^= 1;
        let mut assembler = CallAssembler::default();
        assembler
            .push(messages[0].message_type, &messages[0].payload)
            .unwrap();
        assert!(matches!(
            assembler.push(messages[1].message_type, &messages[1].payload),
            Err(CallError::HashMismatch)
        ));
    }

    #[test]
    fn result_round_trips_and_validates_total() {
        let expected = CallResult {
            response_schema_id: 0x4000_0007,
            operation_uuid: Some([8; 16]),
            native_status: PackedEncoder::new(0x1005, 1)
                .field(1, WireType::U16, REQUIRED, 1_u16.to_le_bytes())
                .unwrap()
                .field(2, WireType::I64, REQUIRED, 0_i64.to_le_bytes())
                .unwrap()
                .encode()
                .unwrap(),
            body: vec![9; CHUNK_MAX + 5],
        };
        let messages = expected.messages().unwrap();
        let mut assembler = ResultAssembler::default();
        let mut observed = None;
        for message in messages {
            observed = assembler
                .push(message.message_type, &message.payload)
                .unwrap()
                .or(observed);
        }
        assert_eq!(observed, Some(expected));
    }
}
