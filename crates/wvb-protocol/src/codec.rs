use std::collections::BTreeSet;

use crate::ProtocolError;

const PREFIX_BYTES: usize = 8;
const FIELD_HEADER_BYTES: usize = 8;
pub const FIELD_COUNT_MAX: usize = 4_096;
pub const NESTING_MAX: usize = 32;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    U8 = 1,
    U16 = 2,
    U32 = 3,
    U64 = 4,
    I32 = 5,
    I64 = 6,
    F32 = 7,
    F64 = 8,
    Bool = 9,
    Bytes = 10,
    Utf8 = 11,
    Uuid128 = 12,
    Nested = 13,
    RepeatedNested = 14,
}

impl TryFrom<u8> for WireType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::U8),
            2 => Ok(Self::U16),
            3 => Ok(Self::U32),
            4 => Ok(Self::U64),
            5 => Ok(Self::I32),
            6 => Ok(Self::I64),
            7 => Ok(Self::F32),
            8 => Ok(Self::F64),
            9 => Ok(Self::Bool),
            10 => Ok(Self::Bytes),
            11 => Ok(Self::Utf8),
            12 => Ok(Self::Uuid128),
            13 => Ok(Self::Nested),
            14 => Ok(Self::RepeatedNested),
            _ => Err(ProtocolError::FieldTypeInvalid),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedField<'a> {
    pub tag: u16,
    pub wire_type: WireType,
    pub flags: u8,
    pub value: &'a [u8],
}

#[derive(Debug)]
pub struct PackedEncoder {
    schema_id: u32,
    schema_version: u16,
    fields: Vec<OwnedField>,
}

#[derive(Debug)]
struct OwnedField {
    tag: u16,
    wire_type: WireType,
    flags: u8,
    value: Vec<u8>,
}

impl PackedEncoder {
    #[must_use]
    pub fn new(schema_id: u32, schema_version: u16) -> Self {
        Self {
            schema_id,
            schema_version,
            fields: Vec::new(),
        }
    }

    pub fn field(
        mut self,
        tag: u16,
        wire_type: WireType,
        flags: u8,
        value: impl Into<Vec<u8>>,
    ) -> Result<Self, ProtocolError> {
        if tag == 0 || self.fields.len() >= FIELD_COUNT_MAX {
            return Err(ProtocolError::FieldBoundsExceeded);
        }
        let value = value.into();
        validate_scalar(wire_type, &value)?;
        if self
            .fields
            .iter()
            .any(|field| field.tag == tag && flags & 0x02 == 0)
        {
            return Err(ProtocolError::FieldDuplicate);
        }
        self.fields.push(OwnedField {
            tag,
            wire_type,
            flags,
            value,
        });
        Ok(self)
    }

    pub fn encode(mut self) -> Result<Vec<u8>, ProtocolError> {
        self.fields.sort_by_key(|field| field.tag);
        let field_count =
            u16::try_from(self.fields.len()).map_err(|_| ProtocolError::FieldBoundsExceeded)?;
        let payload_bytes = self.fields.iter().try_fold(0_usize, |sum, field| {
            sum.checked_add(FIELD_HEADER_BYTES + field.value.len())
                .ok_or(ProtocolError::FieldBoundsExceeded)
        })?;
        let mut output = Vec::with_capacity(PREFIX_BYTES + payload_bytes);
        output.extend_from_slice(&self.schema_id.to_le_bytes());
        output.extend_from_slice(&self.schema_version.to_le_bytes());
        output.extend_from_slice(&field_count.to_le_bytes());
        for field in self.fields {
            output.extend_from_slice(&field.tag.to_le_bytes());
            output.push(field.wire_type as u8);
            output.push(field.flags);
            let length =
                u32::try_from(field.value.len()).map_err(|_| ProtocolError::FieldBoundsExceeded)?;
            output.extend_from_slice(&length.to_le_bytes());
            output.extend_from_slice(&field.value);
        }
        Ok(output)
    }
}

#[derive(Debug)]
pub struct PackedDecoder<'a> {
    pub schema_id: u32,
    pub schema_version: u16,
    fields: Vec<DecodedField<'a>>,
}

impl<'a> PackedDecoder<'a> {
    pub fn decode(input: &'a [u8]) -> Result<Self, ProtocolError> {
        if input.len() < PREFIX_BYTES {
            return Err(ProtocolError::PackedHeaderInvalid);
        }
        let schema_id = read_u32(input, 0);
        let schema_version = read_u16(input, 4);
        let field_count = usize::from(read_u16(input, 6));
        if field_count > FIELD_COUNT_MAX {
            return Err(ProtocolError::FieldBoundsExceeded);
        }
        let mut offset = PREFIX_BYTES;
        let mut last_tag = 0_u16;
        let mut seen_non_repeated = BTreeSet::new();
        let mut fields = Vec::with_capacity(field_count);
        for _ in 0..field_count {
            if input.len().saturating_sub(offset) < FIELD_HEADER_BYTES {
                return Err(ProtocolError::PackedHeaderInvalid);
            }
            let tag = read_u16(input, offset);
            let wire_type = WireType::try_from(input[offset + 2])?;
            let flags = input[offset + 3];
            let length = usize::try_from(read_u32(input, offset + 4))
                .map_err(|_| ProtocolError::FieldBoundsExceeded)?;
            offset += FIELD_HEADER_BYTES;
            let end = offset
                .checked_add(length)
                .ok_or(ProtocolError::FieldBoundsExceeded)?;
            let value = input
                .get(offset..end)
                .ok_or(ProtocolError::FieldBoundsExceeded)?;
            if tag == 0 || tag < last_tag {
                return Err(ProtocolError::FieldOrderInvalid);
            }
            if flags & 0x02 == 0 && !seen_non_repeated.insert(tag) {
                return Err(ProtocolError::FieldDuplicate);
            }
            validate_scalar(wire_type, value)?;
            fields.push(DecodedField {
                tag,
                wire_type,
                flags,
                value,
            });
            last_tag = tag;
            offset = end;
        }
        if offset != input.len() {
            return Err(ProtocolError::FieldBoundsExceeded);
        }
        Ok(Self {
            schema_id,
            schema_version,
            fields,
        })
    }

    #[must_use]
    pub fn fields(&self) -> &[DecodedField<'a>] {
        &self.fields
    }

    #[must_use]
    pub fn field(&self, tag: u16) -> Option<DecodedField<'a>> {
        self.fields.iter().copied().find(|field| field.tag == tag)
    }
}

fn validate_scalar(wire_type: WireType, value: &[u8]) -> Result<(), ProtocolError> {
    let exact = match wire_type {
        WireType::U8 | WireType::Bool => Some(1),
        WireType::U16 => Some(2),
        WireType::U32 | WireType::I32 | WireType::F32 => Some(4),
        WireType::U64 | WireType::I64 | WireType::F64 => Some(8),
        WireType::Uuid128 => Some(16),
        WireType::Bytes | WireType::Nested | WireType::RepeatedNested | WireType::Utf8 => None,
    };
    if exact.is_some_and(|size| value.len() != size) {
        return Err(ProtocolError::FieldTypeInvalid);
    }
    if wire_type == WireType::Bool && value[0] > 1 {
        return Err(ProtocolError::FieldTypeInvalid);
    }
    if wire_type == WireType::Utf8 && std::str::from_utf8(value).is_err() {
        return Err(ProtocolError::FieldTypeInvalid);
    }
    Ok(())
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    let mut bytes = [0_u8; 2];
    bytes.copy_from_slice(&input[offset..offset + 2]);
    u16::from_le_bytes(bytes)
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(&input[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_fields_round_trip() {
        let encoded = PackedEncoder::new(0x2000_0100, 1)
            .field(2, WireType::U32, 0x01, 42_u32.to_le_bytes())
            .unwrap()
            .field(1, WireType::Utf8, 0x01, b"adapter".to_vec())
            .unwrap()
            .encode()
            .unwrap();
        let decoded = PackedDecoder::decode(&encoded).unwrap();
        assert_eq!(decoded.schema_id, 0x2000_0100);
        assert_eq!(decoded.fields()[0].tag, 1);
        assert_eq!(decoded.fields()[1].tag, 2);
    }

    #[test]
    fn duplicates_and_invalid_utf8_fail() {
        let duplicate = PackedEncoder::new(1, 1)
            .field(1, WireType::U8, 0, [1])
            .unwrap()
            .field(1, WireType::U8, 0, [2])
            .unwrap_err();
        assert_eq!(duplicate, ProtocolError::FieldDuplicate);
        let utf8 = PackedEncoder::new(1, 1)
            .field(1, WireType::Utf8, 0, [0xff])
            .unwrap_err();
        assert_eq!(utf8, ProtocolError::FieldTypeInvalid);
    }
}
