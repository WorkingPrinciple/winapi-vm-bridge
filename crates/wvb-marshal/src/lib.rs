//! Bounded canonical marshalling primitives for generated adapters.

use std::collections::BTreeMap;

const NULL_LENGTH: u32 = u32::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarshalError {
    BoundExceeded,
    Truncated,
    TrailingBytes,
    InvalidUtf8,
    InvalidUtf16,
    DuplicateField,
    UnknownField,
    MissingField,
    LayoutOverlap,
    LayoutOverflow,
}

impl std::fmt::Display for MarshalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for MarshalError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NullableBytes {
    Null,
    Present(Vec<u8>),
}

impl NullableBytes {
    pub fn encode(&self, max_bytes: usize) -> Result<Vec<u8>, MarshalError> {
        let mut output = Vec::new();
        match self {
            Self::Null => output.extend_from_slice(&NULL_LENGTH.to_le_bytes()),
            Self::Present(value) => {
                if value.len() > max_bytes {
                    return Err(MarshalError::BoundExceeded);
                }
                let length = u32::try_from(value.len()).map_err(|_| MarshalError::BoundExceeded)?;
                output.extend_from_slice(&length.to_le_bytes());
                output.extend_from_slice(value);
            }
        }
        Ok(output)
    }

    pub fn decode(input: &[u8], max_bytes: usize) -> Result<Self, MarshalError> {
        let (value, consumed) = Self::decode_prefix(input, max_bytes)?;
        if consumed != input.len() {
            return Err(MarshalError::TrailingBytes);
        }
        Ok(value)
    }

    fn decode_prefix(input: &[u8], max_bytes: usize) -> Result<(Self, usize), MarshalError> {
        let length = read_u32(input, 0)?;
        if length == NULL_LENGTH {
            return Ok((Self::Null, 4));
        }
        let length = usize::try_from(length).map_err(|_| MarshalError::BoundExceeded)?;
        if length > max_bytes {
            return Err(MarshalError::BoundExceeded);
        }
        let end = 4_usize
            .checked_add(length)
            .ok_or(MarshalError::BoundExceeded)?;
        let value = input.get(4..end).ok_or(MarshalError::Truncated)?;
        Ok((Self::Present(value.to_vec()), end))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NullableUtf8 {
    Null,
    Present(String),
}

impl NullableUtf8 {
    pub fn encode(&self, max_bytes: usize) -> Result<Vec<u8>, MarshalError> {
        match self {
            Self::Null => NullableBytes::Null.encode(max_bytes),
            Self::Present(value) => {
                NullableBytes::Present(value.as_bytes().to_vec()).encode(max_bytes)
            }
        }
    }

    pub fn decode(input: &[u8], max_bytes: usize) -> Result<Self, MarshalError> {
        match NullableBytes::decode(input, max_bytes)? {
            NullableBytes::Null => Ok(Self::Null),
            NullableBytes::Present(value) => String::from_utf8(value)
                .map(Self::Present)
                .map_err(|_| MarshalError::InvalidUtf8),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NullableUtf16 {
    Null,
    Present(Vec<u16>),
}

impl NullableUtf16 {
    pub fn encode(&self, max_code_units: usize) -> Result<Vec<u8>, MarshalError> {
        match self {
            Self::Null => NullableBytes::Null.encode(max_code_units.saturating_mul(2)),
            Self::Present(value) => {
                if value.len() > max_code_units
                    || char::decode_utf16(value.iter().copied()).any(|result| result.is_err())
                {
                    return Err(if value.len() > max_code_units {
                        MarshalError::BoundExceeded
                    } else {
                        MarshalError::InvalidUtf16
                    });
                }
                let bytes = value
                    .iter()
                    .flat_map(|unit| unit.to_le_bytes())
                    .collect::<Vec<_>>();
                NullableBytes::Present(bytes).encode(max_code_units.saturating_mul(2))
            }
        }
    }

    pub fn decode(input: &[u8], max_code_units: usize) -> Result<Self, MarshalError> {
        match NullableBytes::decode(input, max_code_units.saturating_mul(2))? {
            NullableBytes::Null => Ok(Self::Null),
            NullableBytes::Present(bytes) => {
                if bytes.len() % 2 != 0 {
                    return Err(MarshalError::InvalidUtf16);
                }
                let (pairs, remainder) = bytes.as_chunks::<2>();
                if !remainder.is_empty() {
                    return Err(MarshalError::InvalidUtf16);
                }
                let units = pairs
                    .iter()
                    .map(|pair| u16::from_le_bytes(*pair))
                    .collect::<Vec<_>>();
                if char::decode_utf16(units.iter().copied()).any(|result| result.is_err()) {
                    return Err(MarshalError::InvalidUtf16);
                }
                Ok(Self::Present(units))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordField {
    pub id: u16,
    pub offset: u32,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordLayout {
    size: u32,
    fields: BTreeMap<u16, RecordField>,
}

impl RecordLayout {
    pub fn new(
        size: u32,
        fields: impl IntoIterator<Item = RecordField>,
    ) -> Result<Self, MarshalError> {
        let mut ordered = BTreeMap::new();
        let mut ranges = Vec::new();
        for field in fields {
            if ordered.contains_key(&field.id) {
                return Err(MarshalError::DuplicateField);
            }
            let end = field
                .offset
                .checked_add(field.size)
                .ok_or(MarshalError::LayoutOverflow)?;
            if end > size {
                return Err(MarshalError::LayoutOverflow);
            }
            if ranges
                .iter()
                .any(|&(start, previous_end)| field.offset < previous_end && end > start)
            {
                return Err(MarshalError::LayoutOverlap);
            }
            ranges.push((field.offset, end));
            ordered.insert(field.id, field);
        }
        Ok(Self {
            size,
            fields: ordered,
        })
    }

    #[must_use]
    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn encode(&self, values: &BTreeMap<u16, Vec<u8>>) -> Result<Vec<u8>, MarshalError> {
        if values.keys().any(|id| !self.fields.contains_key(id)) {
            return Err(MarshalError::UnknownField);
        }
        let size = usize::try_from(self.size).map_err(|_| MarshalError::LayoutOverflow)?;
        let mut output = vec![0_u8; size];
        for (id, field) in &self.fields {
            let value = values.get(id).ok_or(MarshalError::MissingField)?;
            let expected = usize::try_from(field.size).map_err(|_| MarshalError::LayoutOverflow)?;
            if value.len() != expected {
                return Err(MarshalError::BoundExceeded);
            }
            let start = usize::try_from(field.offset).map_err(|_| MarshalError::LayoutOverflow)?;
            output[start..start + expected].copy_from_slice(value);
        }
        Ok(output)
    }

    pub fn decode(&self, input: &[u8]) -> Result<BTreeMap<u16, Vec<u8>>, MarshalError> {
        if input.len() != usize::try_from(self.size).map_err(|_| MarshalError::LayoutOverflow)? {
            return Err(MarshalError::BoundExceeded);
        }
        self.fields
            .iter()
            .map(|(id, field)| {
                let start =
                    usize::try_from(field.offset).map_err(|_| MarshalError::LayoutOverflow)?;
                let size = usize::try_from(field.size).map_err(|_| MarshalError::LayoutOverflow)?;
                Ok((*id, input[start..start + size].to_vec()))
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsufficientBuffer {
    pub required_bytes: usize,
}

pub fn copy_response(source: &[u8], destination: &mut [u8]) -> Result<usize, InsufficientBuffer> {
    if destination.len() < source.len() {
        return Err(InsufficientBuffer {
            required_bytes: source.len(),
        });
    }
    destination[..source.len()].copy_from_slice(source);
    Ok(source.len())
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, MarshalError> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or(MarshalError::Truncated)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| MarshalError::Truncated)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_empty_and_present_buffers_remain_distinct() {
        let null = NullableBytes::Null.encode(8).unwrap();
        let empty = NullableBytes::Present(Vec::new()).encode(8).unwrap();
        let value = NullableBytes::Present(vec![1, 2, 3]).encode(8).unwrap();
        assert_ne!(null, empty);
        assert_eq!(
            NullableBytes::decode(&null, 8).unwrap(),
            NullableBytes::Null
        );
        assert_eq!(
            NullableBytes::decode(&empty, 8).unwrap(),
            NullableBytes::Present(Vec::new())
        );
        assert_eq!(
            NullableBytes::decode(&value, 8).unwrap(),
            NullableBytes::Present(vec![1, 2, 3])
        );
        assert_eq!(
            NullableBytes::Present(vec![0; 9]).encode(8),
            Err(MarshalError::BoundExceeded)
        );
    }

    #[test]
    fn strings_reject_invalid_encodings() {
        assert_eq!(
            NullableUtf8::decode(&[1, 0, 0, 0, 0xff], 8),
            Err(MarshalError::InvalidUtf8)
        );
        let unpaired_surrogate = NullableBytes::Present(0xd800_u16.to_le_bytes().to_vec())
            .encode(8)
            .unwrap();
        assert_eq!(
            NullableUtf16::decode(&unpaired_surrogate, 4),
            Err(MarshalError::InvalidUtf16)
        );
    }

    #[test]
    fn record_layout_preserves_padding_and_rejects_overlap() {
        let layout = RecordLayout::new(
            8,
            [
                RecordField {
                    id: 1,
                    offset: 0,
                    size: 2,
                },
                RecordField {
                    id: 2,
                    offset: 4,
                    size: 4,
                },
            ],
        )
        .unwrap();
        let values = BTreeMap::from([(1, vec![1, 2]), (2, vec![3, 4, 5, 6])]);
        let encoded = layout.encode(&values).unwrap();
        assert_eq!(encoded, vec![1, 2, 0, 0, 3, 4, 5, 6]);
        assert_eq!(layout.decode(&encoded).unwrap(), values);
        assert_eq!(
            RecordLayout::new(
                4,
                [
                    RecordField {
                        id: 1,
                        offset: 0,
                        size: 3,
                    },
                    RecordField {
                        id: 2,
                        offset: 2,
                        size: 2,
                    },
                ],
            ),
            Err(MarshalError::LayoutOverlap)
        );
    }

    #[test]
    fn insufficient_buffer_reports_exact_required_size_without_partial_copy() {
        let mut destination = [9_u8; 2];
        assert_eq!(
            copy_response(&[1, 2, 3], &mut destination),
            Err(InsufficientBuffer { required_bytes: 3 })
        );
        assert_eq!(destination, [9, 9]);
        let mut destination = [0_u8; 3];
        assert_eq!(copy_response(&[1, 2, 3], &mut destination), Ok(3));
        assert_eq!(destination, [1, 2, 3]);
    }
}
