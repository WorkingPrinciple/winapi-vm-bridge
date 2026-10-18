use crate::ProtocolError;

pub const ENVELOPE_BYTES: usize = 80;
pub const LOGICAL_PAYLOAD_MAX: usize = 1_048_576;
const ENVELOPE_BYTES_U16: u16 = 80;
const LOGICAL_PAYLOAD_MAX_U32: u32 = 1_048_576;
const MAGIC: [u8; 4] = *b"WVB2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeFlags(u16);

impl EnvelopeFlags {
    pub const REQUEST: Self = Self(0x0001);
    pub const RESPONSE: Self = Self(0x0002);
    pub const END_STREAM: Self = Self(0x0004);
    pub const OPTIONAL_MESSAGE: Self = Self(0x0008);
    pub const ACK_REQUIRED: Self = Self(0x0010);
    pub const CONTROL_PRIORITY: Self = Self(0x0020);
    pub const SENSITIVE: Self = Self(0x0040);
    pub const RETRY: Self = Self(0x0080);
    pub const FINAL_CHUNK: Self = Self(0x0100);
    const KNOWN: u16 = 0x01ff;

    pub fn from_bits(bits: u16) -> Result<Self, ProtocolError> {
        if bits & !Self::KNOWN != 0 || bits & Self::REQUEST.0 != 0 && bits & Self::RESPONSE.0 != 0 {
            return Err(ProtocolError::FlagsInvalid);
        }
        Ok(Self(bits))
    }

    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub minor: u8,
    pub message_type: u16,
    pub flags: EnvelopeFlags,
    pub connection_epoch: u64,
    pub stream_id: u32,
    pub stream_sequence: u32,
    pub message_id: [u8; 16],
    pub correlation_id: [u8; 16],
    pub remaining_budget_ms: u64,
    pub payload_length: u32,
}

impl Envelope {
    pub fn encode(&self) -> Result<[u8; ENVELOPE_BYTES], ProtocolError> {
        if self.payload_length > LOGICAL_PAYLOAD_MAX_U32 {
            return Err(ProtocolError::LogicalFrameTooLarge);
        }
        let mut output = [0_u8; ENVELOPE_BYTES];
        output[0..4].copy_from_slice(&MAGIC);
        output[4..6].copy_from_slice(&ENVELOPE_BYTES_U16.to_le_bytes());
        output[6] = 2;
        output[7] = self.minor;
        output[8..10].copy_from_slice(&self.message_type.to_le_bytes());
        output[10..12].copy_from_slice(&self.flags.bits().to_le_bytes());
        output[12..20].copy_from_slice(&self.connection_epoch.to_le_bytes());
        output[20..24].copy_from_slice(&self.stream_id.to_le_bytes());
        output[24..28].copy_from_slice(&self.stream_sequence.to_le_bytes());
        output[28..44].copy_from_slice(&self.message_id);
        output[44..60].copy_from_slice(&self.correlation_id);
        output[60..68].copy_from_slice(&self.remaining_budget_ms.to_le_bytes());
        output[68..72].copy_from_slice(&self.payload_length.to_le_bytes());
        output[72..76].copy_from_slice(&self.payload_length.to_le_bytes());
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.len() != ENVELOPE_BYTES
            || input[0..4] != MAGIC
            || read_u16(input, 4) != ENVELOPE_BYTES_U16
            || input[6] != 2
            || input[76..80] != [0, 0, 0, 0]
        {
            return Err(ProtocolError::EnvelopeInvalid);
        }
        let payload_length = read_u32(input, 68);
        let logical_length = read_u32(input, 72);
        if payload_length != logical_length || payload_length > LOGICAL_PAYLOAD_MAX_U32 {
            return Err(ProtocolError::EnvelopeInvalid);
        }
        Ok(Self {
            minor: input[7],
            message_type: read_u16(input, 8),
            flags: EnvelopeFlags::from_bits(read_u16(input, 10))?,
            connection_epoch: read_u64(input, 12),
            stream_id: read_u32(input, 20),
            stream_sequence: read_u32(input, 24),
            message_id: read_array_16(input, 28),
            correlation_id: read_array_16(input, 44),
            remaining_budget_ms: read_u64(input, 60),
            payload_length,
        })
    }
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

fn read_u64(input: &[u8], offset: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&input[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

fn read_array_16(input: &[u8], offset: usize) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&input[offset..offset + 16]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip_is_byte_stable() {
        let value = Envelope {
            minor: 0,
            message_type: 0x100,
            flags: EnvelopeFlags::REQUEST,
            connection_epoch: 42,
            stream_id: 1,
            stream_sequence: 0,
            message_id: [7; 16],
            correlation_id: [0; 16],
            remaining_budget_ms: 15_000,
            payload_length: 123,
        };
        let bytes = value.encode().unwrap();
        assert_eq!(Envelope::decode(&bytes).unwrap(), value);
        assert_eq!(value.encode().unwrap(), bytes);
    }

    #[test]
    fn invalid_flags_and_reserved_bytes_fail() {
        assert_eq!(
            EnvelopeFlags::from_bits(
                EnvelopeFlags::REQUEST.bits() | EnvelopeFlags::RESPONSE.bits()
            ),
            Err(ProtocolError::FlagsInvalid)
        );
        let value = Envelope {
            minor: 0,
            message_type: 1,
            flags: EnvelopeFlags::CONTROL_PRIORITY,
            connection_epoch: 0,
            stream_id: 0,
            stream_sequence: 0,
            message_id: [1; 16],
            correlation_id: [0; 16],
            remaining_budget_ms: 0,
            payload_length: 0,
        };
        let mut bytes = value.encode().unwrap();
        bytes[79] = 1;
        assert_eq!(
            Envelope::decode(&bytes),
            Err(ProtocolError::EnvelopeInvalid)
        );
    }
}
