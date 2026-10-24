use crate::ProtocolError;

pub const NOISE_CIPHERTEXT_MAX: usize = u16::MAX as usize;
pub const NOISE_TAG_BYTES: usize = 16;
pub const NOISE_PLAINTEXT_MAX: usize = NOISE_CIPHERTEXT_MAX - NOISE_TAG_BYTES;
pub const FRAGMENT_HEADER_BYTES: usize = 32;
pub const FRAGMENT_BODY_MAX: usize = NOISE_PLAINTEXT_MAX - FRAGMENT_HEADER_BYTES;
pub const LOGICAL_FRAGMENT_MAX: usize = 17;
const MAGIC: [u8; 4] = *b"WVF2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentHeader {
    pub connection_epoch: u64,
    pub physical_sequence: u64,
    pub logical_frame_id: u64,
    pub fragment_index: u16,
    pub fragment_count: u16,
}

impl FragmentHeader {
    #[must_use]
    pub fn encode(self) -> [u8; FRAGMENT_HEADER_BYTES] {
        let mut output = [0_u8; FRAGMENT_HEADER_BYTES];
        output[0..4].copy_from_slice(&MAGIC);
        output[4..12].copy_from_slice(&self.connection_epoch.to_le_bytes());
        output[12..20].copy_from_slice(&self.physical_sequence.to_le_bytes());
        output[20..28].copy_from_slice(&self.logical_frame_id.to_le_bytes());
        output[28..30].copy_from_slice(&self.fragment_index.to_le_bytes());
        output[30..32].copy_from_slice(&self.fragment_count.to_le_bytes());
        output
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.len() < FRAGMENT_HEADER_BYTES || input[0..4] != MAGIC {
            return Err(ProtocolError::FragmentHeaderInvalid);
        }
        let connection_epoch = read_u64(&input[4..12]);
        let physical_sequence = read_u64(&input[12..20]);
        let logical_frame_id = read_u64(&input[20..28]);
        let fragment_index = read_u16(&input[28..30]);
        let fragment_count = read_u16(&input[30..32]);
        if fragment_count == 0
            || usize::from(fragment_count) > LOGICAL_FRAGMENT_MAX
            || fragment_index >= fragment_count
        {
            return Err(ProtocolError::FragmentCountInvalid);
        }
        Ok(Self {
            connection_epoch,
            physical_sequence,
            logical_frame_id,
            fragment_index,
            fragment_count,
        })
    }
}

fn read_u16(input: &[u8]) -> u16 {
    u16::from_le_bytes(input.try_into().expect("fixed u16 slice"))
}

fn read_u64(input: &[u8]) -> u64 {
    u64::from_le_bytes(input.try_into().expect("fixed u64 slice"))
}

pub fn fragment_logical_frame(
    logical: &[u8],
    connection_epoch: u64,
    first_physical_sequence: u64,
    logical_frame_id: u64,
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    let fragment_count = logical.len().div_ceil(FRAGMENT_BODY_MAX).max(1);
    if fragment_count > LOGICAL_FRAGMENT_MAX {
        return Err(ProtocolError::LogicalFrameTooLarge);
    }
    let count = u16::try_from(fragment_count).map_err(|_| ProtocolError::FragmentCountInvalid)?;
    let mut fragments = Vec::with_capacity(fragment_count);
    for index in 0..fragment_count {
        let index_u64 = u64::try_from(index).map_err(|_| ProtocolError::FragmentCountInvalid)?;
        let sequence = first_physical_sequence
            .checked_add(index_u64)
            .ok_or(ProtocolError::SequenceExhausted)?;
        let start = index * FRAGMENT_BODY_MAX;
        let end = logical.len().min(start + FRAGMENT_BODY_MAX);
        let fragment_index =
            u16::try_from(index).map_err(|_| ProtocolError::FragmentCountInvalid)?;
        let header = FragmentHeader {
            connection_epoch,
            physical_sequence: sequence,
            logical_frame_id,
            fragment_index,
            fragment_count: count,
        };
        let mut fragment = Vec::with_capacity(FRAGMENT_HEADER_BYTES + end.saturating_sub(start));
        fragment.extend_from_slice(&header.encode());
        fragment.extend_from_slice(&logical[start..end]);
        debug_assert!(fragment.len() <= NOISE_PLAINTEXT_MAX);
        fragments.push(fragment);
    }
    Ok(fragments)
}

#[derive(Debug)]
pub struct Reassembler {
    active: Option<ActiveFrame>,
    expected_physical_sequence: u64,
}

#[derive(Debug)]
struct ActiveFrame {
    epoch: u64,
    frame_id: u64,
    count: u16,
    next_index: u16,
    next_physical_sequence: u64,
    bytes: Vec<u8>,
}

impl Reassembler {
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        self.active.is_none()
    }

    #[must_use]
    pub const fn new(first_physical_sequence: u64) -> Self {
        Self {
            active: None,
            expected_physical_sequence: first_physical_sequence,
        }
    }

    pub fn push(
        &mut self,
        plaintext: &[u8],
        expected_epoch: u64,
    ) -> Result<Option<Vec<u8>>, ProtocolError> {
        if plaintext.len() > NOISE_PLAINTEXT_MAX {
            return Err(ProtocolError::PhysicalMessageTooLarge);
        }
        let header = FragmentHeader::decode(plaintext)?;
        if header.connection_epoch != expected_epoch {
            return Err(ProtocolError::FragmentEpochInvalid);
        }
        if header.physical_sequence != self.expected_physical_sequence {
            return Err(ProtocolError::FragmentOrderInvalid);
        }
        self.expected_physical_sequence = self
            .expected_physical_sequence
            .checked_add(1)
            .ok_or(ProtocolError::SequenceExhausted)?;
        let body = &plaintext[FRAGMENT_HEADER_BYTES..];
        if body.len() > FRAGMENT_BODY_MAX {
            return Err(ProtocolError::PhysicalMessageTooLarge);
        }

        match &mut self.active {
            None => {
                if header.fragment_index != 0 {
                    return Err(ProtocolError::FragmentOrderInvalid);
                }
                let mut bytes = Vec::with_capacity(usize::from(header.fragment_count) * body.len());
                bytes.extend_from_slice(body);
                if header.fragment_count == 1 {
                    return Ok(Some(bytes));
                }
                self.active = Some(ActiveFrame {
                    epoch: header.connection_epoch,
                    frame_id: header.logical_frame_id,
                    count: header.fragment_count,
                    next_index: 1,
                    next_physical_sequence: header
                        .physical_sequence
                        .checked_add(1)
                        .ok_or(ProtocolError::SequenceExhausted)?,
                    bytes,
                });
                Ok(None)
            }
            Some(active) => {
                if header.connection_epoch != active.epoch
                    || header.logical_frame_id != active.frame_id
                    || header.fragment_count != active.count
                    || header.fragment_index != active.next_index
                    || header.physical_sequence != active.next_physical_sequence
                {
                    return Err(ProtocolError::FragmentOrderInvalid);
                }
                active.bytes.extend_from_slice(body);
                active.next_index = active
                    .next_index
                    .checked_add(1)
                    .ok_or(ProtocolError::SequenceExhausted)?;
                active.next_physical_sequence = active
                    .next_physical_sequence
                    .checked_add(1)
                    .ok_or(ProtocolError::SequenceExhausted)?;
                if active.next_index == active.count {
                    return Ok(self.active.take().map(|frame| frame.bytes));
                }
                Ok(None)
            }
        }
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_maximum_noise_plaintext_fits() {
        let logical = vec![0x5a; FRAGMENT_BODY_MAX];
        let frames = fragment_logical_frame(&logical, 7, 11, 13).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), NOISE_PLAINTEXT_MAX);
    }

    #[test]
    fn one_mebibyte_round_trips_in_seventeen_fragments() {
        let logical = vec![0xa5; 1_048_656];
        let frames = fragment_logical_frame(&logical, 9, 100, 200).unwrap();
        assert_eq!(frames.len(), 17);
        let mut reassembler = Reassembler::new(100);
        let mut result = None;
        for frame in frames {
            result = reassembler.push(&frame, 9).unwrap().or(result);
        }
        assert_eq!(result.unwrap(), logical);
    }

    #[test]
    fn eighteenth_fragment_is_rejected() {
        let logical = vec![0_u8; FRAGMENT_BODY_MAX * 17 + 1];
        assert_eq!(
            fragment_logical_frame(&logical, 1, 1, 1),
            Err(ProtocolError::LogicalFrameTooLarge)
        );
    }

    #[test]
    fn gaps_and_wrong_epoch_are_rejected() {
        let logical = vec![1_u8; FRAGMENT_BODY_MAX + 1];
        let mut frames = fragment_logical_frame(&logical, 4, 8, 12).unwrap();
        let mut reassembler = Reassembler::new(8);
        assert!(reassembler.push(&frames[0], 4).unwrap().is_none());
        frames[1][12..20].copy_from_slice(&99_u64.to_le_bytes());
        assert_eq!(
            reassembler.push(&frames[1], 4),
            Err(ProtocolError::FragmentOrderInvalid)
        );
        assert_eq!(
            Reassembler::new(8).push(&frames[0], 5),
            Err(ProtocolError::FragmentEpochInvalid)
        );
    }
}
