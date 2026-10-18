use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    PhysicalMessageTooLarge,
    PhysicalLengthInvalid,
    FragmentHeaderInvalid,
    FragmentOrderInvalid,
    FragmentCountInvalid,
    FragmentEpochInvalid,
    LogicalFrameTooLarge,
    EnvelopeInvalid,
    FlagsInvalid,
    SequenceExhausted,
    PackedHeaderInvalid,
    FieldOrderInvalid,
    FieldDuplicate,
    FieldTypeInvalid,
    FieldBoundsExceeded,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ProtocolError {}
