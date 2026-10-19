use crate::ProtocolError;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Hello = 0x0001,
    HelloAck = 0x0002,
    Ping = 0x0003,
    Pong = 0x0004,
    GoAway = 0x0005,
    WindowUpdate = 0x0006,
    ProtocolError = 0x0007,
    GenericAck = 0x0008,
    PairRequest = 0x0010,
    PairOffer = 0x0011,
    PairCommit = 0x0012,
    PairAccept = 0x0013,
    PairReject = 0x0014,
    PairComplete = 0x0015,
    CallBegin = 0x0100,
    CallData = 0x0101,
    CallEnd = 0x0102,
    ResultBegin = 0x0110,
    ResultData = 0x0111,
    ResultEnd = 0x0112,
    Cancel = 0x0120,
    CancelAck = 0x0121,
    TransferBegin = 0x0130,
    TransferData = 0x0131,
    TransferEnd = 0x0132,
    TransferCancel = 0x0133,
    TransferCancelAck = 0x0134,
    TransferReceipt = 0x0135,
    CallbackRegister = 0x0200,
    CallbackInvoke = 0x0201,
    CallbackResult = 0x0202,
    CallbackUnregister = 0x0203,
    HandleClose = 0x0300,
    HandleStatus = 0x0301,
    OperationQuery = 0x0400,
    OperationState = 0x0401,
    ReceiptQuery = 0x0402,
    ReceiptResult = 0x0403,
    AuditCheckpoint = 0x0410,
}

impl TryFrom<u16> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        const ALL: &[MessageType] = &[
            MessageType::Hello,
            MessageType::HelloAck,
            MessageType::Ping,
            MessageType::Pong,
            MessageType::GoAway,
            MessageType::WindowUpdate,
            MessageType::ProtocolError,
            MessageType::GenericAck,
            MessageType::PairRequest,
            MessageType::PairOffer,
            MessageType::PairCommit,
            MessageType::PairAccept,
            MessageType::PairReject,
            MessageType::PairComplete,
            MessageType::CallBegin,
            MessageType::CallData,
            MessageType::CallEnd,
            MessageType::ResultBegin,
            MessageType::ResultData,
            MessageType::ResultEnd,
            MessageType::Cancel,
            MessageType::CancelAck,
            MessageType::TransferBegin,
            MessageType::TransferData,
            MessageType::TransferEnd,
            MessageType::TransferCancel,
            MessageType::TransferCancelAck,
            MessageType::TransferReceipt,
            MessageType::CallbackRegister,
            MessageType::CallbackInvoke,
            MessageType::CallbackResult,
            MessageType::CallbackUnregister,
            MessageType::HandleClose,
            MessageType::HandleStatus,
            MessageType::OperationQuery,
            MessageType::OperationState,
            MessageType::ReceiptQuery,
            MessageType::ReceiptResult,
            MessageType::AuditCheckpoint,
        ];
        ALL.iter()
            .copied()
            .find(|kind| *kind as u16 == value)
            .ok_or(ProtocolError::EnvelopeInvalid)
    }
}

#[must_use]
pub const fn top_level_schema_id(message_type: MessageType) -> u32 {
    0x2000_0000 | message_type as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_ids_are_stable_and_unique() {
        assert_eq!(top_level_schema_id(MessageType::CallBegin), 0x2000_0100);
        assert_ne!(
            top_level_schema_id(MessageType::CallBegin),
            top_level_schema_id(MessageType::CallData)
        );
    }
}
