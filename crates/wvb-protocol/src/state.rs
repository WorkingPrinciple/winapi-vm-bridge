#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    New,
    RequestOpen,
    Queued,
    Running,
    ResultOpen,
    Terminal,
    Canceled,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallEvent {
    Begin,
    RequestComplete,
    Dispatch,
    ResultBegin,
    ResultComplete,
    CancelBeforeDispatch,
    CancelConfirmed,
    DisconnectUnknown,
}

impl CallState {
    #[must_use]
    pub fn apply(self, event: CallEvent) -> Option<Self> {
        match (self, event) {
            (Self::New, CallEvent::Begin) => Some(Self::RequestOpen),
            (Self::RequestOpen, CallEvent::RequestComplete) => Some(Self::Queued),
            (Self::Queued, CallEvent::Dispatch) => Some(Self::Running),
            (Self::Running, CallEvent::ResultBegin) => Some(Self::ResultOpen),
            (Self::ResultOpen, CallEvent::ResultComplete) => Some(Self::Terminal),
            (Self::Queued, CallEvent::CancelBeforeDispatch)
            | (Self::Running, CallEvent::CancelConfirmed) => Some(Self::Canceled),
            (Self::Running | Self::ResultOpen, CallEvent::DisconnectUnknown) => Some(Self::Unknown),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    New,
    Open,
    HashVerified,
    Receipted,
    Closed,
    Canceled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferEvent {
    Begin,
    EndVerified,
    ReceiptCommitted,
    Close,
    Cancel,
    HashMismatch,
}

impl TransferState {
    #[must_use]
    pub fn apply(self, event: TransferEvent) -> Option<Self> {
        match (self, event) {
            (Self::New, TransferEvent::Begin) => Some(Self::Open),
            (Self::Open, TransferEvent::EndVerified) => Some(Self::HashVerified),
            (Self::HashVerified, TransferEvent::ReceiptCommitted) => Some(Self::Receipted),
            (Self::Receipted, TransferEvent::Close) => Some(Self::Closed),
            (Self::Open | Self::HashVerified, TransferEvent::Cancel) => Some(Self::Canceled),
            (Self::Open, TransferEvent::HashMismatch) => Some(Self::Failed),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_requires_exact_order() {
        let state = CallState::New
            .apply(CallEvent::Begin)
            .and_then(|s| s.apply(CallEvent::RequestComplete))
            .and_then(|s| s.apply(CallEvent::Dispatch))
            .and_then(|s| s.apply(CallEvent::ResultBegin))
            .and_then(|s| s.apply(CallEvent::ResultComplete));
        assert_eq!(state, Some(CallState::Terminal));
        assert_eq!(CallState::New.apply(CallEvent::Dispatch), None);
    }

    #[test]
    fn transfer_requires_receipt_before_close() {
        let state = TransferState::New
            .apply(TransferEvent::Begin)
            .and_then(|s| s.apply(TransferEvent::EndVerified))
            .and_then(|s| s.apply(TransferEvent::ReceiptCommitted))
            .and_then(|s| s.apply(TransferEvent::Close));
        assert_eq!(state, Some(TransferState::Closed));
        assert_eq!(
            TransferState::HashVerified.apply(TransferEvent::Close),
            None
        );
    }
}
