//! Canonical numeric registries shared by protocol and durable runtime state.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryError;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStatus {
    Queued = 1,
    Waiting = 2,
    Running = 3,
    Blocked = 4,
    Canceling = 5,
    Canceled = 6,
    Succeeded = 7,
    Failed = 8,
    Partial = 9,
    Expired = 10,
    Unknown = 11,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackOrdering {
    Serial = 1,
    Parallel = 2,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackExecutor {
    Worker = 1,
    Sta = 2,
    CallerRendezvous = 3,
    EventLoop = 4,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKind {
    CallInput = 1,
    CallOutput = 2,
    FileInput = 3,
    FileOutput = 4,
    Stdin = 5,
    Stdout = 6,
    Stderr = 7,
    DiagnosticArtifact = 8,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferTerminal {
    Complete = 1,
    Canceled = 2,
    Failed = 3,
    HashMismatch = 4,
    LimitExceeded = 5,
}

macro_rules! numeric_registry {
    ($type:ty, {$($value:literal => $variant:path),+ $(,)?}) => {
        impl TryFrom<u16> for $type {
            type Error = RegistryError;

            fn try_from(value: u16) -> Result<Self, Self::Error> {
                match value {
                    $($value => Ok($variant),)+
                    _ => Err(RegistryError),
                }
            }
        }

        impl From<$type> for u16 {
            fn from(value: $type) -> Self {
                value as Self
            }
        }
    };
}

numeric_registry!(OperationStatus, {
    1 => OperationStatus::Queued,
    2 => OperationStatus::Waiting,
    3 => OperationStatus::Running,
    4 => OperationStatus::Blocked,
    5 => OperationStatus::Canceling,
    6 => OperationStatus::Canceled,
    7 => OperationStatus::Succeeded,
    8 => OperationStatus::Failed,
    9 => OperationStatus::Partial,
    10 => OperationStatus::Expired,
    11 => OperationStatus::Unknown,
});
numeric_registry!(CallbackOrdering, {
    1 => CallbackOrdering::Serial,
    2 => CallbackOrdering::Parallel,
});
numeric_registry!(CallbackExecutor, {
    1 => CallbackExecutor::Worker,
    2 => CallbackExecutor::Sta,
    3 => CallbackExecutor::CallerRendezvous,
    4 => CallbackExecutor::EventLoop,
});
numeric_registry!(TransferKind, {
    1 => TransferKind::CallInput,
    2 => TransferKind::CallOutput,
    3 => TransferKind::FileInput,
    4 => TransferKind::FileOutput,
    5 => TransferKind::Stdin,
    6 => TransferKind::Stdout,
    7 => TransferKind::Stderr,
    8 => TransferKind::DiagnosticArtifact,
});
numeric_registry!(TransferTerminal, {
    1 => TransferTerminal::Complete,
    2 => TransferTerminal::Canceled,
    3 => TransferTerminal::Failed,
    4 => TransferTerminal::HashMismatch,
    5 => TransferTerminal::LimitExceeded,
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_numeric_values_are_complete_and_stable() {
        for value in 1..=11 {
            assert_eq!(u16::from(OperationStatus::try_from(value).unwrap()), value);
        }
        for value in 1..=2 {
            assert_eq!(u16::from(CallbackOrdering::try_from(value).unwrap()), value);
        }
        for value in 1..=4 {
            assert_eq!(u16::from(CallbackExecutor::try_from(value).unwrap()), value);
        }
        for value in 1..=8 {
            assert_eq!(u16::from(TransferKind::try_from(value).unwrap()), value);
        }
        for value in 1..=5 {
            assert_eq!(u16::from(TransferTerminal::try_from(value).unwrap()), value);
        }
    }
}
