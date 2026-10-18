//! Canonical `WinAPI` VM Bridge protocol-v2 wire primitives.

mod codec;
mod envelope;
mod error;
mod flow;
mod fragment;
mod messages;
mod state;

pub use codec::{DecodedField, NESTING_MAX, PackedDecoder, PackedEncoder, WireType};
pub use envelope::{ENVELOPE_BYTES, Envelope, EnvelopeFlags, LOGICAL_PAYLOAD_MAX};
pub use error::ProtocolError;
pub use flow::{CreditWindow, FlowError};
pub use fragment::{
    FRAGMENT_BODY_MAX, FRAGMENT_HEADER_BYTES, FragmentHeader, LOGICAL_FRAGMENT_MAX,
    NOISE_CIPHERTEXT_MAX, NOISE_PLAINTEXT_MAX, Reassembler, fragment_logical_frame,
};
pub use messages::{MessageType, top_level_schema_id};
pub use state::{CallEvent, CallState, TransferEvent, TransferState};
