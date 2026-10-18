//! Canonical `WinAPI` VM Bridge protocol-v2 wire primitives.

mod envelope;
mod error;
mod fragment;

pub use envelope::{ENVELOPE_BYTES, Envelope, EnvelopeFlags, LOGICAL_PAYLOAD_MAX};
pub use error::ProtocolError;
pub use fragment::{
    FRAGMENT_BODY_MAX, FRAGMENT_HEADER_BYTES, FragmentHeader, LOGICAL_FRAGMENT_MAX,
    NOISE_CIPHERTEXT_MAX, NOISE_PLAINTEXT_MAX, Reassembler, fragment_logical_frame,
};
