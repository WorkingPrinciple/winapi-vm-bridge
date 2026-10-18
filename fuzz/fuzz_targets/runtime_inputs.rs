#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use wvb_exe::{Limits, ProcessRequest, ProcessResult};
use wvb_protocol::{Envelope, MessageType, PackedDecoder};
use wvb_receipt::RuntimeReceipt;
use wvb_transfer::TransferMessage;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    match data[0] % 5 {
        0 => {
            let _ = Envelope::decode(&data[1..]);
        }
        1 => {
            let _ = PackedDecoder::decode(&data[1..]);
        }
        2 => {
            for message_type in [
                MessageType::TransferBegin,
                MessageType::TransferData,
                MessageType::TransferEnd,
                MessageType::TransferCancel,
                MessageType::TransferCancelAck,
                MessageType::TransferReceipt,
            ] {
                let _ = TransferMessage::decode(message_type, &data[1..]);
            }
        }
        3 => {
            let limits = Limits {
                max_arguments: 32,
                max_argument_bytes: 4096,
                max_stdin_bytes: 1024 * 1024,
                max_stdout_bytes: 1024 * 1024,
                max_stderr_bytes: 1024 * 1024,
                environment_allowlist: BTreeSet::from([
                    String::from("TEMP"),
                    String::from("WVB_MODE"),
                ]),
            };
            let _ = ProcessRequest::decode(&data[1..], &limits);
            let _ = ProcessResult::decode(&data[1..], &limits);
        }
        _ => {
            if let Ok(receipt) = serde_json::from_slice::<RuntimeReceipt>(&data[1..]) {
                let _ = receipt.canonical_bytes();
            }
        }
    }
});
