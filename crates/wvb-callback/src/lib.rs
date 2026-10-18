//! Callback protocol messages and actor/epoch-bound runtime routing.

use std::collections::BTreeMap;

use wvb_lifecycle::{ActorId, CallbackRegistry, CallbackThread, CallbackToken, LifecycleError};
use wvb_protocol::{
    MessageType, PackedDecoder, PackedEncoder, ProtocolError, WireType, top_level_schema_id,
};

const REQUIRED: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackRegister {
    pub callback_id: [u8; 16],
    pub contract_hash: [u8; 32],
    pub lease_budget_ms: u64,
    pub ordering: u16,
    pub max_concurrency: u16,
    pub reentrant: bool,
    pub executor: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackInvoke {
    pub callback_id: [u8; 16],
    pub invocation_id: [u8; 16],
    pub payload_schema_id: u32,
    pub parent_call_id: Option<[u8; 16]>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackResult {
    pub invocation_id: [u8; 16],
    pub native_status: Vec<u8>,
    pub payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallbackUnregister {
    pub callback_id: [u8; 16],
    pub reason: u16,
    pub drain: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackMessage {
    Register(CallbackRegister),
    Invoke(CallbackInvoke),
    Result(CallbackResult),
    Unregister(CallbackUnregister),
}

#[derive(Debug)]
struct Registered {
    token: CallbackToken,
    contract_hash: [u8; 32],
    expires_unix_ms: u64,
}

#[derive(Debug)]
pub struct CallbackService {
    registry: CallbackRegistry,
    maximum_payload_bytes: usize,
    callbacks: BTreeMap<[u8; 16], Registered>,
    invocations: BTreeMap<[u8; 16], CallbackToken>,
}

impl CallbackService {
    #[must_use]
    pub fn new(
        actor_id: ActorId,
        epoch: u64,
        maximum_callbacks: usize,
        maximum_payload_bytes: usize,
    ) -> Self {
        Self {
            registry: CallbackRegistry::new(actor_id, epoch, maximum_callbacks),
            maximum_payload_bytes,
            callbacks: BTreeMap::new(),
            invocations: BTreeMap::new(),
        }
    }

    pub fn register(
        &mut self,
        request: &CallbackRegister,
        now_unix_ms: u64,
        registering_thread: u64,
    ) -> Result<(), CallbackError> {
        if request.contract_hash == [0; 32]
            || request.lease_budget_ms == 0
            || request.max_concurrency == 0
            || !matches!(request.ordering, 1..=3)
            || !matches!(request.executor, 1..=3)
            || self.callbacks.contains_key(&request.callback_id)
        {
            return Err(CallbackError::Invalid);
        }
        let thread = match request.executor {
            1 => CallbackThread::Any,
            2 => CallbackThread::Registering(registering_thread),
            3 => CallbackThread::Serialized,
            _ => return Err(CallbackError::Invalid),
        };
        let token = self
            .registry
            .register(thread, request.reentrant, request.max_concurrency)?;
        let expires_unix_ms = now_unix_ms
            .checked_add(request.lease_budget_ms)
            .ok_or(CallbackError::Invalid)?;
        self.callbacks.insert(
            request.callback_id,
            Registered {
                token,
                contract_hash: request.contract_hash,
                expires_unix_ms,
            },
        );
        Ok(())
    }

    pub fn begin_invoke(
        &mut self,
        contract_hash: [u8; 32],
        request: &CallbackInvoke,
        now_unix_ms: u64,
        thread_id: u64,
    ) -> Result<(), CallbackError> {
        if request.payload.len() > self.maximum_payload_bytes
            || self.invocations.contains_key(&request.invocation_id)
        {
            return Err(CallbackError::Invalid);
        }
        let callback = self
            .callbacks
            .get(&request.callback_id)
            .ok_or(CallbackError::Unknown)?;
        if callback.contract_hash != contract_hash {
            return Err(CallbackError::WrongContract);
        }
        if now_unix_ms >= callback.expires_unix_ms {
            return Err(CallbackError::Expired);
        }
        self.registry.begin(callback.token, thread_id)?;
        self.invocations
            .insert(request.invocation_id, callback.token);
        Ok(())
    }

    pub fn finish_invoke(&mut self, invocation_id: [u8; 16]) -> Result<(), CallbackError> {
        let token = self
            .invocations
            .remove(&invocation_id)
            .ok_or(CallbackError::Unknown)?;
        self.registry.end(token)?;
        Ok(())
    }

    pub fn unregister(&mut self, request: CallbackUnregister) -> Result<(), CallbackError> {
        let callback = self
            .callbacks
            .get(&request.callback_id)
            .ok_or(CallbackError::Unknown)?;
        self.registry.unregister(callback.token)?;
        self.callbacks.remove(&request.callback_id);
        Ok(())
    }

    pub fn disconnect(&mut self, next_epoch: u64) {
        self.registry.disconnect(next_epoch);
        self.callbacks.clear();
        self.invocations.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackError {
    Lifecycle(LifecycleError),
    Invalid,
    Unknown,
    WrongContract,
    Expired,
    Protocol,
}

impl std::fmt::Display for CallbackError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CallbackError {}

impl From<LifecycleError> for CallbackError {
    fn from(value: LifecycleError) -> Self {
        Self::Lifecycle(value)
    }
}

impl From<ProtocolError> for CallbackError {
    fn from(_value: ProtocolError) -> Self {
        Self::Protocol
    }
}

impl CallbackMessage {
    pub fn encode(&self) -> Result<(MessageType, Vec<u8>), CallbackError> {
        match self {
            Self::Register(value) => Ok((
                MessageType::CallbackRegister,
                PackedEncoder::new(top_level_schema_id(MessageType::CallbackRegister), 1)
                    .field(1, WireType::Uuid128, REQUIRED, value.callback_id)?
                    .field(2, WireType::Bytes, REQUIRED, value.contract_hash)?
                    .field(
                        3,
                        WireType::U64,
                        REQUIRED,
                        value.lease_budget_ms.to_le_bytes(),
                    )?
                    .field(4, WireType::U16, REQUIRED, value.ordering.to_le_bytes())?
                    .field(
                        5,
                        WireType::U16,
                        REQUIRED,
                        value.max_concurrency.to_le_bytes(),
                    )?
                    .field(6, WireType::Bool, REQUIRED, [u8::from(value.reentrant)])?
                    .field(7, WireType::U16, REQUIRED, value.executor.to_le_bytes())?
                    .encode()?,
            )),
            Self::Invoke(value) => {
                let mut encoder =
                    PackedEncoder::new(top_level_schema_id(MessageType::CallbackInvoke), 1)
                        .field(1, WireType::Uuid128, REQUIRED, value.callback_id)?
                        .field(2, WireType::Uuid128, REQUIRED, value.invocation_id)?
                        .field(
                            3,
                            WireType::U32,
                            REQUIRED,
                            value.payload_schema_id.to_le_bytes(),
                        )?
                        .field(5, WireType::Bytes, REQUIRED, value.payload.clone())?;
                if let Some(parent) = value.parent_call_id {
                    encoder = encoder.field(4, WireType::Uuid128, 0, parent)?;
                }
                Ok((MessageType::CallbackInvoke, encoder.encode()?))
            }
            Self::Result(value) => {
                let mut encoder =
                    PackedEncoder::new(top_level_schema_id(MessageType::CallbackResult), 1)
                        .field(1, WireType::Uuid128, REQUIRED, value.invocation_id)?
                        .field(2, WireType::Nested, REQUIRED, value.native_status.clone())?;
                if let Some(payload) = &value.payload {
                    encoder = encoder.field(3, WireType::Bytes, 0, payload.clone())?;
                }
                Ok((MessageType::CallbackResult, encoder.encode()?))
            }
            Self::Unregister(value) => Ok((
                MessageType::CallbackUnregister,
                PackedEncoder::new(top_level_schema_id(MessageType::CallbackUnregister), 1)
                    .field(1, WireType::Uuid128, REQUIRED, value.callback_id)?
                    .field(2, WireType::U16, REQUIRED, value.reason.to_le_bytes())?
                    .field(3, WireType::Bool, REQUIRED, [u8::from(value.drain)])?
                    .encode()?,
            )),
        }
    }

    pub fn decode(message_type: MessageType, payload: &[u8]) -> Result<Self, CallbackError> {
        let decoder = PackedDecoder::decode(payload)?;
        if decoder.schema_id != top_level_schema_id(message_type) || decoder.schema_version != 1 {
            return Err(CallbackError::Protocol);
        }
        match message_type {
            MessageType::CallbackRegister => Ok(Self::Register(CallbackRegister {
                callback_id: uuid(&decoder, 1)?,
                contract_hash: hash(&decoder, 2)?,
                lease_budget_ms: u64_value(&decoder, 3)?,
                ordering: u16_value(&decoder, 4)?,
                max_concurrency: u16_value(&decoder, 5)?,
                reentrant: bool_value(&decoder, 6)?,
                executor: u16_value(&decoder, 7)?,
            })),
            MessageType::CallbackInvoke => Ok(Self::Invoke(CallbackInvoke {
                callback_id: uuid(&decoder, 1)?,
                invocation_id: uuid(&decoder, 2)?,
                payload_schema_id: u32_value(&decoder, 3)?,
                parent_call_id: optional_uuid(&decoder, 4)?,
                payload: required(&decoder, 5, WireType::Bytes)?.to_vec(),
            })),
            MessageType::CallbackResult => Ok(Self::Result(CallbackResult {
                invocation_id: uuid(&decoder, 1)?,
                native_status: required(&decoder, 2, WireType::Nested)?.to_vec(),
                payload: optional(&decoder, 3, WireType::Bytes)?.map(<[u8]>::to_vec),
            })),
            MessageType::CallbackUnregister => Ok(Self::Unregister(CallbackUnregister {
                callback_id: uuid(&decoder, 1)?,
                reason: u16_value(&decoder, 2)?,
                drain: bool_value(&decoder, 3)?,
            })),
            _ => Err(CallbackError::Protocol),
        }
    }
}

fn required<'a>(
    decoder: &'a PackedDecoder<'a>,
    tag: u16,
    wire_type: WireType,
) -> Result<&'a [u8], CallbackError> {
    let field = decoder.field(tag).ok_or(CallbackError::Protocol)?;
    if field.wire_type != wire_type || field.flags & REQUIRED == 0 {
        return Err(CallbackError::Protocol);
    }
    Ok(field.value)
}

fn optional<'a>(
    decoder: &'a PackedDecoder<'a>,
    tag: u16,
    wire_type: WireType,
) -> Result<Option<&'a [u8]>, CallbackError> {
    decoder
        .field(tag)
        .map(|field| {
            if field.wire_type != wire_type || field.flags & REQUIRED != 0 {
                return Err(CallbackError::Protocol);
            }
            Ok(field.value)
        })
        .transpose()
}

fn uuid(decoder: &PackedDecoder<'_>, tag: u16) -> Result<[u8; 16], CallbackError> {
    required(decoder, tag, WireType::Uuid128)?
        .try_into()
        .map_err(|_| CallbackError::Protocol)
}

fn optional_uuid(decoder: &PackedDecoder<'_>, tag: u16) -> Result<Option<[u8; 16]>, CallbackError> {
    optional(decoder, tag, WireType::Uuid128)?
        .map(|value| value.try_into().map_err(|_| CallbackError::Protocol))
        .transpose()
}

fn hash(decoder: &PackedDecoder<'_>, tag: u16) -> Result<[u8; 32], CallbackError> {
    required(decoder, tag, WireType::Bytes)?
        .try_into()
        .map_err(|_| CallbackError::Protocol)
}

fn bool_value(decoder: &PackedDecoder<'_>, tag: u16) -> Result<bool, CallbackError> {
    match required(decoder, tag, WireType::Bool)? {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(CallbackError::Protocol),
    }
}

fn u16_value(decoder: &PackedDecoder<'_>, tag: u16) -> Result<u16, CallbackError> {
    Ok(u16::from_le_bytes(
        required(decoder, tag, WireType::U16)?
            .try_into()
            .map_err(|_| CallbackError::Protocol)?,
    ))
}

fn u32_value(decoder: &PackedDecoder<'_>, tag: u16) -> Result<u32, CallbackError> {
    Ok(u32::from_le_bytes(
        required(decoder, tag, WireType::U32)?
            .try_into()
            .map_err(|_| CallbackError::Protocol)?,
    ))
}

fn u64_value(decoder: &PackedDecoder<'_>, tag: u16) -> Result<u64, CallbackError> {
    Ok(u64::from_le_bytes(
        required(decoder, tag, WireType::U64)?
            .try_into()
            .map_err(|_| CallbackError::Protocol)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration() -> CallbackRegister {
        CallbackRegister {
            callback_id: [1; 16],
            contract_hash: [2; 32],
            lease_budget_ms: 1_000,
            ordering: 1,
            max_concurrency: 2,
            reentrant: true,
            executor: 2,
        }
    }

    #[test]
    fn callback_messages_round_trip_with_exact_shapes() {
        let messages = [
            CallbackMessage::Register(registration()),
            CallbackMessage::Invoke(CallbackInvoke {
                callback_id: [1; 16],
                invocation_id: [3; 16],
                payload_schema_id: 7,
                parent_call_id: Some([4; 16]),
                payload: b"request".to_vec(),
            }),
            CallbackMessage::Result(CallbackResult {
                invocation_id: [3; 16],
                native_status: b"status".to_vec(),
                payload: Some(b"response".to_vec()),
            }),
            CallbackMessage::Unregister(CallbackUnregister {
                callback_id: [1; 16],
                reason: 1,
                drain: true,
            }),
        ];
        for message in messages {
            let (message_type, payload) = message.encode().unwrap();
            assert_eq!(
                CallbackMessage::decode(message_type, &payload).unwrap(),
                message
            );
        }
    }

    #[test]
    fn service_enforces_contract_lease_thread_reentrancy_and_disconnect() {
        let mut service = CallbackService::new([9; 16], 4, 2, 1024);
        let registration = registration();
        service.register(&registration, 10, 44).unwrap();
        let invoke = CallbackInvoke {
            callback_id: registration.callback_id,
            invocation_id: [3; 16],
            payload_schema_id: 7,
            parent_call_id: None,
            payload: b"request".to_vec(),
        };
        assert_eq!(
            service.begin_invoke([8; 32], &invoke, 11, 44),
            Err(CallbackError::WrongContract)
        );
        assert_eq!(
            service.begin_invoke(registration.contract_hash, &invoke, 11, 45),
            Err(CallbackError::Lifecycle(LifecycleError::WrongThread))
        );
        service
            .begin_invoke(registration.contract_hash, &invoke, 11, 44)
            .unwrap();
        service.finish_invoke(invoke.invocation_id).unwrap();
        service
            .unregister(CallbackUnregister {
                callback_id: registration.callback_id,
                reason: 1,
                drain: true,
            })
            .unwrap();
        assert_eq!(
            service.begin_invoke(registration.contract_hash, &invoke, 11, 44),
            Err(CallbackError::Unknown)
        );
        service.disconnect(5);
    }

    #[test]
    fn expired_and_oversized_callbacks_fail_closed() {
        let mut service = CallbackService::new([9; 16], 4, 2, 4);
        let registration = registration();
        service.register(&registration, 10, 44).unwrap();
        let invoke = CallbackInvoke {
            callback_id: registration.callback_id,
            invocation_id: [3; 16],
            payload_schema_id: 7,
            parent_call_id: None,
            payload: b"large".to_vec(),
        };
        assert_eq!(
            service.begin_invoke(registration.contract_hash, &invoke, 11, 44),
            Err(CallbackError::Invalid)
        );
        let mut invoke = invoke;
        invoke.payload.clear();
        assert_eq!(
            service.begin_invoke(registration.contract_hash, &invoke, 1_010, 44),
            Err(CallbackError::Expired)
        );
    }
}
