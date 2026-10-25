//! One authenticated connection's COM objects, confined to an owner thread.

use std::collections::BTreeMap;
use std::sync::{Mutex, mpsc};
use std::thread::{self, JoinHandle};

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::oneshot;
use wvb_broker::{BrokerError, CallHandler, OperationSchema};
use wvb_call::{CallRequest, CallResult};
use wvb_control::{HandleClose, HandleStatus};
use wvb_lifecycle::{HandleTable, HandleToken};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectSlice {
    pub abi: String,
    pub activation: Activation,
    pub interface_iid: String,
    pub interface_kind: String,
    pub handle_type: u32,
    pub method_slot: u32,
    pub activation_operation_id: u32,
    pub method_operation_id: u32,
    pub close_operation_id: u32,
    pub max_objects: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub kind: String,
    pub clsid: String,
}

impl ObjectSlice {
    pub fn validate(&self, operations: &BTreeMap<u32, OperationSchema>) -> Result<(), BrokerError> {
        let ids = [
            self.activation_operation_id,
            self.method_operation_id,
            self.close_operation_id,
        ];
        if self.abi != "com-u32-v1"
            || self.activation.kind != "com-local-server"
            || self.interface_kind != "iunknown"
            || self.method_slot != 3
            || self.handle_type == 0
            || !(1..=64).contains(&self.max_objects)
            || !guid(&self.interface_iid)
            || !guid(&self.activation.clsid)
            || operations.len() != 3
            || ids
                .iter()
                .any(|id| *id == 0 || !operations.contains_key(id))
            || ids[0] == ids[1]
            || ids[0] == ids[2]
            || ids[1] == ids[2]
        {
            return Err(failure("unsupported or unbound object slice"));
        }
        Ok(())
    }
}

fn guid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// Constructed and destroyed on the apartment thread. Native addresses never
/// enter commands or responses; object values stay in that thread's table.
pub trait ObjectBackend {
    fn activate(&mut self) -> (i32, Option<usize>);
    fn invoke(&mut self, object: usize, input: u32) -> (i32, u32);
    fn release(&mut self, object: usize);
}

enum Command {
    Call(
        CallRequest,
        oneshot::Sender<Result<CallResult, BrokerError>>,
    ),
    Close(
        HandleClose,
        oneshot::Sender<Result<HandleStatus, BrokerError>>,
    ),
    Shutdown,
}

struct Owner {
    sender: mpsc::Sender<Command>,
    thread: JoinHandle<()>,
}

pub struct ObjectSession {
    owner: Mutex<Option<Owner>>,
}

impl ObjectSession {
    pub fn start<F>(
        actor: [u8; 16],
        epoch: [u8; 16],
        adapter: [u8; 32],
        slice: ObjectSlice,
        operations: BTreeMap<u32, OperationSchema>,
        factory: F,
    ) -> Result<Self, BrokerError>
    where
        F: FnOnce() -> Result<Box<dyn ObjectBackend>, BrokerError> + Send + 'static,
    {
        slice.validate(&operations)?;
        let (sender, receiver) = mpsc::channel();
        let (ready, initialized) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("wvb-com-mta".into())
            .spawn(move || {
                let mut backend = match factory() {
                    Ok(backend) => backend,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                let mut table = HandleTable::new(actor, internal_epoch(epoch), slice.max_objects);
                if ready.send(Ok(())).is_err() {
                    return;
                }
                while let Ok(command) = receiver.recv() {
                    match command {
                        Command::Call(request, response) => {
                            let result = execute(
                                &mut *backend,
                                &mut table,
                                actor,
                                epoch,
                                adapter,
                                &slice,
                                &operations,
                                &request,
                            );
                            let _ = response.send(result);
                        }
                        Command::Close(request, response) => {
                            let result = close(&mut *backend, &mut table, actor, epoch, request);
                            let _ = response.send(Ok(result));
                        }
                        Command::Shutdown => break,
                    }
                }
                for object in table.restart(0) {
                    backend.release(object);
                }
            })
            .map_err(|error| failure(&format!("COM owner thread: {error}")))?;
        match initialized.recv() {
            Ok(Ok(())) => Ok(Self {
                owner: Mutex::new(Some(Owner { sender, thread })),
            }),
            other => {
                thread
                    .join()
                    .map_err(|_| failure("COM owner initialization panicked"))?;
                match other {
                    Ok(Err(error)) => Err(error),
                    _ => Err(failure("COM owner initialization channel closed")),
                }
            }
        }
    }

    fn send(&self, command: Command) -> Result<(), BrokerError> {
        self.owner
            .lock()
            .map_err(|_| failure("COM owner lock poisoned"))?
            .as_ref()
            .ok_or_else(|| failure("object session closed"))?
            .sender
            .send(command)
            .map_err(|_| failure("COM owner stopped"))
    }

    fn take_owner(&self) -> Result<Option<Owner>, BrokerError> {
        Ok(self
            .owner
            .lock()
            .map_err(|_| failure("COM owner lock poisoned"))?
            .take())
    }
}

impl Owner {
    fn stop(self) -> Result<(), BrokerError> {
        let sent = self.sender.send(Command::Shutdown);
        self.thread
            .join()
            .map_err(|_| failure("COM owner panicked; cleanup unknown"))?;
        sent.map_err(|_| failure("COM owner stopped unexpectedly"))
    }
}

impl Drop for ObjectSession {
    fn drop(&mut self) {
        match self.take_owner() {
            Ok(Some(owner)) => {
                if let Err(error) = owner.stop() {
                    eprintln!("wvb: object cleanup failed: {error}");
                }
            }
            Ok(None) => {}
            Err(error) => eprintln!("wvb: object owner unavailable during cleanup: {error}"),
        }
    }
}

#[async_trait]
impl CallHandler for ObjectSession {
    async fn handle_call(&self, request: CallRequest) -> Result<CallResult, BrokerError> {
        let (response, receiver) = oneshot::channel();
        self.send(Command::Call(request, response))?;
        receiver
            .await
            .map_err(|_| failure("COM owner response lost; completion unknown"))?
    }

    async fn handle_close(&self, request: HandleClose) -> Result<HandleStatus, BrokerError> {
        let (response, receiver) = oneshot::channel();
        self.send(Command::Close(request, response))?;
        receiver
            .await
            .map_err(|_| failure("COM close response lost; completion unknown"))?
    }

    async fn disconnect(&self) -> Result<(), BrokerError> {
        if let Some(owner) = self.take_owner()? {
            tokio::task::spawn_blocking(move || owner.stop())
                .await
                .map_err(|_| failure("COM owner join failed; cleanup unknown"))??;
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn execute(
    backend: &mut dyn ObjectBackend,
    table: &mut HandleTable<usize>,
    actor: [u8; 16],
    epoch: [u8; 16],
    adapter: [u8; 32],
    slice: &ObjectSlice,
    operations: &BTreeMap<u32, OperationSchema>,
    request: &CallRequest,
) -> Result<CallResult, BrokerError> {
    if request.adapter_hash != adapter {
        return Err(failure("object adapter mismatch"));
    }
    let schema = operations
        .get(&request.operation_id)
        .ok_or_else(|| failure("unknown object operation"))?;
    if request.request_schema_id != schema.request_schema_id {
        return Err(failure("object schema mismatch"));
    }
    let mut body = Vec::new();
    if request.operation_id == slice.activation_operation_id {
        if !request.body.is_empty() {
            return Err(failure("activation request must be empty"));
        }
        let (hr, object) = backend.activate();
        if hr < 0 {
            if let Some(object) = object {
                backend.release(object);
            }
            body.extend_from_slice(&hr.to_le_bytes());
            body.resize(32, 0);
        } else {
            let object = object.ok_or_else(|| failure("successful activation returned null"))?;
            let token = match table.insert(slice.handle_type, object) {
                Ok(token) => token,
                Err(error) => {
                    backend.release(object);
                    return Err(failure(&error.to_string()));
                }
            };
            body.extend_from_slice(&hr.to_le_bytes());
            body.extend_from_slice(&encode_token(epoch, token));
        }
    } else if request.operation_id == slice.method_operation_id {
        if request.body.len() != 32 {
            return Err(failure("method request must be 32 bytes"));
        }
        let token = decode_token(&request.body[..28], actor, epoch)?;
        if token.type_id != slice.handle_type {
            return Err(failure("wrong object IID/type"));
        }
        let object = *table
            .get(token)
            .map_err(|error| failure(&error.to_string()))?;
        let input = u32::from_le_bytes(request.body[28..32].try_into().expect("bounded input"));
        let (hr, output) = backend.invoke(object, input);
        body.extend_from_slice(&hr.to_le_bytes());
        body.extend_from_slice(&(if hr >= 0 { output } else { 0 }).to_le_bytes());
    } else {
        return Err(failure("close requires HANDLE_CLOSE"));
    }
    Ok(CallResult {
        response_schema_id: schema.response_schema_id,
        operation_uuid: None,
        native_status: 0_i32.to_le_bytes().to_vec(),
        body,
    })
}

fn close(
    backend: &mut dyn ObjectBackend,
    table: &mut HandleTable<usize>,
    actor: [u8; 16],
    epoch: [u8; 16],
    request: HandleClose,
) -> HandleStatus {
    let result = if request.owner_actor_id != actor || request.broker_epoch != epoch {
        Err(failure("handle session/owner mismatch"))
    } else {
        table
            .close(HandleToken {
                actor,
                epoch: internal_epoch(epoch),
                slot: request.slot,
                generation: request.generation,
                type_id: request.handle_type,
            })
            .map_err(|error| failure(&error.to_string()))
    };
    let (disposition, hr) = match result {
        Ok(object) => {
            backend.release(object);
            (0, 0_i32)
        }
        Err(_) => (1, i32::from_le_bytes(0x8007_0006_u32.to_le_bytes())),
    };
    HandleStatus {
        disposition,
        native_status: Some(hr.to_le_bytes().to_vec()),
        receipt: None,
    }
}

fn decode_token(
    bytes: &[u8],
    actor: [u8; 16],
    epoch: [u8; 16],
) -> Result<HandleToken, BrokerError> {
    if bytes.len() != 28 || bytes[..16] != epoch {
        return Err(failure("handle epoch/session mismatch"));
    }
    Ok(HandleToken {
        actor,
        epoch: internal_epoch(epoch),
        slot: u32::from_le_bytes(bytes[16..20].try_into().expect("token")),
        generation: u32::from_le_bytes(bytes[20..24].try_into().expect("token")),
        type_id: u32::from_le_bytes(bytes[24..28].try_into().expect("token")),
    })
}

fn encode_token(epoch: [u8; 16], token: HandleToken) -> [u8; 28] {
    let mut output = [0; 28];
    output[..16].copy_from_slice(&epoch);
    output[16..20].copy_from_slice(&token.slot.to_le_bytes());
    output[20..24].copy_from_slice(&token.generation.to_le_bytes());
    output[24..28].copy_from_slice(&token.type_id.to_le_bytes());
    output
}

fn failure(reason: &str) -> BrokerError {
    BrokerError::Handler(reason.into())
}

fn internal_epoch(epoch: [u8; 16]) -> u64 {
    u64::from_le_bytes([
        epoch[0], epoch[1], epoch[2], epoch[3], epoch[4], epoch[5], epoch[6], epoch[7],
    ])
}
