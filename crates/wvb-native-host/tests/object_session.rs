use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::thread::{self, ThreadId};

use wvb_broker::{CallHandler, OperationSchema};
use wvb_call::CallRequest;
use wvb_control::HandleClose;
use wvb_native_host::object::{Activation, ObjectBackend, ObjectSession, ObjectSlice};

type Events = Arc<Mutex<Vec<(&'static str, ThreadId)>>>;

struct Target {
    events: Events,
    activation: (i32, Option<usize>),
}

impl Target {
    fn event(&self, name: &'static str) {
        self.events
            .lock()
            .unwrap()
            .push((name, thread::current().id()));
    }
}

impl ObjectBackend for Target {
    fn activate(&mut self) -> (i32, Option<usize>) {
        self.event("activate");
        self.activation
    }
    fn invoke(&mut self, object: usize, input: u32) -> (i32, u32) {
        assert_eq!(object, 17);
        self.event("invoke");
        if input == u32::MAX {
            (i32::from_le_bytes(0x8007_0057_u32.to_le_bytes()), 999)
        } else {
            (1, input + 1)
        }
    }
    fn release(&mut self, object: usize) {
        assert_eq!(object, 17);
        self.event("release");
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        self.event("drop");
    }
}

fn definition() -> (ObjectSlice, BTreeMap<u32, OperationSchema>) {
    let slice = ObjectSlice {
        abi: "com-u32-v1".into(),
        activation: Activation {
            kind: "com-local-server".into(),
            clsid: "BA9A4DA2-79FE-4B31-8DB4-201AF0266C11".into(),
            runtime_class: None,
            factory_iid: None,
        },
        interface_iid: "BA9A4DA2-79FE-4B31-8DB4-201AF0266C12".into(),
        interface_kind: "iunknown".into(),
        handle_type: 7,
        method_slot: 3,
        activation_operation_id: 1,
        method_operation_id: 2,
        close_operation_id: 3,
        max_objects: 2,
        factory_handle_type: None,
        factory_method_slot: None,
        create_operation_id: None,
    };
    let operations = (1..=3)
        .map(|id| {
            (
                id,
                OperationSchema {
                    request_schema_id: id * 2,
                    response_schema_id: id * 2 + 1,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    (slice, operations)
}

fn start(events: Events, epoch: [u8; 16]) -> ObjectSession {
    start_with_result(events, epoch, (0, Some(17)))
}

fn start_with_result(
    events: Events,
    epoch: [u8; 16],
    activation: (i32, Option<usize>),
) -> ObjectSession {
    let (slice, operations) = definition();
    ObjectSession::start([1; 16], epoch, [3; 32], slice, operations, move || {
        events
            .lock()
            .unwrap()
            .push(("init", thread::current().id()));
        Ok(Box::new(Target { events, activation }))
    })
    .unwrap()
}

fn request(operation: u32, body: Vec<u8>) -> CallRequest {
    CallRequest {
        adapter_hash: [3; 32],
        operation_id: operation,
        request_schema_id: operation * 2,
        deduplication_mode: 0,
        idempotency_key: None,
        disconnect_policy: 0,
        sensitivity: 0,
        body,
    }
}

fn close(token: &[u8]) -> HandleClose {
    HandleClose {
        broker_epoch: token[..16].try_into().unwrap(),
        owner_actor_id: [1; 16],
        slot: u32::from_le_bytes(token[16..20].try_into().unwrap()),
        generation: u32::from_le_bytes(token[20..24].try_into().unwrap()),
        handle_type: u32::from_le_bytes(token[24..28].try_into().unwrap()),
    }
}

#[tokio::test]
async fn scalar_method_hresult_close_and_disconnect_stay_on_one_owner_thread() {
    let events = Events::default();
    let session = start(events.clone(), [4; 16]);
    let response = session.handle_call(request(1, vec![])).await.unwrap();
    assert_eq!(response.body.len(), 32);
    assert_eq!(&response.body[..4], &[0; 4]);
    assert_eq!(&response.body[4..20], &[4; 16]);
    let token = &response.body[4..];
    let mut body = token.to_vec();
    body.extend_from_slice(&41_u32.to_le_bytes());
    let response = session.handle_call(request(2, body.clone())).await.unwrap();
    assert_eq!(response.native_status, [0; 4]);
    assert_eq!(response.body, [1, 0, 0, 0, 42, 0, 0, 0]); // S_FALSE is preserved.
    body[28..].copy_from_slice(&u32::MAX.to_le_bytes());
    let response = session.handle_call(request(2, body.clone())).await.unwrap();
    assert_eq!(response.native_status, [0; 4]);
    assert_eq!(response.body, [0x57, 0, 7, 0x80, 0, 0, 0, 0]);
    assert_eq!(
        session
            .handle_close(close(token))
            .await
            .unwrap()
            .disposition,
        0
    );
    assert!(session.handle_call(request(2, body)).await.is_err());
    assert_ne!(
        session
            .handle_close(close(token))
            .await
            .unwrap()
            .disposition,
        0
    );
    let second = session.handle_call(request(1, vec![])).await.unwrap();
    assert_ne!(token, &second.body[4..]);
    session.disconnect().await.unwrap();
    assert!(session.handle_call(request(1, vec![])).await.is_err());
    drop(session);
    let events = events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|(event, _)| *event == "release")
            .count(),
        2
    );
    assert_eq!(events.last().unwrap().0, "drop");
    let owner = events[0].1;
    assert_ne!(owner, thread::current().id());
    assert!(events.iter().all(|(_, id)| *id == owner));
}

#[tokio::test]
async fn rejects_full_epoch_other_session_type_schema_adapter_and_truncation_before_execution() {
    let events = Events::default();
    let session = start(events.clone(), [4; 16]);
    let response = session.handle_call(request(1, vec![])).await.unwrap();
    let mut body = response.body[4..].to_vec();
    body.extend_from_slice(&41_u32.to_le_bytes());
    let other = start(Events::default(), [5; 16]);
    assert!(other.handle_call(request(2, body.clone())).await.is_err());
    other.disconnect().await.unwrap();
    for offset in [0, 15, 16, 20, 24] {
        let mut bad = body.clone();
        bad[offset] ^= 1;
        assert!(session.handle_call(request(2, bad)).await.is_err());
    }
    let mut wrong = request(2, body.clone());
    wrong.adapter_hash[0] ^= 1;
    assert!(session.handle_call(wrong).await.is_err());
    let mut wrong = request(2, body.clone());
    wrong.request_schema_id ^= 1;
    assert!(session.handle_call(wrong).await.is_err());
    assert!(
        session
            .handle_call(request(2, body[..31].to_vec()))
            .await
            .is_err()
    );
    assert!(session.handle_call(request(1, vec![0])).await.is_err());
    let mut wrong = close(&body[..28]);
    wrong.owner_actor_id[0] ^= 1;
    assert_ne!(session.handle_close(wrong).await.unwrap().disposition, 0);
    session.disconnect().await.unwrap();
    assert!(
        !events
            .lock()
            .unwrap()
            .iter()
            .any(|(event, _)| *event == "invoke")
    );
}

#[tokio::test]
async fn dropped_response_and_session_still_retire_all_leases() {
    let events = Events::default();
    let session = start(events.clone(), [4; 16]);
    session.handle_call(request(1, vec![])).await.unwrap();
    drop(session);
    let events = events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|(event, _)| *event == "release")
            .count(),
        1
    );
    assert_eq!(events.last().unwrap().0, "drop");
}

#[tokio::test]
async fn capacity_and_failed_activation_release_unpublished_references() {
    let events = Events::default();
    let session = start(events.clone(), [4; 16]);
    session.handle_call(request(1, vec![])).await.unwrap();
    session.handle_call(request(1, vec![])).await.unwrap();
    assert!(session.handle_call(request(1, vec![])).await.is_err());
    session.disconnect().await.unwrap();
    assert_eq!(
        events
            .lock()
            .unwrap()
            .iter()
            .filter(|(event, _)| *event == "release")
            .count(),
        3
    );

    let events = Events::default();
    let hr = i32::from_le_bytes(0x8000_4005_u32.to_le_bytes());
    let session = start_with_result(events.clone(), [4; 16], (hr, Some(17)));
    let result = session.handle_call(request(1, vec![])).await.unwrap();
    assert_eq!(result.native_status, [0; 4]);
    assert_eq!(&result.body[..4], &hr.to_le_bytes());
    assert_eq!(&result.body[4..], &[0; 28]);
    session.disconnect().await.unwrap();
    assert_eq!(
        events
            .lock()
            .unwrap()
            .iter()
            .filter(|(event, _)| *event == "release")
            .count(),
        1
    );

    let session = start_with_result(Events::default(), [4; 16], (0, None));
    assert!(session.handle_call(request(1, vec![])).await.is_err());
    session.disconnect().await.unwrap();
}

#[test]
fn invalid_or_extra_contract_bindings_are_rejected() {
    let (slice, operations) = definition();
    for invalid in [
        ObjectSlice {
            max_objects: 0,
            ..slice.clone()
        },
        ObjectSlice {
            max_objects: 65,
            ..slice.clone()
        },
        ObjectSlice {
            method_slot: 4,
            ..slice.clone()
        },
        ObjectSlice {
            method_operation_id: slice.activation_operation_id,
            ..slice.clone()
        },
        ObjectSlice {
            close_operation_id: 4,
            ..slice.clone()
        },
        ObjectSlice {
            interface_iid: "not-an-iid".into(),
            ..slice.clone()
        },
    ] {
        assert!(invalid.validate(&operations).is_err());
    }
    let mut extra = operations.clone();
    extra.insert(
        4,
        OperationSchema {
            request_schema_id: 8,
            response_schema_id: 9,
        },
    );
    assert!(slice.validate(&extra).is_err());
}
