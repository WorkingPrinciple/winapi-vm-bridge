use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::thread::{self, ThreadId};

use serde_json::json;
use wvb_broker::{CallHandler, OperationSchema};
use wvb_call::CallRequest;
use wvb_control::HandleClose;
use wvb_native_host::object::{ObjectBackend, ObjectSession, ObjectSlice};

type Events = Arc<Mutex<Vec<(&'static str, ThreadId)>>>;

struct Target {
    events: Events,
    fail_create: bool,
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
        self.event("factory");
        (0, Some(17))
    }
    fn create(&mut self, factory: usize) -> Result<(i32, Option<usize>), wvb_broker::BrokerError> {
        assert_eq!(factory, 17);
        self.event("create");
        Ok((if self.fail_create { -2_147_024_809 } else { 1 }, Some(23)))
    }
    fn invoke(&mut self, instance: usize, input: u32) -> (i32, u32) {
        assert_eq!(instance, 23);
        self.event("invoke");
        if input == u32::MAX {
            (-2_147_024_809, 999)
        } else {
            (0, input + 1)
        }
    }
    fn release(&mut self, object: usize) {
        self.event(match object {
            17 => "release-factory",
            23 => "release-instance",
            _ => panic!(),
        });
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        self.event("drop");
    }
}

fn definition() -> (ObjectSlice, BTreeMap<u32, OperationSchema>) {
    let slice = serde_json::from_value(json!({
        "abi":"winrt-u32-v1",
        "activation":{"kind":"winrt-factory","runtime_class":"Wvb.Test.WvbScalarRuntimeClass",
            "factory_iid":"5F1C7A3E-2B4D-4E6F-8A9B-0C1D2E3F4A51"},
        "interface_iid":"5F1C7A3E-2B4D-4E6F-8A9B-0C1D2E3F4A52",
        "interface_kind":"iinspectable","handle_type":9,"method_slot":8,
        "factory_handle_type":8,"factory_method_slot":7,
        "activation_operation_id":1,"create_operation_id":2,
        "method_operation_id":3,"close_operation_id":4,"max_objects":8
    }))
    .unwrap();
    let operations = (1..=4)
        .map(|id| {
            (
                id,
                OperationSchema {
                    request_schema_id: id * 2,
                    response_schema_id: id * 2 + 1,
                },
            )
        })
        .collect();
    (slice, operations)
}

fn start(events: Events, fail_create: bool, capacity: usize) -> ObjectSession {
    let (mut slice, operations) = definition();
    slice.max_objects = capacity;
    ObjectSession::start([1; 16], [4; 16], [3; 32], slice, operations, move || {
        events
            .lock()
            .unwrap()
            .push(("init", thread::current().id()));
        Ok(Box::new(Target {
            events,
            fail_create,
        }))
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
#[allow(clippy::too_many_lines)]
async fn factory_and_instance_are_independent_typed_leases_on_one_owner() {
    let events = Events::default();
    let session = start(events.clone(), false, 8);
    let activated = session.handle_call(request(1, vec![])).await.unwrap();
    let factory = activated.body[4..].to_vec();
    assert_eq!(u32::from_le_bytes(factory[24..].try_into().unwrap()), 8);
    let created = session
        .handle_call(request(2, factory.clone()))
        .await
        .unwrap();
    assert_eq!(&created.body[..4], &1_i32.to_le_bytes());
    let instance = created.body[4..].to_vec();
    assert_eq!(u32::from_le_bytes(instance[24..].try_into().unwrap()), 9);
    let mut wrong_method = factory.clone();
    wrong_method.extend_from_slice(&41_u32.to_le_bytes());
    assert!(session.handle_call(request(3, wrong_method)).await.is_err());
    assert!(
        session
            .handle_call(request(2, instance.clone()))
            .await
            .is_err()
    );
    let mut forged = instance.clone();
    forged[24..].copy_from_slice(&8_u32.to_le_bytes());
    assert!(session.handle_call(request(2, forged)).await.is_err());
    let mut other_epoch = factory.clone();
    other_epoch[15] ^= 1;
    assert!(session.handle_call(request(2, other_epoch)).await.is_err());
    assert_eq!(
        session
            .handle_close(close(&factory))
            .await
            .unwrap()
            .disposition,
        0
    );
    assert!(
        session
            .handle_call(request(2, factory.clone()))
            .await
            .is_err()
    );
    let mut method = instance.clone();
    method.extend_from_slice(&41_u32.to_le_bytes());
    assert_eq!(
        session
            .handle_call(request(3, method.clone()))
            .await
            .unwrap()
            .body,
        [0, 0, 0, 0, 42, 0, 0, 0]
    );
    method[28..].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        session.handle_call(request(3, method)).await.unwrap().body,
        [0x57, 0, 7, 0x80, 0, 0, 0, 0]
    );
    assert_eq!(
        session
            .handle_close(close(&instance))
            .await
            .unwrap()
            .disposition,
        0
    );
    assert_ne!(
        session
            .handle_close(close(&instance))
            .await
            .unwrap()
            .disposition,
        0
    );
    session.disconnect().await.unwrap();
    let events = events.lock().unwrap();
    assert_eq!(
        events.iter().filter(|(name, _)| *name == "create").count(),
        1
    );
    assert_eq!(
        events.iter().filter(|(name, _)| *name == "invoke").count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|(name, _)| *name == "release-factory")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|(name, _)| *name == "release-instance")
            .count(),
        1
    );
    assert_eq!(events.last().unwrap().0, "drop");
    assert!(
        events
            .iter()
            .all(|(_, owner)| *owner == events[0].1 && *owner != thread::current().id())
    );
}

#[test]
fn malformed_or_cross_profile_slices_are_rejected_before_start() {
    let (slice, operations) = definition();
    for index in 0..13 {
        let mut invalid = slice.clone();
        match index {
            0 => invalid.create_operation_id = None,
            1 => invalid.create_operation_id = Some(3),
            2 => invalid.factory_handle_type = Some(9),
            3 => invalid.factory_handle_type = Some(0),
            4 => invalid.factory_method_slot = Some(6),
            5 => invalid.method_slot = 3,
            6 => invalid.activation.clsid = "BA9A4DA2-79FE-4B31-8DB4-201AF0266C11".into(),
            7 => invalid.activation.runtime_class = Some("Wvb.Test.\0Scalar".into()),
            8 => invalid.activation.runtime_class = Some("Wvb..Scalar".into()),
            9 => invalid.activation.factory_iid = Some(invalid.interface_iid.clone()),
            10 => invalid.max_objects = 65,
            11 => invalid.abi = "com-u32-v1".into(),
            12 => invalid.interface_kind = "iunknown".into(),
            _ => unreachable!(),
        }
        assert!(invalid.validate(&operations).is_err(), "{index}");
    }
}

#[tokio::test]
async fn failure_capacity_and_disconnect_retire_unpublished_instances_and_factories() {
    for (fail, capacity) in [(true, 8), (false, 1), (false, 8)] {
        let events = Events::default();
        let session = start(events.clone(), fail, capacity);
        let factory = session.handle_call(request(1, vec![])).await.unwrap().body[4..].to_vec();
        let result = session.handle_call(request(2, factory)).await;
        if fail {
            let body = result.unwrap().body;
            assert_eq!(&body[..4], &(-2_147_024_809_i32).to_le_bytes());
            assert!(body[4..].iter().all(|byte| *byte == 0));
        } else if capacity == 1 {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().body.len(), 32);
        }
        session.disconnect().await.unwrap();
        let events = events.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|(name, _)| *name == "release-instance")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|(name, _)| *name == "release-factory")
                .count(),
            1
        );
        assert_eq!(events.last().unwrap().0, "drop");
    }
}
