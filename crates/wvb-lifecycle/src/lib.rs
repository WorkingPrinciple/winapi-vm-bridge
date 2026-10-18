//! Actor-bound handle, callback and asynchronous-call lifecycle primitives.

use std::collections::BTreeMap;

pub type ActorId = [u8; 16];
pub type CallId = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleError {
    Capacity,
    Unknown,
    Stale,
    WrongActor,
    WrongType,
    WrongEpoch,
    WrongThread,
    ReentrancyDenied,
    Busy,
    Terminal,
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for LifecycleError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HandleToken {
    pub actor: ActorId,
    pub epoch: u64,
    pub slot: u32,
    pub generation: u32,
    pub type_id: u32,
}

#[derive(Debug)]
struct HandleSlot<T> {
    generation: u32,
    value: Option<T>,
    type_id: u32,
}

#[derive(Debug)]
pub struct HandleTable<T> {
    actor: ActorId,
    epoch: u64,
    maximum: usize,
    slots: Vec<HandleSlot<T>>,
    free: Vec<u32>,
}

impl<T> HandleTable<T> {
    #[must_use]
    pub fn new(actor: ActorId, epoch: u64, maximum: usize) -> Self {
        Self {
            actor,
            epoch,
            maximum,
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    pub fn insert(&mut self, type_id: u32, value: T) -> Result<HandleToken, LifecycleError> {
        let slot_index = if let Some(index) = self.free.pop() {
            index
        } else {
            if self.slots.len() >= self.maximum {
                return Err(LifecycleError::Capacity);
            }
            let index = u32::try_from(self.slots.len()).map_err(|_| LifecycleError::Capacity)?;
            self.slots.push(HandleSlot {
                generation: 1,
                value: None,
                type_id,
            });
            index
        };
        let slot = self
            .slots
            .get_mut(usize::try_from(slot_index).map_err(|_| LifecycleError::Capacity)?)
            .ok_or(LifecycleError::Unknown)?;
        slot.type_id = type_id;
        slot.value = Some(value);
        Ok(HandleToken {
            actor: self.actor,
            epoch: self.epoch,
            slot: slot_index,
            generation: slot.generation,
            type_id,
        })
    }

    pub fn get(&self, token: HandleToken) -> Result<&T, LifecycleError> {
        self.validate(token)?;
        self.slots[usize::try_from(token.slot).map_err(|_| LifecycleError::Unknown)?]
            .value
            .as_ref()
            .ok_or(LifecycleError::Stale)
    }

    pub fn get_mut(&mut self, token: HandleToken) -> Result<&mut T, LifecycleError> {
        self.validate(token)?;
        self.slots[usize::try_from(token.slot).map_err(|_| LifecycleError::Unknown)?]
            .value
            .as_mut()
            .ok_or(LifecycleError::Stale)
    }

    pub fn close(&mut self, token: HandleToken) -> Result<T, LifecycleError> {
        self.validate(token)?;
        let index = usize::try_from(token.slot).map_err(|_| LifecycleError::Unknown)?;
        let slot = &mut self.slots[index];
        let value = slot.value.take().ok_or(LifecycleError::Stale)?;
        slot.generation = slot
            .generation
            .checked_add(1)
            .ok_or(LifecycleError::Terminal)?;
        self.free.push(token.slot);
        Ok(value)
    }

    pub fn restart(&mut self, epoch: u64) -> Vec<T> {
        self.epoch = epoch;
        self.free.clear();
        let mut invalidated = Vec::new();
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if let Some(value) = slot.value.take() {
                invalidated.push(value);
            }
            slot.generation = slot.generation.saturating_add(1);
            if let Ok(index) = u32::try_from(index) {
                self.free.push(index);
            }
        }
        invalidated
    }

    fn validate(&self, token: HandleToken) -> Result<(), LifecycleError> {
        if token.actor != self.actor {
            return Err(LifecycleError::WrongActor);
        }
        if token.epoch != self.epoch {
            return Err(LifecycleError::WrongEpoch);
        }
        let slot = self
            .slots
            .get(usize::try_from(token.slot).map_err(|_| LifecycleError::Unknown)?)
            .ok_or(LifecycleError::Unknown)?;
        if token.generation != slot.generation || slot.value.is_none() {
            return Err(LifecycleError::Stale);
        }
        if token.type_id != slot.type_id {
            return Err(LifecycleError::WrongType);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackThread {
    Any,
    Registering(u64),
    Serialized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallbackToken {
    pub actor: ActorId,
    pub epoch: u64,
    pub id: u64,
}

#[derive(Debug)]
struct Callback {
    thread: CallbackThread,
    allow_reentrant: bool,
    in_flight: u32,
}

#[derive(Debug)]
pub struct CallbackRegistry {
    actor: ActorId,
    epoch: u64,
    maximum: usize,
    next_id: u64,
    callbacks: BTreeMap<u64, Callback>,
    serialized_in_flight: bool,
}

impl CallbackRegistry {
    #[must_use]
    pub fn new(actor: ActorId, epoch: u64, maximum: usize) -> Self {
        Self {
            actor,
            epoch,
            maximum,
            next_id: 1,
            callbacks: BTreeMap::new(),
            serialized_in_flight: false,
        }
    }

    pub fn register(
        &mut self,
        thread: CallbackThread,
        allow_reentrant: bool,
    ) -> Result<CallbackToken, LifecycleError> {
        if self.callbacks.len() >= self.maximum {
            return Err(LifecycleError::Capacity);
        }
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(LifecycleError::Terminal)?;
        self.callbacks.insert(
            id,
            Callback {
                thread,
                allow_reentrant,
                in_flight: 0,
            },
        );
        Ok(CallbackToken {
            actor: self.actor,
            epoch: self.epoch,
            id,
        })
    }

    pub fn begin(&mut self, token: CallbackToken, thread_id: u64) -> Result<(), LifecycleError> {
        self.validate_token(token)?;
        let callback = self
            .callbacks
            .get_mut(&token.id)
            .ok_or(LifecycleError::Unknown)?;
        match callback.thread {
            CallbackThread::Any => {}
            CallbackThread::Registering(expected) if expected == thread_id => {}
            CallbackThread::Registering(_) => return Err(LifecycleError::WrongThread),
            CallbackThread::Serialized if self.serialized_in_flight => {
                return Err(LifecycleError::Busy);
            }
            CallbackThread::Serialized => self.serialized_in_flight = true,
        }
        if callback.in_flight > 0 && !callback.allow_reentrant {
            if callback.thread == CallbackThread::Serialized {
                self.serialized_in_flight = false;
            }
            return Err(LifecycleError::ReentrancyDenied);
        }
        callback.in_flight = callback
            .in_flight
            .checked_add(1)
            .ok_or(LifecycleError::Terminal)?;
        Ok(())
    }

    pub fn end(&mut self, token: CallbackToken) -> Result<(), LifecycleError> {
        self.validate_token(token)?;
        let callback = self
            .callbacks
            .get_mut(&token.id)
            .ok_or(LifecycleError::Unknown)?;
        callback.in_flight = callback
            .in_flight
            .checked_sub(1)
            .ok_or(LifecycleError::Terminal)?;
        if callback.thread == CallbackThread::Serialized {
            self.serialized_in_flight = false;
        }
        Ok(())
    }

    pub fn unregister(&mut self, token: CallbackToken) -> Result<(), LifecycleError> {
        self.validate_token(token)?;
        let callback = self
            .callbacks
            .get(&token.id)
            .ok_or(LifecycleError::Unknown)?;
        if callback.in_flight != 0 {
            return Err(LifecycleError::Busy);
        }
        self.callbacks.remove(&token.id);
        Ok(())
    }

    pub fn disconnect(&mut self, epoch: u64) {
        self.callbacks.clear();
        self.serialized_in_flight = false;
        self.epoch = epoch;
    }

    fn validate_token(&self, token: CallbackToken) -> Result<(), LifecycleError> {
        if token.actor != self.actor {
            return Err(LifecycleError::WrongActor);
        }
        if token.epoch != self.epoch {
            return Err(LifecycleError::WrongEpoch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncState {
    Queued,
    Running,
    CompletionCommitted,
    CancellationCommitted,
    OutcomeUnknown,
}

#[derive(Debug, Default)]
pub struct AsyncRegistry {
    calls: BTreeMap<CallId, AsyncState>,
}

impl AsyncRegistry {
    pub fn begin(&mut self, call: CallId) -> Result<(), LifecycleError> {
        if self.calls.insert(call, AsyncState::Queued).is_some() {
            return Err(LifecycleError::Busy);
        }
        Ok(())
    }

    pub fn dispatch(&mut self, call: CallId) -> Result<(), LifecycleError> {
        self.transition(call, AsyncState::Queued, AsyncState::Running)
    }

    pub fn complete(&mut self, call: CallId) -> Result<AsyncState, LifecycleError> {
        let state = self.calls.get_mut(&call).ok_or(LifecycleError::Unknown)?;
        match *state {
            AsyncState::Queued | AsyncState::Running => {
                *state = AsyncState::CompletionCommitted;
                Ok(*state)
            }
            AsyncState::CompletionCommitted | AsyncState::CancellationCommitted => {
                Err(LifecycleError::Terminal)
            }
            AsyncState::OutcomeUnknown => Err(LifecycleError::Terminal),
        }
    }

    pub fn cancel(&mut self, call: CallId) -> Result<AsyncState, LifecycleError> {
        let state = self.calls.get_mut(&call).ok_or(LifecycleError::Unknown)?;
        match *state {
            AsyncState::Queued | AsyncState::Running => {
                *state = AsyncState::CancellationCommitted;
                Ok(*state)
            }
            AsyncState::CompletionCommitted | AsyncState::CancellationCommitted => {
                Err(LifecycleError::Terminal)
            }
            AsyncState::OutcomeUnknown => Err(LifecycleError::Terminal),
        }
    }

    pub fn disconnect(&mut self) {
        for state in self.calls.values_mut() {
            if matches!(*state, AsyncState::Queued | AsyncState::Running) {
                *state = AsyncState::OutcomeUnknown;
            }
        }
    }

    #[must_use]
    pub fn state(&self, call: CallId) -> Option<AsyncState> {
        self.calls.get(&call).copied()
    }

    fn transition(
        &mut self,
        call: CallId,
        expected: AsyncState,
        next: AsyncState,
    ) -> Result<(), LifecycleError> {
        let state = self.calls.get_mut(&call).ok_or(LifecycleError::Unknown)?;
        if *state != expected {
            return Err(LifecycleError::Terminal);
        }
        *state = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_actor_epoch_generation_and_type_bound() {
        let actor = [1; 16];
        let mut table = HandleTable::new(actor, 7, 2);
        let first = table.insert(10, String::from("first")).unwrap();
        assert_eq!(table.get(first).unwrap(), "first");
        assert_eq!(
            table.get(HandleToken {
                actor: [2; 16],
                ..first
            }),
            Err(LifecycleError::WrongActor)
        );
        assert_eq!(
            table.get(HandleToken {
                type_id: 11,
                ..first
            }),
            Err(LifecycleError::WrongType)
        );
        assert_eq!(table.close(first).unwrap(), "first");
        assert_eq!(table.get(first), Err(LifecycleError::Stale));
        let second = table.insert(10, String::from("second")).unwrap();
        assert_eq!(second.slot, first.slot);
        assert_ne!(second.generation, first.generation);
        assert_eq!(table.restart(8), vec![String::from("second")]);
        assert_eq!(table.get(second), Err(LifecycleError::WrongEpoch));
    }

    #[test]
    fn callbacks_enforce_thread_reentrancy_and_unregister_order() {
        let actor = [3; 16];
        let mut callbacks = CallbackRegistry::new(actor, 9, 2);
        let token = callbacks
            .register(CallbackThread::Registering(44), false)
            .unwrap();
        assert_eq!(callbacks.begin(token, 45), Err(LifecycleError::WrongThread));
        callbacks.begin(token, 44).unwrap();
        assert_eq!(
            callbacks.begin(token, 44),
            Err(LifecycleError::ReentrancyDenied)
        );
        assert_eq!(callbacks.unregister(token), Err(LifecycleError::Busy));
        callbacks.end(token).unwrap();
        callbacks.unregister(token).unwrap();
        assert_eq!(callbacks.begin(token, 44), Err(LifecycleError::Unknown));
    }

    #[test]
    fn first_async_terminal_state_wins_and_disconnect_is_unknown() {
        let first = [1; 16];
        let second = [2; 16];
        let mut calls = AsyncRegistry::default();
        calls.begin(first).unwrap();
        calls.dispatch(first).unwrap();
        assert_eq!(
            calls.cancel(first).unwrap(),
            AsyncState::CancellationCommitted
        );
        assert_eq!(calls.complete(first), Err(LifecycleError::Terminal));
        calls.begin(second).unwrap();
        calls.dispatch(second).unwrap();
        calls.disconnect();
        assert_eq!(calls.state(second), Some(AsyncState::OutcomeUnknown));
        assert_eq!(calls.cancel(second), Err(LifecycleError::Terminal));
    }
}
