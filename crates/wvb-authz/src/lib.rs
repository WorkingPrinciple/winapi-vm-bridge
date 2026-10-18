//! Default-deny actor and operation authorization.

use std::collections::{BTreeMap, BTreeSet};

pub type ActorId = [u8; 16];
pub type AdapterHash = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Invoke,
    Operator,
    AdapterAdmin,
    PairingAdmin,
    Auditor,
    ServiceAdmin,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Grant {
    pub role: Role,
    pub adapter_hash: Option<AdapterHash>,
    pub operation_id: Option<u32>,
    pub expires_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub id: ActorId,
    pub public_key: [u8; 32],
    pub status: ActorStatus,
    grants: BTreeSet<Grant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationError {
    UnknownActor,
    Revoked,
    Denied,
}

#[derive(Debug, Default)]
pub struct Registry {
    actors: BTreeMap<ActorId, Actor>,
    keys: BTreeMap<[u8; 32], ActorId>,
}

impl Registry {
    pub fn register(
        &mut self,
        id: ActorId,
        public_key: [u8; 32],
    ) -> Result<(), AuthorizationError> {
        if self.actors.contains_key(&id) || self.keys.contains_key(&public_key) {
            return Err(AuthorizationError::Denied);
        }
        self.actors.insert(
            id,
            Actor {
                id,
                public_key,
                status: ActorStatus::Active,
                grants: BTreeSet::new(),
            },
        );
        self.keys.insert(public_key, id);
        Ok(())
    }

    pub fn actor_for_key(&self, public_key: &[u8; 32]) -> Result<ActorId, AuthorizationError> {
        let id = *self
            .keys
            .get(public_key)
            .ok_or(AuthorizationError::UnknownActor)?;
        let actor = self
            .actors
            .get(&id)
            .ok_or(AuthorizationError::UnknownActor)?;
        if actor.status != ActorStatus::Active {
            return Err(AuthorizationError::Revoked);
        }
        Ok(id)
    }

    pub fn grant(&mut self, actor_id: ActorId, grant: Grant) -> Result<(), AuthorizationError> {
        let actor = self
            .actors
            .get_mut(&actor_id)
            .ok_or(AuthorizationError::UnknownActor)?;
        if actor.status != ActorStatus::Active {
            return Err(AuthorizationError::Revoked);
        }
        actor.grants.insert(grant);
        Ok(())
    }

    pub fn revoke(&mut self, actor_id: ActorId) -> Result<(), AuthorizationError> {
        let actor = self
            .actors
            .get_mut(&actor_id)
            .ok_or(AuthorizationError::UnknownActor)?;
        actor.status = ActorStatus::Revoked;
        Ok(())
    }

    pub fn authorize_invoke(
        &self,
        actor_id: ActorId,
        adapter_hash: AdapterHash,
        operation_id: u32,
        now_unix_ms: u64,
    ) -> Result<(), AuthorizationError> {
        let actor = self
            .actors
            .get(&actor_id)
            .ok_or(AuthorizationError::UnknownActor)?;
        if actor.status != ActorStatus::Active {
            return Err(AuthorizationError::Revoked);
        }
        let allowed = actor.grants.iter().any(|grant| {
            grant.role == Role::Invoke
                && grant.adapter_hash.is_none_or(|hash| hash == adapter_hash)
                && grant.operation_id.is_none_or(|id| id == operation_id)
                && grant
                    .expires_at_unix_ms
                    .is_none_or(|expires| now_unix_ms < expires)
        });
        if allowed {
            Ok(())
        } else {
            Err(AuthorizationError::Denied)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_is_default_deny_scoped_and_expiring() {
        let actor = [1; 16];
        let key = [2; 32];
        let adapter = [3; 32];
        let mut registry = Registry::default();
        registry.register(actor, key).unwrap();
        assert_eq!(
            registry.authorize_invoke(actor, adapter, 7, 10),
            Err(AuthorizationError::Denied)
        );
        registry
            .grant(
                actor,
                Grant {
                    role: Role::Invoke,
                    adapter_hash: Some(adapter),
                    operation_id: Some(7),
                    expires_at_unix_ms: Some(100),
                },
            )
            .unwrap();
        registry.authorize_invoke(actor, adapter, 7, 99).unwrap();
        assert_eq!(
            registry.authorize_invoke(actor, adapter, 8, 99),
            Err(AuthorizationError::Denied)
        );
        assert_eq!(
            registry.authorize_invoke(actor, adapter, 7, 100),
            Err(AuthorizationError::Denied)
        );
        registry.revoke(actor).unwrap();
        assert_eq!(
            registry.actor_for_key(&key),
            Err(AuthorizationError::Revoked)
        );
    }
}
