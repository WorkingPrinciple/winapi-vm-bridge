//! Default-deny actor and operation authorization.

use std::collections::{BTreeMap, BTreeSet};
use wvb_state::{StateError, Store};

pub type ActorId = [u8; 16];
pub type AdapterHash = [u8; 32];

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Invoke = 1,
    Operator = 2,
    AdapterAdmin = 3,
    PairingAdmin = 4,
    Auditor = 5,
    ServiceAdmin = 6,
}

impl TryFrom<u16> for Role {
    type Error = RestoreError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Invoke),
            2 => Ok(Self::Operator),
            3 => Ok(Self::AdapterAdmin),
            4 => Ok(Self::PairingAdmin),
            5 => Ok(Self::Auditor),
            6 => Ok(Self::ServiceAdmin),
            _ => Err(RestoreError::InvalidRecord),
        }
    }
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

#[derive(Debug)]
pub enum RestoreError {
    State(StateError),
    InvalidRecord,
}

impl std::fmt::Display for RestoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RestoreError {}

impl From<StateError> for RestoreError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}

#[derive(Debug, Default)]
pub struct Registry {
    actors: BTreeMap<ActorId, Actor>,
    keys: BTreeMap<[u8; 32], ActorId>,
}

impl Registry {
    pub fn from_store(store: &Store) -> Result<Self, RestoreError> {
        let mut registry = Self::default();
        for actor in store.actors()? {
            registry
                .register(actor.actor_id, actor.public_key)
                .map_err(|_| RestoreError::InvalidRecord)?;
            if !actor.active {
                registry
                    .revoke(actor.actor_id)
                    .map_err(|_| RestoreError::InvalidRecord)?;
            }
        }
        for grant in store.active_grants()? {
            registry
                .grant(
                    grant.actor_id,
                    Grant {
                        role: Role::try_from(grant.role)?,
                        adapter_hash: grant.adapter_hash,
                        operation_id: grant.operation_id,
                        expires_at_unix_ms: grant.expires_unix_ms,
                    },
                )
                .map_err(|_| RestoreError::InvalidRecord)?;
        }
        Ok(registry)
    }

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
        self.authorize_role_exact(
            actor_id,
            Role::Invoke,
            adapter_hash,
            Some(operation_id),
            now_unix_ms,
        )
    }

    /// Authorizes a role using wildcard-compatible grant semantics.
    ///
    /// A grant with no adapter or operation scope matches any requested scope.
    pub fn authorize_role(
        &self,
        actor_id: ActorId,
        role: Role,
        adapter_hash: Option<AdapterHash>,
        operation_id: Option<u32>,
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
            grant.role == role
                && grant
                    .adapter_hash
                    .is_none_or(|hash| adapter_hash == Some(hash))
                && grant.operation_id.is_none_or(|id| operation_id == Some(id))
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

    pub fn authorize_role_exact(
        &self,
        actor_id: ActorId,
        role: Role,
        adapter_hash: AdapterHash,
        operation_id: Option<u32>,
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
            grant.role == role
                && grant.adapter_hash == Some(adapter_hash)
                && grant.operation_id == operation_id
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
    use tempfile::tempdir;
    use wvb_state::{ActorRecord, GrantRecord};

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

    #[test]
    fn durable_registry_restores_active_and_revoked_actors() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.db");
        let actor = [1; 16];
        let key = [2; 32];
        let adapter = [3; 32];
        let mut store = Store::open(&path).unwrap();
        store
            .commit_pairing(
                &ActorRecord {
                    actor_id: actor,
                    public_key: key,
                    label: String::from("Mac"),
                    active: true,
                },
                &[GrantRecord {
                    actor_id: actor,
                    role: Role::Invoke as u16,
                    adapter_hash: Some(adapter),
                    operation_id: Some(7),
                    expires_unix_ms: None,
                }],
                b"pair",
            )
            .unwrap();
        let registry = Registry::from_store(&store).unwrap();
        assert_eq!(registry.actor_for_key(&key).unwrap(), actor);
        registry.authorize_invoke(actor, adapter, 7, 1).unwrap();

        store.revoke_actor(actor, b"revoke").unwrap();
        let registry = Registry::from_store(&store).unwrap();
        assert_eq!(
            registry.actor_for_key(&key),
            Err(AuthorizationError::Revoked)
        );
        assert_eq!(
            registry.authorize_invoke(actor, adapter, 7, 1),
            Err(AuthorizationError::Revoked)
        );
    }

    #[test]
    fn exact_authorization_rejects_wildcard_and_wrong_scopes() {
        let actor = [1; 16];
        let key = [2; 32];
        let adapter = [3; 32];
        let mut registry = Registry::default();
        registry.register(actor, key).unwrap();
        registry
            .grant(
                actor,
                Grant {
                    role: Role::Invoke,
                    adapter_hash: None,
                    operation_id: None,
                    expires_at_unix_ms: None,
                },
            )
            .unwrap();
        assert_eq!(
            registry.authorize_invoke(actor, adapter, 7, 1),
            Err(AuthorizationError::Denied)
        );
        registry
            .grant(
                actor,
                Grant {
                    role: Role::Invoke,
                    adapter_hash: Some([4; 32]),
                    operation_id: Some(7),
                    expires_at_unix_ms: None,
                },
            )
            .unwrap();
        registry
            .grant(
                actor,
                Grant {
                    role: Role::Invoke,
                    adapter_hash: Some(adapter),
                    operation_id: Some(8),
                    expires_at_unix_ms: None,
                },
            )
            .unwrap();
        assert_eq!(
            registry.authorize_invoke(actor, adapter, 7, 1),
            Err(AuthorizationError::Denied)
        );
    }
}
