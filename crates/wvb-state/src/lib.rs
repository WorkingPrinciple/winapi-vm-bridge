//! Durable event, actor and receipt state for the Windows broker.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

const ZERO_HASH: [u8; 32] = [0; 32];

#[derive(Debug)]
pub enum StateError {
    Sql(rusqlite::Error),
    Corrupt(&'static str),
    AnchorRollback,
}

impl std::fmt::Display for StateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for StateError {}

impl From<rusqlite::Error> for StateError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sql(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub sequence: u64,
    pub kind: String,
    pub payload: Vec<u8>,
    pub previous_hash: [u8; 32],
    pub event_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorRecord {
    pub actor_id: [u8; 16],
    pub public_key: [u8; 32],
    pub label: String,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecord {
    pub actor_id: [u8; 16],
    pub role: u16,
    pub adapter_hash: Option<[u8; 32]>,
    pub operation_id: Option<u32>,
    pub expires_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorState {
    pub database_generation: u64,
    pub checkpoint_sequence: u64,
    pub event_sequence: u64,
    pub event_hash: [u8; 32],
    pub key_generation: u64,
}

pub trait RollbackAnchor {
    fn load(&self) -> Result<Option<AnchorState>, StateError>;
    fn store(&mut self, state: AnchorState) -> Result<(), StateError>;
}

pub struct Store {
    connection: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StateError> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), StateError> {
        self.connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS metadata(
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            ) STRICT;
            INSERT OR IGNORE INTO metadata(key,value) VALUES
                ('schema_version',2),
                ('database_generation',1),
                ('checkpoint_sequence',0),
                ('key_generation',1);
            CREATE TABLE IF NOT EXISTS events(
                sequence INTEGER PRIMARY KEY,
                kind TEXT NOT NULL,
                payload BLOB NOT NULL,
                previous_hash BLOB NOT NULL CHECK(length(previous_hash)=32),
                event_hash BLOB NOT NULL UNIQUE CHECK(length(event_hash)=32)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS actors(
                actor_id BLOB PRIMARY KEY CHECK(length(actor_id)=16),
                public_key BLOB NOT NULL UNIQUE CHECK(length(public_key)=32),
                label TEXT NOT NULL,
                status INTEGER NOT NULL,
                created_event INTEGER NOT NULL REFERENCES events(sequence),
                revoked_event INTEGER REFERENCES events(sequence)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS grants(
                actor_id BLOB NOT NULL REFERENCES actors(actor_id),
                role INTEGER NOT NULL,
                adapter_hash BLOB,
                operation_id INTEGER,
                expires_unix_ms INTEGER,
                created_event INTEGER NOT NULL REFERENCES events(sequence),
                revoked_event INTEGER REFERENCES events(sequence)
            ) STRICT;
            CREATE UNIQUE INDEX IF NOT EXISTS grants_normalized_unique
                ON grants(
                    actor_id,
                    role,
                    IFNULL(hex(adapter_hash),''),
                    IFNULL(operation_id,-1)
                );
            CREATE TABLE IF NOT EXISTS receipts(
                receipt_id BLOB PRIMARY KEY CHECK(length(receipt_id)=16),
                actor_id BLOB REFERENCES actors(actor_id),
                request_hash BLOB,
                terminal_status INTEGER NOT NULL,
                event_sequence INTEGER NOT NULL REFERENCES events(sequence),
                event_hash BLOB NOT NULL CHECK(length(event_hash)=32),
                payload BLOB NOT NULL
            ) STRICT;
            ",
        )?;
        let schema_version = self.metadata("schema_version")?;
        if schema_version == 1 {
            self.connection.execute_batch(
                "
                BEGIN IMMEDIATE;
                DROP INDEX IF EXISTS grants_normalized_unique;
                CREATE TABLE grants_v2(
                    actor_id BLOB NOT NULL REFERENCES actors(actor_id),
                    role INTEGER NOT NULL,
                    adapter_hash BLOB,
                    operation_id INTEGER,
                    expires_unix_ms INTEGER,
                    created_event INTEGER NOT NULL REFERENCES events(sequence),
                    revoked_event INTEGER REFERENCES events(sequence)
                ) STRICT;
                INSERT INTO grants_v2(
                    actor_id,role,adapter_hash,operation_id,expires_unix_ms,
                    created_event,revoked_event
                )
                SELECT
                    actor_id,role,adapter_hash,operation_id,expires_unix_ms,
                    created_event,revoked_event
                FROM grants;
                DROP TABLE grants;
                ALTER TABLE grants_v2 RENAME TO grants;
                CREATE UNIQUE INDEX grants_normalized_unique
                    ON grants(
                        actor_id,
                        role,
                        IFNULL(hex(adapter_hash),''),
                        IFNULL(operation_id,-1)
                    );
                UPDATE metadata SET value=2 WHERE key='schema_version';
                COMMIT;
                ",
            )?;
        } else if schema_version != 2 {
            return Err(StateError::Corrupt("unsupported schema version"));
        }
        Ok(())
    }

    pub fn append_event(&mut self, kind: &str, payload: &[u8]) -> Result<Event, StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let event = Self::append_event_transaction(&transaction, kind, payload)?;
        transaction.commit()?;
        Ok(event)
    }

    pub fn commit_pairing(
        &mut self,
        actor: &ActorRecord,
        grants: &[GrantRecord],
        audit_payload: &[u8],
    ) -> Result<Event, StateError> {
        if !actor.active || grants.iter().any(|grant| grant.actor_id != actor.actor_id) {
            return Err(StateError::Corrupt("invalid pairing records"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let event = Self::append_event_transaction(&transaction, "pair-committed", audit_payload)?;
        let event_sequence = sql_i64(event.sequence)?;
        transaction.execute(
            "INSERT INTO actors(actor_id,public_key,label,status,created_event,revoked_event)
             VALUES(?1,?2,?3,1,?4,NULL)",
            params![
                actor.actor_id.as_slice(),
                actor.public_key.as_slice(),
                actor.label,
                event_sequence
            ],
        )?;
        for grant in grants {
            transaction.execute(
                "INSERT INTO grants(
                    actor_id,role,adapter_hash,operation_id,expires_unix_ms,
                    created_event,revoked_event
                 ) VALUES(?1,?2,?3,?4,?5,?6,NULL)",
                params![
                    grant.actor_id.as_slice(),
                    i64::from(grant.role),
                    grant.adapter_hash.as_ref().map(<[u8; 32]>::as_slice),
                    grant.operation_id.map(i64::from),
                    grant.expires_unix_ms.map(sql_i64).transpose()?,
                    event_sequence
                ],
            )?;
        }
        transaction.commit()?;
        Ok(event)
    }

    pub fn revoke_actor(
        &mut self,
        actor_id: [u8; 16],
        audit_payload: &[u8],
    ) -> Result<Event, StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let event = Self::append_event_transaction(&transaction, "actor-revoked", audit_payload)?;
        let changed = transaction.execute(
            "UPDATE actors SET status=2,revoked_event=?2
             WHERE actor_id=?1 AND status=1",
            params![actor_id.as_slice(), sql_i64(event.sequence)?],
        )?;
        if changed != 1 {
            return Err(StateError::Corrupt("actor not active"));
        }
        transaction.execute(
            "UPDATE grants SET revoked_event=?2
             WHERE actor_id=?1 AND revoked_event IS NULL",
            params![actor_id.as_slice(), sql_i64(event.sequence)?],
        )?;
        transaction.commit()?;
        Ok(event)
    }

    pub fn actors(&self) -> Result<Vec<ActorRecord>, StateError> {
        let mut statement = self
            .connection
            .prepare("SELECT actor_id,public_key,label,status FROM actors ORDER BY actor_id")?;
        let rows = statement.query_map([], |row| {
            let actor_id = fixed_array_sql::<16>(row.get(0)?)?;
            let public_key = fixed_array_sql::<32>(row.get(1)?)?;
            let status: i64 = row.get(3)?;
            if !matches!(status, 1 | 2) {
                return Err(rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Integer,
                    "invalid actor status".into(),
                ));
            }
            Ok(ActorRecord {
                actor_id,
                public_key,
                label: row.get(2)?,
                active: status == 1,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StateError::Sql)
    }

    pub fn active_grants(&self) -> Result<Vec<GrantRecord>, StateError> {
        let mut statement = self.connection.prepare(
            "SELECT actor_id,role,adapter_hash,operation_id,expires_unix_ms
             FROM grants WHERE revoked_event IS NULL
             ORDER BY actor_id,role,adapter_hash,operation_id",
        )?;
        let rows = statement.query_map([], |row| {
            let role = sql_u64(row, 1)?;
            let operation = row
                .get::<_, Option<i64>>(3)?
                .map(|value| {
                    u32::try_from(value).map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Integer,
                            "operation id exceeds u32".into(),
                        )
                    })
                })
                .transpose()?;
            let expires = row
                .get::<_, Option<i64>>(4)?
                .map(|value| sql_u64_value(value, 4))
                .transpose()?;
            Ok(GrantRecord {
                actor_id: fixed_array_sql::<16>(row.get(0)?)?,
                role: u16::try_from(role).map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Integer,
                        "role exceeds u16".into(),
                    )
                })?,
                adapter_hash: row
                    .get::<_, Option<Vec<u8>>>(2)?
                    .map(fixed_array_sql::<32>)
                    .transpose()?,
                operation_id: operation,
                expires_unix_ms: expires,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StateError::Sql)
    }

    pub fn latest_event(&self) -> Result<Option<Event>, StateError> {
        self.connection
            .query_row(
                "SELECT sequence,kind,payload,previous_hash,event_hash
                 FROM events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| {
                    let previous: Vec<u8> = row.get(3)?;
                    let hash: Vec<u8> = row.get(4)?;
                    Ok(Event {
                        sequence: sql_u64(row, 0)?,
                        kind: row.get(1)?,
                        payload: row.get(2)?,
                        previous_hash: fixed_hash_sql(previous)?,
                        event_hash: fixed_hash_sql(hash)?,
                    })
                },
            )
            .optional()
            .map_err(StateError::Sql)
    }

    fn append_event_transaction(
        transaction: &rusqlite::Transaction<'_>,
        kind: &str,
        payload: &[u8],
    ) -> Result<Event, StateError> {
        let latest: Option<(i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT sequence,event_hash FROM events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (sequence, previous_hash) = match latest {
            Some((sequence, hash)) => (
                u64::try_from(sequence)
                    .map_err(|_| StateError::Corrupt("negative sequence"))?
                    .checked_add(1)
                    .ok_or(StateError::Corrupt("sequence overflow"))?,
                fixed_hash(&hash)?,
            ),
            None => (1, ZERO_HASH),
        };
        let event_hash = event_hash(previous_hash, sequence, kind, payload);
        transaction.execute(
            "INSERT INTO events(sequence,kind,payload,previous_hash,event_hash)
             VALUES(?1,?2,?3,?4,?5)",
            params![
                sql_i64(sequence)?,
                kind,
                payload,
                previous_hash.as_slice(),
                event_hash.as_slice()
            ],
        )?;
        Ok(Event {
            sequence,
            kind: kind.to_owned(),
            payload: payload.to_vec(),
            previous_hash,
            event_hash,
        })
    }

    pub fn verify_chain(&self) -> Result<Option<Event>, StateError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence,kind,payload,previous_hash,event_hash FROM events ORDER BY sequence",
        )?;
        let mut rows = statement.query([])?;
        let mut expected_sequence = 1_u64;
        let mut expected_previous = ZERO_HASH;
        let mut last = None;
        while let Some(row) = rows.next()? {
            let event = Event {
                sequence: sql_u64(row, 0)?,
                kind: row.get(1)?,
                payload: row.get(2)?,
                previous_hash: fixed_hash(&row.get::<_, Vec<u8>>(3)?)?,
                event_hash: fixed_hash(&row.get::<_, Vec<u8>>(4)?)?,
            };
            if event.sequence != expected_sequence || event.previous_hash != expected_previous {
                return Err(StateError::Corrupt("event chain ordering"));
            }
            if event.event_hash
                != event_hash(
                    event.previous_hash,
                    event.sequence,
                    &event.kind,
                    &event.payload,
                )
            {
                return Err(StateError::Corrupt("event hash mismatch"));
            }
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(StateError::Corrupt("sequence overflow"))?;
            expected_previous = event.event_hash;
            last = Some(event);
        }
        Ok(last)
    }

    pub fn anchor_state(&self) -> Result<AnchorState, StateError> {
        let latest = self.latest_event()?;
        Ok(AnchorState {
            database_generation: self.metadata("database_generation")?,
            checkpoint_sequence: self.metadata("checkpoint_sequence")?,
            event_sequence: latest.as_ref().map_or(0, |event| event.sequence),
            event_hash: latest.map_or(ZERO_HASH, |event| event.event_hash),
            key_generation: self.metadata("key_generation")?,
        })
    }

    pub fn reconcile_anchor(&self, anchor: AnchorState) -> Result<(), StateError> {
        let database = self.anchor_state()?;
        if anchor.database_generation > database.database_generation
            || anchor.event_sequence > database.event_sequence
            || anchor.event_sequence == database.event_sequence
                && anchor.event_hash != database.event_hash
        {
            return Err(StateError::AnchorRollback);
        }
        Ok(())
    }

    fn metadata(&self, key: &str) -> Result<u64, StateError> {
        self.connection
            .query_row("SELECT value FROM metadata WHERE key=?1", [key], |row| {
                sql_u64(row, 0)
            })
            .map_err(StateError::Sql)
    }
}

fn event_hash(previous: [u8; 32], sequence: u64, kind: &str, payload: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(previous);
    digest.update(sequence.to_le_bytes());
    digest.update((kind.len() as u64).to_le_bytes());
    digest.update(kind.as_bytes());
    digest.update((payload.len() as u64).to_le_bytes());
    digest.update(payload);
    digest.finalize().into()
}

fn fixed_hash(value: &[u8]) -> Result<[u8; 32], StateError> {
    value
        .try_into()
        .map_err(|_| StateError::Corrupt("invalid hash length"))
}

fn fixed_hash_sql(value: Vec<u8>) -> rusqlite::Result<[u8; 32]> {
    value.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            "invalid hash length".into(),
        )
    })
}

fn fixed_array_sql<const N: usize>(value: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    value.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            "invalid fixed array length".into(),
        )
    })
}

fn sql_i64(value: u64) -> Result<i64, StateError> {
    i64::try_from(value).map_err(|_| StateError::Corrupt("value exceeds sqlite integer"))
}

fn sql_u64_value(value: i64, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            "negative integer for unsigned field".into(),
        )
    })
}

fn sql_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    sql_u64_value(value, index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[derive(Default)]
    struct MemoryAnchor(Option<AnchorState>);

    impl RollbackAnchor for MemoryAnchor {
        fn load(&self) -> Result<Option<AnchorState>, StateError> {
            Ok(self.0)
        }

        fn store(&mut self, state: AnchorState) -> Result<(), StateError> {
            self.0 = Some(state);
            Ok(())
        }
    }

    #[test]
    fn event_chain_survives_reopen_and_detects_rollback_anchor() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.db");
        let anchor = {
            let mut store = Store::open(&path).unwrap();
            store.append_event("created", b"one").unwrap();
            store.append_event("completed", b"two").unwrap();
            store.verify_chain().unwrap();
            store.anchor_state().unwrap()
        };
        let store = Store::open(&path).unwrap();
        assert_eq!(store.verify_chain().unwrap().unwrap().sequence, 2);
        store.reconcile_anchor(anchor).unwrap();
        let future = AnchorState {
            event_sequence: 3,
            ..anchor
        };
        assert!(matches!(
            store.reconcile_anchor(future),
            Err(StateError::AnchorRollback)
        ));
    }

    #[test]
    fn rollback_anchor_interface_round_trips_without_claiming_product_tpm() {
        let mut anchor = MemoryAnchor::default();
        let value = AnchorState {
            database_generation: 1,
            checkpoint_sequence: 2,
            event_sequence: 3,
            event_hash: [4; 32],
            key_generation: 5,
        };
        anchor.store(value).unwrap();
        assert_eq!(anchor.load().unwrap(), Some(value));
    }

    #[test]
    fn pairing_and_revocation_are_atomic_durable_and_audited() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("actors.db");
        let actor = ActorRecord {
            actor_id: [1; 16],
            public_key: [2; 32],
            label: String::from("Mac"),
            active: true,
        };
        let grants = [
            GrantRecord {
                actor_id: actor.actor_id,
                role: 1,
                adapter_hash: Some([3; 32]),
                operation_id: Some(7),
                expires_unix_ms: Some(1_000),
            },
            GrantRecord {
                actor_id: actor.actor_id,
                role: 5,
                adapter_hash: None,
                operation_id: None,
                expires_unix_ms: None,
            },
        ];
        {
            let mut store = Store::open(&path).unwrap();
            let paired = store
                .commit_pairing(&actor, &grants, b"pair receipt")
                .unwrap();
            assert_eq!(paired.sequence, 1);
            assert_eq!(store.actors().unwrap(), vec![actor.clone()]);
            assert_eq!(store.active_grants().unwrap(), grants);
            let revoked = store
                .revoke_actor(actor.actor_id, b"revoke receipt")
                .unwrap();
            assert_eq!(revoked.sequence, 2);
            assert!(store.active_grants().unwrap().is_empty());
            assert!(!store.actors().unwrap()[0].active);
            store.verify_chain().unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.verify_chain().unwrap().unwrap().sequence, 2);
        assert!(!store.actors().unwrap()[0].active);
        assert!(store.active_grants().unwrap().is_empty());
    }

    #[test]
    fn failed_pairing_rolls_back_event_and_actor_together() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("rollback.db");
        let mut store = Store::open(&path).unwrap();
        let actor = ActorRecord {
            actor_id: [4; 16],
            public_key: [5; 32],
            label: String::from("Mac"),
            active: true,
        };
        store.commit_pairing(&actor, &[], b"first").unwrap();
        assert!(store.commit_pairing(&actor, &[], b"duplicate").is_err());
        assert_eq!(store.verify_chain().unwrap().unwrap().sequence, 1);
        assert_eq!(store.actors().unwrap().len(), 1);
    }
}
