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
                ('schema_version',1),
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
                revoked_event INTEGER REFERENCES events(sequence),
                PRIMARY KEY(actor_id,role,adapter_hash,operation_id)
            ) STRICT;
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
        Ok(())
    }

    pub fn append_event(&mut self, kind: &str, payload: &[u8]) -> Result<Event, StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
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
        let sequence_sql =
            i64::try_from(sequence).map_err(|_| StateError::Corrupt("sequence exceeds sqlite"))?;
        transaction.execute(
            "INSERT INTO events(sequence,kind,payload,previous_hash,event_hash)
             VALUES(?1,?2,?3,?4,?5)",
            params![
                sequence_sql,
                kind,
                payload,
                previous_hash.as_slice(),
                event_hash.as_slice()
            ],
        )?;
        transaction.commit()?;
        Ok(Event {
            sequence,
            kind: kind.to_owned(),
            payload: payload.to_vec(),
            previous_hash,
            event_hash,
        })
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

fn sql_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            "negative integer for unsigned field".into(),
        )
    })
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
}
