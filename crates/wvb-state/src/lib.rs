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

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStatus {
    Queued = 1,
    Running = 2,
    Succeeded = 3,
    Failed = 4,
    Cancelled = 5,
    Unknown = 6,
}

impl TryFrom<u16> for OperationStatus {
    type Error = StateError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Queued),
            2 => Ok(Self::Running),
            3 => Ok(Self::Succeeded),
            4 => Ok(Self::Failed),
            5 => Ok(Self::Cancelled),
            6 => Ok(Self::Unknown),
            _ => Err(StateError::Corrupt("invalid operation status")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRecord {
    pub operation_id: [u8; 16],
    pub operation_type: String,
    pub actor_id: [u8; 16],
    pub target_hash: [u8; 32],
    pub status: OperationStatus,
    pub stage: u32,
    pub attempt: u32,
    pub idempotency_hash: Option<[u8; 32]>,
    pub retryable: bool,
    pub cancellable: bool,
    pub rerunnable: bool,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
    pub started_unix_ms: Option<u64>,
    pub completed_unix_ms: Option<u64>,
    pub trace_id: [u8; 16],
    pub terminal_receipt_id: Option<[u8; 16]>,
    pub detail: Vec<u8>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleAdmissionRecord {
    pub bundle_descriptor_hash: [u8; 32],
    pub contract_hash: [u8; 32],
    pub contract_format: String,
    pub contract_major: u32,
    pub bundle_format: String,
    pub bundle_major: u32,
    pub dispatcher_abi: String,
    pub dispatcher_abi_major: u32,
    pub approval_payload: Vec<u8>,
    pub admitted_by: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptRecord {
    pub receipt_id: [u8; 16],
    pub actor_id: Option<[u8; 16]>,
    pub request_hash: Option<[u8; 32]>,
    pub terminal_status: i32,
    pub event_sequence: u64,
    pub event_hash: [u8; 32],
    pub payload: Vec<u8>,
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
        self.create_schema()?;
        let mut schema_version = self.metadata("schema_version")?;
        if schema_version == 1 {
            self.migrate_v1_to_v2()?;
            schema_version = 2;
        }
        if schema_version == 2 {
            self.migrate_v2_to_v3()?;
            schema_version = 3;
        }
        if schema_version == 3 {
            self.migrate_v3_to_v4()?;
            schema_version = 4;
        }
        if schema_version != 4 {
            return Err(StateError::Corrupt("unsupported schema version"));
        }
        Ok(())
    }

    fn migrate_v3_to_v4(&self) -> Result<(), StateError> {
        self.connection.execute_batch(
            "
            BEGIN IMMEDIATE;
            CREATE TABLE operations(
                operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=16),
                operation_type TEXT NOT NULL,
                actor_id BLOB NOT NULL REFERENCES actors(actor_id)
                    CHECK(length(actor_id)=16),
                target_hash BLOB NOT NULL CHECK(length(target_hash)=32),
                status INTEGER NOT NULL,
                stage INTEGER NOT NULL,
                attempt INTEGER NOT NULL,
                idempotency_hash BLOB,
                retryable INTEGER NOT NULL,
                cancellable INTEGER NOT NULL,
                rerunnable INTEGER NOT NULL,
                created_unix_ms INTEGER NOT NULL,
                updated_unix_ms INTEGER NOT NULL,
                started_unix_ms INTEGER,
                completed_unix_ms INTEGER,
                trace_id BLOB NOT NULL CHECK(length(trace_id)=16),
                terminal_receipt_id BLOB REFERENCES receipts(receipt_id),
                detail BLOB NOT NULL,
                created_event INTEGER NOT NULL REFERENCES events(sequence),
                updated_event INTEGER NOT NULL REFERENCES events(sequence)
            ) STRICT;
            UPDATE metadata SET value=4 WHERE key='schema_version';
            COMMIT;
            ",
        )?;
        Ok(())
    }

    fn create_schema(&self) -> Result<(), StateError> {
        self.connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS metadata(
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            ) STRICT;
            INSERT OR IGNORE INTO metadata(key,value) VALUES
                ('schema_version',4),
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
            CREATE TABLE IF NOT EXISTS bundle_admissions(
                bundle_descriptor_hash BLOB PRIMARY KEY
                    CHECK(length(bundle_descriptor_hash)=32),
                contract_hash BLOB NOT NULL CHECK(length(contract_hash)=32),
                contract_format TEXT NOT NULL,
                contract_major INTEGER NOT NULL,
                bundle_format TEXT NOT NULL,
                bundle_major INTEGER NOT NULL,
                dispatcher_abi TEXT NOT NULL,
                dispatcher_abi_major INTEGER NOT NULL,
                approval_payload BLOB NOT NULL,
                admitted_by BLOB NOT NULL REFERENCES actors(actor_id)
                    CHECK(length(admitted_by)=16),
                admitted_event INTEGER NOT NULL REFERENCES events(sequence),
                revoked_event INTEGER REFERENCES events(sequence)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS operations(
                operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=16),
                operation_type TEXT NOT NULL,
                actor_id BLOB NOT NULL REFERENCES actors(actor_id)
                    CHECK(length(actor_id)=16),
                target_hash BLOB NOT NULL CHECK(length(target_hash)=32),
                status INTEGER NOT NULL,
                stage INTEGER NOT NULL,
                attempt INTEGER NOT NULL,
                idempotency_hash BLOB,
                retryable INTEGER NOT NULL,
                cancellable INTEGER NOT NULL,
                rerunnable INTEGER NOT NULL,
                created_unix_ms INTEGER NOT NULL,
                updated_unix_ms INTEGER NOT NULL,
                started_unix_ms INTEGER,
                completed_unix_ms INTEGER,
                trace_id BLOB NOT NULL CHECK(length(trace_id)=16),
                terminal_receipt_id BLOB REFERENCES receipts(receipt_id),
                detail BLOB NOT NULL,
                created_event INTEGER NOT NULL REFERENCES events(sequence),
                updated_event INTEGER NOT NULL REFERENCES events(sequence)
            ) STRICT;
            ",
        )?;
        Ok(())
    }

    fn migrate_v1_to_v2(&self) -> Result<(), StateError> {
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
        Ok(())
    }

    fn migrate_v2_to_v3(&self) -> Result<(), StateError> {
        self.connection.execute_batch(
            "
            BEGIN IMMEDIATE;
            CREATE TABLE bundle_admissions(
                bundle_descriptor_hash BLOB PRIMARY KEY
                    CHECK(length(bundle_descriptor_hash)=32),
                contract_hash BLOB NOT NULL CHECK(length(contract_hash)=32),
                contract_format TEXT NOT NULL,
                contract_major INTEGER NOT NULL,
                bundle_format TEXT NOT NULL,
                bundle_major INTEGER NOT NULL,
                dispatcher_abi TEXT NOT NULL,
                dispatcher_abi_major INTEGER NOT NULL,
                approval_payload BLOB NOT NULL,
                admitted_by BLOB NOT NULL REFERENCES actors(actor_id)
                    CHECK(length(admitted_by)=16),
                admitted_event INTEGER NOT NULL REFERENCES events(sequence),
                revoked_event INTEGER REFERENCES events(sequence)
            ) STRICT;
            UPDATE metadata SET value=3 WHERE key='schema_version';
            COMMIT;
            ",
        )?;
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

    pub fn commit_bundle_admission(
        &mut self,
        record: &BundleAdmissionRecord,
        audit_payload: &[u8],
    ) -> Result<Event, StateError> {
        if record.contract_format.is_empty()
            || record.bundle_format.is_empty()
            || record.dispatcher_abi.is_empty()
            || record.approval_payload.is_empty()
        {
            return Err(StateError::Corrupt("invalid bundle admission"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active_actor: Option<i64> = transaction
            .query_row(
                "SELECT status FROM actors WHERE actor_id=?1",
                [record.admitted_by.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if active_actor != Some(1) {
            return Err(StateError::Corrupt("admitting actor not active"));
        }
        let event = Self::append_event_transaction(&transaction, "bundle-admitted", audit_payload)?;
        transaction.execute(
            "INSERT INTO bundle_admissions(
                bundle_descriptor_hash,contract_hash,contract_format,contract_major,
                bundle_format,bundle_major,dispatcher_abi,dispatcher_abi_major,
                approval_payload,admitted_by,admitted_event,revoked_event
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL)",
            params![
                record.bundle_descriptor_hash.as_slice(),
                record.contract_hash.as_slice(),
                record.contract_format,
                i64::from(record.contract_major),
                record.bundle_format,
                i64::from(record.bundle_major),
                record.dispatcher_abi,
                i64::from(record.dispatcher_abi_major),
                record.approval_payload,
                record.admitted_by.as_slice(),
                sql_i64(event.sequence)?
            ],
        )?;
        transaction.commit()?;
        Ok(event)
    }

    pub fn revoke_bundle_admission(
        &mut self,
        bundle_descriptor_hash: [u8; 32],
        audit_payload: &[u8],
    ) -> Result<Event, StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let event = Self::append_event_transaction(&transaction, "bundle-revoked", audit_payload)?;
        let changed = transaction.execute(
            "UPDATE bundle_admissions SET revoked_event=?2
             WHERE bundle_descriptor_hash=?1 AND revoked_event IS NULL",
            params![bundle_descriptor_hash.as_slice(), sql_i64(event.sequence)?],
        )?;
        if changed != 1 {
            return Err(StateError::Corrupt("bundle admission not active"));
        }
        transaction.commit()?;
        Ok(event)
    }

    pub fn active_bundle_admissions(&self) -> Result<Vec<BundleAdmissionRecord>, StateError> {
        let mut statement = self.connection.prepare(
            "SELECT
                bundle_descriptor_hash,contract_hash,contract_format,contract_major,
                bundle_format,bundle_major,dispatcher_abi,dispatcher_abi_major,
                approval_payload,admitted_by
             FROM bundle_admissions
             WHERE revoked_event IS NULL
             ORDER BY bundle_descriptor_hash",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(BundleAdmissionRecord {
                bundle_descriptor_hash: fixed_array_sql::<32>(row.get(0)?)?,
                contract_hash: fixed_array_sql::<32>(row.get(1)?)?,
                contract_format: row.get(2)?,
                contract_major: sql_u32(row, 3)?,
                bundle_format: row.get(4)?,
                bundle_major: sql_u32(row, 5)?,
                dispatcher_abi: row.get(6)?,
                dispatcher_abi_major: sql_u32(row, 7)?,
                approval_payload: row.get(8)?,
                admitted_by: fixed_array_sql::<16>(row.get(9)?)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StateError::Sql)
    }

    pub fn commit_receipt(
        &mut self,
        receipt_id: [u8; 16],
        actor_id: Option<[u8; 16]>,
        request_hash: Option<[u8; 32]>,
        terminal_status: i32,
        payload: &[u8],
    ) -> Result<ReceiptRecord, StateError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let event = Self::append_event_transaction(&transaction, "receipt-committed", payload)?;
        transaction.execute(
            "INSERT INTO receipts(
                receipt_id,actor_id,request_hash,terminal_status,
                event_sequence,event_hash,payload
             ) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                receipt_id.as_slice(),
                actor_id.as_ref().map(<[u8; 16]>::as_slice),
                request_hash.as_ref().map(<[u8; 32]>::as_slice),
                i64::from(terminal_status),
                sql_i64(event.sequence)?,
                event.event_hash.as_slice(),
                payload
            ],
        )?;
        transaction.commit()?;
        Ok(ReceiptRecord {
            receipt_id,
            actor_id,
            request_hash,
            terminal_status,
            event_sequence: event.sequence,
            event_hash: event.event_hash,
            payload: payload.to_vec(),
        })
    }

    pub fn receipt(&self, receipt_id: [u8; 16]) -> Result<Option<ReceiptRecord>, StateError> {
        self.connection
            .query_row(
                "SELECT actor_id,request_hash,terminal_status,event_sequence,event_hash,payload
                 FROM receipts WHERE receipt_id=?1",
                [receipt_id.as_slice()],
                |row| {
                    let terminal_status = i32::try_from(row.get::<_, i64>(2)?).map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Integer,
                            "terminal status exceeds i32".into(),
                        )
                    })?;
                    Ok(ReceiptRecord {
                        receipt_id,
                        actor_id: row
                            .get::<_, Option<Vec<u8>>>(0)?
                            .map(fixed_array_sql::<16>)
                            .transpose()?,
                        request_hash: row
                            .get::<_, Option<Vec<u8>>>(1)?
                            .map(fixed_array_sql::<32>)
                            .transpose()?,
                        terminal_status,
                        event_sequence: sql_u64(row, 3)?,
                        event_hash: fixed_array_sql::<32>(row.get(4)?)?,
                        payload: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(StateError::Sql)
    }

    pub fn create_operation(
        &mut self,
        operation: &OperationRecord,
        audit_payload: &[u8],
    ) -> Result<Event, StateError> {
        validate_operation(operation, None)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let event =
            Self::append_event_transaction(&transaction, "operation-created", audit_payload)?;
        transaction.execute(
            "INSERT INTO operations(
                operation_id,operation_type,actor_id,target_hash,status,stage,attempt,
                idempotency_hash,retryable,cancellable,rerunnable,created_unix_ms,
                updated_unix_ms,started_unix_ms,completed_unix_ms,trace_id,
                terminal_receipt_id,detail,created_event,updated_event
             ) VALUES(
                ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,
                ?17,?18,?19,?19
             )",
            params![
                operation.operation_id.as_slice(),
                operation.operation_type,
                operation.actor_id.as_slice(),
                operation.target_hash.as_slice(),
                i64::from(operation.status as u16),
                i64::from(operation.stage),
                i64::from(operation.attempt),
                operation
                    .idempotency_hash
                    .as_ref()
                    .map(<[u8; 32]>::as_slice),
                i64::from(u8::from(operation.retryable)),
                i64::from(u8::from(operation.cancellable)),
                i64::from(u8::from(operation.rerunnable)),
                sql_i64(operation.created_unix_ms)?,
                sql_i64(operation.updated_unix_ms)?,
                operation.started_unix_ms.map(sql_i64).transpose()?,
                operation.completed_unix_ms.map(sql_i64).transpose()?,
                operation.trace_id.as_slice(),
                operation
                    .terminal_receipt_id
                    .as_ref()
                    .map(<[u8; 16]>::as_slice),
                operation.detail,
                sql_i64(event.sequence)?
            ],
        )?;
        transaction.commit()?;
        Ok(event)
    }

    pub fn transition_operation(
        &mut self,
        expected: OperationStatus,
        operation: &OperationRecord,
        audit_payload: &[u8],
    ) -> Result<Event, StateError> {
        validate_operation(operation, Some(expected))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let event =
            Self::append_event_transaction(&transaction, "operation-transition", audit_payload)?;
        let changed = transaction.execute(
            "UPDATE operations SET
                status=?2,stage=?3,attempt=?4,idempotency_hash=?5,retryable=?6,
                cancellable=?7,rerunnable=?8,updated_unix_ms=?9,started_unix_ms=?10,
                completed_unix_ms=?11,terminal_receipt_id=?12,detail=?13,updated_event=?14
             WHERE operation_id=?1 AND status=?15",
            params![
                operation.operation_id.as_slice(),
                i64::from(operation.status as u16),
                i64::from(operation.stage),
                i64::from(operation.attempt),
                operation
                    .idempotency_hash
                    .as_ref()
                    .map(<[u8; 32]>::as_slice),
                i64::from(u8::from(operation.retryable)),
                i64::from(u8::from(operation.cancellable)),
                i64::from(u8::from(operation.rerunnable)),
                sql_i64(operation.updated_unix_ms)?,
                operation.started_unix_ms.map(sql_i64).transpose()?,
                operation.completed_unix_ms.map(sql_i64).transpose()?,
                operation
                    .terminal_receipt_id
                    .as_ref()
                    .map(<[u8; 16]>::as_slice),
                operation.detail,
                sql_i64(event.sequence)?,
                i64::from(expected as u16)
            ],
        )?;
        if changed != 1 {
            return Err(StateError::Corrupt("operation transition conflict"));
        }
        transaction.commit()?;
        Ok(event)
    }

    pub fn operation(&self, operation_id: [u8; 16]) -> Result<Option<OperationRecord>, StateError> {
        self.connection
            .query_row(
                "SELECT
                    operation_type,actor_id,target_hash,status,stage,attempt,
                    idempotency_hash,retryable,cancellable,rerunnable,created_unix_ms,
                    updated_unix_ms,started_unix_ms,completed_unix_ms,trace_id,
                    terminal_receipt_id,detail
                 FROM operations WHERE operation_id=?1",
                [operation_id.as_slice()],
                |row| operation_from_row(operation_id, row),
            )
            .optional()
            .map_err(StateError::Sql)
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

fn validate_operation(
    operation: &OperationRecord,
    previous: Option<OperationStatus>,
) -> Result<(), StateError> {
    if operation.operation_type.is_empty()
        || operation.updated_unix_ms < operation.created_unix_ms
        || operation.attempt == 0
    {
        return Err(StateError::Corrupt("invalid operation record"));
    }
    if let Some(previous) = previous {
        let allowed = matches!(
            (previous, operation.status),
            (
                OperationStatus::Queued,
                OperationStatus::Running | OperationStatus::Cancelled
            ) | (
                OperationStatus::Running,
                OperationStatus::Succeeded
                    | OperationStatus::Failed
                    | OperationStatus::Cancelled
                    | OperationStatus::Unknown
            ) | (
                OperationStatus::Unknown,
                OperationStatus::Succeeded | OperationStatus::Failed
            )
        );
        if !allowed {
            return Err(StateError::Corrupt("invalid operation transition"));
        }
    } else if operation.status != OperationStatus::Queued
        || operation.stage != 0
        || operation.started_unix_ms.is_some()
        || operation.completed_unix_ms.is_some()
        || operation.terminal_receipt_id.is_some()
    {
        return Err(StateError::Corrupt("invalid initial operation"));
    }
    match operation.status {
        OperationStatus::Queued => {}
        OperationStatus::Running => {
            if operation.started_unix_ms.is_none()
                || operation.completed_unix_ms.is_some()
                || operation.terminal_receipt_id.is_some()
            {
                return Err(StateError::Corrupt("invalid running operation"));
            }
        }
        OperationStatus::Succeeded
        | OperationStatus::Failed
        | OperationStatus::Cancelled
        | OperationStatus::Unknown => {
            if operation.started_unix_ms.is_none()
                || operation.completed_unix_ms.is_none()
                || operation.terminal_receipt_id.is_none()
                || operation.cancellable
            {
                return Err(StateError::Corrupt("invalid terminal operation"));
            }
        }
    }
    Ok(())
}

fn operation_from_row(
    operation_id: [u8; 16],
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<OperationRecord> {
    let status = u16::try_from(sql_u64(row, 3)?)
        .map_err(|_| integer_conversion_error(3, "operation status exceeds u16"))?;
    let boolean = |index| -> rusqlite::Result<bool> {
        match row.get::<_, i64>(index)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(integer_conversion_error(index, "invalid boolean")),
        }
    };
    Ok(OperationRecord {
        operation_id,
        operation_type: row.get(0)?,
        actor_id: fixed_array_sql::<16>(row.get(1)?)?,
        target_hash: fixed_array_sql::<32>(row.get(2)?)?,
        status: OperationStatus::try_from(status)
            .map_err(|_| integer_conversion_error(3, "invalid operation status"))?,
        stage: sql_u32(row, 4)?,
        attempt: sql_u32(row, 5)?,
        idempotency_hash: row
            .get::<_, Option<Vec<u8>>>(6)?
            .map(fixed_array_sql::<32>)
            .transpose()?,
        retryable: boolean(7)?,
        cancellable: boolean(8)?,
        rerunnable: boolean(9)?,
        created_unix_ms: sql_u64(row, 10)?,
        updated_unix_ms: sql_u64(row, 11)?,
        started_unix_ms: optional_u64(row, 12)?,
        completed_unix_ms: optional_u64(row, 13)?,
        trace_id: fixed_array_sql::<16>(row.get(14)?)?,
        terminal_receipt_id: row
            .get::<_, Option<Vec<u8>>>(15)?
            .map(fixed_array_sql::<16>)
            .transpose()?,
        detail: row.get(16)?,
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

fn sql_u32(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u32> {
    let value = sql_u64(row, index)?;
    u32::try_from(value).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            "integer exceeds u32".into(),
        )
    })
}

fn optional_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<u64>> {
    row.get::<_, Option<i64>>(index)?
        .map(|value| sql_u64_value(value, index))
        .transpose()
}

fn integer_conversion_error(index: usize, message: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Integer, message.into())
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

    #[test]
    fn bundle_admission_and_revocation_are_atomic_and_durable() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("bundle.db");
        let actor = ActorRecord {
            actor_id: [1; 16],
            public_key: [2; 32],
            label: String::from("operator"),
            active: true,
        };
        let record = BundleAdmissionRecord {
            bundle_descriptor_hash: [3; 32],
            contract_hash: [4; 32],
            contract_format: String::from("whiny.adapter-contract.v3"),
            contract_major: 3,
            bundle_format: String::from("whiny.adapter-bundle.v1"),
            bundle_major: 1,
            dispatcher_abi: String::from("whiny.dispatch.v1"),
            dispatcher_abi_major: 1,
            approval_payload: b"opaque-runtime-approval".to_vec(),
            admitted_by: actor.actor_id,
        };
        {
            let mut store = Store::open(&path).unwrap();
            store.commit_pairing(&actor, &[], b"pair").unwrap();
            store.commit_bundle_admission(&record, b"admit").unwrap();
            assert_eq!(
                store.active_bundle_admissions().unwrap(),
                vec![record.clone()]
            );
            assert!(
                store
                    .commit_bundle_admission(&record, b"duplicate")
                    .is_err()
            );
            assert_eq!(store.verify_chain().unwrap().unwrap().sequence, 2);
            store
                .revoke_bundle_admission(record.bundle_descriptor_hash, b"revoke")
                .unwrap();
            assert!(store.active_bundle_admissions().unwrap().is_empty());
        }
        let store = Store::open(&path).unwrap();
        assert!(store.active_bundle_admissions().unwrap().is_empty());
        assert_eq!(store.verify_chain().unwrap().unwrap().sequence, 3);
    }

    #[test]
    fn receipts_commit_with_their_audit_event() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("receipts.db");
        let mut store = Store::open(&path).unwrap();
        let receipt = store
            .commit_receipt([1; 16], None, Some([2; 32]), 7, b"terminal receipt")
            .unwrap();
        assert_eq!(receipt.event_sequence, 1);
        assert_eq!(store.receipt([1; 16]).unwrap(), Some(receipt));
        assert!(
            store
                .commit_receipt([1; 16], None, None, 0, b"duplicate")
                .is_err()
        );
        assert_eq!(store.verify_chain().unwrap().unwrap().sequence, 1);
    }

    #[test]
    fn durable_operation_first_terminal_transition_wins_and_reopens() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("operations.db");
        let actor = ActorRecord {
            actor_id: [1; 16],
            public_key: [2; 32],
            label: String::from("operator"),
            active: true,
        };
        let mut operation = OperationRecord {
            operation_id: [3; 16],
            operation_type: String::from("bundle-install"),
            actor_id: actor.actor_id,
            target_hash: [4; 32],
            status: OperationStatus::Queued,
            stage: 0,
            attempt: 1,
            idempotency_hash: Some([5; 32]),
            retryable: true,
            cancellable: true,
            rerunnable: false,
            created_unix_ms: 10,
            updated_unix_ms: 10,
            started_unix_ms: None,
            completed_unix_ms: None,
            trace_id: [6; 16],
            terminal_receipt_id: None,
            detail: b"queued".to_vec(),
        };
        {
            let mut store = Store::open(&path).unwrap();
            store.commit_pairing(&actor, &[], b"pair").unwrap();
            store.create_operation(&operation, b"created").unwrap();
            operation.status = OperationStatus::Running;
            operation.stage = 1;
            operation.updated_unix_ms = 11;
            operation.started_unix_ms = Some(11);
            operation.detail = b"running".to_vec();
            store
                .transition_operation(OperationStatus::Queued, &operation, b"running")
                .unwrap();
            let receipt_id = [7; 16];
            store
                .commit_receipt(
                    receipt_id,
                    Some(actor.actor_id),
                    operation.idempotency_hash,
                    0,
                    b"succeeded",
                )
                .unwrap();
            operation.status = OperationStatus::Succeeded;
            operation.stage = 2;
            operation.updated_unix_ms = 12;
            operation.completed_unix_ms = Some(12);
            operation.terminal_receipt_id = Some(receipt_id);
            operation.cancellable = false;
            operation.detail = b"succeeded".to_vec();
            store
                .transition_operation(OperationStatus::Running, &operation, b"succeeded")
                .unwrap();
            let mut cancelled = operation.clone();
            cancelled.status = OperationStatus::Cancelled;
            assert!(
                store
                    .transition_operation(
                        OperationStatus::Running,
                        &cancelled,
                        b"late cancellation"
                    )
                    .is_err()
            );
            assert_eq!(
                store.operation(operation.operation_id).unwrap(),
                Some(operation.clone())
            );
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.operation(operation.operation_id).unwrap(),
            Some(operation)
        );
        store.verify_chain().unwrap();
    }
}
