use crate::store::{
    LandRecord, ObjectStore, safe_lz4_decompress, sort_revisions_oldest_first,
};
use chrono::{DateTime, SecondsFormat, Utc};
use gitx_core::{
    ChangeId, ChangeSet, GitxError, ObjectHash, OpId, OpLogEntry, Result, Stack, WorkspaceRef,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS changesets (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    change_id TEXT NOT NULL,
    created_at_ns INTEGER NOT NULL,
    payload BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_changesets_change_id ON changesets (change_id);

CREATE TABLE IF NOT EXISTS stacks (
    name TEXT PRIMARY KEY,
    payload BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS oplog (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    payload BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS lands (
    land_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    previous_head TEXT,
    new_head TEXT NOT NULL,
    landed_changes BLOB NOT NULL,
    timestamp TEXT NOT NULL,
    reverted_by INTEGER
);
CREATE INDEX IF NOT EXISTS idx_lands_target ON lands (target, land_seq DESC);

CREATE TABLE IF NOT EXISTS bookmarks (
    name TEXT PRIMARY KEY,
    hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workspaces (
    name TEXT PRIMARY KEY,
    payload BLOB NOT NULL
);
"#;

/// Local durable `ObjectStore` backed by SQLite (WAL mode) for metadata/oplog/ledger
/// and an LZ4-compressed sharded filesystem CAS (`cas/<2-hex>/<hash>`) for chunks and objects.
pub struct LocalStore {
    root_dir: PathBuf,
    cas_dir: PathBuf,
    conn: Mutex<Connection>,
}

impl LocalStore {
    pub fn open(root_dir: impl AsRef<Path>) -> Result<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();
        let cas_dir = root_dir.join("cas");
        fs::create_dir_all(&cas_dir)?;

        let db_path = root_dir.join("metadata.sqlite");
        let conn = Connection::open(&db_path).map_err(sqlite_err)?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(sqlite_err)?;

        conn.execute_batch(SCHEMA_SQL).map_err(sqlite_err)?;

        Ok(Self {
            root_dir,
            cas_dir,
            conn: Mutex::new(conn),
        })
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    fn lock_conn(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| GitxError::Storage("sqlite connection mutex poisoned".to_string()))
    }

    fn cas_path(&self, hash: ObjectHash) -> (PathBuf, PathBuf, String) {
        let hex = hash.to_hex();
        let shard_dir = self.cas_dir.join(&hex[..2]);
        let file_path = shard_dir.join(&hex);
        (shard_dir, file_path, hex)
    }

    fn write_cas(&self, hash: ObjectHash, bytes: &[u8]) -> Result<()> {
        let (shard_dir, file_path, hex) = self.cas_path(hash);
        if file_path.exists() {
            return Ok(());
        }

        fs::create_dir_all(&shard_dir)?;
        let compressed = lz4_flex::compress_prepend_size(bytes);

        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!(".tmp.{hex}.{}.{n}", std::process::id());
        let tmp_path = shard_dir.join(tmp_name);

        let write_result = (|| -> std::io::Result<()> {
            let mut file = File::create(&tmp_path)?;
            file.write_all(&compressed)?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(err) = write_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(err.into());
        }

        if let Err(err) = fs::rename(&tmp_path, &file_path) {
            let _ = fs::remove_file(&tmp_path);
            if !file_path.exists() {
                return Err(err.into());
            }
        } else {
            #[cfg(unix)]
            if let Ok(dir) = File::open(&shard_dir) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    fn read_cas(&self, hash: ObjectHash, label: &str) -> Result<Vec<u8>> {
        let (_, file_path, _) = self.cas_path(hash);
        let compressed = match fs::read(&file_path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return Err(GitxError::NotFound(format!("{label} {hash}")));
            }
            Err(err) => return Err(err.into()),
        };

        safe_lz4_decompress(&compressed, label, hash)
    }
}

fn sqlite_err(err: rusqlite::Error) -> GitxError {
    GitxError::Storage(err.to_string())
}

fn ser_err(err: bincode::Error) -> GitxError {
    GitxError::Serialization(err.to_string())
}

fn row_to_land_record(row: &rusqlite::Row<'_>) -> Result<LandRecord> {
    let land_seq: i64 = row.get(0).map_err(sqlite_err)?;
    let target: String = row.get(1).map_err(sqlite_err)?;
    let prev_str: Option<String> = row.get(2).map_err(sqlite_err)?;
    let new_str: String = row.get(3).map_err(sqlite_err)?;
    let changes_blob: Vec<u8> = row.get(4).map_err(sqlite_err)?;
    let ts_str: String = row.get(5).map_err(sqlite_err)?;
    let reverted_by: Option<i64> = row.get(6).map_err(sqlite_err)?;

    let previous_head = prev_str
        .as_deref()
        .map(ObjectHash::from_str)
        .transpose()?;
    let new_head = ObjectHash::from_str(&new_str)?;
    let landed_changes: Vec<ChangeId> = bincode::deserialize(&changes_blob).map_err(ser_err)?;
    let timestamp = DateTime::parse_from_rfc3339(&ts_str)
        .map_err(|e| GitxError::Serialization(format!("invalid land timestamp '{ts_str}': {e}")))?
        .with_timezone(&Utc);

    Ok(LandRecord {
        land_seq: land_seq as u64,
        target,
        previous_head,
        new_head,
        landed_changes,
        timestamp,
        reverted_by: reverted_by.map(|v| v as u64),
    })
}

impl ObjectStore for LocalStore {
    fn put_chunk(&self, hash: ObjectHash, data: &[u8]) -> Result<()> {
        self.write_cas(hash, data)
    }

    fn get_chunk(&self, hash: ObjectHash) -> Result<Vec<u8>> {
        self.read_cas(hash, "chunk")
    }

    fn has_chunk(&self, hash: ObjectHash) -> Result<bool> {
        let (_, file_path, _) = self.cas_path(hash);
        Ok(file_path.is_file())
    }

    fn put_raw_object(&self, hash: ObjectHash, bytes: &[u8]) -> Result<()> {
        self.write_cas(hash, bytes)
    }

    fn get_raw_object(&self, hash: ObjectHash) -> Result<Vec<u8>> {
        self.read_cas(hash, "object")
    }

    fn put_changeset(&self, cs: &ChangeSet) -> Result<ObjectHash> {
        let payload = bincode::serialize(cs).map_err(ser_err)?;
        let created_at_ns = cs
            .created_at
            .timestamp_nanos_opt()
            .unwrap_or_else(|| cs.created_at.timestamp_micros().saturating_mul(1_000));

        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO changesets (id, change_id, created_at_ns, payload)
             VALUES (?1, ?2, ?3, ?4)",
            params![cs.id.to_hex(), cs.change_id.to_string(), created_at_ns, payload],
        )
        .map_err(sqlite_err)?;
        Ok(cs.id)
    }

    fn get_changeset(&self, id: ObjectHash) -> Result<ChangeSet> {
        let conn = self.lock_conn()?;
        let payload: Option<Vec<u8>> = conn
            .query_row(
                "SELECT payload FROM changesets WHERE id = ?1",
                params![id.to_hex()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_err)?;

        let bytes = payload.ok_or_else(|| GitxError::NotFound(format!("changeset {id}")))?;
        bincode::deserialize(&bytes).map_err(ser_err)
    }

    fn list_changesets(&self) -> Result<Vec<ChangeSet>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare("SELECT payload FROM changesets ORDER BY seq ASC")
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(sqlite_err)?;

        let mut out = Vec::new();
        for row in rows {
            let bytes = row.map_err(sqlite_err)?;
            out.push(bincode::deserialize(&bytes).map_err(ser_err)?);
        }
        Ok(out)
    }

    fn get_revisions_for_change(&self, change_id: ChangeId) -> Result<Vec<ChangeSet>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare("SELECT seq, payload FROM changesets WHERE change_id = ?1 ORDER BY seq ASC")
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map(params![change_id.to_string()], |row| {
                let seq: i64 = row.get(0)?;
                let payload: Vec<u8> = row.get(1)?;
                Ok((seq as u64, payload))
            })
            .map_err(sqlite_err)?;

        let mut items = Vec::new();
        for row in rows {
            let (seq, bytes) = row.map_err(sqlite_err)?;
            let cs: ChangeSet = bincode::deserialize(&bytes).map_err(ser_err)?;
            items.push((seq, cs));
        }
        Ok(sort_revisions_oldest_first(items))
    }

    fn delete_changeset(&self, id: ObjectHash) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute("DELETE FROM changesets WHERE id = ?1", params![id.to_hex()])
            .map_err(sqlite_err)?;
        Ok(())
    }

    fn put_stack(&self, stack: &Stack) -> Result<()> {
        let payload = bincode::serialize(stack).map_err(ser_err)?;
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO stacks (name, payload) VALUES (?1, ?2)",
            params![stack.name, payload],
        )
        .map_err(sqlite_err)?;
        Ok(())
    }

    fn get_stack(&self, name: &str) -> Result<Stack> {
        let conn = self.lock_conn()?;
        let payload: Option<Vec<u8>> = conn
            .query_row(
                "SELECT payload FROM stacks WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_err)?;

        let bytes = payload.ok_or_else(|| GitxError::NotFound(format!("stack '{name}'")))?;
        bincode::deserialize(&bytes).map_err(ser_err)
    }

    fn list_stacks(&self) -> Result<Vec<Stack>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare("SELECT payload FROM stacks ORDER BY name ASC")
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(sqlite_err)?;

        let mut out = Vec::new();
        for row in rows {
            let bytes = row.map_err(sqlite_err)?;
            out.push(bincode::deserialize(&bytes).map_err(ser_err)?);
        }
        Ok(out)
    }

    fn delete_stack(&self, name: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute("DELETE FROM stacks WHERE name = ?1", params![name])
            .map_err(sqlite_err)?;
        Ok(())
    }

    fn append_op(&self, op: &OpLogEntry) -> Result<()> {
        let payload = bincode::serialize(op).map_err(ser_err)?;
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO oplog (id, payload) VALUES (?1, ?2)",
            params![op.id.0.to_string(), payload],
        )
        .map_err(sqlite_err)?;
        Ok(())
    }

    fn get_op(&self, id: OpId) -> Result<OpLogEntry> {
        let conn = self.lock_conn()?;
        let payload: Option<Vec<u8>> = conn
            .query_row(
                "SELECT payload FROM oplog WHERE id = ?1",
                params![id.0.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_err)?;

        let bytes = payload.ok_or_else(|| GitxError::NotFound(format!("oplog entry {:?}", id)))?;
        bincode::deserialize(&bytes).map_err(ser_err)
    }

    fn latest_op(&self) -> Result<Option<OpLogEntry>> {
        let conn = self.lock_conn()?;
        let payload: Option<Vec<u8>> = conn
            .query_row(
                "SELECT payload FROM oplog ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_err)?;

        payload
            .map(|bytes| bincode::deserialize(&bytes).map_err(ser_err))
            .transpose()
    }

    fn list_ops(&self, limit: usize) -> Result<Vec<OpLogEntry>> {
        let conn = self.lock_conn()?;
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = conn
            .prepare("SELECT payload FROM oplog ORDER BY seq DESC LIMIT ?1")
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map(params![limit_i64], |row| row.get::<_, Vec<u8>>(0))
            .map_err(sqlite_err)?;

        let mut out = Vec::new();
        for row in rows {
            let bytes = row.map_err(sqlite_err)?;
            out.push(bincode::deserialize(&bytes).map_err(ser_err)?);
        }
        Ok(out)
    }

    fn record_land(
        &self,
        target: &str,
        expected_previous: Option<ObjectHash>,
        new_head: ObjectHash,
        changes: Vec<ChangeId>,
    ) -> Result<LandRecord> {
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_err)?;

        let current_head_str: Option<String> = tx
            .query_row(
                "SELECT hash FROM bookmarks WHERE name = ?1",
                params![target],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_err)?;

        let current_head = current_head_str
            .as_deref()
            .map(ObjectHash::from_str)
            .transpose()?;

        if current_head != expected_previous {
            return Err(GitxError::Merge(format!(
                "CAS conflict landing onto '{target}': expected previous head {expected_previous:?}, actual {current_head:?}"
            )));
        }

        let timestamp = Utc::now();
        let ts_str = timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true);
        let changes_blob = bincode::serialize(&changes).map_err(ser_err)?;
        let prev_hex = expected_previous.map(|h| h.to_hex());
        let new_hex = new_head.to_hex();

        tx.execute(
            "INSERT INTO lands (target, previous_head, new_head, landed_changes, timestamp, reverted_by)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
            params![target, prev_hex, new_hex, changes_blob, ts_str],
        )
        .map_err(sqlite_err)?;

        let land_seq = tx.last_insert_rowid() as u64;

        tx.execute(
            "INSERT OR REPLACE INTO bookmarks (name, hash) VALUES (?1, ?2)",
            params![target, new_hex],
        )
        .map_err(sqlite_err)?;

        tx.commit().map_err(sqlite_err)?;

        Ok(LandRecord {
            land_seq,
            target: target.to_string(),
            previous_head: expected_previous,
            new_head,
            landed_changes: changes,
            timestamp,
            reverted_by: None,
        })
    }

    fn get_land(&self, land_seq: u64) -> Result<LandRecord> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT land_seq, target, previous_head, new_head, landed_changes, timestamp, reverted_by
                 FROM lands WHERE land_seq = ?1",
            )
            .map_err(sqlite_err)?;

        let mut rows = stmt.query(params![land_seq as i64]).map_err(sqlite_err)?;
        match rows.next().map_err(sqlite_err)? {
            Some(row) => row_to_land_record(row),
            None => Err(GitxError::NotFound(format!("land record {land_seq}"))),
        }
    }

    fn list_lands(&self, target: &str, limit: usize) -> Result<Vec<LandRecord>> {
        let conn = self.lock_conn()?;
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = conn
            .prepare(
                "SELECT land_seq, target, previous_head, new_head, landed_changes, timestamp, reverted_by
                 FROM lands WHERE target = ?1 ORDER BY land_seq DESC LIMIT ?2",
            )
            .map_err(sqlite_err)?;

        let mut rows = stmt.query(params![target, limit_i64]).map_err(sqlite_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(sqlite_err)? {
            out.push(row_to_land_record(row)?);
        }
        Ok(out)
    }

    fn list_all_lands(&self, after_land_seq: u64, limit: usize) -> Result<Vec<LandRecord>> {
        let conn = self.lock_conn()?;
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = conn
            .prepare(
                "SELECT land_seq, target, previous_head, new_head, landed_changes, timestamp, reverted_by
                 FROM lands WHERE land_seq > ?1 ORDER BY land_seq ASC LIMIT ?2",
            )
            .map_err(sqlite_err)?;

        let mut rows = stmt
            .query(params![after_land_seq as i64, limit_i64])
            .map_err(sqlite_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(sqlite_err)? {
            out.push(row_to_land_record(row)?);
        }
        Ok(out)
    }

    fn mark_reverted(&self, land_seq: u64, reverted_by: u64) -> Result<()> {
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_err)?;

        let existing: Option<Option<i64>> = tx
            .query_row(
                "SELECT reverted_by FROM lands WHERE land_seq = ?1",
                params![land_seq as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_err)?;

        let existing_reverted =
            existing.ok_or_else(|| GitxError::NotFound(format!("land record {land_seq}")))?;

        if let Some(prev_reverter) = existing_reverted
            && prev_reverter as u64 != reverted_by
        {
            return Err(GitxError::Merge(format!(
                "land record {land_seq} already reverted by {prev_reverter}"
            )));
        }

        tx.execute(
            "UPDATE lands SET reverted_by = ?1 WHERE land_seq = ?2",
            params![reverted_by as i64, land_seq as i64],
        )
        .map_err(sqlite_err)?;

        tx.commit().map_err(sqlite_err)?;
        Ok(())
    }

    fn revert_land(&self, land_seq: u64) -> Result<LandRecord> {
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_err)?;

        let original = {
            let mut stmt = tx
                .prepare(
                    "SELECT land_seq, target, previous_head, new_head, landed_changes, timestamp, reverted_by
                     FROM lands WHERE land_seq = ?1",
                )
                .map_err(sqlite_err)?;
            let mut rows = stmt.query(params![land_seq as i64]).map_err(sqlite_err)?;
            match rows.next().map_err(sqlite_err)? {
                Some(row) => row_to_land_record(row)?,
                None => return Err(GitxError::NotFound(format!("land record {land_seq}"))),
            }
        };

        if let Some(existing_rev) = original.reverted_by {
            return Err(GitxError::Merge(format!(
                "land record {land_seq} already reverted by {existing_rev}"
            )));
        }
        let previous_head = original.previous_head.ok_or_else(|| {
            GitxError::Merge(format!(
                "land record {land_seq} has no previous_head to revert to"
            ))
        })?;

        let current_head_str: Option<String> = tx
            .query_row(
                "SELECT hash FROM bookmarks WHERE name = ?1",
                params![&original.target],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_err)?;
        let current_head = current_head_str
            .as_deref()
            .map(ObjectHash::from_str)
            .transpose()?;

        if current_head != Some(original.new_head) {
            return Err(GitxError::Merge(format!(
                "cannot revert land_seq {land_seq}: target '{}' head is {current_head:?}, expected {}",
                original.target, original.new_head
            )));
        }

        let timestamp = Utc::now();
        let ts_str = timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true);
        let changes: Vec<ChangeId> = Vec::new();
        let changes_blob = bincode::serialize(&changes).map_err(ser_err)?;
        let prev_hex = Some(original.new_head.to_hex());
        let new_hex = previous_head.to_hex();

        tx.execute(
            "INSERT INTO lands (target, previous_head, new_head, landed_changes, timestamp, reverted_by)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
            params![&original.target, prev_hex, &new_hex, changes_blob, ts_str],
        )
        .map_err(sqlite_err)?;
        let revert_seq = tx.last_insert_rowid() as u64;

        tx.execute(
            "INSERT OR REPLACE INTO bookmarks (name, hash) VALUES (?1, ?2)",
            params![&original.target, &new_hex],
        )
        .map_err(sqlite_err)?;

        tx.execute(
            "UPDATE lands SET reverted_by = ?1 WHERE land_seq = ?2",
            params![revert_seq as i64, land_seq as i64],
        )
        .map_err(sqlite_err)?;

        tx.commit().map_err(sqlite_err)?;

        Ok(LandRecord {
            land_seq: revert_seq,
            target: original.target,
            previous_head: Some(original.new_head),
            new_head: previous_head,
            landed_changes: changes,
            timestamp,
            reverted_by: None,
        })
    }

    fn get_bookmark(&self, name: &str) -> Result<Option<ObjectHash>> {
        let conn = self.lock_conn()?;
        let hash_str: Option<String> = conn
            .query_row(
                "SELECT hash FROM bookmarks WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_err)?;

        hash_str.as_deref().map(ObjectHash::from_str).transpose()
    }

    fn set_bookmark(&self, name: &str, hash: ObjectHash) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO bookmarks (name, hash) VALUES (?1, ?2)",
            params![name, hash.to_hex()],
        )
        .map_err(sqlite_err)?;
        Ok(())
    }

    fn cas_bookmark(
        &self,
        name: &str,
        expected: Option<ObjectHash>,
        new_hash: ObjectHash,
    ) -> Result<()> {
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_err)?;
        let current_str: Option<String> = tx
            .query_row(
                "SELECT hash FROM bookmarks WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_err)?;
        let current = current_str
            .as_deref()
            .map(ObjectHash::from_str)
            .transpose()?;
        if current != expected {
            return Err(GitxError::Merge(format!(
                "CAS conflict updating bookmark '{name}': expected {expected:?}, actual {current:?}"
            )));
        }
        tx.execute(
            "INSERT OR REPLACE INTO bookmarks (name, hash) VALUES (?1, ?2)",
            params![name, new_hash.to_hex()],
        )
        .map_err(sqlite_err)?;
        tx.commit().map_err(sqlite_err)?;
        Ok(())
    }

    fn cas_bookmarks(&self, updates: &[(String, Option<ObjectHash>, ObjectHash)]) -> Result<()> {
        if updates.is_empty() {
            return Ok(());
        }
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_err)?;
        for (name, expected, _) in updates {
            let current_str: Option<String> = tx
                .query_row(
                    "SELECT hash FROM bookmarks WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sqlite_err)?;
            let current = current_str
                .as_deref()
                .map(ObjectHash::from_str)
                .transpose()?;
            if current != *expected {
                return Err(GitxError::Merge(format!(
                    "CAS conflict updating bookmark '{name}': expected {expected:?}, actual {current:?}"
                )));
            }
        }
        for (name, _, new_hash) in updates {
            tx.execute(
                "INSERT OR REPLACE INTO bookmarks (name, hash) VALUES (?1, ?2)",
                params![name, new_hash.to_hex()],
            )
            .map_err(sqlite_err)?;
        }
        tx.commit().map_err(sqlite_err)?;
        Ok(())
    }

    fn list_bookmarks(&self) -> Result<BTreeMap<String, ObjectHash>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare("SELECT name, hash FROM bookmarks ORDER BY name ASC")
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let hash_str: String = row.get(1)?;
                Ok((name, hash_str))
            })
            .map_err(sqlite_err)?;

        let mut out = BTreeMap::new();
        for row in rows {
            let (name, hash_str) = row.map_err(sqlite_err)?;
            out.insert(name, ObjectHash::from_str(&hash_str)?);
        }
        Ok(out)
    }

    fn put_workspace(&self, ws: &WorkspaceRef) -> Result<()> {
        let payload = bincode::serialize(ws).map_err(ser_err)?;
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO workspaces (name, payload) VALUES (?1, ?2)",
            params![ws.name, payload],
        )
        .map_err(sqlite_err)?;
        Ok(())
    }

    fn get_workspace(&self, name: &str) -> Result<Option<WorkspaceRef>> {
        let conn = self.lock_conn()?;
        let payload: Option<Vec<u8>> = conn
            .query_row(
                "SELECT payload FROM workspaces WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_err)?;

        payload
            .map(|bytes| bincode::deserialize(&bytes).map_err(ser_err))
            .transpose()
    }

    fn list_workspaces(&self) -> Result<BTreeMap<String, WorkspaceRef>> {
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare("SELECT name, payload FROM workspaces ORDER BY name ASC")
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let payload: Vec<u8> = row.get(1)?;
                Ok((name, payload))
            })
            .map_err(sqlite_err)?;

        let mut out = BTreeMap::new();
        for row in rows {
            let (name, bytes) = row.map_err(sqlite_err)?;
            let ws: WorkspaceRef = bincode::deserialize(&bytes).map_err(ser_err)?;
            out.insert(name, ws);
        }
        Ok(out)
    }

    fn remove_workspace(&self, name: &str) -> Result<()> {
        let conn = self.lock_conn()?;
        conn.execute("DELETE FROM workspaces WHERE name = ?1", params![name])
            .map_err(sqlite_err)?;
        Ok(())
    }
}
