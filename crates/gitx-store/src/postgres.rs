//! Live PostgreSQL runtime driver for [`crate::MetadataBackend`] using `tokio-postgres`.
//!
//! Runs `tokio-postgres` operations on a dedicated shared multi-threaded Tokio runtime bridged
//! through a synchronous channel, so every [`crate::MetadataBackend`] call is safe both from
//! synchronous code and from inside existing Axum/Tonic Tokio worker threads (zero nested-runtime
//! panics).

use crate::metadata::{POSTGRES_MIGRATIONS, PostgresConfig, pg_queries};
use crate::store::{LandRecord, sort_revisions_oldest_first};
use chrono::{DateTime, Utc};
use gitx_core::{
    ChangeId, ChangeSet, GitxError, ObjectHash, OpId, OpLogEntry, Result, Stack, WorkspaceRef,
};
use std::collections::BTreeMap;
use std::future::Future;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use tokio::runtime::Runtime;
use tokio_postgres::{Client, NoTls, Row};

static PG_RUNTIME: OnceLock<Runtime> = OnceLock::new();
static PG_RUNTIME_INIT: Mutex<()> = Mutex::new(());

fn pg_runtime() -> Result<&'static Runtime> {
    if let Some(rt) = PG_RUNTIME.get() {
        return Ok(rt);
    }
    let _guard = PG_RUNTIME_INIT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(rt) = PG_RUNTIME.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("gitx-pg-metadata")
        .enable_all()
        .build()
        .map_err(|e| GitxError::Storage(format!("failed to start postgres runtime: {e}")))?;
    if let Err(unused) = PG_RUNTIME.set(rt) {
        unused.shutdown_background();
    }
    Ok(PG_RUNTIME.get().expect("pg runtime initialized"))
}

fn run_pg<F, T>(fut: F) -> Result<T>
where
    F: Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let rt = pg_runtime()?;
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    rt.spawn(async move {
        let res = fut.await;
        let _ = tx.send(res);
    });
    rx.recv()
        .map_err(|e| GitxError::Storage(format!("postgres worker channel closed: {e}")))?
}

fn pg_err(err: tokio_postgres::Error) -> GitxError {
    GitxError::Storage(format!("postgres error: {err}"))
}

fn ser_err(err: bincode::Error) -> GitxError {
    GitxError::Serialization(err.to_string())
}

fn row_to_land(row: &Row) -> Result<LandRecord> {
    let land_seq: i64 = row.try_get(0).map_err(pg_err)?;
    let target: String = row.try_get(1).map_err(pg_err)?;
    let prev_str: Option<String> = row.try_get(2).map_err(pg_err)?;
    let new_str: String = row.try_get(3).map_err(pg_err)?;
    let changes_blob: Vec<u8> = row.try_get(4).map_err(pg_err)?;
    let timestamp: DateTime<Utc> = row.try_get(5).map_err(pg_err)?;
    let reverted_by: Option<i64> = row.try_get(6).map_err(pg_err)?;

    let previous_head = prev_str.as_deref().map(ObjectHash::from_str).transpose()?;
    let new_head = ObjectHash::from_str(&new_str)?;
    let landed_changes: Vec<ChangeId> = bincode::deserialize(&changes_blob).map_err(ser_err)?;

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

/// Live connected PostgreSQL client wrapper implementing full ACID metadata persistence.
pub struct LivePostgresClient {
    config: PostgresConfig,
    client: std::sync::Arc<tokio::sync::Mutex<Client>>,
}

impl LivePostgresClient {
    /// Connect to PostgreSQL, initialize the configured schema, and apply `POSTGRES_MIGRATIONS`.
    pub fn connect(config: PostgresConfig) -> Result<Self> {
        let uri = config.connection_uri()?;
        let schema = config.schema.clone();
        let client = run_pg(async move {
            let (mut client, connection) =
                tokio_postgres::connect(&uri, NoTls).await.map_err(pg_err)?;
            tokio::spawn(async move {
                let _ = connection.await;
            });

            if schema != "public" {
                let setup = format!(
                    "CREATE SCHEMA IF NOT EXISTS {schema}; SET search_path TO {schema}, public;"
                );
                client.batch_execute(&setup).await.map_err(pg_err)?;
            }

            let tx = client.transaction().await.map_err(pg_err)?;
            tx.batch_execute(
                "CREATE TABLE IF NOT EXISTS gitx_schema_migrations (
                     version INTEGER PRIMARY KEY,
                     name TEXT NOT NULL,
                     applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                 );",
            )
            .await
            .map_err(pg_err)?;

            for migration in POSTGRES_MIGRATIONS {
                let existing = tx
                    .query_opt(
                        "SELECT version FROM gitx_schema_migrations WHERE version = $1",
                        &[&(migration.version as i32)],
                    )
                    .await
                    .map_err(pg_err)?;
                if existing.is_none() {
                    tx.batch_execute(migration.sql).await.map_err(pg_err)?;
                    tx.execute(
                        "INSERT INTO gitx_schema_migrations (version, name) VALUES ($1, $2)",
                        &[&(migration.version as i32), &migration.name],
                    )
                    .await
                    .map_err(pg_err)?;
                }
            }
            tx.commit().await.map_err(pg_err)?;
            Ok(client)
        })?;

        Ok(Self {
            config,
            client: std::sync::Arc::new(tokio::sync::Mutex::new(client)),
        })
    }

    pub fn config(&self) -> &PostgresConfig {
        &self.config
    }

    pub fn applied_migrations(&self) -> Result<Vec<u32>> {
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let rows = guard
                .query(
                    "SELECT version FROM gitx_schema_migrations ORDER BY version ASC",
                    &[],
                )
                .await
                .map_err(pg_err)?;
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                let v: i32 = row.try_get(0).map_err(pg_err)?;
                out.push(v as u32);
            }
            Ok(out)
        })
    }

    pub fn put_changeset(&self, cs: &ChangeSet) -> Result<ObjectHash> {
        let id = cs.id;
        let id_hex = cs.id.to_hex();
        let change_id = cs.change_id.to_string();
        let created_at_ns = cs
            .created_at
            .timestamp_nanos_opt()
            .unwrap_or_else(|| cs.created_at.timestamp_micros().saturating_mul(1_000));
        let payload = bincode::serialize(cs).map_err(ser_err)?;
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            guard
                .execute(
                    pg_queries::INSERT_CHANGESET,
                    &[&id_hex, &change_id, &created_at_ns, &payload],
                )
                .await
                .map_err(pg_err)?;
            Ok(id)
        })
    }

    pub fn get_changeset(&self, id: ObjectHash) -> Result<ChangeSet> {
        let id_hex = id.to_hex();
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let row = guard
                .query_opt(pg_queries::SELECT_CHANGESET, &[&id_hex])
                .await
                .map_err(pg_err)?
                .ok_or_else(|| GitxError::NotFound(format!("changeset {id}")))?;
            let bytes: Vec<u8> = row.try_get(0).map_err(pg_err)?;
            bincode::deserialize(&bytes).map_err(ser_err)
        })
    }

    pub fn list_changesets(&self) -> Result<Vec<ChangeSet>> {
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let rows = guard
                .query(pg_queries::LIST_CHANGESETS, &[])
                .await
                .map_err(pg_err)?;
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                let bytes: Vec<u8> = row.try_get(0).map_err(pg_err)?;
                out.push(bincode::deserialize(&bytes).map_err(ser_err)?);
            }
            Ok(out)
        })
    }

    pub fn get_revisions_for_change(&self, change_id: ChangeId) -> Result<Vec<ChangeSet>> {
        let cid = change_id.to_string();
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let rows = guard
                .query(pg_queries::SELECT_REVISIONS_FOR_CHANGE, &[&cid])
                .await
                .map_err(pg_err)?;
            let mut items = Vec::with_capacity(rows.len());
            for row in rows {
                let seq: i64 = row.try_get(0).map_err(pg_err)?;
                let bytes: Vec<u8> = row.try_get(1).map_err(pg_err)?;
                let cs: ChangeSet = bincode::deserialize(&bytes).map_err(ser_err)?;
                items.push((seq as u64, cs));
            }
            Ok(sort_revisions_oldest_first(items))
        })
    }

    pub fn delete_changeset(&self, id: ObjectHash) -> Result<()> {
        let id_hex = id.to_hex();
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            guard
                .execute("DELETE FROM changesets WHERE id = $1", &[&id_hex])
                .await
                .map_err(pg_err)?;
            Ok(())
        })
    }

    pub fn put_stack(&self, stack: &Stack) -> Result<()> {
        let name = stack.name.clone();
        let payload = bincode::serialize(stack).map_err(ser_err)?;
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            guard
                .execute(pg_queries::UPSERT_STACK, &[&name, &payload])
                .await
                .map_err(pg_err)?;
            Ok(())
        })
    }

    pub fn get_stack(&self, name: &str) -> Result<Stack> {
        let name_owned = name.to_string();
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let row = guard
                .query_opt(pg_queries::SELECT_STACK, &[&name_owned])
                .await
                .map_err(pg_err)?
                .ok_or_else(|| GitxError::NotFound(format!("stack '{name_owned}'")))?;
            let bytes: Vec<u8> = row.try_get(0).map_err(pg_err)?;
            bincode::deserialize(&bytes).map_err(ser_err)
        })
    }

    pub fn list_stacks(&self) -> Result<Vec<Stack>> {
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let rows = guard
                .query(pg_queries::LIST_STACKS, &[])
                .await
                .map_err(pg_err)?;
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                let bytes: Vec<u8> = row.try_get(0).map_err(pg_err)?;
                out.push(bincode::deserialize(&bytes).map_err(ser_err)?);
            }
            Ok(out)
        })
    }

    pub fn delete_stack(&self, name: &str) -> Result<()> {
        let name_owned = name.to_string();
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            guard
                .execute(pg_queries::DELETE_STACK, &[&name_owned])
                .await
                .map_err(pg_err)?;
            Ok(())
        })
    }

    pub fn append_op(&self, op: &OpLogEntry) -> Result<()> {
        let id = op.id.0.to_string();
        let payload = bincode::serialize(op).map_err(ser_err)?;
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            guard
                .execute(pg_queries::INSERT_OPLOG, &[&id, &payload])
                .await
                .map_err(pg_err)?;
            Ok(())
        })
    }

    pub fn get_op(&self, id: OpId) -> Result<OpLogEntry> {
        let id_str = id.0.to_string();
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let row = guard
                .query_opt(pg_queries::SELECT_OPLOG, &[&id_str])
                .await
                .map_err(pg_err)?
                .ok_or_else(|| GitxError::NotFound(format!("oplog entry {id:?}")))?;
            let bytes: Vec<u8> = row.try_get(0).map_err(pg_err)?;
            bincode::deserialize(&bytes).map_err(ser_err)
        })
    }

    pub fn latest_op(&self) -> Result<Option<OpLogEntry>> {
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let Some(row) = guard
                .query_opt(pg_queries::SELECT_LATEST_OPLOG, &[])
                .await
                .map_err(pg_err)?
            else {
                return Ok(None);
            };
            let bytes: Vec<u8> = row.try_get(0).map_err(pg_err)?;
            Ok(Some(bincode::deserialize(&bytes).map_err(ser_err)?))
        })
    }

    pub fn list_ops(&self, limit: usize) -> Result<Vec<OpLogEntry>> {
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let rows = guard
                .query(pg_queries::LIST_OPLOG, &[&limit_i64])
                .await
                .map_err(pg_err)?;
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                let bytes: Vec<u8> = row.try_get(0).map_err(pg_err)?;
                out.push(bincode::deserialize(&bytes).map_err(ser_err)?);
            }
            Ok(out)
        })
    }

    pub fn record_land(
        &self,
        target: &str,
        expected_previous: Option<ObjectHash>,
        new_head: ObjectHash,
        changes: Vec<ChangeId>,
    ) -> Result<LandRecord> {
        let target_owned = target.to_string();
        let changes_blob = bincode::serialize(&changes).map_err(ser_err)?;
        let prev_hex = expected_previous.map(|h| h.to_hex());
        let new_hex = new_head.to_hex();
        let timestamp = Utc::now();
        let client = std::sync::Arc::clone(&self.client);

        run_pg(async move {
            let mut guard = client.lock().await;
            let tx = guard.transaction().await.map_err(pg_err)?;

            let current_row = tx
                .query_opt(pg_queries::LOCK_BOOKMARK_FOR_CAS, &[&target_owned])
                .await
                .map_err(pg_err)?;
            let current_head = match current_row {
                Some(r) => {
                    let h: String = r.try_get(0).map_err(pg_err)?;
                    Some(ObjectHash::from_str(&h)?)
                }
                None => None,
            };

            if current_head != expected_previous {
                return Err(GitxError::Merge(format!(
                    "CAS conflict landing onto '{target_owned}': expected previous head {expected_previous:?}, actual {current_head:?}"
                )));
            }

            let row = tx
                .query_one(
                    pg_queries::INSERT_LAND_RETURNING,
                    &[
                        &target_owned,
                        &prev_hex,
                        &new_hex,
                        &changes_blob,
                        &timestamp,
                    ],
                )
                .await
                .map_err(pg_err)?;
            let land_seq = row.try_get::<_, i64>(0).map_err(pg_err)? as u64;

            tx.execute(pg_queries::UPSERT_BOOKMARK, &[&target_owned, &new_hex])
                .await
                .map_err(pg_err)?;
            tx.commit().await.map_err(pg_err)?;

            Ok(LandRecord {
                land_seq,
                target: target_owned,
                previous_head: expected_previous,
                new_head,
                landed_changes: changes,
                timestamp,
                reverted_by: None,
            })
        })
    }

    pub fn get_land(&self, land_seq: u64) -> Result<LandRecord> {
        let seq_i64 = land_seq as i64;
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let row = guard
                .query_opt(pg_queries::SELECT_LAND, &[&seq_i64])
                .await
                .map_err(pg_err)?
                .ok_or_else(|| GitxError::NotFound(format!("land record {land_seq}")))?;
            row_to_land(&row)
        })
    }

    pub fn list_lands(&self, target: &str, limit: usize) -> Result<Vec<LandRecord>> {
        let target_owned = target.to_string();
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let rows = guard
                .query(pg_queries::LIST_LANDS, &[&target_owned, &limit_i64])
                .await
                .map_err(pg_err)?;
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                out.push(row_to_land(&row)?);
            }
            Ok(out)
        })
    }

    pub fn list_all_lands(&self, after_land_seq: u64, limit: usize) -> Result<Vec<LandRecord>> {
        let after_i64 = after_land_seq as i64;
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let rows = guard
                .query(
                    "SELECT land_seq, target, previous_head, new_head, landed_changes, timestamp, reverted_by
                     FROM lands WHERE land_seq > $1 ORDER BY land_seq ASC LIMIT $2",
                    &[&after_i64, &limit_i64],
                )
                .await
                .map_err(pg_err)?;
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                out.push(row_to_land(&row)?);
            }
            Ok(out)
        })
    }

    pub fn mark_reverted(&self, land_seq: u64, reverted_by: u64) -> Result<()> {
        let seq_i64 = land_seq as i64;
        let rev_i64 = reverted_by as i64;
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let mut guard = client.lock().await;
            let tx = guard.transaction().await.map_err(pg_err)?;
            let row = tx
                .query_opt(pg_queries::LOCK_LAND_REVERTED_BY, &[&seq_i64])
                .await
                .map_err(pg_err)?
                .ok_or_else(|| GitxError::NotFound(format!("land record {land_seq}")))?;
            let existing: Option<i64> = row.try_get(0).map_err(pg_err)?;
            if let Some(prev) = existing
                && prev as u64 != reverted_by
            {
                return Err(GitxError::Merge(format!(
                    "land record {land_seq} already reverted by {prev}"
                )));
            }
            tx.execute(pg_queries::UPDATE_LAND_REVERTED_BY, &[&rev_i64, &seq_i64])
                .await
                .map_err(pg_err)?;
            tx.commit().await.map_err(pg_err)?;
            Ok(())
        })
    }

    pub fn revert_land(&self, land_seq: u64) -> Result<LandRecord> {
        let seq_i64 = land_seq as i64;
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let mut guard = client.lock().await;
            let tx = guard.transaction().await.map_err(pg_err)?;

            let orig_row = tx
                .query_opt(
                    "SELECT land_seq, target, previous_head, new_head, landed_changes, timestamp, reverted_by
                     FROM lands WHERE land_seq = $1 FOR UPDATE",
                    &[&seq_i64],
                )
                .await
                .map_err(pg_err)?
                .ok_or_else(|| GitxError::NotFound(format!("land record {land_seq}")))?;
            let original = row_to_land(&orig_row)?;

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

            let cur_row = tx
                .query_opt(pg_queries::LOCK_BOOKMARK_FOR_CAS, &[&original.target])
                .await
                .map_err(pg_err)?;
            let current_head = match cur_row {
                Some(r) => {
                    let h: String = r.try_get(0).map_err(pg_err)?;
                    Some(ObjectHash::from_str(&h)?)
                }
                None => None,
            };
            if current_head != Some(original.new_head) {
                return Err(GitxError::Merge(format!(
                    "cannot revert land_seq {land_seq}: target '{}' head is {current_head:?}, expected {}",
                    original.target, original.new_head
                )));
            }

            let timestamp = Utc::now();
            let changes: Vec<ChangeId> = Vec::new();
            let changes_blob = bincode::serialize(&changes).map_err(ser_err)?;
            let prev_hex = Some(original.new_head.to_hex());
            let new_hex = previous_head.to_hex();

            let rev_row = tx
                .query_one(
                    pg_queries::INSERT_LAND_RETURNING,
                    &[
                        &original.target,
                        &prev_hex,
                        &new_hex,
                        &changes_blob,
                        &timestamp,
                    ],
                )
                .await
                .map_err(pg_err)?;
            let revert_seq = rev_row.try_get::<_, i64>(0).map_err(pg_err)? as u64;

            tx.execute(pg_queries::UPSERT_BOOKMARK, &[&original.target, &new_hex])
                .await
                .map_err(pg_err)?;
            tx.execute(
                pg_queries::UPDATE_LAND_REVERTED_BY,
                &[&(revert_seq as i64), &seq_i64],
            )
            .await
            .map_err(pg_err)?;
            tx.commit().await.map_err(pg_err)?;

            Ok(LandRecord {
                land_seq: revert_seq,
                target: original.target,
                previous_head: Some(original.new_head),
                new_head: previous_head,
                landed_changes: changes,
                timestamp,
                reverted_by: None,
            })
        })
    }

    pub fn get_bookmark(&self, name: &str) -> Result<Option<ObjectHash>> {
        let name_owned = name.to_string();
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let Some(row) = guard
                .query_opt(pg_queries::SELECT_BOOKMARK, &[&name_owned])
                .await
                .map_err(pg_err)?
            else {
                return Ok(None);
            };
            let h: String = row.try_get(0).map_err(pg_err)?;
            Ok(Some(ObjectHash::from_str(&h)?))
        })
    }

    pub fn set_bookmark(&self, name: &str, hash: ObjectHash) -> Result<()> {
        let name_owned = name.to_string();
        let hex = hash.to_hex();
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            guard
                .execute(pg_queries::UPSERT_BOOKMARK, &[&name_owned, &hex])
                .await
                .map_err(pg_err)?;
            Ok(())
        })
    }

    pub fn cas_bookmark(
        &self,
        name: &str,
        expected: Option<ObjectHash>,
        new_hash: ObjectHash,
    ) -> Result<()> {
        self.cas_bookmarks(&[(name.to_string(), expected, new_hash)])
    }

    pub fn cas_bookmarks(
        &self,
        updates: &[(String, Option<ObjectHash>, ObjectHash)],
    ) -> Result<()> {
        if updates.is_empty() {
            return Ok(());
        }
        let owned: Vec<(String, Option<ObjectHash>, ObjectHash)> = updates.to_vec();
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let mut guard = client.lock().await;
            let tx = guard.transaction().await.map_err(pg_err)?;
            for (name, expected, _) in &owned {
                let row = tx
                    .query_opt(pg_queries::LOCK_BOOKMARK_FOR_CAS, &[name])
                    .await
                    .map_err(pg_err)?;
                let current = match row {
                    Some(r) => {
                        let h: String = r.try_get(0).map_err(pg_err)?;
                        Some(ObjectHash::from_str(&h)?)
                    }
                    None => None,
                };
                if current != *expected {
                    return Err(GitxError::Merge(format!(
                        "CAS conflict updating bookmark '{name}': expected {expected:?}, actual {current:?}"
                    )));
                }
            }
            for (name, _, new_hash) in &owned {
                let hex = new_hash.to_hex();
                tx.execute(pg_queries::UPSERT_BOOKMARK, &[name, &hex])
                    .await
                    .map_err(pg_err)?;
            }
            tx.commit().await.map_err(pg_err)?;
            Ok(())
        })
    }

    pub fn list_bookmarks(&self) -> Result<BTreeMap<String, ObjectHash>> {
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let rows = guard
                .query(pg_queries::LIST_BOOKMARKS, &[])
                .await
                .map_err(pg_err)?;
            let mut out = BTreeMap::new();
            for row in rows {
                let name: String = row.try_get(0).map_err(pg_err)?;
                let hex: String = row.try_get(1).map_err(pg_err)?;
                out.insert(name, ObjectHash::from_str(&hex)?);
            }
            Ok(out)
        })
    }

    pub fn put_workspace(&self, ws: &WorkspaceRef) -> Result<()> {
        let name = ws.name.clone();
        let payload = bincode::serialize(ws).map_err(ser_err)?;
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            guard
                .execute(pg_queries::UPSERT_WORKSPACE, &[&name, &payload])
                .await
                .map_err(pg_err)?;
            Ok(())
        })
    }

    pub fn get_workspace(&self, name: &str) -> Result<Option<WorkspaceRef>> {
        let name_owned = name.to_string();
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let Some(row) = guard
                .query_opt(pg_queries::SELECT_WORKSPACE, &[&name_owned])
                .await
                .map_err(pg_err)?
            else {
                return Ok(None);
            };
            let bytes: Vec<u8> = row.try_get(0).map_err(pg_err)?;
            Ok(Some(bincode::deserialize(&bytes).map_err(ser_err)?))
        })
    }

    pub fn list_workspaces(&self) -> Result<BTreeMap<String, WorkspaceRef>> {
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            let rows = guard
                .query(pg_queries::LIST_WORKSPACES, &[])
                .await
                .map_err(pg_err)?;
            let mut out = BTreeMap::new();
            for row in rows {
                let name: String = row.try_get(0).map_err(pg_err)?;
                let bytes: Vec<u8> = row.try_get(1).map_err(pg_err)?;
                out.insert(name, bincode::deserialize(&bytes).map_err(ser_err)?);
            }
            Ok(out)
        })
    }

    pub fn remove_workspace(&self, name: &str) -> Result<()> {
        let name_owned = name.to_string();
        let client = std::sync::Arc::clone(&self.client);
        run_pg(async move {
            let guard = client.lock().await;
            guard
                .execute(pg_queries::DELETE_WORKSPACE, &[&name_owned])
                .await
                .map_err(pg_err)?;
            Ok(())
        })
    }
}
