use crate::anchor::relocate_anchor;
use crate::checkpoint::Checkpoint;
use crate::record::{CodeAnchor, ContextRecord};
use chrono::SecondsFormat;
use gitx_core::{ChangeId, DomainId, GitxError, Result};
use rusqlite::{Connection, OptionalExtension, params, types::Value};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;
use ulid::Ulid;

/// A single matching context record returned by [`ContextStore::why`], together with the
/// matched anchor and its relocated 1-based line range in the current file content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhyMatch {
    pub record: ContextRecord,
    pub matched_anchor: CodeAnchor,
    pub relocated_lines: (u32, u32),
}

/// SQLite-backed store for durable "Why" context records and sub-commit agent checkpoints.
pub struct ContextStore {
    conn: Mutex<Connection>,
}

impl ContextStore {
    /// Open or create a persistent SQLite context store at `path` in WAL mode.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path).map_err(map_db_err)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(map_db_err)?;

        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an ephemeral in-memory SQLite context store.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(map_db_err)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(map_db_err)?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS context_records (
                 id TEXT PRIMARY KEY,
                 change_id TEXT NOT NULL,
                 revision TEXT NOT NULL,
                 visibility TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 payload_json TEXT NOT NULL
             );

             CREATE INDEX IF NOT EXISTS idx_context_records_change_vis
                 ON context_records (change_id, visibility, created_at);

             CREATE TABLE IF NOT EXISTS context_anchors (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 record_id TEXT NOT NULL REFERENCES context_records(id) ON DELETE CASCADE,
                 path TEXT NOT NULL,
                 visibility TEXT NOT NULL,
                 anchor_index INTEGER NOT NULL
             );

             CREATE INDEX IF NOT EXISTS idx_context_anchors_path_vis
                 ON context_anchors (path, visibility);

             CREATE TABLE IF NOT EXISTS checkpoints (
                 id TEXT PRIMARY KEY,
                 workspace TEXT NOT NULL,
                 session_id TEXT NOT NULL,
                 tree_hash TEXT NOT NULL,
                 parent_checkpoint TEXT,
                 created_at TEXT NOT NULL,
                 payload_json TEXT NOT NULL
             );

             CREATE INDEX IF NOT EXISTS idx_checkpoints_workspace_created
                 ON checkpoints (workspace, created_at DESC, id DESC);",
        )
        .map_err(map_db_err)
    }

    fn lock_conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| GitxError::Storage("context store mutex poisoned".to_string()))
    }

    /// Persist a durable context record and index its code anchors.
    pub fn add_record(&self, rec: &ContextRecord) -> Result<()> {
        let payload_json = serde_json::to_string(rec).map_err(map_json_err)?;
        let id_str = rec.id.0.to_string();
        let change_id_str = rec.change_id.0.to_string();
        let revision_str = rec.revision.to_hex();
        let visibility_str = rec.visibility.as_str();
        let created_at_str = rec.created_at.to_rfc3339_opts(SecondsFormat::Nanos, true);

        let mut conn = self.lock_conn()?;
        let tx = conn.transaction().map_err(map_db_err)?;

        tx.execute(
            "DELETE FROM context_anchors WHERE record_id = ?1",
            params![&id_str],
        )
        .map_err(map_db_err)?;

        tx.execute(
            "INSERT OR REPLACE INTO context_records
                 (id, change_id, revision, visibility, created_at, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &id_str,
                &change_id_str,
                &revision_str,
                visibility_str,
                &created_at_str,
                &payload_json,
            ],
        )
        .map_err(map_db_err)?;

        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO context_anchors (record_id, path, visibility, anchor_index)
                     VALUES (?1, ?2, ?3, ?4)",
                )
                .map_err(map_db_err)?;

            for (idx, anchor) in rec.anchors.iter().enumerate() {
                stmt.execute(params![&id_str, &anchor.path, visibility_str, idx as i64])
                    .map_err(map_db_err)?;
            }
        }

        tx.commit().map_err(map_db_err)?;
        Ok(())
    }

    /// Fetch all context records for `change_id` whose visibility domain is in `allowed_domains`.
    pub fn records_for_change(
        &self,
        change_id: ChangeId,
        allowed_domains: &[DomainId],
    ) -> Result<Vec<ContextRecord>> {
        if allowed_domains.is_empty() {
            return Ok(Vec::new());
        }

        let placeholders = make_placeholders(2, allowed_domains.len());
        let sql = format!(
            "SELECT payload_json
             FROM context_records
             WHERE change_id = ?1
               AND visibility IN ({placeholders})
             ORDER BY created_at ASC, id ASC"
        );

        let mut bind_values: Vec<Value> = Vec::with_capacity(1 + allowed_domains.len());
        bind_values.push(Value::Text(change_id.0.to_string()));
        for domain in allowed_domains {
            bind_values.push(Value::Text(domain.as_str().to_string()));
        }

        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(&sql).map_err(map_db_err)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(bind_values), |row| {
                row.get::<_, String>(0)
            })
            .map_err(map_db_err)?;

        let mut records = Vec::new();
        for row in rows {
            let json = row.map_err(map_db_err)?;
            let rec: ContextRecord = serde_json::from_str(&json).map_err(map_json_err)?;
            if rec.is_visible_to(allowed_domains) {
                records.push(rec);
            }
        }

        Ok(records)
    }

    /// Answer "why does this line exist?" by loading authorized records anchored to `path`,
    /// relocating each anchor against `current_file_content`, and returning those covering
    /// `line_1based`.
    pub fn why(
        &self,
        path: &str,
        line_1based: u32,
        current_file_content: &str,
        allowed_domains: &[DomainId],
    ) -> Result<Vec<WhyMatch>> {
        if allowed_domains.is_empty() || line_1based == 0 {
            return Ok(Vec::new());
        }

        let placeholders = make_placeholders(2, allowed_domains.len());
        let sql = format!(
            "SELECT DISTINCT r.payload_json, r.created_at, r.id
             FROM context_records r
             INNER JOIN context_anchors a ON a.record_id = r.id
             WHERE a.path = ?1
               AND r.visibility IN ({placeholders})
               AND a.visibility IN ({placeholders})
             ORDER BY r.created_at DESC, r.id DESC"
        );

        let mut bind_values: Vec<Value> = Vec::with_capacity(1 + allowed_domains.len());
        bind_values.push(Value::Text(path.to_string()));
        for domain in allowed_domains {
            bind_values.push(Value::Text(domain.as_str().to_string()));
        }

        let candidate_jsons: Vec<String> = {
            let conn = self.lock_conn()?;
            let mut stmt = conn.prepare(&sql).map_err(map_db_err)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(bind_values), |row| {
                    row.get::<_, String>(0)
                })
                .map_err(map_db_err)?;

            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(map_db_err)?);
            }
            out
        };

        let mut matches = Vec::new();
        for json in candidate_jsons {
            let rec: ContextRecord = serde_json::from_str(&json).map_err(map_json_err)?;
            // Defense-in-depth domain filter.
            if !rec.is_visible_to(allowed_domains) {
                continue;
            }

            for anchor in &rec.anchors {
                if anchor.path != path {
                    continue;
                }
                if let Some((start, end)) = relocate_anchor(anchor, current_file_content)
                    && line_1based >= start
                    && line_1based <= end
                {
                    matches.push(WhyMatch {
                        record: rec.clone(),
                        matched_anchor: anchor.clone(),
                        relocated_lines: (start, end),
                    });
                }
            }
        }

        Ok(matches)
    }

    /// Persist a sub-commit agent checkpoint.
    pub fn save_checkpoint(&self, cp: &Checkpoint) -> Result<()> {
        let payload_json = serde_json::to_string(cp).map_err(map_json_err)?;
        let id_str = cp.id.to_string();
        let tree_hash_str = cp.tree_hash.to_hex();
        let parent_str = cp.parent_checkpoint.map(|u| u.to_string());
        let created_at_str = cp.created_at.to_rfc3339_opts(SecondsFormat::Nanos, true);

        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO checkpoints
                 (id, workspace, session_id, tree_hash, parent_checkpoint, created_at, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                &id_str,
                &cp.workspace,
                &cp.session_id,
                &tree_hash_str,
                parent_str.as_deref(),
                &created_at_str,
                &payload_json,
            ],
        )
        .map_err(map_db_err)?;
        Ok(())
    }

    /// List checkpoints for a workspace, newest first, up to `limit`.
    pub fn list_checkpoints(&self, workspace: &str, limit: usize) -> Result<Vec<Checkpoint>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT payload_json
                 FROM checkpoints
                 WHERE workspace = ?1
                 ORDER BY created_at DESC, id DESC
                 LIMIT ?2",
            )
            .map_err(map_db_err)?;

        let rows = stmt
            .query_map(params![workspace, limit as i64], |row| {
                row.get::<_, String>(0)
            })
            .map_err(map_db_err)?;

        let mut checkpoints = Vec::new();
        for row in rows {
            let json = row.map_err(map_db_err)?;
            let cp: Checkpoint = serde_json::from_str(&json).map_err(map_json_err)?;
            checkpoints.push(cp);
        }

        Ok(checkpoints)
    }

    /// Fetch a single checkpoint by its ULID.
    pub fn get_checkpoint(&self, id: Ulid) -> Result<Option<Checkpoint>> {
        let conn = self.lock_conn()?;
        let json: Option<String> = conn
            .query_row(
                "SELECT payload_json FROM checkpoints WHERE id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_db_err)?;

        match json {
            Some(raw) => {
                let cp: Checkpoint = serde_json::from_str(&raw).map_err(map_json_err)?;
                Ok(Some(cp))
            }
            None => Ok(None),
        }
    }
}

fn make_placeholders(start_index: usize, count: usize) -> String {
    (start_index..start_index + count)
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn map_db_err(err: rusqlite::Error) -> GitxError {
    GitxError::Storage(err.to_string())
}

fn map_json_err(err: serde_json::Error) -> GitxError {
    GitxError::Serialization(err.to_string())
}
