//! SQL metadata backend, Postgres configuration/DDL/migrations, and [`MetadataBackend`] trait.

use crate::store::{LandRecord, sort_revisions_oldest_first};
use chrono::{DateTime, SecondsFormat, Utc};
use gitx_core::{
    ChangeId, ChangeSet, GitxError, ObjectHash, OpId, OpLogEntry, Result, Stack, WorkspaceRef,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};

/// Metadata persistence abstraction paired with a content-addressed blob backend in
/// [`crate::TieredObjectStore`].
pub trait MetadataBackend: Send + Sync {
    // ---- ChangeSet storage ----
    fn put_changeset(&self, cs: &ChangeSet) -> Result<ObjectHash>;
    fn get_changeset(&self, id: ObjectHash) -> Result<ChangeSet>;
    fn list_changesets(&self) -> Result<Vec<ChangeSet>>;
    fn get_revisions_for_change(&self, change_id: ChangeId) -> Result<Vec<ChangeSet>>;
    fn delete_changeset(&self, id: ObjectHash) -> Result<()>;

    // ---- Stack storage ----
    fn put_stack(&self, stack: &Stack) -> Result<()>;
    fn get_stack(&self, name: &str) -> Result<Stack>;
    fn list_stacks(&self) -> Result<Vec<Stack>>;
    fn delete_stack(&self, name: &str) -> Result<()>;

    // ---- OpLog ----
    fn append_op(&self, op: &OpLogEntry) -> Result<()>;
    fn get_op(&self, id: OpId) -> Result<OpLogEntry>;
    fn latest_op(&self) -> Result<Option<OpLogEntry>>;
    fn list_ops(&self, limit: usize) -> Result<Vec<OpLogEntry>>;

    // ---- Atomic Landing ledger ----
    fn record_land(
        &self,
        target: &str,
        expected_previous: Option<ObjectHash>,
        new_head: ObjectHash,
        changes: Vec<ChangeId>,
    ) -> Result<LandRecord>;
    fn get_land(&self, land_seq: u64) -> Result<LandRecord>;
    fn list_lands(&self, target: &str, limit: usize) -> Result<Vec<LandRecord>>;
    fn list_all_lands(&self, after_land_seq: u64, limit: usize) -> Result<Vec<LandRecord>>;
    fn mark_reverted(&self, land_seq: u64, reverted_by: u64) -> Result<()>;
    fn revert_land(&self, land_seq: u64) -> Result<LandRecord>;

    // ---- Bookmarks & Workspaces ----
    fn get_bookmark(&self, name: &str) -> Result<Option<ObjectHash>>;
    fn set_bookmark(&self, name: &str, hash: ObjectHash) -> Result<()>;
    fn cas_bookmark(
        &self,
        name: &str,
        expected: Option<ObjectHash>,
        new_hash: ObjectHash,
    ) -> Result<()>;
    fn cas_bookmarks(&self, updates: &[(String, Option<ObjectHash>, ObjectHash)]) -> Result<()>;
    fn list_bookmarks(&self) -> Result<BTreeMap<String, ObjectHash>>;
    fn put_workspace(&self, ws: &WorkspaceRef) -> Result<()>;
    fn get_workspace(&self, name: &str) -> Result<Option<WorkspaceRef>>;
    fn list_workspaces(&self) -> Result<BTreeMap<String, WorkspaceRef>>;
    fn remove_workspace(&self, name: &str) -> Result<()>;
}

/// SQL dialect targeted by [`SqlMetadataBackend`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SqlDialect {
    Sqlite,
    Postgres,
}

/// PostgreSQL TLS verification mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PostgresSslMode {
    Disable,
    #[default]
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl PostgresSslMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Prefer => "prefer",
            Self::Require => "require",
            Self::VerifyCa => "verify-ca",
            Self::VerifyFull => "verify-full",
        }
    }
}

/// Connection pool & schema configuration for the PostgreSQL metadata backend.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout_secs: u64,
    pub schema: String,
    pub ssl_mode: PostgresSslMode,
    pub application_name: String,
}

impl fmt::Debug for PostgresConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresConfig")
            .field("url", &"<redacted>")
            .field("max_connections", &self.max_connections)
            .field("min_connections", &self.min_connections)
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .field("schema", &self.schema)
            .field("ssl_mode", &self.ssl_mode)
            .field("application_name", &self.application_name)
            .finish()
    }
}

impl PostgresConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            max_connections: 16,
            min_connections: 1,
            connect_timeout_secs: 10,
            schema: "public".to_string(),
            ssl_mode: PostgresSslMode::Prefer,
            application_name: "gitx-server".to_string(),
        }
    }

    pub fn with_max_connections(mut self, max: u32) -> Self {
        self.max_connections = max;
        self
    }

    pub fn with_min_connections(mut self, min: u32) -> Self {
        self.min_connections = min;
        self
    }

    pub fn with_connect_timeout_secs(mut self, secs: u64) -> Self {
        self.connect_timeout_secs = secs;
        self
    }

    pub fn with_schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = schema.into();
        self
    }

    pub fn with_ssl_mode(mut self, ssl_mode: PostgresSslMode) -> Self {
        self.ssl_mode = ssl_mode;
        self
    }

    pub fn with_application_name(mut self, app: impl Into<String>) -> Self {
        self.application_name = app.into();
        self
    }

    /// Validates connection URL scheme, pool bounds, and SQL schema identifier safety.
    pub fn validate(&self) -> Result<()> {
        let trimmed = self.url.trim();
        let redacted = redact_url_credentials(trimmed);
        let rest = trimmed
            .strip_prefix("postgres://")
            .or_else(|| trimmed.strip_prefix("postgresql://"))
            .ok_or_else(|| {
                GitxError::Storage(format!(
                    "invalid postgres URL '{redacted}': must start with postgres:// or postgresql://"
                ))
            })?;

        let (authority, db_part) = rest.split_once('/').ok_or_else(|| {
            GitxError::Storage(format!(
                "invalid postgres URL '{redacted}': missing database name"
            ))
        })?;
        let host_part = authority
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(authority);
        if host_part.trim().is_empty() {
            return Err(GitxError::Storage(format!(
                "invalid postgres URL '{redacted}': missing host"
            )));
        }
        let db_name = db_part.split('?').next().unwrap_or("");
        if db_name.trim().is_empty() {
            return Err(GitxError::Storage(format!(
                "invalid postgres URL '{redacted}': empty database name"
            )));
        }

        if self.max_connections == 0 {
            return Err(GitxError::Storage(
                "postgres max_connections must be >= 1".to_string(),
            ));
        }
        if self.min_connections > self.max_connections {
            return Err(GitxError::Storage(format!(
                "postgres min_connections ({}) exceeds max_connections ({})",
                self.min_connections, self.max_connections
            )));
        }
        if self.connect_timeout_secs == 0 {
            return Err(GitxError::Storage(
                "postgres connect_timeout_secs must be >= 1".to_string(),
            ));
        }

        if self.schema.is_empty()
            || !self
                .schema
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            || self.schema.starts_with(|c: char| c.is_ascii_digit())
        {
            return Err(GitxError::Storage(format!(
                "invalid postgres schema identifier '{}'",
                self.schema
            )));
        }

        Ok(())
    }

    /// Builds a normalized PostgreSQL libpq connection URI including `sslmode`,
    /// `connect_timeout`, and `application_name`.
    pub fn connection_uri(&self) -> Result<String> {
        self.validate()?;
        let sep = if self.url.contains('?') { '&' } else { '?' };
        let mut uri = self.url.trim().to_string();
        let mut params = Vec::new();
        if !uri.contains("sslmode=") {
            params.push(format!("sslmode={}", self.ssl_mode.as_str()));
        }
        if !uri.contains("connect_timeout=") {
            params.push(format!("connect_timeout={}", self.connect_timeout_secs));
        }
        if !uri.contains("application_name=") && !self.application_name.is_empty() {
            params.push(format!("application_name={}", self.application_name));
        }
        if !params.is_empty() {
            uri.push(sep);
            uri.push_str(&params.join("&"));
        }
        Ok(uri)
    }

    /// Renders the PostgreSQL DDL scoped to `self.schema` (creating the schema if non-`public`).
    pub fn scoped_schema_ddl(&self) -> Result<String> {
        self.validate()?;
        let mut ddl = String::new();
        if self.schema != "public" {
            ddl.push_str(&format!(
                "CREATE SCHEMA IF NOT EXISTS {};\nSET search_path TO {}, public;\n\n",
                self.schema, self.schema
            ));
        }
        ddl.push_str(&postgres_schema_ddl());
        Ok(ddl)
    }
}

/// Versioned SQL schema migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    pub version: u32,
    pub name: &'static str,
    pub sql: &'static str,
}

/// PostgreSQL schema migrations (transactional DDL using `BIGSERIAL`, `BYTEA`, `TIMESTAMPTZ`).
pub const POSTGRES_MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial_core_metadata_tables",
        sql: r#"
CREATE TABLE IF NOT EXISTS gitx_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS changesets (
    seq BIGSERIAL PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    change_id TEXT NOT NULL,
    created_at_ns BIGINT NOT NULL,
    payload BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_changesets_change_id ON changesets (change_id, seq ASC);

CREATE TABLE IF NOT EXISTS stacks (
    name TEXT PRIMARY KEY,
    payload BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS oplog (
    seq BIGSERIAL PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    payload BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS lands (
    land_seq BIGSERIAL PRIMARY KEY,
    target TEXT NOT NULL,
    previous_head TEXT,
    new_head TEXT NOT NULL,
    landed_changes BYTEA NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    reverted_by BIGINT
);
CREATE INDEX IF NOT EXISTS idx_lands_target ON lands (target, land_seq DESC);

CREATE TABLE IF NOT EXISTS bookmarks (
    name TEXT PRIMARY KEY,
    hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workspaces (
    name TEXT PRIMARY KEY,
    payload BYTEA NOT NULL
);
"#,
    },
    Migration {
        version: 2,
        name: "land_outbox_events",
        sql: r#"
CREATE TABLE IF NOT EXISTS land_outbox (
    event_id BIGSERIAL PRIMARY KEY,
    land_seq BIGINT NOT NULL REFERENCES lands(land_seq) ON DELETE CASCADE,
    target TEXT NOT NULL,
    payload BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_land_outbox_pending ON land_outbox (delivered_at, event_id ASC);
"#,
    },
];

/// SQLite schema migrations (used for local development, embedded mode, and hermetic CI tests).
pub const SQLITE_MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial_core_metadata_tables",
        sql: r#"
CREATE TABLE IF NOT EXISTS gitx_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS changesets (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    change_id TEXT NOT NULL,
    created_at_ns INTEGER NOT NULL,
    payload BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_changesets_change_id ON changesets (change_id, seq ASC);

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
"#,
    },
    Migration {
        version: 2,
        name: "land_outbox_events",
        sql: r#"
CREATE TABLE IF NOT EXISTS land_outbox (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    land_seq INTEGER NOT NULL REFERENCES lands(land_seq) ON DELETE CASCADE,
    target TEXT NOT NULL,
    payload BLOB NOT NULL,
    created_at TEXT NOT NULL,
    delivered_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_land_outbox_pending ON land_outbox (delivered_at, event_id ASC);
"#,
    },
];

/// Returns the combined PostgreSQL DDL across all registered migrations.
pub fn postgres_schema_ddl() -> String {
    POSTGRES_MIGRATIONS
        .iter()
        .map(|m| format!("-- Migration {}: {}\n{}", m.version, m.name, m.sql.trim()))
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// Returns the combined SQLite DDL across all registered migrations.
pub fn sqlite_schema_ddl() -> String {
    SQLITE_MIGRATIONS
        .iter()
        .map(|m| format!("-- Migration {}: {}\n{}", m.version, m.name, m.sql.trim()))
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// Parameterized PostgreSQL SQL statements for the server metadata adapter.
pub mod pg_queries {
    pub const INSERT_CHANGESET: &str = "INSERT INTO changesets (id, change_id, created_at_ns, payload) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING";
    pub const SELECT_CHANGESET: &str = "SELECT payload FROM changesets WHERE id = $1";
    pub const LIST_CHANGESETS: &str = "SELECT payload FROM changesets ORDER BY seq ASC";
    pub const SELECT_REVISIONS_FOR_CHANGE: &str =
        "SELECT seq, payload FROM changesets WHERE change_id = $1 ORDER BY seq ASC";

    pub const UPSERT_STACK: &str = "INSERT INTO stacks (name, payload) VALUES ($1, $2) \
         ON CONFLICT (name) DO UPDATE SET payload = EXCLUDED.payload";
    pub const SELECT_STACK: &str = "SELECT payload FROM stacks WHERE name = $1";
    pub const LIST_STACKS: &str = "SELECT payload FROM stacks ORDER BY name ASC";
    pub const DELETE_STACK: &str = "DELETE FROM stacks WHERE name = $1";

    pub const INSERT_OPLOG: &str = "INSERT INTO oplog (id, payload) VALUES ($1, $2)";
    pub const SELECT_OPLOG: &str = "SELECT payload FROM oplog WHERE id = $1";
    pub const SELECT_LATEST_OPLOG: &str = "SELECT payload FROM oplog ORDER BY seq DESC LIMIT 1";
    pub const LIST_OPLOG: &str = "SELECT payload FROM oplog ORDER BY seq DESC LIMIT $1";

    pub const LOCK_BOOKMARK_FOR_CAS: &str = "SELECT hash FROM bookmarks WHERE name = $1 FOR UPDATE";
    pub const INSERT_LAND_RETURNING: &str = "INSERT INTO lands (target, previous_head, new_head, landed_changes, timestamp, reverted_by) \
         VALUES ($1, $2, $3, $4, $5, NULL) RETURNING land_seq";
    pub const SELECT_LAND: &str = "SELECT land_seq, target, previous_head, new_head, landed_changes, timestamp, reverted_by \
         FROM lands WHERE land_seq = $1";
    pub const LIST_LANDS: &str = "SELECT land_seq, target, previous_head, new_head, landed_changes, timestamp, reverted_by \
         FROM lands WHERE target = $1 ORDER BY land_seq DESC LIMIT $2";
    pub const LOCK_LAND_REVERTED_BY: &str =
        "SELECT reverted_by FROM lands WHERE land_seq = $1 FOR UPDATE";
    pub const UPDATE_LAND_REVERTED_BY: &str =
        "UPDATE lands SET reverted_by = $1 WHERE land_seq = $2";

    pub const SELECT_BOOKMARK: &str = "SELECT hash FROM bookmarks WHERE name = $1";
    pub const UPSERT_BOOKMARK: &str = "INSERT INTO bookmarks (name, hash) VALUES ($1, $2) \
         ON CONFLICT (name) DO UPDATE SET hash = EXCLUDED.hash";
    pub const LIST_BOOKMARKS: &str = "SELECT name, hash FROM bookmarks ORDER BY name ASC";

    pub const UPSERT_WORKSPACE: &str = "INSERT INTO workspaces (name, payload) VALUES ($1, $2) \
         ON CONFLICT (name) DO UPDATE SET payload = EXCLUDED.payload";
    pub const SELECT_WORKSPACE: &str = "SELECT payload FROM workspaces WHERE name = $1";
    pub const LIST_WORKSPACES: &str = "SELECT name, payload FROM workspaces ORDER BY name ASC";
    pub const DELETE_WORKSPACE: &str = "DELETE FROM workspaces WHERE name = $1";
}

enum SqlEngine {
    Sqlite {
        path: Option<PathBuf>,
        conn: Mutex<Connection>,
    },
    PostgresConfigured {
        config: PostgresConfig,
    },
    #[cfg(feature = "distributed")]
    PostgresLive(crate::postgres::LivePostgresClient),
}

/// SQL-backed metadata backend supporting local/in-memory SQLite execution and live
/// PostgreSQL (`tokio-postgres`) execution, schema DDL, and versioned SQL migrations.
pub struct SqlMetadataBackend {
    engine: SqlEngine,
}

impl SqlMetadataBackend {
    /// Open (or create) a SQLite metadata database at `db_path` in WAL mode and apply migrations.
    pub fn open_sqlite(db_path: impl AsRef<Path>) -> Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        if let Some(parent) = db_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let mut conn = Connection::open(&db_path).map_err(sqlite_err)?;
        configure_and_migrate_sqlite(&mut conn, true)?;
        Ok(Self {
            engine: SqlEngine::Sqlite {
                path: Some(db_path),
                conn: Mutex::new(conn),
            },
        })
    }

    /// Create an in-memory SQLite metadata database with all migrations applied (ideal for tests).
    pub fn in_memory_sqlite() -> Result<Self> {
        let mut conn = Connection::open_in_memory().map_err(sqlite_err)?;
        configure_and_migrate_sqlite(&mut conn, false)?;
        Ok(Self {
            engine: SqlEngine::Sqlite {
                path: None,
                conn: Mutex::new(conn),
            },
        })
    }

    /// Configure a PostgreSQL metadata backend from [`PostgresConfig`] without opening a live
    /// network socket (useful for offline config validation and DDL generation).
    pub fn from_postgres_config(config: PostgresConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            engine: SqlEngine::PostgresConfigured { config },
        })
    }

    /// Connect to a live PostgreSQL database, initialize the configured schema, and apply
    /// [`POSTGRES_MIGRATIONS`] transactionally via `tokio-postgres`.
    #[cfg(feature = "distributed")]
    pub fn connect_postgres(config: PostgresConfig) -> Result<Self> {
        let live = crate::postgres::LivePostgresClient::connect(config)?;
        Ok(Self {
            engine: SqlEngine::PostgresLive(live),
        })
    }

    /// Convenience constructor connecting directly to a `postgres://` / `postgresql://` URI.
    #[cfg(feature = "distributed")]
    pub fn connect_postgres_url(url: impl Into<String>) -> Result<Self> {
        Self::connect_postgres(PostgresConfig::new(url))
    }

    /// Returns the SQL dialect configured for this backend.
    pub fn dialect(&self) -> SqlDialect {
        match &self.engine {
            SqlEngine::Sqlite { .. } => SqlDialect::Sqlite,
            SqlEngine::PostgresConfigured { .. } => SqlDialect::Postgres,
            #[cfg(feature = "distributed")]
            SqlEngine::PostgresLive(_) => SqlDialect::Postgres,
        }
    }

    /// Returns `true` if backed by an active live PostgreSQL connection.
    pub fn is_live_postgres(&self) -> bool {
        #[cfg(feature = "distributed")]
        {
            matches!(self.engine, SqlEngine::PostgresLive(_))
        }
        #[cfg(not(feature = "distributed"))]
        {
            false
        }
    }

    /// Returns the SQLite file path, if backed by an on-disk SQLite database.
    pub fn sqlite_path(&self) -> Option<&Path> {
        match &self.engine {
            SqlEngine::Sqlite { path, .. } => path.as_deref(),
            SqlEngine::PostgresConfigured { .. } => None,
            #[cfg(feature = "distributed")]
            SqlEngine::PostgresLive(_) => None,
        }
    }

    /// Returns the [`PostgresConfig`], if configured for PostgreSQL.
    pub fn postgres_config(&self) -> Option<&PostgresConfig> {
        match &self.engine {
            SqlEngine::PostgresConfigured { config } => Some(config),
            #[cfg(feature = "distributed")]
            SqlEngine::PostgresLive(pg) => Some(pg.config()),
            SqlEngine::Sqlite { .. } => None,
        }
    }

    /// Returns the versioned SQL migrations for this backend's dialect.
    pub fn migrations(&self) -> &'static [Migration] {
        match self.dialect() {
            SqlDialect::Sqlite => SQLITE_MIGRATIONS,
            SqlDialect::Postgres => POSTGRES_MIGRATIONS,
        }
    }

    /// Returns the full schema DDL for this backend's dialect (respecting custom Postgres schema).
    pub fn schema_ddl(&self) -> Result<String> {
        match &self.engine {
            SqlEngine::Sqlite { .. } => Ok(sqlite_schema_ddl()),
            SqlEngine::PostgresConfigured { config } => config.scoped_schema_ddl(),
            #[cfg(feature = "distributed")]
            SqlEngine::PostgresLive(pg) => pg.config().scoped_schema_ddl(),
        }
    }

    /// Returns the list of applied migration versions recorded in `gitx_schema_migrations`.
    pub fn applied_migrations(&self) -> Result<Vec<u32>> {
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.applied_migrations();
        }
        let conn = self.lock_sqlite()?;
        let mut stmt = conn
            .prepare("SELECT version FROM gitx_schema_migrations ORDER BY version ASC")
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, i64>(0))
            .map_err(sqlite_err)?;
        let mut versions = Vec::new();
        for row in rows {
            versions.push(row.map_err(sqlite_err)? as u32);
        }
        Ok(versions)
    }

    fn lock_sqlite(&self) -> Result<MutexGuard<'_, Connection>> {
        match &self.engine {
            SqlEngine::Sqlite { conn, .. } => conn
                .lock()
                .map_err(|_| GitxError::Storage("sqlite metadata mutex poisoned".to_string())),
            SqlEngine::PostgresConfigured { config } => Err(GitxError::Storage(format!(
                "postgres backend configured for '{}' (schema '{}') is not connected; call SqlMetadataBackend::connect_postgres(config) to open a live connection",
                redact_url_credentials(&config.url),
                config.schema
            ))),
            #[cfg(feature = "distributed")]
            SqlEngine::PostgresLive(_) => Err(GitxError::Storage(
                "internal error: lock_sqlite called on live postgres backend".to_string(),
            )),
        }
    }
}

fn configure_and_migrate_sqlite(conn: &mut Connection, enable_wal: bool) -> Result<()> {
    let pragmas = if enable_wal {
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA foreign_keys = ON;"
    } else {
        "PRAGMA foreign_keys = ON;"
    };
    conn.execute_batch(pragmas).map_err(sqlite_err)?;

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_err)?;

    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS gitx_schema_migrations (
             version INTEGER PRIMARY KEY,
             name TEXT NOT NULL,
             applied_at TEXT NOT NULL
         );",
    )
    .map_err(sqlite_err)?;

    for migration in SQLITE_MIGRATIONS {
        let already_applied: Option<i64> = tx
            .query_row(
                "SELECT version FROM gitx_schema_migrations WHERE version = ?1",
                params![migration.version as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_err)?;

        if already_applied.is_none() {
            tx.execute_batch(migration.sql).map_err(sqlite_err)?;
            let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
            tx.execute(
                "INSERT INTO gitx_schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
                params![migration.version as i64, migration.name, now],
            )
            .map_err(sqlite_err)?;
        }
    }

    tx.commit().map_err(sqlite_err)?;
    Ok(())
}

fn redact_url_credentials(url: &str) -> String {
    if let Some((scheme, rest)) = url.split_once("://") {
        let (authority, tail) = match rest.find(['/', '?', '#']) {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };
        if let Some((_, host)) = authority.rsplit_once('@') {
            return format!("{scheme}://<redacted>@{host}{tail}");
        }
    }
    url.to_string()
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

    let previous_head = prev_str.as_deref().map(ObjectHash::from_str).transpose()?;
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

impl MetadataBackend for SqlMetadataBackend {
    fn put_changeset(&self, cs: &ChangeSet) -> Result<ObjectHash> {
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.put_changeset(cs);
        }
        let payload = bincode::serialize(cs).map_err(ser_err)?;
        let created_at_ns = cs
            .created_at
            .timestamp_nanos_opt()
            .unwrap_or_else(|| cs.created_at.timestamp_micros().saturating_mul(1_000));

        let conn = self.lock_sqlite()?;
        conn.execute(
            "INSERT OR IGNORE INTO changesets (id, change_id, created_at_ns, payload)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                cs.id.to_hex(),
                cs.change_id.to_string(),
                created_at_ns,
                payload
            ],
        )
        .map_err(sqlite_err)?;
        Ok(cs.id)
    }

    fn get_changeset(&self, id: ObjectHash) -> Result<ChangeSet> {
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.get_changeset(id);
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.list_changesets();
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.get_revisions_for_change(change_id);
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.delete_changeset(id);
        }
        let conn = self.lock_sqlite()?;
        conn.execute("DELETE FROM changesets WHERE id = ?1", params![id.to_hex()])
            .map_err(sqlite_err)?;
        Ok(())
    }

    fn put_stack(&self, stack: &Stack) -> Result<()> {
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.put_stack(stack);
        }
        let payload = bincode::serialize(stack).map_err(ser_err)?;
        let conn = self.lock_sqlite()?;
        conn.execute(
            "INSERT OR REPLACE INTO stacks (name, payload) VALUES (?1, ?2)",
            params![stack.name, payload],
        )
        .map_err(sqlite_err)?;
        Ok(())
    }

    fn get_stack(&self, name: &str) -> Result<Stack> {
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.get_stack(name);
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.list_stacks();
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.delete_stack(name);
        }
        let conn = self.lock_sqlite()?;
        conn.execute("DELETE FROM stacks WHERE name = ?1", params![name])
            .map_err(sqlite_err)?;
        Ok(())
    }

    fn append_op(&self, op: &OpLogEntry) -> Result<()> {
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.append_op(op);
        }
        let payload = bincode::serialize(op).map_err(ser_err)?;
        let conn = self.lock_sqlite()?;
        conn.execute(
            "INSERT INTO oplog (id, payload) VALUES (?1, ?2)",
            params![op.id.0.to_string(), payload],
        )
        .map_err(sqlite_err)?;
        Ok(())
    }

    fn get_op(&self, id: OpId) -> Result<OpLogEntry> {
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.get_op(id);
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.latest_op();
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.list_ops(limit);
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.record_land(target, expected_previous, new_head, changes);
        }
        let mut conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.get_land(land_seq);
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.list_lands(target, limit);
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.list_all_lands(after_land_seq, limit);
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.mark_reverted(land_seq, reverted_by);
        }
        let mut conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.revert_land(land_seq);
        }
        let mut conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.get_bookmark(name);
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.set_bookmark(name, hash);
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.cas_bookmark(name, expected, new_hash);
        }
        let mut conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.cas_bookmarks(updates);
        }
        if updates.is_empty() {
            return Ok(());
        }
        let mut conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.list_bookmarks();
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.put_workspace(ws);
        }
        let payload = bincode::serialize(ws).map_err(ser_err)?;
        let conn = self.lock_sqlite()?;
        conn.execute(
            "INSERT OR REPLACE INTO workspaces (name, payload) VALUES (?1, ?2)",
            params![ws.name, payload],
        )
        .map_err(sqlite_err)?;
        Ok(())
    }

    fn get_workspace(&self, name: &str) -> Result<Option<WorkspaceRef>> {
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.get_workspace(name);
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.list_workspaces();
        }
        let conn = self.lock_sqlite()?;
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
        #[cfg(feature = "distributed")]
        if let SqlEngine::PostgresLive(ref pg) = self.engine {
            return pg.remove_workspace(name);
        }
        let conn = self.lock_sqlite()?;
        conn.execute("DELETE FROM workspaces WHERE name = ?1", params![name])
            .map_err(sqlite_err)?;
        Ok(())
    }
}
