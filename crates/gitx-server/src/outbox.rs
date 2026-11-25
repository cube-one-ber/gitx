//! Persistent SQLite webhook outbox for atomic `land` and `revert` events.
//!
//! Tracks delivery state per `(event_id, destination_url)` so retries and startup replays
//! never re-send duplicate webhooks to destinations that already succeeded.

use chrono::{DateTime, SecondsFormat, Utc};
use gitx_core::{EmbargoState, GitxError, ObjectHash, Result};
use gitx_store::ObjectStore;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_DISPATCH_ATTEMPTS: u32 = 3;

/// Single persisted outbox event emitted on atomic `land` or `revert`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxEvent {
    pub event_id: u64,
    pub event_type: String,
    pub target: String,
    pub land_seq: u64,
    pub previous_head: Option<String>,
    pub new_head: String,
    pub payload_json: String,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub delivery_attempts: u32,
    pub last_error: Option<String>,
}

/// Durable SQLite-backed webhook outbox with per-destination delivery state.
pub struct WebhookOutbox {
    conn: Mutex<Connection>,
    dispatch_lock: Arc<tokio::sync::Mutex<()>>,
}

impl WebhookOutbox {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref())
            .map_err(|e| GitxError::Storage(format!("failed to open outbox sqlite: {e}")))?;
        Self::init_conn(conn)
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| GitxError::Storage(format!("failed to open in-memory outbox: {e}")))?;
        Self::init_conn(conn)
    }

    fn init_conn(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             CREATE TABLE IF NOT EXISTS land_outbox (
                 event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_type TEXT NOT NULL,
                 target TEXT NOT NULL,
                 land_seq INTEGER NOT NULL,
                 previous_head TEXT,
                 new_head TEXT NOT NULL,
                 payload_json TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 delivered_at TEXT,
                 delivery_attempts INTEGER NOT NULL DEFAULT 0,
                 last_error TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_outbox_pending ON land_outbox (delivered_at, event_id ASC);
             CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_land_seq_unique ON land_outbox (land_seq);
             CREATE TABLE IF NOT EXISTS land_outbox_deliveries (
                 event_id INTEGER NOT NULL,
                 url TEXT NOT NULL,
                 delivered_at TEXT,
                 delivery_attempts INTEGER NOT NULL DEFAULT 0,
                 last_error TEXT,
                 PRIMARY KEY (event_id, url)
             );",
        )
        .map_err(|e| GitxError::Storage(format!("failed to initialize outbox schema: {e}")))?;

        Ok(Self {
            conn: Mutex::new(conn),
            dispatch_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub fn record_event(
        &self,
        event_type: &str,
        target: &str,
        land_seq: u64,
        previous_head: Option<ObjectHash>,
        new_head: ObjectHash,
        payload: &serde_json::Value,
    ) -> Result<OutboxEvent> {
        let now = Utc::now();
        let created_str = now.to_rfc3339_opts(SecondsFormat::Nanos, true);
        let prev_hex = previous_head.map(|h| h.to_hex());
        let new_hex = new_head.to_hex();
        let payload_json = serde_json::to_string(payload)
            .map_err(|e| GitxError::Serialization(e.to_string()))?;

        let conn = self
            .conn
            .lock()
            .map_err(|_| GitxError::Storage("outbox mutex poisoned".to_string()))?;
        conn.execute(
            "INSERT INTO land_outbox (event_type, target, land_seq, previous_head, new_head, payload_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(land_seq) DO UPDATE SET
                 event_type = excluded.event_type,
                 payload_json = excluded.payload_json
             WHERE land_outbox.delivered_at IS NULL",
            params![
                event_type,
                target,
                land_seq as i64,
                prev_hex,
                new_hex,
                payload_json,
                created_str,
            ],
        )
        .map_err(|e| GitxError::Storage(format!("failed to insert outbox event: {e}")))?;

        let event = conn
            .query_row(
                "SELECT event_id, event_type, target, land_seq, previous_head, new_head,
                        payload_json, created_at, delivered_at, delivery_attempts, last_error
                 FROM land_outbox
                 WHERE land_seq = ?1",
                params![land_seq as i64],
                decode_outbox_row,
            )
            .map_err(|e| GitxError::Storage(format!("failed to read inserted outbox event: {e}")))?;
        Ok(event)
    }

    /// Returns `true` if ANY outbox event (`land`, `revert`, or `auto_revert`) already exists
    /// for `land_seq`.
    pub fn has_event_for_land_seq(&self, land_seq: u64) -> Result<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GitxError::Storage("outbox mutex poisoned".to_string()))?;
        let exists: i64 = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM land_outbox WHERE land_seq = ?1)",
                params![land_seq as i64],
                |row| row.get(0),
            )
            .map_err(|e| GitxError::Storage(format!("failed to check outbox land_seq: {e}")))?;
        Ok(exists != 0)
    }

    /// Insert a backfill outbox event ONLY if no row exists for `land_seq` (`INSERT OR IGNORE`),
    /// so concurrent reconciliation can never overwrite or downgrade a richer live event.
    pub fn insert_event_if_absent(
        &self,
        event_type: &str,
        target: &str,
        land_seq: u64,
        previous_head: Option<ObjectHash>,
        new_head: ObjectHash,
        payload: &serde_json::Value,
    ) -> Result<bool> {
        let now = Utc::now();
        let created_str = now.to_rfc3339_opts(SecondsFormat::Nanos, true);
        let prev_hex = previous_head.map(|h| h.to_hex());
        let new_hex = new_head.to_hex();
        let payload_json = serde_json::to_string(payload)
            .map_err(|e| GitxError::Serialization(e.to_string()))?;

        let conn = self
            .conn
            .lock()
            .map_err(|_| GitxError::Storage("outbox mutex poisoned".to_string()))?;
        let inserted = conn
            .execute(
                "INSERT OR IGNORE INTO land_outbox (event_type, target, land_seq, previous_head, new_head, payload_json, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    event_type,
                    target,
                    land_seq as i64,
                    prev_hex,
                    new_hex,
                    payload_json,
                    created_str,
                ],
            )
            .map_err(|e| GitxError::Storage(format!("failed to backfill outbox event: {e}")))?;
        Ok(inserted > 0)
    }

    /// Crash-recovery reconciliation between the durable `lands` ledger in `store` and `land_outbox`.
    pub fn reconcile_from_store(
        &self,
        store: &dyn ObjectStore,
        repo_full_name: &str,
    ) -> Result<usize> {
        let empty = HashSet::new();
        self.reconcile_from_store_excluding(store, repo_full_name, &empty)
    }

    /// Crash-recovery reconciliation skipping any `LandRecord` whose `new_head` or `previous_head`
    /// is currently in `in_flight_heads` (awaiting `post_land_cmd` verification), and inserting
    /// missing rows with `INSERT OR IGNORE` so concurrent live events are never overwritten.
    pub fn reconcile_from_store_excluding(
        &self,
        store: &dyn ObjectStore,
        repo_full_name: &str,
        in_flight_heads: &HashSet<ObjectHash>,
    ) -> Result<usize> {
        let mut all_lands = Vec::new();
        let mut after_seq = 0u64;
        loop {
            let batch = store.list_all_lands(after_seq, 256)?;
            if batch.is_empty() {
                break;
            }
            let batch_len = batch.len();
            if let Some(last) = batch.last() {
                after_seq = last.land_seq;
            }
            all_lands.extend(batch);
            if batch_len < 256 {
                break;
            }
        }
        self.reconcile_records_excluding(store, repo_full_name, &all_lands, in_flight_heads)
    }

    /// Reconcile a pre-snapshotted slice of `LandRecord`s against `land_outbox` (used by
    /// epoch-bracketed `RepoHandle::reconcile_outbox`).
    pub fn reconcile_records_excluding(
        &self,
        store: &dyn ObjectStore,
        repo_full_name: &str,
        all_lands: &[gitx_store::LandRecord],
        in_flight_heads: &HashSet<ObjectHash>,
    ) -> Result<usize> {
        let mut reverted_by_to_orig: HashMap<u64, u64> = HashMap::new();
        for rec in all_lands {
            if let Some(rev_seq) = rec.reverted_by {
                reverted_by_to_orig.insert(rev_seq, rec.land_seq);
            }
        }

        let mut recovered = 0usize;
        for rec in all_lands {
            if in_flight_heads.contains(&rec.new_head)
                || rec
                    .previous_head
                    .is_some_and(|prev| in_flight_heads.contains(&prev))
            {
                continue;
            }
            if self.has_event_for_land_seq(rec.land_seq)? {
                continue;
            }
            if let Some(&orig_seq) = reverted_by_to_orig.get(&rec.land_seq) {
                let payload = json!({
                    "event": "revert",
                    "repo": repo_full_name,
                    "target": rec.target,
                    "reverted_land_seq": orig_seq,
                    "revert_land_seq": rec.land_seq,
                    "restored_head": rec.new_head.to_hex(),
                });
                if self.insert_event_if_absent(
                    "revert",
                    &rec.target,
                    rec.land_seq,
                    rec.previous_head,
                    rec.new_head,
                    &payload,
                )? {
                    recovered += 1;
                }
            } else if rec.reverted_by.is_none() {
                let mut payload = json!({
                    "event": "land",
                    "repo": repo_full_name,
                    "target": rec.target,
                    "land_seq": rec.land_seq,
                    "previous_head": rec.previous_head.map(|h| h.to_hex()),
                    "new_head": rec.new_head.to_hex(),
                });
                if let Ok(cs) = store.get_changeset(rec.new_head)
                    && let Some(EmbargoState::Published {
                        ref advisory_id, ..
                    }) = cs.visibility.embargo
                {
                    payload["advisory_id"] = json!(advisory_id);
                }
                if self.insert_event_if_absent(
                    "land",
                    &rec.target,
                    rec.land_seq,
                    rec.previous_head,
                    rec.new_head,
                    &payload,
                )? {
                    recovered += 1;
                }
            }
        }
        Ok(recovered)
    }

    pub fn list_events(&self, limit: usize) -> Result<Vec<OutboxEvent>> {
        self.list_events_before(None, limit)
    }

    /// Page events newest-first strictly before `before_event_id` (if given).
    pub fn list_events_before(
        &self,
        before_event_id: Option<u64>,
        limit: usize,
    ) -> Result<Vec<OutboxEvent>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GitxError::Storage("outbox mutex poisoned".to_string()))?;
        let mut events = Vec::new();
        if let Some(before) = before_event_id {
            let mut stmt = conn
                .prepare(
                    "SELECT event_id, event_type, target, land_seq, previous_head, new_head,
                            payload_json, created_at, delivered_at, delivery_attempts, last_error
                     FROM land_outbox
                     WHERE event_id < ?1
                     ORDER BY event_id DESC
                     LIMIT ?2",
                )
                .map_err(|e| GitxError::Storage(format!("failed to prepare outbox query: {e}")))?;
            let rows = stmt
                .query_map(params![before as i64, limit.max(1) as i64], decode_outbox_row)
                .map_err(|e| GitxError::Storage(format!("failed to query outbox: {e}")))?;
            for r in rows {
                events.push(
                    r.map_err(|e| GitxError::Storage(format!("failed to decode outbox row: {e}")))?,
                );
            }
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT event_id, event_type, target, land_seq, previous_head, new_head,
                            payload_json, created_at, delivered_at, delivery_attempts, last_error
                     FROM land_outbox
                     ORDER BY event_id DESC
                     LIMIT ?1",
                )
                .map_err(|e| GitxError::Storage(format!("failed to prepare outbox query: {e}")))?;
            let rows = stmt
                .query_map(params![limit.max(1) as i64], decode_outbox_row)
                .map_err(|e| GitxError::Storage(format!("failed to query outbox: {e}")))?;
            for r in rows {
                events.push(
                    r.map_err(|e| GitxError::Storage(format!("failed to decode outbox row: {e}")))?,
                );
            }
        }
        Ok(events)
    }

    /// List undelivered events oldest-first for retry / startup replay.
    pub fn list_pending_events(&self, limit: usize) -> Result<Vec<OutboxEvent>> {
        self.list_pending_events_after(0, limit)
    }

    /// Page undelivered events oldest-first strictly after `after_event_id`.
    pub fn list_pending_events_after(
        &self,
        after_event_id: u64,
        limit: usize,
    ) -> Result<Vec<OutboxEvent>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GitxError::Storage("outbox mutex poisoned".to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT event_id, event_type, target, land_seq, previous_head, new_head,
                        payload_json, created_at, delivered_at, delivery_attempts, last_error
                 FROM land_outbox
                 WHERE delivered_at IS NULL AND event_id > ?1
                 ORDER BY event_id ASC
                 LIMIT ?2",
            )
            .map_err(|e| GitxError::Storage(format!("failed to prepare pending outbox query: {e}")))?;
        let rows = stmt
            .query_map(
                params![after_event_id as i64, limit.max(1) as i64],
                decode_outbox_row,
            )
            .map_err(|e| GitxError::Storage(format!("failed to query pending outbox: {e}")))?;
        let mut events = Vec::new();
        for r in rows {
            events.push(
                r.map_err(|e| GitxError::Storage(format!("failed to decode outbox row: {e}")))?,
            );
        }
        Ok(events)
    }

    /// Returns `true` if `event_id` has already been marked fully delivered.
    pub fn is_delivered(&self, event_id: u64) -> Result<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GitxError::Storage("outbox mutex poisoned".to_string()))?;
        let delivered: Option<Option<String>> = conn
            .query_row(
                "SELECT delivered_at FROM land_outbox WHERE event_id = ?1",
                params![event_id as i64],
                |row| row.get(0),
            )
            .ok();
        Ok(matches!(delivered, Some(Some(_))))
    }

    /// Return only the URLs from `webhook_urls` that have NOT yet been delivered for `event_id`.
    pub fn pending_urls_for_event(
        &self,
        event_id: u64,
        webhook_urls: &[String],
    ) -> Result<Vec<String>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GitxError::Storage("outbox mutex poisoned".to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT url FROM land_outbox_deliveries
                 WHERE event_id = ?1 AND delivered_at IS NOT NULL",
            )
            .map_err(|e| GitxError::Storage(format!("failed to query delivered urls: {e}")))?;
        let rows = stmt
            .query_map(params![event_id as i64], |row| row.get::<_, String>(0))
            .map_err(|e| GitxError::Storage(format!("failed to read delivered urls: {e}")))?;
        let mut delivered: HashSet<String> = HashSet::new();
        for r in rows {
            delivered.insert(
                r.map_err(|e| GitxError::Storage(format!("failed to decode url row: {e}")))?,
            );
        }
        Ok(webhook_urls
            .iter()
            .filter(|u| !delivered.contains(*u))
            .cloned()
            .collect())
    }

    pub fn mark_destination_delivered(&self, event_id: u64, url: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let conn = self
            .conn
            .lock()
            .map_err(|_| GitxError::Storage("outbox mutex poisoned".to_string()))?;
        conn.execute(
            "INSERT INTO land_outbox_deliveries (event_id, url, delivered_at, delivery_attempts, last_error)
             VALUES (?1, ?2, ?3, 1, NULL)
             ON CONFLICT(event_id, url) DO UPDATE SET
                 delivered_at = excluded.delivered_at,
                 delivery_attempts = land_outbox_deliveries.delivery_attempts + 1,
                 last_error = NULL",
            params![event_id as i64, url, now],
        )
        .map_err(|e| GitxError::Storage(format!("failed to record destination delivery: {e}")))?;
        Ok(())
    }

    pub fn record_destination_failure(&self, event_id: u64, url: &str, err: &str) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GitxError::Storage("outbox mutex poisoned".to_string()))?;
        conn.execute(
            "INSERT INTO land_outbox_deliveries (event_id, url, delivered_at, delivery_attempts, last_error)
             VALUES (?1, ?2, NULL, 1, ?3)
             ON CONFLICT(event_id, url) DO UPDATE SET
                 delivery_attempts = land_outbox_deliveries.delivery_attempts + 1,
                 last_error = excluded.last_error",
            params![event_id as i64, url, err],
        )
        .map_err(|e| GitxError::Storage(format!("failed to record destination error: {e}")))?;
        Ok(())
    }

    pub fn mark_delivered(&self, event_id: u64) -> Result<()> {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let conn = self
            .conn
            .lock()
            .map_err(|_| GitxError::Storage("outbox mutex poisoned".to_string()))?;
        conn.execute(
            "UPDATE land_outbox
             SET delivered_at = ?1,
                 delivery_attempts = delivery_attempts + 1,
                 last_error = NULL
             WHERE event_id = ?2 AND delivered_at IS NULL",
            params![now, event_id as i64],
        )
        .map_err(|e| GitxError::Storage(format!("failed to mark outbox delivered: {e}")))?;
        Ok(())
    }

    pub fn record_failure(&self, event_id: u64, err: &str) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GitxError::Storage("outbox mutex poisoned".to_string()))?;
        conn.execute(
            "UPDATE land_outbox
             SET delivery_attempts = delivery_attempts + 1,
                 last_error = ?1
             WHERE event_id = ?2",
            params![err, event_id as i64],
        )
        .map_err(|e| GitxError::Storage(format!("failed to record outbox error: {e}")))?;
        Ok(())
    }
}

fn decode_outbox_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OutboxEvent> {
    let created_raw: String = row.get(7)?;
    let delivered_raw: Option<String> = row.get(8)?;
    Ok(OutboxEvent {
        event_id: row.get::<_, i64>(0)? as u64,
        event_type: row.get(1)?,
        target: row.get(2)?,
        land_seq: row.get::<_, i64>(3)? as u64,
        previous_head: row.get(4)?,
        new_head: row.get(5)?,
        payload_json: row.get(6)?,
        created_at: DateTime::parse_from_rfc3339(&created_raw)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        delivered_at: delivered_raw.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        }),
        delivery_attempts: row.get::<_, i64>(9)? as u32,
        last_error: row.get(10)?,
    })
}

/// Deliver a single outbox event to any not-yet-delivered destination URLs, retrying failed
/// destinations with exponential backoff while never re-sending to already-succeeded URLs.
pub async fn deliver_event_with_retries(
    outbox: Arc<WebhookOutbox>,
    webhook_urls: Vec<String>,
    event: OutboxEvent,
) {
    let _guard = outbox.dispatch_lock.lock().await;
    if matches!(outbox.is_delivered(event.event_id), Ok(true)) {
        return;
    }
    if webhook_urls.is_empty() {
        let _ = outbox.mark_delivered(event.event_id);
        return;
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = outbox.record_failure(event.event_id, &e.to_string());
            return;
        }
    };

    for attempt in 0..MAX_DISPATCH_ATTEMPTS {
        let pending_urls = match outbox.pending_urls_for_event(event.event_id, &webhook_urls) {
            Ok(urls) => urls,
            Err(e) => {
                let _ = outbox.record_failure(event.event_id, &e.to_string());
                return;
            }
        };
        if pending_urls.is_empty() {
            let _ = outbox.mark_delivered(event.event_id);
            return;
        }

        let mut last_err: Option<String> = None;
        for url in &pending_urls {
            match client
                .post(url)
                .header("content-type", "application/json")
                .header("x-gitx-event", &event.event_type)
                .header("x-gitx-event-id", event.event_id.to_string())
                .body(event.payload_json.clone())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    let _ = outbox.mark_destination_delivered(event.event_id, url);
                }
                Ok(resp) => {
                    let msg = format!("webhook {url} returned HTTP {}", resp.status());
                    let _ = outbox.record_destination_failure(event.event_id, url, &msg);
                    last_err = Some(msg);
                }
                Err(e) => {
                    let msg = format!("webhook {url} error: {e}");
                    let _ = outbox.record_destination_failure(event.event_id, url, &msg);
                    last_err = Some(msg);
                }
            }
        }

        if let Some(err) = last_err {
            let _ = outbox.record_failure(event.event_id, &err);
            if attempt + 1 < MAX_DISPATCH_ATTEMPTS {
                let backoff_ms = 100u64.saturating_mul(3u64.pow(attempt));
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
        } else {
            let _ = outbox.mark_delivered(event.event_id);
            return;
        }
    }
}

/// Replay all pending (`delivered_at IS NULL`) outbox events in order with per-destination
/// deduplication and exponential backoff.
pub async fn replay_pending_events(outbox: Arc<WebhookOutbox>, webhook_urls: Vec<String>) {
    let mut after_id = 0u64;
    loop {
        let Ok(pending) = outbox.list_pending_events_after(after_id, 256) else {
            return;
        };
        if pending.is_empty() {
            break;
        }
        for event in &pending {
            after_id = event.event_id;
            deliver_event_with_retries(Arc::clone(&outbox), webhook_urls.clone(), event.clone())
                .await;
        }
        if pending.len() < 256 {
            break;
        }
    }
}

/// Spawn asynchronous HTTP POST delivery for `event` (and drain any earlier pending events).
pub fn spawn_webhook_dispatch(
    outbox: Arc<WebhookOutbox>,
    webhook_urls: Vec<String>,
    event: OutboxEvent,
) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if webhook_urls.is_empty() {
            let _ = outbox.mark_delivered(event.event_id);
            return;
        }
        handle.spawn(async move {
            replay_pending_events(outbox, webhook_urls).await;
        });
    } else if webhook_urls.is_empty() {
        let _ = outbox.mark_delivered(event.event_id);
    }
}

/// Spawn a startup background replay pass for all pending events in `outbox`.
pub fn spawn_startup_replay(outbox: Arc<WebhookOutbox>, webhook_urls: Vec<String>) {
    if webhook_urls.is_empty() {
        return;
    }
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            replay_pending_events(outbox, webhook_urls).await;
        });
    }
}
