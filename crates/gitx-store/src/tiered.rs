//! Distributed tiered CAS storage backed by `object_store` (InMemory, LocalFileSystem,
//! S3/R2, GCS), a bounded in-memory LRU read cache with hit/miss/eviction metrics, and a
//! pluggable [`MetadataBackend`].

use crate::metadata::{MetadataBackend, SqlMetadataBackend};
use crate::store::{LandRecord, ObjectStore, safe_lz4_decompress};
use bytes::Bytes;
use gitx_core::{
    ChangeId, ChangeSet, GitxError, ObjectHash, OpId, OpLogEntry, Result, Stack, WorkspaceRef,
};
use object_store::aws::AmazonS3Builder;
use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::local::LocalFileSystem;
use object_store::memory::InMemory;
use object_store::path::Path as StorePath;
use object_store::{ObjectStore as RemoteObjectStore, PutPayload};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

static STORE_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static STORE_RUNTIME_INIT: Mutex<()> = Mutex::new(());

fn shared_store_runtime() -> Result<&'static tokio::runtime::Runtime> {
    if let Some(rt) = STORE_RUNTIME.get() {
        return Ok(rt);
    }
    let _guard = STORE_RUNTIME_INIT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(rt) = STORE_RUNTIME.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("gitx-tiered-store")
        .enable_all()
        .build()
        .map_err(|e| GitxError::Storage(format!("failed to start store runtime: {e}")))?;
    if let Err(unused_rt) = STORE_RUNTIME.set(rt) {
        unused_rt.shutdown_background();
    }
    Ok(STORE_RUNTIME.get().expect("runtime initialized"))
}

// ---------------------------------------------------------------------------
// Cloud / Local Blob Backend Configuration
// ---------------------------------------------------------------------------

/// Configuration for AWS S3 or S3-compatible object stores (e.g., Cloudflare R2, MinIO).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    pub endpoint: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub prefix: Option<String>,
    pub allow_http: bool,
    pub virtual_hosted_style_request: bool,
}

impl fmt::Debug for S3Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Config")
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("access_key_id", &self.access_key_id)
            .field(
                "secret_access_key",
                &self.secret_access_key.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .field("prefix", &self.prefix)
            .field("allow_http", &self.allow_http)
            .field(
                "virtual_hosted_style_request",
                &self.virtual_hosted_style_request,
            )
            .finish()
    }
}

impl S3Config {
    pub fn new(bucket: impl Into<String>, region: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            region: region.into(),
            endpoint: None,
            access_key_id: None,
            secret_access_key: None,
            session_token: None,
            prefix: None,
            allow_http: false,
            virtual_hosted_style_request: false,
        }
    }

    /// Convenience constructor for Cloudflare R2 (`https://<account_id>.r2.cloudflarestorage.com`).
    pub fn cloudflare_r2(
        account_id: impl AsRef<str>,
        bucket: impl Into<String>,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            region: "auto".to_string(),
            endpoint: Some(format!(
                "https://{}.r2.cloudflarestorage.com",
                account_id.as_ref().trim()
            )),
            access_key_id: Some(access_key_id.into()),
            secret_access_key: Some(secret_access_key.into()),
            session_token: None,
            prefix: None,
            allow_http: false,
            virtual_hosted_style_request: false,
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    pub fn with_credentials(
        mut self,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Self {
        self.access_key_id = Some(access_key_id.into());
        self.secret_access_key = Some(secret_access_key.into());
        self
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    pub fn with_allow_http(mut self, allow_http: bool) -> Self {
        self.allow_http = allow_http;
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.bucket.trim().is_empty() {
            return Err(GitxError::Storage(
                "S3/R2 bucket name must not be empty".to_string(),
            ));
        }
        if self.region.trim().is_empty() {
            return Err(GitxError::Storage(
                "S3/R2 region must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Builds an [`object_store::aws::AmazonS3`] client from this configuration.
    pub fn build(&self) -> Result<Arc<dyn RemoteObjectStore>> {
        self.validate()?;
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(&self.bucket)
            .with_region(&self.region)
            .with_allow_http(self.allow_http)
            .with_virtual_hosted_style_request(self.virtual_hosted_style_request);

        if let Some(ref endpoint) = self.endpoint {
            builder = builder.with_endpoint(endpoint);
        }
        if let Some(ref key_id) = self.access_key_id {
            builder = builder.with_access_key_id(key_id);
        }
        if let Some(ref secret) = self.secret_access_key {
            builder = builder.with_secret_access_key(secret);
        }
        if let Some(ref token) = self.session_token {
            builder = builder.with_token(token);
        }

        let store = builder
            .build()
            .map_err(|e| GitxError::Storage(format!("failed to build S3/R2 object store: {e}")))?;
        Ok(Arc::new(store))
    }
}

/// Configuration for Google Cloud Storage (GCS).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcsConfig {
    pub bucket: String,
    pub service_account_path: Option<PathBuf>,
    pub service_account_key: Option<String>,
    pub prefix: Option<String>,
}

impl fmt::Debug for GcsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GcsConfig")
            .field("bucket", &self.bucket)
            .field("service_account_path", &self.service_account_path)
            .field(
                "service_account_key",
                &self.service_account_key.as_ref().map(|_| "<redacted>"),
            )
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl GcsConfig {
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            service_account_path: None,
            service_account_key: None,
            prefix: None,
        }
    }

    pub fn with_service_account_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.service_account_path = Some(path.into());
        self
    }

    pub fn with_service_account_key(mut self, json_key: impl Into<String>) -> Self {
        self.service_account_key = Some(json_key.into());
        self
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.bucket.trim().is_empty() {
            return Err(GitxError::Storage(
                "GCS bucket name must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Builds an [`object_store::gcp::GoogleCloudStorage`] client from this configuration.
    pub fn build(&self) -> Result<Arc<dyn RemoteObjectStore>> {
        self.validate()?;
        let mut builder = GoogleCloudStorageBuilder::new().with_bucket_name(&self.bucket);
        if let Some(ref path) = self.service_account_path {
            builder = builder.with_service_account_path(path.to_string_lossy());
        }
        if let Some(ref key) = self.service_account_key {
            builder = builder.with_service_account_key(key);
        }
        let store = builder
            .build()
            .map_err(|e| GitxError::Storage(format!("failed to build GCS object store: {e}")))?;
        Ok(Arc::new(store))
    }
}

/// Pluggable object storage backend selector for [`TieredObjectStore`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobBackendConfig {
    InMemory,
    LocalFileSystem { root: PathBuf },
    S3(S3Config),
    Gcs(GcsConfig),
}

impl BlobBackendConfig {
    /// Returns the optional key prefix configured for this backend.
    pub fn key_prefix(&self) -> Option<&str> {
        match self {
            Self::InMemory | Self::LocalFileSystem { .. } => None,
            Self::S3(cfg) => cfg.prefix.as_deref(),
            Self::Gcs(cfg) => cfg.prefix.as_deref(),
        }
    }

    /// Instantiates the underlying `object_store::ObjectStore` implementation.
    pub fn build_object_store(&self) -> Result<Arc<dyn RemoteObjectStore>> {
        match self {
            Self::InMemory => Ok(Arc::new(InMemory::new())),
            Self::LocalFileSystem { root } => {
                std::fs::create_dir_all(root)?;
                let fs = LocalFileSystem::new_with_prefix(root).map_err(|e| {
                    GitxError::Storage(format!(
                        "failed to open local object store at '{}': {e}",
                        root.display()
                    ))
                })?;
                Ok(Arc::new(fs))
            }
            Self::S3(cfg) => cfg.build(),
            Self::Gcs(cfg) => cfg.build(),
        }
    }
}

// ---------------------------------------------------------------------------
// Bounded In-Memory Tiered LRU Cache with Hit / Miss / Eviction Metrics
// ---------------------------------------------------------------------------

/// Bounds and behavior for the in-memory tiered read cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheConfig {
    pub max_bytes: usize,
    pub max_entries: usize,
    pub write_through: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_entries: 16_384,
            write_through: true,
        }
    }
}

impl CacheConfig {
    pub fn new(max_bytes: usize, max_entries: usize) -> Self {
        Self {
            max_bytes,
            max_entries,
            write_through: true,
        }
    }

    pub fn with_write_through(mut self, write_through: bool) -> Self {
        self.write_through = write_through;
        self
    }
}

/// Point-in-time snapshot of tiered cache performance counters.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CacheMetricsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub puts: u64,
    pub cached_entries: usize,
    pub cached_bytes: usize,
    pub hit_rate: f64,
}

struct LruState {
    entries: HashMap<ObjectHash, (u64, Vec<u8>)>,
    recency: BTreeMap<u64, ObjectHash>,
    next_tick: u64,
    current_bytes: usize,
}

impl LruState {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            recency: BTreeMap::new(),
            next_tick: 1,
            current_bytes: 0,
        }
    }

    fn alloc_tick(&mut self) -> u64 {
        let tick = self.next_tick;
        self.next_tick = self.next_tick.wrapping_add(1).max(1);
        tick
    }
}

/// Thread-safe, byte- and entry-bounded LRU cache with atomic hit/miss/eviction metrics.
pub struct BoundedLruCache {
    config: CacheConfig,
    state: Mutex<LruState>,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    puts: AtomicU64,
}

impl BoundedLruCache {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            state: Mutex::new(LruState::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            puts: AtomicU64::new(0),
        }
    }

    pub fn get(&self, key: &ObjectHash) -> Option<Vec<u8>> {
        if self.config.max_bytes == 0 || self.config.max_entries == 0 {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let Ok(mut state) = self.state.lock() else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };

        let existing_tick = state.entries.get(key).map(|(tick, _)| *tick);
        if let Some(old_tick) = existing_tick {
            state.recency.remove(&old_tick);
            let new_tick = state.alloc_tick();
            state.recency.insert(new_tick, *key);
            let entry = state.entries.get_mut(key).expect("key existed");
            entry.0 = new_tick;
            let bytes = entry.1.clone();
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(bytes)
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    pub fn contains_without_metrics(&self, key: &ObjectHash) -> bool {
        self.state
            .lock()
            .map(|s| s.entries.contains_key(key))
            .unwrap_or(false)
    }

    pub fn insert(&self, key: ObjectHash, value: Vec<u8>) {
        if self.config.max_bytes == 0
            || self.config.max_entries == 0
            || value.len() > self.config.max_bytes
        {
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };

        self.puts.fetch_add(1, Ordering::Relaxed);

        if let Some((old_tick, old_val)) = state.entries.remove(&key) {
            state.recency.remove(&old_tick);
            state.current_bytes = state.current_bytes.saturating_sub(old_val.len());
        }

        let needed = value.len();
        while state.entries.len() >= self.config.max_entries
            || state.current_bytes.saturating_add(needed) > self.config.max_bytes
        {
            let Some((_, oldest_key)) = state.recency.pop_first() else {
                break;
            };
            if let Some((_, evicted_val)) = state.entries.remove(&oldest_key) {
                state.current_bytes = state.current_bytes.saturating_sub(evicted_val.len());
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }

        let tick = state.alloc_tick();
        state.current_bytes = state.current_bytes.saturating_add(needed);
        state.recency.insert(tick, key);
        state.entries.insert(key, (tick, value));
    }

    pub fn clear(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.entries.clear();
            state.recency.clear();
            state.current_bytes = 0;
        }
    }

    pub fn metrics(&self) -> CacheMetricsSnapshot {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let evictions = self.evictions.load(Ordering::Relaxed);
        let puts = self.puts.load(Ordering::Relaxed);
        let (cached_entries, cached_bytes) = self
            .state
            .lock()
            .map(|s| (s.entries.len(), s.current_bytes))
            .unwrap_or((0, 0));
        let total = hits + misses;
        let hit_rate = if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        };
        CacheMetricsSnapshot {
            hits,
            misses,
            evictions,
            puts,
            cached_entries,
            cached_bytes,
            hit_rate,
        }
    }
}

// ---------------------------------------------------------------------------
// TieredObjectStore: object_store + Bounded LRU Cache + MetadataBackend
// ---------------------------------------------------------------------------

/// Distributed `ObjectStore` pairing an `object_store` blob backend (`InMemory`,
/// `LocalFileSystem`, S3/R2, or GCS), an LZ4-compressed sharded CAS layout, a bounded
/// in-memory LRU read cache with hit/miss metrics, and a [`MetadataBackend`].
pub struct TieredObjectStore {
    remote: Arc<dyn RemoteObjectStore>,
    metadata: Arc<dyn MetadataBackend>,
    cache: BoundedLruCache,
    prefix: String,
    compress: bool,
    runtime: &'static tokio::runtime::Runtime,
}

impl TieredObjectStore {
    /// Creates a new [`TieredObjectStore`] from explicit blob store, metadata backend, and cache config.
    pub fn new(
        remote: Arc<dyn RemoteObjectStore>,
        metadata: Arc<dyn MetadataBackend>,
        cache_config: CacheConfig,
    ) -> Result<Self> {
        let runtime = shared_store_runtime()?;

        Ok(Self {
            remote,
            metadata,
            cache: BoundedLruCache::new(cache_config),
            prefix: "cas".to_string(),
            compress: true,
            runtime,
        })
    }

    /// Creates a [`TieredObjectStore`] from a [`BlobBackendConfig`] and [`MetadataBackend`].
    pub fn from_config(
        blob_config: &BlobBackendConfig,
        metadata: Arc<dyn MetadataBackend>,
        cache_config: CacheConfig,
    ) -> Result<Self> {
        let remote = blob_config.build_object_store()?;
        let mut store = Self::new(remote, metadata, cache_config)?;
        if let Some(prefix) = blob_config.key_prefix() {
            let trimmed = prefix.trim_matches('/');
            if !trimmed.is_empty() {
                store.prefix = format!("{trimmed}/cas");
            }
        }
        Ok(store)
    }

    /// Convenience constructor backed by `object_store::memory::InMemory` and in-memory SQLite.
    pub fn in_memory(cache_config: CacheConfig) -> Result<Self> {
        let metadata = Arc::new(SqlMetadataBackend::in_memory_sqlite()?);
        Self::from_config(&BlobBackendConfig::InMemory, metadata, cache_config)
    }

    /// Convenience constructor backed by `object_store::local::LocalFileSystem` and on-disk SQLite.
    pub fn local_fs(
        blob_root: impl AsRef<Path>,
        sqlite_path: impl AsRef<Path>,
        cache_config: CacheConfig,
    ) -> Result<Self> {
        let metadata = Arc::new(SqlMetadataBackend::open_sqlite(sqlite_path)?);
        let cfg = BlobBackendConfig::LocalFileSystem {
            root: blob_root.as_ref().to_path_buf(),
        };
        Self::from_config(&cfg, metadata, cache_config)
    }

    /// Sets a custom object key prefix (default `"cas"`).
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        let trimmed = prefix.into();
        let cleaned = trimmed.trim_matches('/').to_string();
        if !cleaned.is_empty() {
            self.prefix = cleaned;
        }
        self
    }

    /// Enables or disables LZ4 compression for blobs written to the remote `object_store`.
    pub fn with_compression(mut self, compress: bool) -> Self {
        self.compress = compress;
        self
    }

    /// Returns a snapshot of tiered cache hit/miss/eviction metrics.
    pub fn cache_metrics(&self) -> CacheMetricsSnapshot {
        self.cache.metrics()
    }

    /// Clears all entries currently resident in the in-memory read cache (metrics are preserved).
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Returns the underlying metadata backend.
    pub fn metadata(&self) -> &dyn MetadataBackend {
        self.metadata.as_ref()
    }

    /// Returns the underlying `object_store::ObjectStore`.
    pub fn remote_store(&self) -> &Arc<dyn RemoteObjectStore> {
        &self.remote
    }

    fn object_path(&self, hash: ObjectHash) -> Result<StorePath> {
        let hex = hash.to_hex();
        let key = format!("{}/{}/{}", self.prefix, &hex[..2], hex);
        StorePath::parse(&key)
            .map_err(|e| GitxError::Storage(format!("invalid object store path '{key}': {e}")))
    }

    /// Executes an async `object_store` operation safely whether called from a plain OS thread,
    /// a `current_thread` Tokio runtime, or a `multi_thread` Tokio runtime.
    fn block_on<F, T>(&self, fut: F) -> Result<T>
    where
        F: Future<Output = Result<T>> + Send,
        T: Send,
    {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                    tokio::task::block_in_place(|| self.runtime.block_on(fut))
                } else {
                    let rt = self.runtime;
                    std::thread::scope(|s| s.spawn(move || rt.block_on(fut)).join()).map_err(
                        |_| {
                            GitxError::Storage(
                                "tiered object store runtime bridge panicked".to_string(),
                            )
                        },
                    )?
                }
            }
            Err(_) => self.runtime.block_on(fut),
        }
    }

    fn put_cas(&self, hash: ObjectHash, data: &[u8]) -> Result<()> {
        let path = self.object_path(hash)?;
        let encoded = if self.compress {
            lz4_flex::compress_prepend_size(data)
        } else {
            data.to_vec()
        };
        let payload = PutPayload::from(Bytes::from(encoded));
        let remote = Arc::clone(&self.remote);

        self.block_on(async move {
            remote
                .put(&path, payload)
                .await
                .map_err(|e| GitxError::Storage(format!("object_store put {hash} failed: {e}")))?;
            Ok::<(), GitxError>(())
        })?;

        if self.cache.config.write_through {
            self.cache.insert(hash, data.to_vec());
        }
        Ok(())
    }

    fn get_cas(&self, hash: ObjectHash, label: &str) -> Result<Vec<u8>> {
        if let Some(hit) = self.cache.get(&hash) {
            return Ok(hit);
        }

        let path = self.object_path(hash)?;
        let remote = Arc::clone(&self.remote);

        let raw_bytes = self.block_on(async move {
            match remote.get(&path).await {
                Ok(result) => result.bytes().await.map_err(|e| {
                    GitxError::Storage(format!("object_store read {label} {hash} failed: {e}"))
                }),
                Err(object_store::Error::NotFound { .. }) => {
                    Err(GitxError::NotFound(format!("{label} {hash}")))
                }
                Err(e) => Err(GitxError::Storage(format!(
                    "object_store get {label} {hash} failed: {e}"
                ))),
            }
        })?;

        let decoded = if self.compress {
            safe_lz4_decompress(&raw_bytes, label, hash)?
        } else {
            raw_bytes.to_vec()
        };

        self.cache.insert(hash, decoded.clone());
        Ok(decoded)
    }

    fn head_cas(&self, hash: ObjectHash) -> Result<bool> {
        if self.cache.contains_without_metrics(&hash) {
            return Ok(true);
        }
        let path = self.object_path(hash)?;
        let remote = Arc::clone(&self.remote);

        self.block_on(async move {
            match remote.head(&path).await {
                Ok(_) => Ok(true),
                Err(object_store::Error::NotFound { .. }) => Ok(false),
                Err(e) => Err(GitxError::Storage(format!(
                    "object_store head {hash} failed: {e}"
                ))),
            }
        })
    }
}

impl ObjectStore for TieredObjectStore {
    fn put_chunk(&self, hash: ObjectHash, data: &[u8]) -> Result<()> {
        self.put_cas(hash, data)
    }

    fn get_chunk(&self, hash: ObjectHash) -> Result<Vec<u8>> {
        self.get_cas(hash, "chunk")
    }

    fn has_chunk(&self, hash: ObjectHash) -> Result<bool> {
        self.head_cas(hash)
    }

    fn put_raw_object(&self, hash: ObjectHash, bytes: &[u8]) -> Result<()> {
        self.put_cas(hash, bytes)
    }

    fn get_raw_object(&self, hash: ObjectHash) -> Result<Vec<u8>> {
        self.get_cas(hash, "object")
    }

    fn put_changeset(&self, cs: &ChangeSet) -> Result<ObjectHash> {
        self.metadata.put_changeset(cs)
    }

    fn get_changeset(&self, id: ObjectHash) -> Result<ChangeSet> {
        self.metadata.get_changeset(id)
    }

    fn list_changesets(&self) -> Result<Vec<ChangeSet>> {
        self.metadata.list_changesets()
    }

    fn get_revisions_for_change(&self, change_id: ChangeId) -> Result<Vec<ChangeSet>> {
        self.metadata.get_revisions_for_change(change_id)
    }

    fn delete_changeset(&self, id: ObjectHash) -> Result<()> {
        self.metadata.delete_changeset(id)
    }

    fn put_stack(&self, stack: &Stack) -> Result<()> {
        self.metadata.put_stack(stack)
    }

    fn get_stack(&self, name: &str) -> Result<Stack> {
        self.metadata.get_stack(name)
    }

    fn list_stacks(&self) -> Result<Vec<Stack>> {
        self.metadata.list_stacks()
    }

    fn delete_stack(&self, name: &str) -> Result<()> {
        self.metadata.delete_stack(name)
    }

    fn append_op(&self, op: &OpLogEntry) -> Result<()> {
        self.metadata.append_op(op)
    }

    fn get_op(&self, id: OpId) -> Result<OpLogEntry> {
        self.metadata.get_op(id)
    }

    fn latest_op(&self) -> Result<Option<OpLogEntry>> {
        self.metadata.latest_op()
    }

    fn list_ops(&self, limit: usize) -> Result<Vec<OpLogEntry>> {
        self.metadata.list_ops(limit)
    }

    fn record_land(
        &self,
        target: &str,
        expected_previous: Option<ObjectHash>,
        new_head: ObjectHash,
        changes: Vec<ChangeId>,
    ) -> Result<LandRecord> {
        self.metadata
            .record_land(target, expected_previous, new_head, changes)
    }

    fn get_land(&self, land_seq: u64) -> Result<LandRecord> {
        self.metadata.get_land(land_seq)
    }

    fn list_lands(&self, target: &str, limit: usize) -> Result<Vec<LandRecord>> {
        self.metadata.list_lands(target, limit)
    }

    fn list_all_lands(&self, after_land_seq: u64, limit: usize) -> Result<Vec<LandRecord>> {
        self.metadata.list_all_lands(after_land_seq, limit)
    }

    fn mark_reverted(&self, land_seq: u64, reverted_by: u64) -> Result<()> {
        self.metadata.mark_reverted(land_seq, reverted_by)
    }

    fn revert_land(&self, land_seq: u64) -> Result<LandRecord> {
        self.metadata.revert_land(land_seq)
    }

    fn get_bookmark(&self, name: &str) -> Result<Option<ObjectHash>> {
        self.metadata.get_bookmark(name)
    }

    fn set_bookmark(&self, name: &str, hash: ObjectHash) -> Result<()> {
        self.metadata.set_bookmark(name, hash)
    }

    fn cas_bookmark(
        &self,
        name: &str,
        expected: Option<ObjectHash>,
        new_hash: ObjectHash,
    ) -> Result<()> {
        self.metadata.cas_bookmark(name, expected, new_hash)
    }

    fn cas_bookmarks(&self, updates: &[(String, Option<ObjectHash>, ObjectHash)]) -> Result<()> {
        self.metadata.cas_bookmarks(updates)
    }

    fn list_bookmarks(&self) -> Result<BTreeMap<String, ObjectHash>> {
        self.metadata.list_bookmarks()
    }

    fn put_workspace(&self, ws: &WorkspaceRef) -> Result<()> {
        self.metadata.put_workspace(ws)
    }

    fn get_workspace(&self, name: &str) -> Result<Option<WorkspaceRef>> {
        self.metadata.get_workspace(name)
    }

    fn list_workspaces(&self) -> Result<BTreeMap<String, WorkspaceRef>> {
        self.metadata.list_workspaces()
    }

    fn remove_workspace(&self, name: &str) -> Result<()> {
        self.metadata.remove_workspace(name)
    }
}
