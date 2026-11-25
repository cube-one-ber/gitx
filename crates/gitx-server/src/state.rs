use crate::derived::DerivedIndex;
use crate::outbox::WebhookOutbox;
use crate::queue::{ConflictResolverFn, MergeQueue};
use gitx_context::ContextStore;
use gitx_core::{ChangeSet, DomainId, EmbargoState, EntryKind, GitxError, ObjectHash, Result};
use gitx_crypto::{AclPolicy, Principal};
use gitx_store::{
    BlobBackendConfig, CacheConfig, LocalStore, MetadataBackend, ObjectStore, SqlMetadataBackend,
    TieredObjectStore,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Configuration for the GitX HTTP + gRPC + Git Smart HTTP server.
#[derive(Clone)]
pub struct ServerConfig {
    pub data_dir: PathBuf,
    pub default_acl: Option<String>,
    pub conflict_resolver: Option<ConflictResolverFn>,
    pub tokens: BTreeMap<String, Principal>,
    /// Optional shared secret used to verify cryptographically signed `gitx1h.*` bearer tokens.
    pub token_signing_secret: Option<Vec<u8>>,
    /// Explicit control over trusting `X-Gitx-*` reverse-proxy identity headers.
    ///
    /// - `Some(true)`: trust `X-Gitx-*` headers when no `Authorization: Bearer` token is provided
    ///   (ONLY safe behind a trusted reverse proxy that strips client-supplied `X-Gitx-*` headers,
    ///   or on loopback-only local development servers).
    /// - `Some(false)`: strictly require registered `Authorization: Bearer` tokens; ignore `X-Gitx-*`.
    /// - `None` (default): automatically disables proxy header trust whenever at least one bearer
    ///   token or signing secret is configured, and allows loopback/dev header auth when none are set.
    pub trust_proxy_headers: Option<bool>,
    /// Optional distributed/tiered blob storage backend (`TieredObjectStore`).
    /// When `None`, each repo uses embedded `LocalStore`.
    pub blob_backend: Option<BlobBackendConfig>,
    /// Optional HTTP webhook URLs dispatched asynchronously from each repo's `land_outbox`.
    pub webhook_urls: Vec<String>,
    /// Optional post-land verification shell command. If it exits non-zero, the server
    /// automatically performs an O(1) atomic `revert_land`.
    pub post_land_cmd: Option<String>,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("data_dir", &self.data_dir)
            .field("default_acl", &self.default_acl)
            .field("conflict_resolver", &self.conflict_resolver.is_some())
            .field("token_count", &self.tokens.len())
            .field("has_signing_secret", &self.token_signing_secret.is_some())
            .field("trust_proxy_headers", &self.trust_proxy_headers)
            .field("blob_backend", &self.blob_backend)
            .field("webhook_urls", &self.webhook_urls)
            .field("has_post_land_cmd", &self.post_land_cmd.is_some())
            .finish()
    }
}

impl ServerConfig {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            default_acl: None,
            conflict_resolver: None,
            tokens: BTreeMap::new(),
            token_signing_secret: None,
            trust_proxy_headers: None,
            blob_backend: None,
            webhook_urls: Vec::new(),
            post_land_cmd: None,
        }
    }

    pub fn with_default_acl(mut self, acl: impl Into<String>) -> Self {
        self.default_acl = Some(acl.into());
        self
    }

    pub fn with_conflict_resolver(mut self, resolver: ConflictResolverFn) -> Self {
        self.conflict_resolver = Some(resolver);
        self
    }

    /// Registers a bearer authentication token mapped to `principal` for HTTP/gRPC API calls.
    pub fn with_token(mut self, token: impl Into<String>, principal: Principal) -> Self {
        self.tokens.insert(token.into(), principal);
        self
    }

    /// Configure a signing secret for verifying cryptographically signed `gitx1h.*` bearer tokens.
    pub fn with_token_signing_secret(mut self, secret: impl Into<Vec<u8>>) -> Self {
        self.token_signing_secret = Some(secret.into());
        self
    }

    /// Explicitly enable or disable trusting `X-Gitx-*` proxy identity headers.
    pub fn with_trust_proxy_headers(mut self, trust: bool) -> Self {
        self.trust_proxy_headers = Some(trust);
        self
    }

    /// Configure a tiered `object_store` blob backend (`InMemory`, `LocalFileSystem`, S3/R2, GCS).
    pub fn with_blob_backend(mut self, backend: BlobBackendConfig) -> Self {
        self.blob_backend = Some(backend);
        self
    }

    /// Add an HTTP webhook endpoint notified on every atomic `land` and `revert` via `land_outbox`.
    pub fn with_webhook_url(mut self, url: impl Into<String>) -> Self {
        self.webhook_urls.push(url.into());
        self
    }

    /// Configure a post-land verification command; non-zero exit triggers O(1) atomic revert.
    pub fn with_post_land_cmd(mut self, cmd: impl Into<String>) -> Self {
        self.post_land_cmd = Some(cmd.into());
        self
    }
}

/// Summary metadata for a hosted repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoInfo {
    pub owner: String,
    pub name: String,
    pub full_name: String,
    pub default_branch: String,
    pub bookmarks: BTreeMap<String, String>,
}

/// RAII guard tracking a `new_head` whose `post_land_cmd` verification is currently in flight.
///
/// While active, `reconcile_outbox` skips backfilling a `"land"` row for this head and
/// `can_read_changeset_live` withholds public disclosure of an unverified `EmbargoState::Published`
/// changeset until verification succeeds.
pub struct PendingVerificationGuard {
    pending: Arc<RwLock<HashMap<ObjectHash, usize>>>,
    epoch: Arc<AtomicU64>,
    head: ObjectHash,
}

impl Drop for PendingVerificationGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.pending.write()
            && let Some(count) = guard.get_mut(&self.head)
        {
            if *count <= 1 {
                guard.remove(&self.head);
            } else {
                *count -= 1;
            }
        }
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }
}

/// Handle to a single multi-domain GitX repository hosted on the server.
pub struct RepoHandle {
    pub owner: String,
    pub name: String,
    pub root_dir: PathBuf,
    pub store: Arc<dyn ObjectStore>,
    pub context: Arc<ContextStore>,
    pub outbox: Arc<WebhookOutbox>,
    pub acl: RwLock<AclPolicy>,
    pub derived: RwLock<DerivedIndex>,
    pub queue: MergeQueue,
    pub(crate) publish_lock: tokio::sync::Mutex<()>,
    target_locks: Mutex<HashMap<String, Arc<tokio::sync::RwLock<()>>>>,
    pending_verification_heads: Arc<RwLock<HashMap<ObjectHash, usize>>>,
    pending_verification_epoch: Arc<AtomicU64>,
    default_acl: Option<String>,
}

impl RepoHandle {
    /// Open or initialize a repository handle at `root_dir`.
    pub fn open(
        owner: String,
        name: String,
        root_dir: PathBuf,
        default_acl: Option<String>,
    ) -> Result<Self> {
        Self::open_with_backend(owner, name, root_dir, default_acl, None)
    }

    /// Open or initialize a repository handle backed by either embedded `LocalStore` or
    /// distributed `TieredObjectStore`.
    pub fn open_with_backend(
        owner: String,
        name: String,
        root_dir: PathBuf,
        default_acl: Option<String>,
        blob_backend: Option<&BlobBackendConfig>,
    ) -> Result<Self> {
        fs::create_dir_all(&root_dir)?;
        let store: Arc<dyn ObjectStore> = match blob_backend {
            Some(cfg) => {
                let meta: Arc<dyn MetadataBackend> =
                    Arc::new(SqlMetadataBackend::open_sqlite(root_dir.join("metadata.sqlite"))?);
                let repo_cfg = match cfg {
                    BlobBackendConfig::LocalFileSystem { root } => {
                        BlobBackendConfig::LocalFileSystem {
                            root: root.join(&owner).join(&name),
                        }
                    }
                    other => other.clone(),
                };
                Arc::new(TieredObjectStore::from_config(
                    &repo_cfg,
                    meta,
                    CacheConfig::default(),
                )?)
            }
            None => Arc::new(LocalStore::open(&root_dir)?),
        };
        let context = Arc::new(ContextStore::open(root_dir.join("context.sqlite"))?);
        let outbox = Arc::new(WebhookOutbox::open(root_dir.join("outbox.sqlite"))?);
        let _ = outbox.reconcile_from_store(store.as_ref(), &format!("{owner}/{name}"));
        let queue = MergeQueue::open(root_dir.join("queue.sqlite"), None)?;
        let policy = load_initial_acl(&root_dir, store.as_ref(), default_acl.as_deref())?;

        Ok(Self {
            owner,
            name,
            root_dir,
            store,
            context,
            outbox,
            acl: RwLock::new(policy),
            derived: RwLock::new(DerivedIndex::new()),
            queue,
            publish_lock: tokio::sync::Mutex::new(()),
            target_locks: Mutex::new(HashMap::new()),
            pending_verification_heads: Arc::new(RwLock::new(HashMap::new())),
            pending_verification_epoch: Arc::new(AtomicU64::new(0)),
            default_acl,
        })
    }

    fn target_rwlock(&self, target: &str) -> Result<Arc<tokio::sync::RwLock<()>>> {
        let mut guard = self
            .target_locks
            .lock()
            .map_err(|_| GitxError::Storage("target_locks mutex poisoned".to_string()))?;
        Ok(Arc::clone(
            guard
                .entry(target.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::RwLock::new(()))),
        ))
    }

    /// Acquire a shared per-target read lock for staged commits (`update_target: false`): allows
    /// full parallelism among concurrent staged commits while failing fast with `GitxError::Merge`
    /// (`409 Conflict`) if an exclusive write/verification/publish is in flight on `target`.
    pub fn try_read_target(&self, target: &str) -> Result<tokio::sync::OwnedRwLockReadGuard<()>> {
        let lock = self.target_rwlock(target)?;
        lock.try_read_owned().map_err(|_| {
            GitxError::Merge(format!(
                "target '{target}' is currently undergoing an exclusive update or post-land verification; retry shortly"
            ))
        })
    }

    /// Acquire an exclusive per-target write lock for bookmark-mutating operations (`commit` with
    /// `update_target: true`, `land`, `revert_land`, `publish_embargo`, `drain_queue`, and
    /// `git-receive-pack`), eliminating check-then-act races with publication and `post_land_cmd`.
    pub fn try_write_target(&self, target: &str) -> Result<tokio::sync::OwnedRwLockWriteGuard<()>> {
        let lock = self.target_rwlock(target)?;
        lock.try_write_owned().map_err(|_| {
            GitxError::Merge(format!(
                "target '{target}' is currently undergoing an update or post-land verification; retry shortly"
            ))
        })
    }

    /// Track `head` as undergoing in-flight `post_land_cmd` verification until the returned guard drops.
    pub fn track_pending_verification(&self, head: ObjectHash) -> PendingVerificationGuard {
        if let Ok(mut guard) = self.pending_verification_heads.write() {
            *guard.entry(head).or_insert(0) += 1;
        }
        self.pending_verification_epoch
            .fetch_add(1, Ordering::SeqCst);
        PendingVerificationGuard {
            pending: Arc::clone(&self.pending_verification_heads),
            epoch: Arc::clone(&self.pending_verification_epoch),
            head,
        }
    }

    /// Returns `true` if `head` is currently awaiting `post_land_cmd` verification.
    pub fn is_head_pending_verification(&self, head: ObjectHash) -> bool {
        self.pending_verification_heads
            .read()
            .map(|guard| guard.contains_key(&head))
            .unwrap_or(false)
    }

    /// Snapshot all heads currently undergoing in-flight `post_land_cmd` verification.
    pub fn pending_verification_heads_snapshot(&self) -> HashSet<ObjectHash> {
        self.pending_verification_heads
            .read()
            .map(|guard| guard.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Crash-recovery reconciliation of `lands` -> `land_outbox` using an epoch-bracketed
    /// snapshot of `pending_verification_heads` so a concurrent `track_pending_verification` +
    /// `record_land` or `revert_land` + guard drop can never trigger a premature `"land"` backfill.
    pub fn reconcile_outbox(&self) -> Result<usize> {
        let repo_full_name = format!("{}/{}", self.owner, self.name);
        for _ in 0..4 {
            let epoch_before = self.pending_verification_epoch.load(Ordering::SeqCst);
            let pending_before = self.pending_verification_heads_snapshot();
            let mut all_lands = Vec::new();
            let mut after_seq = 0u64;
            loop {
                let batch = self.store.list_all_lands(after_seq, 256)?;
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
            let pending_after = self.pending_verification_heads_snapshot();
            let epoch_after = self.pending_verification_epoch.load(Ordering::SeqCst);
            if epoch_before == epoch_after {
                let mut combined = pending_before;
                combined.extend(pending_after);
                return self.outbox.reconcile_records_excluding(
                    self.store.as_ref(),
                    &repo_full_name,
                    &all_lands,
                    &combined,
                );
            }
        }
        // Verification state changed repeatedly mid-scan; skip reconciliation on this probe rather
        // than risking a torn snapshot (next request / startup replay will reconcile cleanly).
        Ok(0)
    }

    /// Returns `true` iff a `Published` changeset `cs_id` is actually live (not awaiting
    /// `post_land_cmd`, not reverted, and not an unlanded CAS/crash orphan).
    pub fn is_published_changeset_live(&self, cs_id: ObjectHash) -> Result<bool> {
        if self.is_head_pending_verification(cs_id) {
            return Ok(false);
        }
        let mut saw_any_land = false;
        let mut after_seq = 0u64;
        loop {
            let lands = self.store.list_all_lands(after_seq, 256)?;
            if lands.is_empty() {
                break;
            }
            let batch_len = lands.len();
            for rec in lands {
                after_seq = rec.land_seq;
                if rec.new_head == cs_id {
                    saw_any_land = true;
                    if rec.reverted_by.is_none() {
                        return Ok(true);
                    }
                }
            }
            if batch_len < 256 {
                break;
            }
        }
        if saw_any_land {
            return Ok(false);
        }
        // Fallback for stores/tests populated directly via `set_bookmark` without `record_land`:
        // a Published changeset with no land record is only live if a bookmark currently points to it.
        let bookmarks = self.store.list_bookmarks()?;
        Ok(bookmarks.values().any(|&h| h == cs_id))
    }

    /// Returns `true` if `cs` is an `EmbargoState::Published` changeset that is NOT currently live
    /// (still undergoing `post_land_cmd` verification, auto-reverted, or an unlanded orphan) and
    /// therefore must never be used as a parent/base by concurrent writes.
    pub fn is_unlive_published_changeset(&self, cs: &ChangeSet) -> Result<bool> {
        if !matches!(cs.visibility.embargo, Some(EmbargoState::Published { .. })) {
            return Ok(false);
        }
        Ok(!self.is_published_changeset_live(cs.id)?)
    }

    /// Returns `true` iff `advisory` has a live (unreverted, landed) `EmbargoState::Published`
    /// changeset in this repository.
    pub fn is_advisory_published(&self, advisory: &str) -> Result<bool> {
        let all_cs = self.store.list_changesets()?;
        for cs in &all_cs {
            if matches!(
                &cs.visibility.embargo,
                Some(EmbargoState::Published { advisory_id, .. }) if advisory_id == advisory
            ) && self.is_published_changeset_live(cs.id)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Server-side changeset read check: delegates to `AclPolicy::can_read_changeset`, except that
    /// an unlanded, auto-reverted, or in-flight `EmbargoState::Published` changeset is NEVER
    /// disclosed publicly (only admins or principals authorized to read its underlying active
    /// embargo revision may access it).
    pub fn can_read_changeset_live(
        &self,
        policy: &AclPolicy,
        principal: &Principal,
        cs: &ChangeSet,
    ) -> bool {
        if !matches!(cs.visibility.embargo, Some(EmbargoState::Published { .. })) {
            return policy.can_read_changeset(principal, cs);
        }
        if matches!(self.is_published_changeset_live(cs.id), Ok(true)) {
            return policy.can_read_changeset(principal, cs);
        }
        if principal.is_anonymous {
            return false;
        }
        if principal.roles.iter().any(|r| r == "admin") {
            return true;
        }
        if let Some(prev_rev) = cs.previous_revision
            && let Ok(embargo_cs) = self.store.get_changeset(prev_rev)
        {
            return policy.can_read_changeset(principal, &embargo_cs);
        }
        false
    }

    /// Install or clear an optional conflict-resolver hook for this repository's merge queue.
    pub fn set_conflict_resolver(&self, resolver: Option<ConflictResolverFn>) {
        self.queue.set_conflict_resolver(resolver);
    }

    /// Return a cloned snapshot of the current [`AclPolicy`].
    pub fn acl_snapshot(&self) -> Result<AclPolicy> {
        self.acl
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| GitxError::Storage("acl rwlock poisoned".to_string()))
    }

    /// Return the current effective `.gitxacl` text on disk or from `default_acl`, if any.
    pub fn current_acl_text(&self) -> Option<String> {
        let disk_path = self.root_dir.join(".gitxacl");
        if disk_path.is_file()
            && let Ok(text) = fs::read_to_string(&disk_path)
        {
            return Some(text);
        }
        self.default_acl.clone()
    }

    /// Returns `true` if the server has a configured `default_acl` template.
    pub fn has_default_acl(&self) -> bool {
        self.default_acl.is_some()
    }

    /// Parse and install a new `.gitxacl` policy both in memory and on disk.
    pub fn update_acl_from_text(&self, text: &str) -> Result<AclPolicy> {
        let parsed = AclPolicy::parse(text)?;
        fs::write(self.root_dir.join(".gitxacl"), text)?;
        let mut guard = self
            .acl
            .write()
            .map_err(|_| GitxError::Storage("acl rwlock poisoned".to_string()))?;
        *guard = parsed.clone();
        Ok(parsed)
    }

    /// Reload `.gitxacl` from the current `master` tree (if present), falling back to
    /// `default_acl` or `AclPolicy::default_secure()` (clearing any stale on-disk `.gitxacl`
    /// if `master` exists without a committed `.gitxacl`).
    pub fn reload_acl_from_store(&self) -> Result<AclPolicy> {
        let policy = if let Some(text) = read_committed_acl(self.store.as_ref())? {
            fs::write(self.root_dir.join(".gitxacl"), &text)?;
            AclPolicy::parse(&text)?
        } else {
            if self.store.get_bookmark("master")?.is_some() {
                let disk_acl = self.root_dir.join(".gitxacl");
                if disk_acl.is_file() {
                    let _ = fs::remove_file(&disk_acl);
                }
            }
            load_initial_acl(
                &self.root_dir,
                self.store.as_ref(),
                self.default_acl.as_deref(),
            )?
        };
        let mut guard = self
            .acl
            .write()
            .map_err(|_| GitxError::Storage("acl rwlock poisoned".to_string()))?;
        *guard = policy.clone();
        Ok(policy)
    }

    /// Reload `.gitxacl` from `store` ONLY if `.gitxacl` in the `public` tree actually changed
    /// between `old_master` and `new_master`, preserving API-configured per-repo `<root_dir>/.gitxacl`
    /// policies across ordinary non-ACL updates to `master`.
    pub fn reload_acl_if_master_acl_changed(
        &self,
        old_master: Option<ObjectHash>,
        new_master: Option<ObjectHash>,
    ) -> Result<()> {
        let old_acl = read_public_acl_bytes_at(self.store.as_ref(), old_master)?;
        let new_acl = read_public_acl_bytes_at(self.store.as_ref(), new_master)?;
        if old_acl != new_acl {
            self.reload_acl_from_store()?;
        }
        Ok(())
    }

    /// Build serializable repository metadata.
    pub fn info(&self) -> Result<RepoInfo> {
        let bookmarks = self
            .store
            .list_bookmarks()?
            .into_iter()
            .map(|(k, v)| (k, v.to_hex()))
            .collect();
        Ok(RepoInfo {
            owner: self.owner.clone(),
            name: self.name.clone(),
            full_name: format!("{}/{}", self.owner, self.name),
            default_branch: "master".to_string(),
            bookmarks,
        })
    }
}

/// Shared multi-repository state for the GitX HTTP and gRPC servers.
pub struct AppState {
    pub config: ServerConfig,
    repos: RwLock<BTreeMap<(String, String), Arc<RepoHandle>>>,
    tokens: RwLock<BTreeMap<String, Principal>>,
}

impl AppState {
    pub fn new(config: ServerConfig) -> Self {
        let initial_tokens = config.tokens.clone();
        Self {
            config,
            repos: RwLock::new(BTreeMap::new()),
            tokens: RwLock::new(initial_tokens),
        }
    }

    /// Register or replace a bearer token mapping at runtime.
    pub fn register_token(&self, token: impl Into<String>, principal: Principal) {
        if let Ok(mut guard) = self.tokens.write() {
            guard.insert(token.into(), principal);
        }
    }

    /// Revoke a previously registered bearer token.
    pub fn revoke_token(&self, token: &str) {
        if let Ok(mut guard) = self.tokens.write() {
            guard.remove(token);
        }
    }

    /// Resolve a bearer token to its authenticated [`Principal`].
    /// Checks static registered tokens first, then verifies cryptographically signed `gitx1h.*`
    /// tokens if `config.token_signing_secret` is configured.
    pub fn resolve_token(&self, token: &str) -> Option<Principal> {
        if let Some(p) = self
            .tokens
            .read()
            .ok()
            .and_then(|guard| guard.get(token).cloned())
        {
            return Some(p);
        }
        if let Some(ref secret) = self.config.token_signing_secret {
            let now = chrono::Utc::now().timestamp();
            if let Ok(p) = gitx_crypto::verify_token_hmac(token, secret, now) {
                return Some(p);
            }
        }
        None
    }

    /// Returns `true` if at least one bearer token or signing secret is configured on this server.
    pub fn has_configured_tokens(&self) -> bool {
        self.config.token_signing_secret.is_some()
            || self.tokens.read().map(|g| !g.is_empty()).unwrap_or(false)
    }

    /// Execute the configured post-land verification hook, if any.
    /// Returns `Ok(())` if no hook is configured or if it exits with status 0,
    /// or `Err(reason)` if verification fails (triggering O(1) atomic auto-revert).
    pub fn run_post_land_hook(
        &self,
        repo_full_name: &str,
        target: &str,
        land_seq: u64,
        new_head: ObjectHash,
    ) -> std::result::Result<(), String> {
        let Some(ref cmd) = self.config.post_land_cmd else {
            return Ok(());
        };
        let output = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .env("GITX_REPO", repo_full_name)
            .env("GITX_TARGET", target)
            .env("GITX_LAND_SEQ", land_seq.to_string())
            .env("GITX_NEW_HEAD", new_head.to_hex())
            .output()
            .map_err(|e| format!("failed to spawn post-land hook: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!(
                "post-land verification failed ({}): {}",
                output.status,
                stderr.trim()
            ))
        }
    }

    /// Execute the configured post-land verification hook asynchronously on a blocking thread
    /// pool so shell commands never block the Tokio async worker.
    pub async fn run_post_land_hook_async(
        self: &Arc<Self>,
        repo_full_name: String,
        target: String,
        land_seq: u64,
        new_head: ObjectHash,
    ) -> std::result::Result<(), String> {
        if self.config.post_land_cmd.is_none() {
            return Ok(());
        }
        let state = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            state.run_post_land_hook(&repo_full_name, &target, land_seq, new_head)
        })
        .await
        .map_err(|e| format!("post-land hook task join error: {e}"))?
    }

    /// Spawn startup replay for any undelivered webhook outbox events across all existing repos.
    pub fn replay_all_pending_outboxes(&self) {
        if self.config.webhook_urls.is_empty() {
            return;
        }
        let Ok(repos) = self.list_repos(None) else {
            return;
        };
        for info in repos {
            if let Ok(Some(handle)) = self.get_repo(&info.owner, &info.name) {
                let _ = handle.reconcile_outbox();
                crate::outbox::spawn_startup_replay(
                    Arc::clone(&handle.outbox),
                    self.config.webhook_urls.clone(),
                );
            }
        }
    }

    /// Returns `true` if `X-Gitx-*` reverse-proxy headers are trusted when no Bearer token is sent.
    ///
    /// Defaults to `false` whenever bearer tokens are configured, closing token-auth bypasses.
    pub fn trusts_proxy_headers(&self) -> bool {
        self.config
            .trust_proxy_headers
            .unwrap_or_else(|| !self.has_configured_tokens())
    }

    /// Returns `true` if `{owner}/{name}` already exists in memory or on disk.
    pub fn repo_exists(&self, owner: &str, name: &str) -> Result<bool> {
        validate_repo_segment(owner, "owner")?;
        validate_repo_segment(name, "name")?;
        let key = (owner.to_string(), name.to_string());
        if let Ok(guard) = self.repos.read()
            && guard.contains_key(&key)
        {
            return Ok(true);
        }
        Ok(self.repo_dir(owner, name).join("metadata.sqlite").exists())
    }

    fn repos_base_dir(&self) -> PathBuf {
        self.config.data_dir.join("repos")
    }

    fn repo_dir(&self, owner: &str, name: &str) -> PathBuf {
        self.repos_base_dir().join(owner).join(name)
    }

    /// Push-to-create: returns `(handle, existed)` atomically under the `repos` lock so concurrent
    /// creators cannot race on initial `.gitxacl` provisioning.
    pub fn get_or_create_repo_with_status(
        &self,
        owner: &str,
        name: &str,
    ) -> Result<(Arc<RepoHandle>, bool)> {
        validate_repo_segment(owner, "owner")?;
        validate_repo_segment(name, "name")?;

        let key = (owner.to_string(), name.to_string());
        {
            let guard = self
                .repos
                .read()
                .map_err(|_| GitxError::Storage("repos rwlock poisoned".to_string()))?;
            if let Some(handle) = guard.get(&key) {
                return Ok((Arc::clone(handle), true));
            }
        }

        let mut guard = self
            .repos
            .write()
            .map_err(|_| GitxError::Storage("repos rwlock poisoned".to_string()))?;
        if let Some(handle) = guard.get(&key) {
            return Ok((Arc::clone(handle), true));
        }

        let dir = self.repo_dir(owner, name);
        let existed = dir.join("metadata.sqlite").exists();
        let handle = Arc::new(RepoHandle::open_with_backend(
            owner.to_string(),
            name.to_string(),
            dir,
            self.config.default_acl.clone(),
            self.config.blob_backend.as_ref(),
        )?);
        handle.set_conflict_resolver(self.config.conflict_resolver.clone());
        crate::outbox::spawn_startup_replay(
            Arc::clone(&handle.outbox),
            self.config.webhook_urls.clone(),
        );
        guard.insert(key, Arc::clone(&handle));
        Ok((handle, existed))
    }

    /// Push-to-create: returns an existing repository handle or automatically provisions
    /// `{data_dir}/repos/{owner}/{name}` on demand.
    pub fn get_or_create_repo(&self, owner: &str, name: &str) -> Result<Arc<RepoHandle>> {
        self.get_or_create_repo_with_status(owner, name)
            .map(|(handle, _)| handle)
    }

    /// Return an existing repository handle without creating a new repo if absent.
    pub fn get_repo(&self, owner: &str, name: &str) -> Result<Option<Arc<RepoHandle>>> {
        validate_repo_segment(owner, "owner")?;
        validate_repo_segment(name, "name")?;

        let key = (owner.to_string(), name.to_string());
        {
            let guard = self
                .repos
                .read()
                .map_err(|_| GitxError::Storage("repos rwlock poisoned".to_string()))?;
            if let Some(handle) = guard.get(&key) {
                return Ok(Some(Arc::clone(handle)));
            }
        }

        let dir = self.repo_dir(owner, name);
        if !dir.join("metadata.sqlite").exists() {
            return Ok(None);
        }

        let mut guard = self
            .repos
            .write()
            .map_err(|_| GitxError::Storage("repos rwlock poisoned".to_string()))?;
        if let Some(handle) = guard.get(&key) {
            return Ok(Some(Arc::clone(handle)));
        }

        let handle = Arc::new(RepoHandle::open_with_backend(
            owner.to_string(),
            name.to_string(),
            dir,
            self.config.default_acl.clone(),
            self.config.blob_backend.as_ref(),
        )?);
        handle.set_conflict_resolver(self.config.conflict_resolver.clone());
        crate::outbox::spawn_startup_replay(
            Arc::clone(&handle.outbox),
            self.config.webhook_urls.clone(),
        );
        guard.insert(key, Arc::clone(&handle));
        Ok(Some(handle))
    }

    /// List hosted repositories, optionally filtered by `owner`.
    pub fn list_repos(&self, owner_filter: Option<&str>) -> Result<Vec<RepoInfo>> {
        if let Some(owner) = owner_filter {
            validate_repo_segment(owner, "owner")?;
        }

        let mut keys: Vec<(String, String)> = Vec::new();
        {
            let guard = self
                .repos
                .read()
                .map_err(|_| GitxError::Storage("repos rwlock poisoned".to_string()))?;
            for (owner, name) in guard.keys() {
                if owner_filter.is_none_or(|f| f == owner) {
                    keys.push((owner.clone(), name.clone()));
                }
            }
        }

        let base = self.repos_base_dir();
        if base.is_dir() {
            for owner_entry in fs::read_dir(&base)? {
                let owner_entry = owner_entry?;
                if !owner_entry.file_type()?.is_dir() {
                    continue;
                }
                let owner = owner_entry.file_name().to_string_lossy().to_string();
                if owner_filter.is_some_and(|f| f != owner) {
                    continue;
                }
                if validate_repo_segment(&owner, "owner").is_err() {
                    continue;
                }
                for repo_entry in fs::read_dir(owner_entry.path())? {
                    let repo_entry = repo_entry?;
                    if !repo_entry.file_type()?.is_dir() {
                        continue;
                    }
                    let name = repo_entry.file_name().to_string_lossy().to_string();
                    if validate_repo_segment(&name, "name").is_err() {
                        continue;
                    }
                    if repo_entry.path().join("metadata.sqlite").exists() {
                        let pair = (owner.clone(), name);
                        if !keys.contains(&pair) {
                            keys.push(pair);
                        }
                    }
                }
            }
        }

        keys.sort();
        keys.dedup();

        let mut out = Vec::with_capacity(keys.len());
        for (owner, name) in keys {
            if let Some(handle) = self.get_repo(&owner, &name)? {
                out.push(handle.info()?);
            }
        }
        Ok(out)
    }
}

pub fn validate_repo_segment(seg: &str, label: &str) -> Result<()> {
    if seg.is_empty()
        || seg == "."
        || seg == ".."
        || seg.len() > 128
        || !seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(GitxError::InvalidDomain(format!(
            "invalid repository {label} '{seg}'"
        )));
    }
    Ok(())
}

fn load_initial_acl(
    root_dir: &Path,
    store: &dyn ObjectStore,
    default_acl: Option<&str>,
) -> Result<AclPolicy> {
    let disk_acl = root_dir.join(".gitxacl");
    if disk_acl.is_file() {
        let text = fs::read_to_string(&disk_acl)?;
        return AclPolicy::parse(&text);
    }

    if let Some(text) = read_committed_acl(store)? {
        return AclPolicy::parse(&text);
    }

    if let Some(default_text) = default_acl {
        return AclPolicy::parse(default_text);
    }

    Ok(AclPolicy::default_secure())
}

fn read_public_acl_bytes_at(
    store: &dyn ObjectStore,
    head: Option<ObjectHash>,
) -> Result<Option<Vec<u8>>> {
    let Some(head_id) = head else {
        return Ok(None);
    };
    let cs = store.get_changeset(head_id)?;
    let Some(&pub_tree_hash) = cs.domain_trees.get(&DomainId::public()) else {
        return Ok(None);
    };
    let tree = store.get_tree(pub_tree_hash)?;
    match tree.entries.get(".gitxacl") {
        Some(EntryKind::File { blob_hash, .. }) => Ok(Some(store.read_blob_bytes(*blob_hash)?)),
        _ => Ok(None),
    }
}

fn read_committed_acl(store: &dyn ObjectStore) -> Result<Option<String>> {
    let Some(head_hash) = store.get_bookmark("master")? else {
        return Ok(None);
    };
    let cs = store.get_changeset(head_hash)?;
    let Some(&pub_tree_hash) = cs.domain_trees.get(&DomainId::public()) else {
        return Ok(None);
    };
    let pub_tree = store.get_tree(pub_tree_hash)?;
    let Some(EntryKind::File { blob_hash, .. }) = pub_tree.entries.get(".gitxacl") else {
        return Ok(None);
    };
    let bytes = store.read_blob_bytes(*blob_hash)?;
    let text = String::from_utf8(bytes)
        .map_err(|e| GitxError::Crypto(format!(".gitxacl is not valid UTF-8: {e}")))?;
    Ok(Some(text))
}
