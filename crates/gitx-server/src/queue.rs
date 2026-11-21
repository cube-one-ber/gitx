//! Batched lock-free agentic merge queue with semantic auto-merge and optional
//! conflict-resolver hooks.
//!
//! Concurrent agents upload ChangeSets lock-free (`POST /commit` with `update_target: false`),
//! enqueue them onto a target bookmark (`POST /queue/enqueue`), and drain the batch atomically
//! (`POST /queue/drain`). All clean (and hook-resolved) ChangeSets in the batch are merged
//! semantically and landed via a **single** atomic `store.record_land(...)` transaction,
//! while unresolvable conflicts are isolated and skipped without aborting clean entries.

use crate::api::{compute_public_parents, get_existing_repo, load_domain_tree_or_empty};
use crate::auth::{AuthenticatedPrincipal, can_write_domain_effective};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::Json;
use axum::extract::{Path, Query, State};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use gitx_core::{
    Actor, ChangeId, ChangeSet, ChangeSetBuilder, DomainId, DomainTree, EmbargoState, EntryKind,
    FileMode, Identity, ObjectHash, VisibilityPolicy,
};
use gitx_crypto::scan_content;
use gitx_merge::{merge_domain_trees, resolve_conflict_in_tree};
use gitx_store::ObjectStore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Optional conflict-resolver hook invoked during `/queue/drain` whenever a 3-way semantic
/// merge produces a file conflict.
///
/// Arguments: `(path, base_bytes, ours_bytes, theirs_bytes)`.
/// Return `Some(resolved_bytes)` to resolve the conflict and keep landing the entry,
/// or `None` to leave the conflict unresolved (marking the entry `Conflicted` and skipping it).
pub type ConflictResolverFn =
    Arc<dyn Fn(&str, &[u8], &[u8], &[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// Lifecycle status of an entry in the batched merge queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum QueueStatus {
    Pending,
    Landed { land_seq: u64 },
    Conflicted { conflict_paths: Vec<String> },
    Rejected { reason: String },
}

/// A single ChangeSet queued for batched landing onto a target bookmark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueEntry {
    pub id: u64,
    pub changeset_id: String,
    pub change_id: String,
    pub target: String,
    pub submitted_by: String,
    pub enqueued_at: DateTime<Utc>,
    pub status: QueueStatus,
}

/// Per-repository batched merge queue.
pub struct MergeQueue {
    next_id: AtomicU64,
    entries: RwLock<Vec<QueueEntry>>,
    conflict_resolver: RwLock<Option<ConflictResolverFn>>,
    drain_lock: tokio::sync::Mutex<()>,
}

impl Default for MergeQueue {
    fn default() -> Self {
        Self::new(None)
    }
}

impl MergeQueue {
    pub fn new(conflict_resolver: Option<ConflictResolverFn>) -> Self {
        Self {
            next_id: AtomicU64::new(1),
            entries: RwLock::new(Vec::new()),
            conflict_resolver: RwLock::new(conflict_resolver),
            drain_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Install or clear the conflict-resolver hook for this repository's merge queue.
    pub fn set_conflict_resolver(&self, resolver: Option<ConflictResolverFn>) {
        if let Ok(mut guard) = self.conflict_resolver.write() {
            *guard = resolver;
        }
    }

    /// Return a cloned handle to the currently configured conflict-resolver hook, if any.
    pub fn conflict_resolver(&self) -> Option<ConflictResolverFn> {
        self.conflict_resolver
            .read()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// Append a ChangeSet to the target queue (or return its existing pending entry idempotently).
    pub fn enqueue_entry(
        &self,
        changeset_id: String,
        change_id: String,
        target: String,
        submitted_by: String,
    ) -> ApiResult<(QueueEntry, usize)> {
        let mut guard = self
            .entries
            .write()
            .map_err(|_| ApiError::internal("merge queue rwlock poisoned"))?;

        if let Some(existing) = guard.iter().find(|e| {
            e.target == target
                && e.changeset_id == changeset_id
                && matches!(e.status, QueueStatus::Pending)
        }) {
            let pending_depth = guard
                .iter()
                .filter(|e| e.target == target && matches!(e.status, QueueStatus::Pending))
                .count();
            return Ok((existing.clone(), pending_depth));
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = QueueEntry {
            id,
            changeset_id,
            change_id,
            target: target.clone(),
            submitted_by,
            enqueued_at: Utc::now(),
            status: QueueStatus::Pending,
        };
        guard.push(entry.clone());

        let pending_depth = guard
            .iter()
            .filter(|e| e.target == target && matches!(e.status, QueueStatus::Pending))
            .count();

        Ok((entry, pending_depth))
    }

    /// Snapshot all entries for `target`, optionally filtering to only pending entries.
    pub fn entries_for_target(&self, target: &str, pending_only: bool) -> ApiResult<Vec<QueueEntry>> {
        let guard = self
            .entries
            .read()
            .map_err(|_| ApiError::internal("merge queue rwlock poisoned"))?;
        Ok(guard
            .iter()
            .filter(|e| {
                e.target == target && (!pending_only || matches!(e.status, QueueStatus::Pending))
            })
            .cloned()
            .collect())
    }

    fn update_statuses(&self, updates: &[(u64, QueueStatus)]) -> ApiResult<()> {
        if updates.is_empty() {
            return Ok(());
        }
        let mut guard = self
            .entries
            .write()
            .map_err(|_| ApiError::internal("merge queue rwlock poisoned"))?;
        for (id, status) in updates {
            if let Some(entry) = guard.iter_mut().find(|e| e.id == *id) {
                entry.status = status.clone();
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// HTTP API Types & Handlers
// ---------------------------------------------------------------------------

fn default_target() -> String {
    "master".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnqueueRequest {
    pub changeset_id: String,
    #[serde(default = "default_target")]
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnqueueResponse {
    pub entry: QueueEntry,
    pub queue_depth: usize,
}

/// `POST /v1/repos/{owner}/{name}/queue/enqueue`
pub async fn enqueue(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<EnqueueRequest>,
) -> ApiResult<Json<EnqueueResponse>> {
    if principal.is_anonymous {
        return Err(ApiError::forbidden(
            "anonymous callers are not permitted to enqueue changes",
        ));
    }

    let repo = get_existing_repo(&state, &owner, &name)?;
    let policy = repo.acl_snapshot()?;

    let cs_hash = ObjectHash::from_str(&req.changeset_id)?;
    let cs = repo.store.get_changeset(cs_hash)?;

    if !policy.can_read_changeset(&principal, &cs) {
        return Err(ApiError::forbidden(format!(
            "principal '{}' cannot access changeset {}",
            principal.id, cs_hash
        )));
    }

    let embargo_allowed = match &cs.visibility.embargo {
        Some(EmbargoState::Active {
            allowed_domains, ..
        }) => allowed_domains.as_slice(),
        _ => &[],
    };
    if !can_write_domain_effective(
        &policy,
        &principal,
        &cs.visibility.primary_domain,
        embargo_allowed,
    ) {
        return Err(ApiError::forbidden(format!(
            "principal '{}' cannot write to domain '{}'",
            principal.id, cs.visibility.primary_domain
        )));
    }

    let (entry, queue_depth) = repo.queue.enqueue_entry(
        cs.id.to_hex(),
        cs.change_id.to_string(),
        req.target,
        principal.id,
    )?;

    Ok(Json(EnqueueResponse { entry, queue_depth }))
}

#[derive(Debug, Clone, Deserialize)]
pub struct QueueListQuery {
    #[serde(default = "default_target")]
    pub target: String,
    #[serde(default)]
    pub pending_only: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueListResponse {
    pub target: String,
    pub pending_count: usize,
    pub entries: Vec<QueueEntry>,
}

/// `GET /v1/repos/{owner}/{name}/queue?target=master`
pub async fn list_queue(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<QueueListQuery>,
) -> ApiResult<Json<QueueListResponse>> {
    let repo = get_existing_repo(&state, &owner, &name)?;
    let policy = repo.acl_snapshot()?;
    let pending_only = query.pending_only.unwrap_or(false);

    let raw_entries = repo.queue.entries_for_target(&query.target, pending_only)?;
    let mut visible_entries = Vec::with_capacity(raw_entries.len());

    for entry in raw_entries {
        if let Ok(hash) = ObjectHash::from_str(&entry.changeset_id)
            && let Ok(cs) = repo.store.get_changeset(hash)
            && !policy.can_read_changeset(&principal, &cs)
        {
            continue;
        }
        visible_entries.push(entry);
    }

    let pending_count = visible_entries
        .iter()
        .filter(|e| matches!(e.status, QueueStatus::Pending))
        .count();

    Ok(Json(QueueListResponse {
        target: query.target,
        pending_count,
        entries: visible_entries,
    }))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DrainRequest {
    #[serde(default = "default_target")]
    pub target: String,
    #[serde(default)]
    pub max_batch_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrainResponse {
    pub target: String,
    pub land_seq: Option<u64>,
    pub previous_head: Option<String>,
    pub new_head: Option<String>,
    pub landed: Vec<QueueEntry>,
    pub conflicted: Vec<QueueEntry>,
    pub rejected: Vec<QueueEntry>,
    pub resolved_conflicts: Vec<String>,
}

/// `POST /v1/repos/{owner}/{name}/queue/drain`
///
/// Semantically merges pending queued ChangeSets onto the target bookmark head,
/// invokes the configured [`ConflictResolverFn`] hook on any merge conflict, skips
/// unresolvable conflicts without aborting clean entries, and lands the combined
/// batch atomically via a SINGLE `store.record_land(...)` call.
pub async fn drain_queue(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<Json<DrainResponse>> {
    if principal.is_anonymous {
        return Err(ApiError::forbidden(
            "anonymous callers are not permitted to drain the merge queue",
        ));
    }

    let req: DrainRequest = if body.is_empty() {
        DrainRequest::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| ApiError::bad_request(format!("invalid drain JSON: {e}")))?
    };

    let target = if req.target.trim().is_empty() {
        default_target()
    } else {
        req.target
    };

    let repo = get_existing_repo(&state, &owner, &name)?;
    let _drain_guard = repo.queue.drain_lock.lock().await;

    let policy = repo.acl_snapshot()?;
    let resolver = repo.queue.conflict_resolver();

    let mut pending = repo.queue.entries_for_target(&target, true)?;
    if let Some(limit) = req.max_batch_size {
        pending.truncate(limit);
    }

    let initial_head = repo.store.get_bookmark(&target)?;
    if pending.is_empty() {
        let head_hex = initial_head.map(|h| h.to_hex());
        return Ok(Json(DrainResponse {
            target,
            land_seq: None,
            previous_head: head_hex.clone(),
            new_head: head_hex,
            landed: Vec::new(),
            conflicted: Vec::new(),
            rejected: Vec::new(),
            resolved_conflicts: Vec::new(),
        }));
    }

    let initial_cs = initial_head
        .map(|h| repo.store.get_changeset(h))
        .transpose()?;

    // Working accumulated trees for the batch (mutated ONLY when an entry merges cleanly).
    let mut acc_trees: BTreeMap<DomainId, DomainTree> = BTreeMap::new();
    let mut has_acc_state = false;
    if let Some(ref base_head_cs) = initial_cs {
        for (dom, &tree_hash) in &base_head_cs.domain_trees {
            acc_trees.insert(dom.clone(), repo.store.get_tree(tree_hash)?);
        }
        has_acc_state = true;
    }

    let mut staged_landed: Vec<(QueueEntry, ChangeSet)> = Vec::new();
    let mut landed_cs_ids: Vec<ObjectHash> = Vec::new();
    let mut landed_cs_map: BTreeMap<ObjectHash, ChangeSet> = BTreeMap::new();
    let mut conflicted_entries: Vec<QueueEntry> = Vec::new();
    let mut rejected_entries: Vec<QueueEntry> = Vec::new();
    let mut resolved_conflicts: Vec<String> = Vec::new();
    let mut status_updates: Vec<(u64, QueueStatus)> = Vec::new();

    for mut entry in pending {
        let cs_hash = match ObjectHash::from_str(&entry.changeset_id) {
            Ok(h) => h,
            Err(e) => {
                let status = QueueStatus::Rejected {
                    reason: format!("invalid changeset hash: {e}"),
                };
                entry.status = status.clone();
                status_updates.push((entry.id, status));
                rejected_entries.push(entry);
                continue;
            }
        };

        let incoming_cs = match repo.store.get_changeset(cs_hash) {
            Ok(cs) => cs,
            Err(e) => {
                let status = QueueStatus::Rejected {
                    reason: format!("changeset not found: {e}"),
                };
                entry.status = status.clone();
                status_updates.push((entry.id, status));
                rejected_entries.push(entry);
                continue;
            }
        };

        if !policy.can_read_changeset(&principal, &incoming_cs) {
            let status = QueueStatus::Rejected {
                reason: format!(
                    "principal '{}' cannot read changeset {}",
                    principal.id, cs_hash
                ),
            };
            entry.status = status.clone();
            status_updates.push((entry.id, status));
            rejected_entries.push(entry);
            continue;
        }

        let embargo_allowed = match &incoming_cs.visibility.embargo {
            Some(EmbargoState::Active {
                allowed_domains, ..
            }) => allowed_domains.as_slice(),
            _ => &[],
        };
        if !can_write_domain_effective(
            &policy,
            &principal,
            &incoming_cs.visibility.primary_domain,
            embargo_allowed,
        ) {
            let status = QueueStatus::Rejected {
                reason: format!(
                    "principal '{}' cannot write to domain '{}'",
                    principal.id, incoming_cs.visibility.primary_domain
                ),
            };
            entry.status = status.clone();
            status_updates.push((entry.id, status));
            rejected_entries.push(entry);
            continue;
        }

        // Fast-path: target has no head yet, or first entry in batch is a direct fast-forward child of initial_head.
        if !has_acc_state
            || (staged_landed.is_empty()
                && (initial_head == Some(incoming_cs.id)
                    || incoming_cs.parents.first().copied() == initial_head))
        {
            let mut next_trees: BTreeMap<DomainId, DomainTree> = BTreeMap::new();
            for (dom, &tree_hash) in &incoming_cs.domain_trees {
                next_trees.insert(dom.clone(), repo.store.get_tree(tree_hash)?);
            }
            acc_trees = next_trees;
            has_acc_state = true;
            landed_cs_ids.push(incoming_cs.id);
            landed_cs_map.insert(incoming_cs.id, incoming_cs.clone());
            staged_landed.push((entry, incoming_cs));
            continue;
        }

        // Determine merge base for 3-way semantic merge of `incoming_cs` onto `acc_trees`.
        let base_cs: Option<ChangeSet> =
            if let Some(first_parent) = incoming_cs.parents.first().copied()
                && let Some(stacked_base) = landed_cs_map.get(&first_parent)
            {
                Some(stacked_base.clone())
            } else if let Some(head_hash) = initial_head {
                let lca = {
                    let mut derived = repo
                        .derived
                        .write()
                        .map_err(|_| ApiError::internal("derived index rwlock poisoned"))?;
                    derived
                        .commit_graph
                        .merge_base(repo.store.as_ref(), head_hash, incoming_cs.id)?
                }
                .or_else(|| incoming_cs.parents.first().copied());
                lca.map(|h| repo.store.get_changeset(h)).transpose()?
            } else {
                incoming_cs
                    .parents
                    .first()
                    .copied()
                    .map(|h| repo.store.get_changeset(h))
                    .transpose()?
            };

        let mut all_domains: BTreeSet<DomainId> = BTreeSet::new();
        if let Some(ref b) = base_cs {
            all_domains.extend(b.domain_trees.keys().cloned());
        }
        all_domains.extend(acc_trees.keys().cloned());
        all_domains.extend(incoming_cs.domain_trees.keys().cloned());

        let mut candidate_trees: BTreeMap<DomainId, DomainTree> = BTreeMap::new();
        let mut unresolved_conflicts: Vec<String> = Vec::new();
        let mut entry_resolved: Vec<String> = Vec::new();
        let mut secret_rejection: Option<String> = None;

        for dom in all_domains {
            let base_tree = load_domain_tree_or_empty(repo.store.as_ref(), base_cs.as_ref(), &dom)?;
            let ours_tree = acc_trees
                .get(&dom)
                .cloned()
                .unwrap_or_else(|| DomainTree::new(dom.clone()));
            let theirs_tree =
                load_domain_tree_or_empty(repo.store.as_ref(), Some(&incoming_cs), &dom)?;

            let store_ref = repo.store.as_ref();
            let mut merge_res = merge_domain_trees(
                &base_tree,
                &ours_tree,
                &theirs_tree,
                |h| store_ref.read_blob_bytes(h),
                |bytes| {
                    let blob = store_ref.put_blob_bytes(bytes)?;
                    Ok((blob.manifest_hash(), blob.total_size))
                },
            )?;

            if !merge_res.conflict_paths.is_empty() {
                for conflict_path in &merge_res.conflict_paths {
                    let Some(ref hook) = resolver else {
                        unresolved_conflicts.push(conflict_path.clone());
                        continue;
                    };

                    let base_bytes = read_tree_file_bytes(store_ref, &base_tree, conflict_path)?;
                    let ours_bytes = read_tree_file_bytes(store_ref, &ours_tree, conflict_path)?;
                    let theirs_bytes =
                        read_tree_file_bytes(store_ref, &theirs_tree, conflict_path)?;

                    if let Some(resolved_bytes) =
                        hook(conflict_path, &base_bytes, &ours_bytes, &theirs_bytes)
                    {
                        if dom.is_public() {
                            let findings = scan_content(conflict_path, &resolved_bytes);
                            if !findings.is_empty() {
                                secret_rejection = Some(format!(
                                    "conflict resolver produced secret content in public path '{conflict_path}'"
                                ));
                                break;
                            }
                        }

                        let mode = match merge_res.tree.entries.get(conflict_path) {
                            Some(EntryKind::Conflict { mode, .. }) => *mode,
                            _ => FileMode::Regular,
                        };
                        let blob = store_ref.put_blob_bytes(&resolved_bytes)?;
                        resolve_conflict_in_tree(
                            &mut merge_res.tree,
                            conflict_path,
                            blob.manifest_hash(),
                            mode,
                            blob.total_size,
                        );
                        entry_resolved.push(conflict_path.clone());
                    } else {
                        unresolved_conflicts.push(conflict_path.clone());
                    }
                }
            }

            if secret_rejection.is_some() {
                break;
            }
            candidate_trees.insert(dom, merge_res.tree);
        }

        if let Some(reason) = secret_rejection {
            let status = QueueStatus::Rejected { reason };
            entry.status = status.clone();
            status_updates.push((entry.id, status));
            rejected_entries.push(entry);
            continue;
        }

        if !unresolved_conflicts.is_empty() {
            unresolved_conflicts.sort();
            unresolved_conflicts.dedup();
            let status = QueueStatus::Conflicted {
                conflict_paths: unresolved_conflicts,
            };
            entry.status = status.clone();
            status_updates.push((entry.id, status));
            conflicted_entries.push(entry);
            continue;
        }

        // Entry merged cleanly (or was resolved by hook): commit into batch accumulator!
        acc_trees = candidate_trees;
        resolved_conflicts.extend(entry_resolved);
        landed_cs_ids.push(incoming_cs.id);
        landed_cs_map.insert(incoming_cs.id, incoming_cs.clone());
        staged_landed.push((entry, incoming_cs));
    }

    // If nothing could be landed, persist conflict/rejection statuses and return without touching the bookmark.
    if staged_landed.is_empty() {
        repo.queue.update_statuses(&status_updates)?;
        let head_hex = initial_head.map(|h| h.to_hex());
        return Ok(Json(DrainResponse {
            target,
            land_seq: None,
            previous_head: head_hex.clone(),
            new_head: head_hex,
            landed: Vec::new(),
            conflicted: conflicted_entries,
            rejected: rejected_entries,
            resolved_conflicts,
        }));
    }

    // Determine final head: direct fast-forward for a single unmodified FF entry, or a
    // single combined batch merge ChangeSet for multi-entry / 3-way-merged batches.
    let is_single_ff = staged_landed.len() == 1
        && resolved_conflicts.is_empty()
        && (initial_head.is_none()
            || initial_head == Some(staged_landed[0].1.id)
            || staged_landed[0].1.parents.first().copied() == initial_head);

    let final_head = if is_single_ff {
        staged_landed[0].1.id
    } else {
        let mut persisted_trees: BTreeMap<DomainId, ObjectHash> = BTreeMap::new();
        for (dom, tree) in &acc_trees {
            let tree_hash = repo.store.put_tree(tree)?;
            persisted_trees.insert(dom.clone(), tree_hash);
        }

        let mut parents: Vec<ObjectHash> = Vec::with_capacity(landed_cs_ids.len() + 1);
        if let Some(head) = initial_head {
            parents.push(head);
        }
        for &cs_id in &landed_cs_ids {
            if !parents.contains(&cs_id) {
                parents.push(cs_id);
            }
        }
        let public_parents = compute_public_parents(repo.store.as_ref(), &parents);

        let batch_visibility = compute_batch_visibility(&staged_landed);
        let author = Identity {
            name: principal.id.clone(),
            email: format!("{}@gitx.local", principal.id),
            key_fingerprint: principal.fingerprint.clone(),
        };
        let description = if staged_landed.len() == 1 {
            format!(
                "Queue merge {} into {}: {}",
                staged_landed[0].1.change_id.short(),
                target,
                staged_landed[0].1.description
            )
        } else {
            format!(
                "Batched queue land of {} changes into {}",
                staged_landed.len(),
                target
            )
        };

        let batch_cs = ChangeSetBuilder::new(author.clone())
            .parents(parents)
            .public_parents(public_parents)
            .domain_trees(persisted_trees)
            .committer(Actor::Human(author))
            .visibility(batch_visibility)
            .has_conflicts(false)
            .description(description)
            .build();

        repo.store.put_changeset(&batch_cs)?;
        batch_cs.id
    };

    let landed_change_ids: Vec<ChangeId> = staged_landed.iter().map(|(_, cs)| cs.change_id).collect();

    // Land the entire batch atomically in a SINGLE transactional `record_land(...)` call!
    let record = repo
        .store
        .record_land(&target, initial_head, final_head, landed_change_ids)?;

    if target == "master" {
        let _ = repo.reload_acl_from_store();
    }

    let mut landed_entries = Vec::with_capacity(staged_landed.len());
    for (mut entry, _) in staged_landed {
        let status = QueueStatus::Landed {
            land_seq: record.land_seq,
        };
        entry.status = status.clone();
        status_updates.push((entry.id, status));
        landed_entries.push(entry);
    }

    repo.queue.update_statuses(&status_updates)?;

    Ok(Json(DrainResponse {
        target: record.target,
        land_seq: Some(record.land_seq),
        previous_head: record.previous_head.map(|h| h.to_hex()),
        new_head: Some(record.new_head.to_hex()),
        landed: landed_entries,
        conflicted: conflicted_entries,
        rejected: rejected_entries,
        resolved_conflicts,
    }))
}

fn read_tree_file_bytes(
    store: &dyn ObjectStore,
    tree: &DomainTree,
    path: &str,
) -> ApiResult<Vec<u8>> {
    match tree.entries.get(path) {
        Some(EntryKind::File { blob_hash, .. }) => Ok(store.read_blob_bytes(*blob_hash)?),
        _ => Ok(Vec::new()),
    }
}

fn compute_batch_visibility(staged: &[(QueueEntry, ChangeSet)]) -> VisibilityPolicy {
    if staged.len() == 1 {
        let vis = &staged[0].1.visibility;
        if vis.reveal_on_land {
            return VisibilityPolicy::public();
        }
        return vis.clone();
    }

    if staged
        .iter()
        .any(|(_, cs)| cs.visibility.primary_domain.is_public() || cs.visibility.reveal_on_land)
    {
        return VisibilityPolicy::public();
    }

    staged
        .first()
        .map(|(_, cs)| cs.visibility.clone())
        .unwrap_or_else(VisibilityPolicy::public)
}
