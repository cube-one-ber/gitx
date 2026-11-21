use crate::auth::{
    AuthenticatedPrincipal, can_publish_embargo, can_write_domain_effective,
    effective_allowed_domains,
};
use crate::derived::DerivedStats;
use crate::error::{ApiError, ApiResult};
use crate::state::{AppState, RepoHandle, RepoInfo};
use axum::Json;
use axum::extract::{Path, Query, State};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use gitx_context::{CodeAnchor, ContextId, ContextKind, ContextRecord, WhyMatch};
use gitx_core::{
    Actor, ChangeSet, ChangeSetBuilder, DomainId, DomainTree, EmbargoState, EntryKind, FileMode,
    Identity, ObjectHash, VisibilityPolicy,
};
use gitx_crypto::{AclPolicy, Principal, scan_content};
use gitx_merge::{merge_domain_trees, unified_diff};
use gitx_store::ObjectStore;
use serde::{Deserialize, Serialize};
use similar::{DiffOp, TextDiff};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::str::FromStr;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Health & Repository Management
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CreateRepoRequest {
    #[serde(default)]
    pub acl: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRepoResponse {
    pub repo: RepoInfo,
}

pub async fn create_repo(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<Json<CreateRepoResponse>> {
    let req: CreateRepoRequest = if body.is_empty() {
        CreateRepoRequest::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| ApiError::bad_request(format!("invalid create repo JSON: {e}")))?
    };

    let repo = state.get_or_create_repo(&owner, &name)?;
    if let Some(acl_text) = req.acl {
        repo.update_acl_from_text(&acl_text)?;
    }

    Ok(Json(CreateRepoResponse { repo: repo.info()? }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListReposResponse {
    pub repos: Vec<RepoInfo>,
}

pub async fn list_all_repos(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<ListReposResponse>> {
    let repos = state.list_repos(None)?;
    Ok(Json(ListReposResponse { repos }))
}

pub async fn list_owner_repos(
    State(state): State<Arc<AppState>>,
    Path(owner): Path<String>,
) -> ApiResult<Json<ListReposResponse>> {
    let repos = state.list_repos(Some(&owner))?;
    Ok(Json(ListReposResponse { repos }))
}

pub async fn list_repo_scoped_repos(
    State(state): State<Arc<AppState>>,
    Path((owner, _name)): Path<(String, String)>,
) -> ApiResult<Json<ListReposResponse>> {
    let repos = state.list_repos(Some(&owner))?;
    Ok(Json(ListReposResponse { repos }))
}

// ---------------------------------------------------------------------------
// Zero-Clone Server-Side Commit (Push-to-Create)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorAgentInput {
    pub harness: String,
    pub model: String,
    pub session_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommitRequest {
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    #[serde(default)]
    pub delete_files: Vec<String>,
    /// Optional encoding for `files` values: `"utf8"` (default) or `"base64"`.
    #[serde(default)]
    pub encoding: Option<String>,
    pub message: String,
    #[serde(default = "default_author_name")]
    pub author_name: String,
    #[serde(default = "default_author_email")]
    pub author_email: String,
    #[serde(default)]
    pub actor_agent: Option<ActorAgentInput>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub parent: Option<String>,
    /// Whether to advance the `target` bookmark to the new changeset (default: `true`).
    #[serde(default)]
    pub update_target: Option<bool>,
    #[serde(default)]
    pub visibility_domain: Option<String>,
    #[serde(default)]
    pub embargo_advisory: Option<String>,
    #[serde(default)]
    pub embargo_allowed_teams: Vec<String>,
    #[serde(default)]
    pub context_prompt: Option<String>,
}

fn default_author_name() -> String {
    "gitx".to_string()
}

fn default_author_email() -> String {
    "gitx@local".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitResponse {
    pub changeset_id: String,
    pub change_id: String,
    pub public_projection_hash: String,
    pub domains_written: Vec<String>,
    pub target: Option<String>,
}

pub async fn commit(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<CommitRequest>,
) -> ApiResult<Json<CommitResponse>> {
    // Push-to-create: automatically provisions repo if it does not yet exist.
    let repo = state.get_or_create_repo(&owner, &name)?;

    if req.files.is_empty() && req.delete_files.is_empty() {
        return Err(ApiError::bad_request(
            "commit must include at least one file or deletion",
        ));
    }

    // Decode all submitted file contents first.
    let mut decoded_files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let global_base64 = req
        .encoding
        .as_deref()
        .is_some_and(|enc| enc.eq_ignore_ascii_case("base64"));

    for (raw_path, raw_val) in &req.files {
        let norm_path = normalize_repo_path(raw_path)?;
        let bytes = decode_file_value(raw_val, global_base64)?;
        decoded_files.insert(norm_path, bytes);
    }

    // Determine effective ACL policy (if `.gitxacl` is being committed, parse and validate it first).
    let mut policy = repo.acl_snapshot()?;
    let new_acl_text = if let Some(acl_bytes) = decoded_files.get(".gitxacl") {
        let text = std::str::from_utf8(acl_bytes)
            .map_err(|e| ApiError::bad_request(format!(".gitxacl must be valid UTF-8: {e}")))?;
        policy = AclPolicy::parse(text)?;
        Some(text.to_string())
    } else {
        None
    };

    // Parse explicit visibility / embargo settings.
    let embargo_allowed_domains: Vec<DomainId> = req
        .embargo_allowed_teams
        .iter()
        .map(|entry| parse_team_or_domain(entry))
        .collect::<Result<Vec<_>, _>>()?;

    let explicit_visibility_domain = req
        .visibility_domain
        .as_deref()
        .map(DomainId::new)
        .transpose()?;

    let embargo_domain = req
        .embargo_advisory
        .as_deref()
        .map(DomainId::embargo)
        .transpose()?;

    // Classify every submitted file and enforce zero-trust secret scanning + write ACLs.
    let mut files_by_domain: BTreeMap<DomainId, Vec<(String, Vec<u8>)>> = BTreeMap::new();
    let mut touched_domains: BTreeSet<DomainId> = BTreeSet::new();

    for (path, bytes) in &decoded_files {
        let target_domain = if let Some(ref emb_dom) = embargo_domain {
            emb_dom.clone()
        } else if let Some(ref vis_dom) = explicit_visibility_domain {
            let acl_routed = policy.domain_for_path(path);
            if vis_dom.is_public() {
                // Caller explicitly requested public: honor ACL secret rules or catch via scanner below.
                DomainId::public()
            } else if acl_routed.is_secret() && !vis_dom.is_secret() {
                acl_routed
            } else {
                vis_dom.clone()
            }
        } else {
            policy.domain_for_path(path)
        };

        // Secret scanner guard: reject unlabelled secrets landing in `public`.
        if target_domain.is_public() {
            let findings = scan_content(path, bytes);
            if !findings.is_empty() {
                return Err(ApiError::secret_rejected(
                    format!(
                        "secret detected in '{path}'; refusing to commit to 'public' domain (route to a 'secret:*' domain instead)"
                    ),
                    findings,
                ));
            }
        }

        if !can_write_domain_effective(
            &policy,
            &principal,
            &target_domain,
            &embargo_allowed_domains,
        ) {
            return Err(ApiError::forbidden(format!(
                "principal '{}' is not authorized to write to domain '{}'",
                principal.id, target_domain
            )));
        }

        touched_domains.insert(target_domain.clone());
        files_by_domain
            .entry(target_domain)
            .or_default()
            .push((path.clone(), bytes.clone()));
    }

    // Validate deletions against write ACLs.
    let mut delete_paths: Vec<String> = Vec::with_capacity(req.delete_files.len());
    for raw_path in &req.delete_files {
        let norm = normalize_repo_path(raw_path)?;
        let dom = embargo_domain
            .clone()
            .or_else(|| explicit_visibility_domain.clone())
            .unwrap_or_else(|| policy.domain_for_path(&norm));
        if !can_write_domain_effective(&policy, &principal, &dom, &embargo_allowed_domains) {
            return Err(ApiError::forbidden(format!(
                "principal '{}' is not authorized to delete '{}' in domain '{}'",
                principal.id, norm, dom
            )));
        }
        touched_domains.insert(dom);
        delete_paths.push(norm);
    }

    // Resolve target bookmark and parent changeset.
    let target_name = req.target.clone().unwrap_or_else(|| "master".to_string());
    let parent_hash = if let Some(ref parent_str) = req.parent {
        Some(resolve_hash_or_bookmark(repo.store.as_ref(), parent_str)?)
    } else if let Some(h) = repo.store.get_bookmark(&target_name)? {
        Some(h)
    } else if target_name != "master" {
        repo.store.get_bookmark("master")?
    } else {
        None
    };

    let parent_cs = parent_hash
        .map(|h| repo.store.get_changeset(h))
        .transpose()?;

    // Start from parent's domain trees (preserving unaffected domains).
    let mut domain_trees: BTreeMap<DomainId, DomainTree> = BTreeMap::new();
    if let Some(ref p_cs) = parent_cs {
        for (dom, &tree_hash) in &p_cs.domain_trees {
            let tree = repo.store.get_tree(tree_hash)?;
            domain_trees.insert(dom.clone(), tree);
        }
    }

    // Apply deletions.
    for path in &delete_paths {
        if let Some(ref emb_dom) = embargo_domain {
            if let Some(tree) = domain_trees.get_mut(emb_dom) {
                tree.remove(path);
            }
        } else {
            for tree in domain_trees.values_mut() {
                if tree.entries.contains_key(path)
                    && can_write_domain_effective(
                        &policy,
                        &principal,
                        &tree.domain,
                        &embargo_allowed_domains,
                    )
                {
                    tree.remove(path);
                }
            }
        }
    }

    // Write blobs and insert into domain trees.
    for (dom, entries) in &files_by_domain {
        let tree = domain_trees
            .entry(dom.clone())
            .or_insert_with(|| DomainTree::new(dom.clone()));
        for (path, bytes) in entries {
            let blob = repo.store.put_blob_bytes(bytes)?;
            tree.insert(
                path.clone(),
                EntryKind::File {
                    blob_hash: blob.manifest_hash(),
                    mode: FileMode::Regular,
                    size: blob.total_size,
                },
            );
        }
    }

    // Persist every non-empty DomainTree.
    let mut domain_tree_hashes: BTreeMap<DomainId, ObjectHash> = BTreeMap::new();
    for (dom, tree) in &domain_trees {
        if !tree.entries.is_empty() || touched_domains.contains(dom) {
            let tree_hash = repo.store.put_tree(tree)?;
            domain_tree_hashes.insert(dom.clone(), tree_hash);
        }
    }

    // Determine ChangeSet VisibilityPolicy.
    let visibility = if let Some(ref advisory) = req.embargo_advisory {
        VisibilityPolicy::embargoed(advisory.clone(), embargo_allowed_domains.clone(), None)?
    } else if let Some(ref vis_dom) = explicit_visibility_domain {
        if vis_dom.is_public() {
            VisibilityPolicy::public()
        } else {
            VisibilityPolicy::private(vis_dom.clone(), false)
        }
    } else if touched_domains.len() == 1 {
        let only_dom = touched_domains.iter().next().expect("len == 1").clone();
        if only_dom.is_public() {
            VisibilityPolicy::public()
        } else {
            VisibilityPolicy::private(only_dom, false)
        }
    } else if touched_domains.contains(&DomainId::public()) {
        VisibilityPolicy::public()
    } else {
        let first_dom = touched_domains
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(DomainId::public);
        VisibilityPolicy::private(first_dom, false)
    };

    let author = Identity {
        name: req.author_name.clone(),
        email: req.author_email.clone(),
        key_fingerprint: principal.fingerprint.clone(),
    };
    let committer = match req.actor_agent {
        Some(ref agent) => Actor::Agent {
            harness: agent.harness.clone(),
            model: agent.model.clone(),
            session_id: agent.session_id.clone(),
            initiated_by: author.clone(),
        },
        None => Actor::Human(author.clone()),
    };

    let parents: Vec<ObjectHash> = parent_hash.into_iter().collect();
    let public_parents = compute_public_parents(repo.store.as_ref(), &parents);

    let cs = ChangeSetBuilder::new(author)
        .parents(parents)
        .public_parents(public_parents)
        .domain_trees(domain_tree_hashes)
        .committer(committer.clone())
        .visibility(visibility)
        .description(req.message.clone())
        .build();

    repo.store.put_changeset(&cs)?;

    let should_update_target = req.update_target.unwrap_or(true);
    let updated_target = if should_update_target {
        repo.store.set_bookmark(&target_name, cs.id)?;
        if let Some(ref acl_text) = new_acl_text {
            repo.update_acl_from_text(acl_text)?;
        }
        Some(target_name)
    } else {
        None
    };

    // Optionally record durable "Why" context records partitioned by each file's domain!
    if let Some(prompt) = req.context_prompt.filter(|p| !p.trim().is_empty()) {
        let (model, harness, session_id) = match &req.actor_agent {
            Some(a) => (a.model.clone(), a.harness.clone(), a.session_id.clone()),
            None => (
                "human".to_string(),
                "gitx-server".to_string(),
                format!("user:{}", principal.id),
            ),
        };

        for (dom, entries) in &files_by_domain {
            let mut anchors = Vec::new();
            for (path, bytes) in entries {
                if let Ok(text) = std::str::from_utf8(bytes) {
                    let line_count = text.lines().count().max(1) as u32;
                    anchors.push(CodeAnchor::from_file_lines(
                        path.clone(),
                        text,
                        1,
                        line_count,
                    ));
                }
            }

            let record_vis = if embargo_domain.is_some() {
                cs.visibility.primary_domain.clone()
            } else {
                dom.clone()
            };

            let rec = ContextRecord {
                id: ContextId::new(),
                change_id: cs.change_id,
                revision: cs.id,
                visibility: record_vis,
                author: committer.clone(),
                kind: ContextKind::Prompt {
                    prompt: prompt.clone(),
                    model: model.clone(),
                    harness: harness.clone(),
                    session_id: session_id.clone(),
                },
                anchors,
                created_at: Utc::now(),
            };
            repo.context.add_record(&rec)?;
        }
    }

    let domains_written: Vec<String> = touched_domains.iter().map(ToString::to_string).collect();

    Ok(Json(CommitResponse {
        changeset_id: cs.id.to_hex(),
        change_id: cs.change_id.to_string(),
        public_projection_hash: cs.public_projection_hash.to_hex(),
        domains_written,
        target: updated_target,
    }))
}

// ---------------------------------------------------------------------------
// ACID Transactional Landing with Semantic Auto-Merge
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct LandRequest {
    pub changeset_id: String,
    #[serde(default = "default_target")]
    pub target: String,
    #[serde(default)]
    pub expected_head: Option<String>,
}

fn default_target() -> String {
    "master".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LandResponse {
    pub land_seq: u64,
    pub target: String,
    pub previous_head: Option<String>,
    pub new_head: String,
    pub conflicts: Vec<String>,
}

pub async fn land(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<LandRequest>,
) -> ApiResult<Json<LandResponse>> {
    if principal.is_anonymous {
        return Err(ApiError::forbidden(
            "anonymous callers are not permitted to land changes",
        ));
    }

    let repo = get_existing_repo(&state, &owner, &name)?;
    let policy = repo.acl_snapshot()?;

    let incoming_hash = ObjectHash::from_str(&req.changeset_id)?;
    let incoming_cs = repo.store.get_changeset(incoming_hash)?;

    if !policy.can_read_changeset(&principal, &incoming_cs) {
        return Err(ApiError::forbidden(format!(
            "principal '{}' cannot access changeset {}",
            principal.id, incoming_hash
        )));
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
        return Err(ApiError::forbidden(format!(
            "principal '{}' cannot write to domain '{}'",
            principal.id, incoming_cs.visibility.primary_domain
        )));
    }

    let current_head = repo.store.get_bookmark(&req.target)?;

    if let Some(ref exp_str) = req.expected_head {
        let exp_hash = ObjectHash::from_str(exp_str)?;
        if current_head != Some(exp_hash) {
            return Err(ApiError::conflict(format!(
                "expected head {} does not match current target '{}' head {:?}",
                exp_hash, req.target, current_head
            )));
        }
    }

    let (final_head, conflicts) = match current_head {
        None => (incoming_cs.id, Vec::new()),
        Some(target_head)
            if target_head == incoming_cs.id
                || incoming_cs.parents.first().copied() == Some(target_head) =>
        {
            (incoming_cs.id, Vec::new())
        }
        Some(target_head) => {
            // Target has moved since incoming's base: perform 3-way semantic auto-merge across every domain.
            let target_cs = repo.store.get_changeset(target_head)?;
            let lca_hash = {
                let mut derived = repo
                    .derived
                    .write()
                    .map_err(|_| ApiError::internal("derived index rwlock poisoned"))?;
                derived
                    .commit_graph
                    .merge_base(repo.store.as_ref(), target_head, incoming_cs.id)?
            }
            .or_else(|| incoming_cs.parents.first().copied());
            let base_cs = lca_hash
                .map(|h| repo.store.get_changeset(h))
                .transpose()?;

            let mut all_domains: BTreeSet<DomainId> = BTreeSet::new();
            if let Some(ref b) = base_cs {
                all_domains.extend(b.domain_trees.keys().cloned());
            }
            all_domains.extend(target_cs.domain_trees.keys().cloned());
            all_domains.extend(incoming_cs.domain_trees.keys().cloned());

            let mut merged_domain_trees: BTreeMap<DomainId, ObjectHash> = BTreeMap::new();
            let mut all_conflicts: Vec<String> = Vec::new();

            for dom in all_domains {
                let base_tree = load_domain_tree_or_empty(repo.store.as_ref(), base_cs.as_ref(), &dom)?;
                let ours_tree = load_domain_tree_or_empty(repo.store.as_ref(), Some(&target_cs), &dom)?;
                let theirs_tree =
                    load_domain_tree_or_empty(repo.store.as_ref(), Some(&incoming_cs), &dom)?;

                let store_ref = repo.store.as_ref();
                let merge_res = merge_domain_trees(
                    &base_tree,
                    &ours_tree,
                    &theirs_tree,
                    |h| store_ref.read_blob_bytes(h),
                    |bytes| {
                        let blob = store_ref.put_blob_bytes(bytes)?;
                        Ok((blob.manifest_hash(), blob.total_size))
                    },
                )?;

                all_conflicts.extend(merge_res.conflict_paths);
                let tree_hash = repo.store.put_tree(&merge_res.tree)?;
                merged_domain_trees.insert(dom, tree_hash);
            }

            let parents = vec![target_head, incoming_cs.id];
            let public_parents = compute_public_parents(repo.store.as_ref(), &parents);
            let merged_visibility = if incoming_cs.visibility.reveal_on_land {
                VisibilityPolicy::public()
            } else {
                incoming_cs.visibility.clone()
            };

            let merged_cs = ChangeSetBuilder::new(incoming_cs.author.clone())
                .change_id(incoming_cs.change_id)
                .previous_revision(Some(incoming_cs.id))
                .parents(parents)
                .public_parents(public_parents)
                .domain_trees(merged_domain_trees)
                .committer(incoming_cs.committer.clone())
                .visibility(merged_visibility)
                .has_conflicts(!all_conflicts.is_empty())
                .description(format!(
                    "Merge {} into {}: {}",
                    incoming_cs.change_id.short(),
                    req.target,
                    incoming_cs.description
                ))
                .build();

            repo.store.put_changeset(&merged_cs)?;
            (merged_cs.id, all_conflicts)
        }
    };

    let record = repo.store.record_land(
        &req.target,
        current_head,
        final_head,
        vec![incoming_cs.change_id],
    )?;

    if req.target == "master" {
        let _ = repo.reload_acl_from_store();
    }

    Ok(Json(LandResponse {
        land_seq: record.land_seq,
        target: record.target,
        previous_head: record.previous_head.map(|h| h.to_hex()),
        new_head: record.new_head.to_hex(),
        conflicts,
    }))
}

// ---------------------------------------------------------------------------
// O(1) Atomic Revert
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevertResponse {
    pub reverted_land_seq: u64,
    pub revert_land_seq: u64,
    pub target: String,
    pub restored_head: String,
}

pub async fn revert_land(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name, land_seq)): Path<(String, String, u64)>,
) -> ApiResult<Json<RevertResponse>> {
    if principal.is_anonymous {
        return Err(ApiError::forbidden(
            "anonymous callers are not permitted to revert lands",
        ));
    }

    let repo = get_existing_repo(&state, &owner, &name)?;
    let original = repo.store.get_land(land_seq)?;

    if let Some(existing_rev) = original.reverted_by {
        return Err(ApiError::conflict(format!(
            "land_seq {land_seq} was already reverted by land_seq {existing_rev}"
        )));
    }

    let previous_head = original.previous_head.ok_or_else(|| {
        ApiError::bad_request(format!(
            "land_seq {land_seq} has no previous_head to revert to"
        ))
    })?;

    let current_head = repo.store.get_bookmark(&original.target)?;
    let revert_rec =
        repo.store
            .record_land(&original.target, current_head, previous_head, Vec::new())?;
    repo.store.mark_reverted(land_seq, revert_rec.land_seq)?;

    if original.target == "master" {
        let _ = repo.reload_acl_from_store();
    }

    Ok(Json(RevertResponse {
        reverted_land_seq: land_seq,
        revert_land_seq: revert_rec.land_seq,
        target: original.target,
        restored_head: previous_head.to_hex(),
    }))
}

// ---------------------------------------------------------------------------
// ACL-Filtered Tree
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct TreeQuery {
    #[serde(default)]
    pub rev: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeFileEntry {
    pub path: String,
    pub domain: String,
    pub size: u64,
    pub blob_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_base64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeResponse {
    pub rev: Option<String>,
    pub domains: Vec<String>,
    pub files: Vec<TreeFileEntry>,
}

pub async fn get_tree(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<TreeQuery>,
) -> ApiResult<Json<TreeResponse>> {
    let repo = get_existing_repo(&state, &owner, &name)?;
    let policy = repo.acl_snapshot()?;

    let domain_filter = query
        .domain
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(DomainId::new)
        .transpose()?;

    let Some(cs) = resolve_visible_changeset(repo.store.as_ref(), &policy, &principal, query.rev.as_deref())? else {
        if let Some(ref dom) = domain_filter
            && !policy.can_read_domain(&principal, dom)
        {
            return Err(ApiError::forbidden(format!(
                "principal '{}' is not authorized to read domain '{}'",
                principal.id, dom
            )));
        }
        return Ok(Json(TreeResponse {
            rev: None,
            domains: Vec::new(),
            files: Vec::new(),
        }));
    };

    let filtered_trees = policy.filter_domain_trees(&principal, &cs);

    if let Some(ref dom) = domain_filter
        && !filtered_trees.contains_key(dom)
        && !policy.can_read_domain(&principal, dom)
    {
        return Err(ApiError::forbidden(format!(
            "principal '{}' is not authorized to read domain '{}'",
            principal.id, dom
        )));
    }

    let ordered_domains = ordered_domain_entries(&filtered_trees, &cs.visibility.primary_domain);
    let mut active_domains: Vec<String> = Vec::new();
    let mut merged: BTreeMap<String, TreeFileEntry> = BTreeMap::new();

    for (dom, tree_hash) in ordered_domains {
        if domain_filter.as_ref().is_some_and(|f| f != dom) {
            continue;
        }
        active_domains.push(dom.to_string());
        let tree = repo.store.get_tree(tree_hash)?;
        for (path, entry) in &tree.entries {
            if let EntryKind::File {
                blob_hash, size, ..
            } = entry
            {
                let bytes = repo.store.read_blob_bytes(*blob_hash)?;
                let (content, content_base64) = match String::from_utf8(bytes) {
                    Ok(s) => (Some(s), None),
                    Err(e) => (None, Some(BASE64_STANDARD.encode(e.into_bytes()))),
                };
                merged.insert(
                    path.clone(),
                    TreeFileEntry {
                        path: path.clone(),
                        domain: dom.to_string(),
                        size: *size,
                        blob_hash: blob_hash.to_hex(),
                        content,
                        content_base64,
                    },
                );
            }
        }
    }

    Ok(Json(TreeResponse {
        rev: Some(cs.id.to_hex()),
        domains: active_domains,
        files: merged.into_values().collect(),
    }))
}

// ---------------------------------------------------------------------------
// Zero-Clone Server-Side Unified Diff
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct DiffQuery {
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffFileEntry {
    pub path: String,
    pub domain: String,
    pub status: String,
    pub patch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResponse {
    pub from: Option<String>,
    pub to: Option<String>,
    pub files: Vec<DiffFileEntry>,
    pub unified_diff: String,
}

pub async fn get_diff(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<DiffQuery>,
) -> ApiResult<Json<DiffResponse>> {
    let repo = get_existing_repo(&state, &owner, &name)?;
    let policy = repo.acl_snapshot()?;

    let to_cs =
        resolve_visible_changeset(repo.store.as_ref(), &policy, &principal, query.to.as_deref())?;

    let from_cs = match query.from.as_deref().filter(|s| !s.is_empty()) {
        Some(from_rev) => {
            resolve_visible_changeset(repo.store.as_ref(), &policy, &principal, Some(from_rev))?
        }
        None => match &to_cs {
            Some(cs) => first_visible_parent(repo.store.as_ref(), &policy, &principal, cs)?,
            None => None,
        },
    };

    let old_files = match &from_cs {
        Some(cs) => materialize_authorized_files(repo.store.as_ref(), &policy, &principal, cs)?,
        None => BTreeMap::new(),
    };
    let new_files = match &to_cs {
        Some(cs) => materialize_authorized_files(repo.store.as_ref(), &policy, &principal, cs)?,
        None => BTreeMap::new(),
    };

    let mut all_paths: BTreeSet<&str> = BTreeSet::new();
    all_paths.extend(old_files.keys().map(String::as_str));
    all_paths.extend(new_files.keys().map(String::as_str));

    let mut files = Vec::new();
    let mut full_diff = String::new();

    for path in all_paths {
        let old_entry = old_files.get(path);
        let new_entry = new_files.get(path);

        match (old_entry, new_entry) {
            (Some((_, old_bytes)), Some((_, new_bytes))) if old_bytes == new_bytes => continue,
            (None, Some((dom, new_bytes))) => {
                let patch = unified_diff(path, &[], new_bytes);
                full_diff.push_str(&patch);
                files.push(DiffFileEntry {
                    path: path.to_string(),
                    domain: dom.to_string(),
                    status: "added".to_string(),
                    patch,
                });
            }
            (Some((dom, old_bytes)), None) => {
                let patch = unified_diff(path, old_bytes, &[]);
                full_diff.push_str(&patch);
                files.push(DiffFileEntry {
                    path: path.to_string(),
                    domain: dom.to_string(),
                    status: "deleted".to_string(),
                    patch,
                });
            }
            (Some((_, old_bytes)), Some((dom, new_bytes))) => {
                let patch = unified_diff(path, old_bytes, new_bytes);
                full_diff.push_str(&patch);
                files.push(DiffFileEntry {
                    path: path.to_string(),
                    domain: dom.to_string(),
                    status: "modified".to_string(),
                    patch,
                });
            }
            (None, None) => {}
        }
    }

    Ok(Json(DiffResponse {
        from: from_cs.map(|c| c.id.to_hex()),
        to: to_cs.map(|c| c.id.to_hex()),
        files,
        unified_diff: full_diff,
    }))
}

// ---------------------------------------------------------------------------
// Zero-Clone Server-Side Grep
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct GrepQuery {
    pub q: String,
    #[serde(default)]
    pub rev: Option<String>,
    #[serde(default)]
    pub case_insensitive: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepMatch {
    pub path: String,
    pub domain: String,
    pub line_number: usize,
    pub line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepResponse {
    pub query: String,
    pub rev: Option<String>,
    pub matches: Vec<GrepMatch>,
}

pub async fn grep(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<GrepQuery>,
) -> ApiResult<Json<GrepResponse>> {
    if query.q.is_empty() {
        return Err(ApiError::bad_request("grep query 'q' must not be empty"));
    }

    let repo = get_existing_repo(&state, &owner, &name)?;
    let policy = repo.acl_snapshot()?;

    let Some(cs) =
        resolve_visible_changeset(repo.store.as_ref(), &policy, &principal, query.rev.as_deref())?
    else {
        return Ok(Json(GrepResponse {
            query: query.q,
            rev: None,
            matches: Vec::new(),
        }));
    };

    let filtered = policy.filter_domain_trees(&principal, &cs);
    let ordered: Vec<(DomainId, ObjectHash)> =
        ordered_domain_entries(&filtered, &cs.visibility.primary_domain)
            .into_iter()
            .map(|(dom, hash)| (dom.clone(), hash))
            .collect();

    // Query domain-partitioned TrigramIndex (strictly scoped to caller's authorized domains).
    let mut candidate_files: BTreeMap<String, (DomainId, ObjectHash)> = BTreeMap::new();
    let fast_hit = {
        let derived = repo
            .derived
            .read()
            .map_err(|_| ApiError::internal("derived index rwlock poisoned"))?;
        if ordered
            .iter()
            .all(|(dom, hash)| derived.trigram.contains(*hash, dom))
        {
            for (idx, (dom, hash)) in ordered.iter().enumerate() {
                if let Some(cands) = derived.trigram.try_query_cached(*hash, dom, &query.q) {
                    for (path, blob_hash) in cands {
                        let shadowed = ordered[idx + 1..].iter().any(|(later_dom, later_hash)| {
                            derived
                                .trigram
                                .cached_tree_contains_path(*later_hash, later_dom, &path)
                                .unwrap_or(false)
                        });
                        if !shadowed {
                            candidate_files.insert(path, (dom.clone(), blob_hash));
                        }
                    }
                }
            }
            true
        } else {
            false
        }
    };

    if !fast_hit {
        let mut derived = repo
            .derived
            .write()
            .map_err(|_| ApiError::internal("derived index rwlock poisoned"))?;
        let mut per_domain_candidates: Vec<(DomainId, Vec<(String, ObjectHash)>)> =
            Vec::with_capacity(ordered.len());
        for (dom, hash) in &ordered {
            let cands =
                derived
                    .trigram
                    .query_or_build(repo.store.as_ref(), *hash, dom, &query.q)?;
            per_domain_candidates.push((dom.clone(), cands));
        }
        for (idx, (dom, cands)) in per_domain_candidates.into_iter().enumerate() {
            for (path, blob_hash) in cands {
                let shadowed = ordered[idx + 1..].iter().any(|(later_dom, later_hash)| {
                    derived
                        .trigram
                        .cached_tree_contains_path(*later_hash, later_dom, &path)
                        .unwrap_or(false)
                });
                if !shadowed {
                    candidate_files.insert(path, (dom.clone(), blob_hash));
                }
            }
        }
    }

    let case_insensitive = query.case_insensitive.unwrap_or(false);
    let needle_lower = query.q.to_lowercase();

    let mut matches = Vec::new();
    for (path, (dom, blob_hash)) in &candidate_files {
        let bytes = repo.store.read_blob_bytes(*blob_hash)?;
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        for (idx, line) in text.lines().enumerate() {
            let matched = if case_insensitive {
                line.to_lowercase().contains(&needle_lower)
            } else {
                line.contains(&query.q)
            };
            if matched {
                matches.push(GrepMatch {
                    path: path.clone(),
                    domain: dom.to_string(),
                    line_number: idx + 1,
                    line: line.to_string(),
                });
            }
        }
    }

    Ok(Json(GrepResponse {
        query: query.q,
        rev: Some(cs.id.to_hex()),
        matches,
    }))
}

// ---------------------------------------------------------------------------
// Zero-Clone Server-Side Blame
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct BlameQuery {
    pub path: String,
    #[serde(default)]
    pub rev: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlameLine {
    pub line_number: usize,
    pub content: String,
    pub changeset_id: String,
    pub change_id: String,
    pub author_name: String,
    pub author_email: String,
    pub timestamp: DateTime<Utc>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlameResponse {
    pub path: String,
    pub rev: String,
    pub lines: Vec<BlameLine>,
}

pub async fn blame(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<BlameQuery>,
) -> ApiResult<Json<BlameResponse>> {
    let norm_path = normalize_repo_path(&query.path)?;
    let repo = get_existing_repo(&state, &owner, &name)?;
    let policy = repo.acl_snapshot()?;

    let Some(head_cs) =
        resolve_visible_changeset(repo.store.as_ref(), &policy, &principal, query.rev.as_deref())?
    else {
        return Err(ApiError::not_found(format!(
            "revision not found for blame of '{norm_path}'"
        )));
    };

    // Resolve the highest-priority authorized domain owning `norm_path` at `head_cs`.
    let filtered = policy.filter_domain_trees(&principal, &head_cs);
    let ordered = ordered_domain_entries(&filtered, &head_cs.visibility.primary_domain);
    let mut target_domain: Option<DomainId> = None;
    for (dom, tree_hash) in ordered.into_iter().rev() {
        let tree = repo.store.get_tree(tree_hash)?;
        if matches!(tree.entries.get(&norm_path), Some(EntryKind::File { .. })) {
            target_domain = Some(dom.clone());
            break;
        }
    }

    let Some(target_domain) = target_domain else {
        return Err(ApiError::not_found(format!(
            "path '{norm_path}' not found at revision {}",
            head_cs.id
        )));
    };

    // Query domain-partitioned PathHistoryIndex (accelerates blame by skipping untouched commits).
    let touching_commits: Vec<ObjectHash> = {
        let cached = {
            let derived = repo
                .derived
                .read()
                .map_err(|_| ApiError::internal("derived index rwlock poisoned"))?;
            derived
                .path_history
                .get_cached(head_cs.id, &norm_path, &target_domain)
        };
        if let Some(commits) = cached {
            commits
        } else {
            let mut derived = repo
                .derived
                .write()
                .map_err(|_| ApiError::internal("derived index rwlock poisoned"))?;
            let crate::derived::DerivedIndex {
                commit_graph,
                path_history,
                ..
            } = &mut *derived;
            path_history.history_for_path(
                repo.store.as_ref(),
                commit_graph,
                head_cs.id,
                &norm_path,
                &target_domain,
            )?
        }
    };

    #[derive(Clone)]
    struct LineAttr {
        changeset_id: String,
        change_id: String,
        author_name: String,
        author_email: String,
        timestamp: DateTime<Utc>,
        message: String,
    }

    let mut prev_text = String::new();
    let mut prev_attrs: Vec<LineAttr> = Vec::new();

    for cs_id in touching_commits {
        let cs = repo.store.get_changeset(cs_id)?;
        if !policy.can_read_changeset(&principal, &cs) {
            continue;
        }
        let blob_opt = if let Some(&tree_hash) = cs.domain_trees.get(&target_domain) {
            let tree = repo.store.get_tree(tree_hash)?;
            match tree.entries.get(&norm_path) {
                Some(EntryKind::File { blob_hash, .. }) => {
                    Some(repo.store.read_blob_bytes(*blob_hash)?)
                }
                _ => None,
            }
        } else {
            None
        };

        let Some(bytes) = blob_opt else {
            prev_text.clear();
            prev_attrs.clear();
            continue;
        };
        let curr_text = String::from_utf8_lossy(&bytes).into_owned();
        let curr_lines: Vec<&str> = curr_text.lines().collect();

        let cs_attr = LineAttr {
            changeset_id: cs.id.to_hex(),
            change_id: cs.change_id.to_string(),
            author_name: cs.author.name.clone(),
            author_email: cs.author.email.clone(),
            timestamp: cs.created_at,
            message: cs.description.clone(),
        };

        if prev_attrs.is_empty() {
            prev_attrs = vec![cs_attr; curr_lines.len()];
            prev_text = curr_text;
            continue;
        }

        let diff = TextDiff::from_lines(&prev_text, &curr_text);
        let mut next_attrs: Vec<LineAttr> = Vec::with_capacity(curr_lines.len());

        for op in diff.ops() {
            match *op {
                DiffOp::Equal {
                    old_index, len, ..
                } => {
                    for offset in 0..len {
                        let attr = prev_attrs
                            .get(old_index + offset)
                            .cloned()
                            .unwrap_or_else(|| cs_attr.clone());
                        next_attrs.push(attr);
                    }
                }
                DiffOp::Insert { new_len, .. } | DiffOp::Replace { new_len, .. } => {
                    for _ in 0..new_len {
                        next_attrs.push(cs_attr.clone());
                    }
                }
                DiffOp::Delete { .. } => {}
            }
        }

        prev_attrs = next_attrs;
        prev_text = curr_text;
    }

    let final_lines: Vec<BlameLine> = prev_text
        .lines()
        .enumerate()
        .map(|(idx, line)| {
            let attr = &prev_attrs[idx];
            BlameLine {
                line_number: idx + 1,
                content: line.to_string(),
                changeset_id: attr.changeset_id.clone(),
                change_id: attr.change_id.clone(),
                author_name: attr.author_name.clone(),
                author_email: attr.author_email.clone(),
                timestamp: attr.timestamp,
                message: attr.message.clone(),
            }
        })
        .collect();

    Ok(Json(BlameResponse {
        path: norm_path,
        rev: head_cs.id.to_hex(),
        lines: final_lines,
    }))
}

// ---------------------------------------------------------------------------
// ACL-Filtered Commit Log
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct LogQuery {
    #[serde(default)]
    pub rev: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub changeset_id: String,
    pub change_id: String,
    pub public_projection_hash: String,
    pub parents: Vec<String>,
    pub author_name: String,
    pub author_email: String,
    pub message: String,
    pub created_at: DateTime<Utc>,
    pub visibility_domain: String,
    pub domains: Vec<String>,
    pub has_conflicts: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogResponse {
    pub rev: Option<String>,
    pub commits: Vec<LogEntry>,
}

pub async fn log_history(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<LogQuery>,
) -> ApiResult<Json<LogResponse>> {
    let repo = get_existing_repo(&state, &owner, &name)?;
    let policy = repo.acl_snapshot()?;
    let limit = query.limit.unwrap_or(50).min(1000);

    let Some(start_hash) = resolve_raw_rev(repo.store.as_ref(), query.rev.as_deref())? else {
        return Ok(Json(LogResponse {
            rev: None,
            commits: Vec::new(),
        }));
    };

    let mut visited: HashSet<ObjectHash> = HashSet::new();
    let mut queue: VecDeque<ObjectHash> = VecDeque::new();
    let mut visible: Vec<ChangeSet> = Vec::new();
    queue.push_back(start_hash);

    while let Some(hash) = queue.pop_front() {
        if !visited.insert(hash) {
            continue;
        }
        let Ok(cs) = repo.store.get_changeset(hash) else {
            continue;
        };
        for &parent in &cs.parents {
            if !visited.contains(&parent) {
                queue.push_back(parent);
            }
        }
        if policy.can_read_changeset(&principal, &cs) {
            visible.push(cs);
        }
    }

    // Order newest first.
    visible.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.id.cmp(&a.id)));
    visible.truncate(limit);

    let visible_head = visible.first().map(|c| c.id.to_hex());
    let commits: Vec<LogEntry> = visible
        .into_iter()
        .map(|cs| {
            let filtered = policy.filter_domain_trees(&principal, &cs);
            let domains: Vec<String> = filtered.keys().map(ToString::to_string).collect();
            let visible_parents = visible_parent_hashes(repo.store.as_ref(), &policy, &principal, &cs);
            LogEntry {
                changeset_id: cs.id.to_hex(),
                change_id: cs.change_id.to_string(),
                public_projection_hash: cs.public_projection_hash.to_hex(),
                parents: visible_parents.into_iter().map(|h| h.to_hex()).collect(),
                author_name: cs.author.name,
                author_email: cs.author.email,
                message: cs.description,
                created_at: cs.created_at,
                visibility_domain: cs.visibility.primary_domain.to_string(),
                domains,
                has_conflicts: cs.has_conflicts,
            }
        })
        .collect();

    Ok(Json(LogResponse {
        rev: visible_head,
        commits,
    }))
}

// ---------------------------------------------------------------------------
// Durable `gitx why` Context Query (ACL-Filtered)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct WhyQuery {
    pub path: String,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub rev: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhyResponse {
    pub path: String,
    pub line: u32,
    pub rev: Option<String>,
    pub matches: Vec<WhyMatch>,
}

pub async fn why(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<WhyQuery>,
) -> ApiResult<Json<WhyResponse>> {
    let norm_path = normalize_repo_path(&query.path)?;
    let line = query.line.unwrap_or(1);

    let repo = get_existing_repo(&state, &owner, &name)?;
    let policy = repo.acl_snapshot()?;

    let Some(cs) =
        resolve_visible_changeset(repo.store.as_ref(), &policy, &principal, query.rev.as_deref())?
    else {
        return Ok(Json(WhyResponse {
            path: norm_path,
            line,
            rev: None,
            matches: Vec::new(),
        }));
    };

    let files = materialize_authorized_files(repo.store.as_ref(), &policy, &principal, &cs)?;
    let Some((_, bytes)) = files.get(&norm_path) else {
        // File does not exist in caller's authorized domains -> return empty matches (no leak).
        return Ok(Json(WhyResponse {
            path: norm_path,
            line,
            rev: Some(cs.id.to_hex()),
            matches: Vec::new(),
        }));
    };

    let content = String::from_utf8_lossy(bytes);
    let allowed_domains = effective_allowed_domains(repo.store.as_ref(), &policy, &principal);
    let matches = repo
        .context
        .why(&norm_path, line, &content, &allowed_domains)?;

    Ok(Json(WhyResponse {
        path: norm_path,
        line,
        rev: Some(cs.id.to_hex()),
        matches,
    }))
}

// ---------------------------------------------------------------------------
// Embargo Publication
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PublishEmbargoRequest {
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishEmbargoResponse {
    pub advisory: String,
    pub target: String,
    pub changeset_id: String,
    pub land_seq: u64,
    pub promoted_paths: Vec<String>,
}

pub async fn publish_embargo(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name, advisory)): Path<(String, String, String)>,
    body: Bytes,
) -> ApiResult<Json<PublishEmbargoResponse>> {
    let req: PublishEmbargoRequest = if body.is_empty() {
        PublishEmbargoRequest::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| ApiError::bad_request(format!("invalid publish JSON: {e}")))?
    };

    let repo = get_existing_repo(&state, &owner, &name)?;
    let policy = repo.acl_snapshot()?;
    let embargo_domain = DomainId::embargo(&advisory)?;

    // Locate the latest active embargo ChangeSet for this advisory.
    let all_cs = repo.store.list_changesets()?;
    let embargo_cs = all_cs
        .into_iter()
        .rev()
        .find(|cs| {
            matches!(
                &cs.visibility.embargo,
                Some(EmbargoState::Active { advisory_id, .. }) if advisory_id == &advisory
            )
        })
        .ok_or_else(|| {
            ApiError::not_found(format!(
                "no active embargo found for advisory '{advisory}'"
            ))
        })?;

    if !can_publish_embargo(&policy, &principal, &embargo_cs) {
        return Err(ApiError::forbidden(format!(
            "principal '{}' is not authorized to publish embargo '{advisory}'",
            principal.id
        )));
    }

    let embargo_tree = match embargo_cs.domain_trees.get(&embargo_domain) {
        Some(&tree_hash) => repo.store.get_tree(tree_hash)?,
        None => DomainTree::new(embargo_domain.clone()),
    };

    let target = req.target.unwrap_or_else(|| "master".to_string());
    let current_head = repo.store.get_bookmark(&target)?;

    let mut domain_trees: BTreeMap<DomainId, DomainTree> = BTreeMap::new();
    let base_source_cs = current_head
        .map(|h| repo.store.get_changeset(h))
        .transpose()?
        .unwrap_or_else(|| embargo_cs.clone());

    for (dom, &tree_hash) in &base_source_cs.domain_trees {
        if dom == &embargo_domain {
            continue;
        }
        domain_trees.insert(dom.clone(), repo.store.get_tree(tree_hash)?);
    }

    let mut promoted_paths: Vec<String> = Vec::new();
    for (path, entry) in &embargo_tree.entries {
        let dest_domain = policy.domain_for_path(path);
        if dest_domain.is_public()
            && let EntryKind::File { blob_hash, .. } = entry
        {
            let bytes = repo.store.read_blob_bytes(*blob_hash)?;
            let findings = scan_content(path, &bytes);
            if !findings.is_empty() {
                return Err(ApiError::secret_rejected(
                    format!(
                        "cannot publish embargo '{advisory}': secret detected in '{path}'"
                    ),
                    findings,
                ));
            }
        }
        let tree = domain_trees
            .entry(dest_domain.clone())
            .or_insert_with(|| DomainTree::new(dest_domain));
        tree.insert(path.clone(), entry.clone());
        promoted_paths.push(path.clone());
    }

    let mut domain_tree_hashes: BTreeMap<DomainId, ObjectHash> = BTreeMap::new();
    for (dom, tree) in &domain_trees {
        let hash = repo.store.put_tree(tree)?;
        domain_tree_hashes.insert(dom.clone(), hash);
    }

    let mut parents = Vec::new();
    if let Some(h) = current_head {
        parents.push(h);
    }
    if !parents.contains(&embargo_cs.id) {
        parents.push(embargo_cs.id);
    }
    let public_parents = compute_public_parents(repo.store.as_ref(), &parents);

    let publisher_identity = Identity {
        name: principal.id.clone(),
        email: format!("{}@gitx.local", principal.id),
        key_fingerprint: principal.fingerprint.clone(),
    };

    let description = req.message.unwrap_or_else(|| {
        format!(
            "Publish advisory {}: {}",
            advisory, embargo_cs.description
        )
    });

    let published_cs = ChangeSetBuilder::new(embargo_cs.author.clone())
        .change_id(embargo_cs.change_id)
        .previous_revision(Some(embargo_cs.id))
        .parents(parents)
        .public_parents(public_parents)
        .domain_trees(domain_tree_hashes)
        .committer(Actor::Human(publisher_identity))
        .visibility(VisibilityPolicy {
            primary_domain: DomainId::public(),
            reveal_on_land: false,
            embargo: Some(EmbargoState::Published {
                advisory_id: advisory.clone(),
                published_at: Utc::now(),
            }),
        })
        .description(description)
        .build();

    repo.store.put_changeset(&published_cs)?;

    let land_rec = repo.store.record_land(
        &target,
        current_head,
        published_cs.id,
        vec![published_cs.change_id],
    )?;

    // Promote context records from the embargo domain into public visibility for disclosed paths.
    let embargo_records = repo
        .context
        .records_for_change(embargo_cs.change_id, std::slice::from_ref(&embargo_domain))?;
    for rec in embargo_records {
        let public_anchors: Vec<CodeAnchor> = rec
            .anchors
            .into_iter()
            .filter(|a| policy.domain_for_path(&a.path).is_public())
            .collect();
        if !public_anchors.is_empty() {
            let promoted_rec = ContextRecord {
                id: ContextId::new(),
                change_id: published_cs.change_id,
                revision: published_cs.id,
                visibility: DomainId::public(),
                author: rec.author,
                kind: rec.kind,
                anchors: public_anchors,
                created_at: Utc::now(),
            };
            repo.context.add_record(&promoted_rec)?;
        }
    }

    Ok(Json(PublishEmbargoResponse {
        advisory,
        target,
        changeset_id: published_cs.id.to_hex(),
        land_seq: land_rec.land_seq,
        promoted_paths,
    }))
}

// ---------------------------------------------------------------------------
// Derived Data Engine Stats (ACL-Filtered)
// ---------------------------------------------------------------------------

/// `GET /v1/repos/{owner}/{name}/derived/stats`
pub async fn derived_stats(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
) -> ApiResult<Json<DerivedStats>> {
    let repo = get_existing_repo(&state, &owner, &name)?;
    let policy = repo.acl_snapshot()?;
    let allowed: BTreeSet<DomainId> =
        effective_allowed_domains(repo.store.as_ref(), &policy, &principal)
            .into_iter()
            .collect();
    let derived = repo
        .derived
        .read()
        .map_err(|_| ApiError::internal("derived index rwlock poisoned"))?;
    Ok(Json(derived.stats_for_domains(&allowed)))
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

pub(crate) struct AuthorizedBlob {
    pub path: String,
    pub domain: String,
    pub blob_hash: String,
    pub size: u64,
    pub content: Vec<u8>,
}

/// Strictly ACL-filtered single-blob lookup used by the gRPC `ReadBlob` RPC.
///
/// Only files reachable inside the caller's authorized visibility domains for the resolved
/// visible ChangeSet can be read. Unauthorized paths and hashes return `NotFound` to prevent
/// existence/ciphertext leaks.
pub(crate) fn read_blob_authorized(
    state: &AppState,
    principal: &Principal,
    owner: &str,
    name: &str,
    rev: Option<&str>,
    path: &str,
    blob_hash_filter: Option<&str>,
) -> ApiResult<AuthorizedBlob> {
    let trimmed_path = path.trim();
    let trimmed_hash = blob_hash_filter.map(str::trim).filter(|s| !s.is_empty());

    if trimmed_path.is_empty() && trimmed_hash.is_none() {
        return Err(ApiError::bad_request(
            "read_blob requires either 'path' or 'blob_hash'",
        ));
    }

    let repo = get_existing_repo(state, owner, name)?;
    let policy = repo.acl_snapshot()?;

    let Some(cs) = resolve_visible_changeset(repo.store.as_ref(), &policy, principal, rev)? else {
        return Err(ApiError::not_found(format!(
            "revision not found in repository '{owner}/{name}'"
        )));
    };

    let filtered = policy.filter_domain_trees(principal, &cs);
    let ordered = ordered_domain_entries(&filtered, &cs.visibility.primary_domain);

    if !trimmed_path.is_empty() {
        let norm_path = normalize_repo_path(trimmed_path)?;
        let expected_hash = trimmed_hash.map(ObjectHash::from_str).transpose()?;

        for (dom, tree_hash) in ordered.into_iter().rev() {
            let tree = repo.store.get_tree(tree_hash)?;
            if let Some(EntryKind::File {
                blob_hash, size, ..
            }) = tree.entries.get(&norm_path)
            {
                if expected_hash.is_some_and(|exp| exp != *blob_hash) {
                    continue;
                }
                let content = repo.store.read_blob_bytes(*blob_hash)?;
                return Ok(AuthorizedBlob {
                    path: norm_path,
                    domain: dom.to_string(),
                    blob_hash: blob_hash.to_hex(),
                    size: *size,
                    content,
                });
            }
        }

        return Err(ApiError::not_found(format!(
            "path '{norm_path}' not found at revision {}",
            cs.id
        )));
    }

    let target_hash = ObjectHash::from_str(trimmed_hash.expect("checked non-empty"))?;
    for (dom, tree_hash) in ordered.into_iter().rev() {
        let tree = repo.store.get_tree(tree_hash)?;
        for (entry_path, entry) in &tree.entries {
            if let EntryKind::File {
                blob_hash, size, ..
            } = entry
                && *blob_hash == target_hash
            {
                let content = repo.store.read_blob_bytes(*blob_hash)?;
                return Ok(AuthorizedBlob {
                    path: entry_path.clone(),
                    domain: dom.to_string(),
                    blob_hash: blob_hash.to_hex(),
                    size: *size,
                    content,
                });
            }
        }
    }

    Err(ApiError::not_found(format!(
        "blob '{target_hash}' not found at revision {}",
        cs.id
    )))
}

pub(crate) fn get_existing_repo(
    state: &AppState,
    owner: &str,
    name: &str,
) -> ApiResult<Arc<RepoHandle>> {
    state
        .get_repo(owner, name)?
        .ok_or_else(|| ApiError::not_found(format!("repository '{owner}/{name}' not found")))
}

fn normalize_repo_path(raw: &str) -> ApiResult<String> {
    let replaced = raw.replace('\\', "/");
    let trimmed = replaced.trim_start_matches("./").trim_start_matches('/');
    if trimmed.is_empty()
        || trimmed.contains('\0')
        || trimmed.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(ApiError::bad_request(format!(
            "invalid repository file path '{raw}'"
        )));
    }
    Ok(trimmed.to_string())
}

fn decode_file_value(raw: &str, global_base64: bool) -> ApiResult<Vec<u8>> {
    if global_base64 {
        return BASE64_STANDARD
            .decode(raw)
            .map_err(|e| ApiError::bad_request(format!("invalid base64 file content: {e}")));
    }
    if let Some(b64) = raw.strip_prefix("base64:") {
        return BASE64_STANDARD
            .decode(b64)
            .map_err(|e| ApiError::bad_request(format!("invalid base64 file content: {e}")));
    }
    Ok(raw.as_bytes().to_vec())
}

fn parse_team_or_domain(raw: &str) -> ApiResult<DomainId> {
    let trimmed = raw.trim();
    if trimmed.contains(':') {
        Ok(DomainId::new(trimmed)?)
    } else {
        Ok(DomainId::team(trimmed)?)
    }
}

fn resolve_hash_or_bookmark(store: &dyn ObjectStore, spec: &str) -> ApiResult<ObjectHash> {
    if let Some(h) = store.get_bookmark(spec)? {
        return Ok(h);
    }
    if let Ok(h) = ObjectHash::from_str(spec) {
        let _ = store.get_changeset(h)?;
        return Ok(h);
    }
    let all = store.list_changesets()?;
    let matches: Vec<ObjectHash> = all
        .iter()
        .filter(|cs| cs.id.to_hex().starts_with(spec) || cs.change_id.to_string() == spec)
        .map(|cs| cs.id)
        .collect();
    match matches.as_slice() {
        [only] => Ok(*only),
        [] => Err(ApiError::not_found(format!("revision '{spec}' not found"))),
        _ => Err(ApiError::bad_request(format!(
            "ambiguous revision prefix '{spec}'"
        ))),
    }
}

fn resolve_raw_rev(store: &dyn ObjectStore, rev: Option<&str>) -> ApiResult<Option<ObjectHash>> {
    let spec = rev.map(str::trim).filter(|s| !s.is_empty());
    match spec {
        None => Ok(store.get_bookmark("master")?),
        Some(s) => {
            if let Some(h) = store.get_bookmark(s)? {
                return Ok(Some(h));
            }
            if let Ok(h) = ObjectHash::from_str(s) {
                match store.get_changeset(h) {
                    Ok(_) => return Ok(Some(h)),
                    Err(_) => return Ok(None),
                }
            }
            let all = store.list_changesets()?;
            let mut found = None;
            for cs in all {
                if cs.id.to_hex().starts_with(s) || cs.change_id.to_string() == s {
                    found = Some(cs.id);
                    break;
                }
            }
            Ok(found)
        }
    }
}

/// Resolve `rev` (defaulting to `master`) and walk back to the nearest ChangeSet
/// visible to `principal` so unauthorized private/embargoed tips never leak.
fn resolve_visible_changeset(
    store: &dyn ObjectStore,
    policy: &AclPolicy,
    principal: &Principal,
    rev: Option<&str>,
) -> ApiResult<Option<ChangeSet>> {
    let Some(start) = resolve_raw_rev(store, rev)? else {
        return Ok(None);
    };
    nearest_visible_changeset(store, policy, principal, start)
}

fn nearest_visible_changeset(
    store: &dyn ObjectStore,
    policy: &AclPolicy,
    principal: &Principal,
    start: ObjectHash,
) -> ApiResult<Option<ChangeSet>> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(start);

    while let Some(hash) = queue.pop_front() {
        if !visited.insert(hash) {
            continue;
        }
        let Ok(cs) = store.get_changeset(hash) else {
            continue;
        };
        if policy.can_read_changeset(principal, &cs) {
            return Ok(Some(cs));
        }
        for &parent in &cs.parents {
            if !visited.contains(&parent) {
                queue.push_back(parent);
            }
        }
    }
    Ok(None)
}

fn first_visible_parent(
    store: &dyn ObjectStore,
    policy: &AclPolicy,
    principal: &Principal,
    cs: &ChangeSet,
) -> ApiResult<Option<ChangeSet>> {
    for &parent in &cs.parents {
        if let Some(vis) = nearest_visible_changeset(store, policy, principal, parent)? {
            return Ok(Some(vis));
        }
    }
    Ok(None)
}

fn visible_parent_hashes(
    store: &dyn ObjectStore,
    policy: &AclPolicy,
    principal: &Principal,
    cs: &ChangeSet,
) -> Vec<ObjectHash> {
    let mut out = Vec::new();
    for &parent in &cs.parents {
        if let Ok(Some(vis)) = nearest_visible_changeset(store, policy, principal, parent)
            && !out.contains(&vis.id)
        {
            out.push(vis.id);
        }
    }
    out
}

fn ordered_domain_entries<'a>(
    filtered: &'a BTreeMap<DomainId, ObjectHash>,
    primary_domain: &DomainId,
) -> Vec<(&'a DomainId, ObjectHash)> {
    let mut entries: Vec<(&DomainId, ObjectHash)> =
        filtered.iter().map(|(d, &h)| (d, h)).collect();
    entries.sort_by(|(a, _), (b, _)| {
        let rank = |d: &DomainId| -> u8 {
            if d.is_public() {
                0
            } else if d == primary_domain && d.is_embargo() {
                2
            } else {
                1
            }
        };
        rank(a).cmp(&rank(b)).then_with(|| a.cmp(b))
    });
    entries
}

/// Materialize all plaintext files from `cs` that `principal` is authorized to read.
fn materialize_authorized_files(
    store: &dyn ObjectStore,
    policy: &AclPolicy,
    principal: &Principal,
    cs: &ChangeSet,
) -> ApiResult<BTreeMap<String, (DomainId, Vec<u8>)>> {
    let filtered = policy.filter_domain_trees(principal, cs);
    let ordered = ordered_domain_entries(&filtered, &cs.visibility.primary_domain);
    let mut out: BTreeMap<String, (DomainId, Vec<u8>)> = BTreeMap::new();

    for (dom, tree_hash) in ordered {
        let tree = store.get_tree(tree_hash)?;
        for (path, entry) in &tree.entries {
            if let EntryKind::File { blob_hash, .. } = entry {
                let bytes = store.read_blob_bytes(*blob_hash)?;
                out.insert(path.clone(), (dom.clone(), bytes));
            }
        }
    }
    Ok(out)
}

pub(crate) fn compute_public_parents(
    store: &dyn ObjectStore,
    parents: &[ObjectHash],
) -> Vec<ObjectHash> {
    let mut out = Vec::new();
    for &p in parents {
        if let Ok(cs) = store.get_changeset(p) {
            if cs.visibility.primary_domain.is_public() && cs.visibility.embargo.is_none() {
                if !out.contains(&cs.public_projection_hash) {
                    out.push(cs.public_projection_hash);
                }
            } else {
                for &pp in &cs.public_parents {
                    if !out.contains(&pp) {
                        out.push(pp);
                    }
                }
            }
        }
    }
    out
}

pub(crate) fn load_domain_tree_or_empty(
    store: &dyn ObjectStore,
    cs: Option<&ChangeSet>,
    domain: &DomainId,
) -> ApiResult<DomainTree> {
    if let Some(c) = cs
        && let Some(&tree_hash) = c.domain_trees.get(domain)
    {
        return Ok(store.get_tree(tree_hash)?);
    }
    Ok(DomainTree::new(domain.clone()))
}
