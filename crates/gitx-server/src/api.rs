use crate::auth::{
    AuthenticatedPrincipal, can_administer_acl, can_publish_embargo, can_write_domain_effective,
    effective_allowed_domains,
};
use crate::derived::{DerivedStats, IndexedSymbol};
use crate::error::{ApiError, ApiResult};
use crate::outbox::{OutboxEvent, spawn_webhook_dispatch};
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
use gitx_crypto::{AclPolicy, Principal, SecretEnvelope, scan_content};
use gitx_merge::{merge_domain_trees, unified_diff};
use gitx_store::ObjectStore;
use serde::{Deserialize, Serialize};
use serde_json::json;
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
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<Json<CreateRepoResponse>> {
    if principal.is_anonymous {
        return Err(ApiError::forbidden(
            "anonymous callers are not permitted to create or configure repositories",
        ));
    }

    let req: CreateRepoRequest = if body.is_empty() {
        CreateRepoRequest::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| ApiError::bad_request(format!("invalid create repo JSON: {e}")))?
    };

    let (repo, existed) = state.get_or_create_repo_with_status(&owner, &name)?;
    if let Some(acl_text) = req.acl {
        if existed || repo.has_default_acl() {
            let existing_policy = repo.acl_snapshot()?;
            let unchanged = repo
                .current_acl_text()
                .is_some_and(|cur| cur.trim() == acl_text.trim());
            if !unchanged && !can_administer_acl(&existing_policy, &principal) {
                return Err(ApiError::forbidden(format!(
                    "principal '{}' is not authorized to modify .gitxacl on '{owner}/{name}'",
                    principal.id
                )));
            }
        }
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
    AuthenticatedPrincipal(_principal): AuthenticatedPrincipal,
) -> ApiResult<Json<ListReposResponse>> {
    let repos = state.list_repos(None)?;
    Ok(Json(ListReposResponse { repos }))
}

pub async fn list_owner_repos(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(_principal): AuthenticatedPrincipal,
    Path(owner): Path<String>,
) -> ApiResult<Json<ListReposResponse>> {
    let repos = state.list_repos(Some(&owner))?;
    Ok(Json(ListReposResponse { repos }))
}

pub async fn list_repo_scoped_repos(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(_principal): AuthenticatedPrincipal,
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
    /// Optional end-to-end encrypted secret envelopes (`domain -> path -> SecretEnvelope JSON`).
    /// The server validates envelope structure and domain ACLs without ever seeing plaintext.
    #[serde(default)]
    pub secret_envelopes: BTreeMap<String, BTreeMap<String, String>>,
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
    // Push-to-create: reject anonymous repository creation or commits before touching disk.
    if principal.is_anonymous {
        return Err(ApiError::forbidden(
            "anonymous callers are not permitted to commit changes",
        ));
    }

    let (repo, existed) = state.get_or_create_repo_with_status(&owner, &name)?;

    if req.files.is_empty() && req.delete_files.is_empty() && req.secret_envelopes.is_empty() {
        return Err(ApiError::bad_request(
            "commit must include at least one file, secret envelope, or deletion",
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

    // Always authorize against the EXISTING repository ACL policy — never let a submitted
    // `.gitxacl` authorize its own commit.
    let policy = repo.acl_snapshot()?;
    let current_acl_text = repo.current_acl_text();
    let new_acl_text = if let Some(acl_bytes) = decoded_files.get(".gitxacl") {
        let text = std::str::from_utf8(acl_bytes)
            .map_err(|e| ApiError::bad_request(format!(".gitxacl must be valid UTF-8: {e}")))?;
        // Validate syntax upfront without replacing `policy` for this request's auth checks.
        let _ = AclPolicy::parse(text)?;

        let unchanged = current_acl_text
            .as_deref()
            .is_some_and(|cur| cur.trim() == text.trim());
        let is_initial_unconfigured_repo =
            !existed && !repo.has_default_acl() && repo.store.get_bookmark("master")?.is_none();
        if !unchanged && !is_initial_unconfigured_repo && !can_administer_acl(&policy, &principal) {
            return Err(ApiError::forbidden(format!(
                "principal '{}' is not authorized to modify .gitxacl",
                principal.id
            )));
        }
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

    // Prevent advisory-ID hijacking / decoy attachment: if this embargo advisory already has a
    // live (unreverted, landed) publication, reject further embargo commits (409), and require
    // admin or existing-advisory publish permission before attaching commits to an active advisory (403).
    if let Some(ref advisory) = req.embargo_advisory {
        if repo.is_advisory_published(advisory)? {
            return Err(ApiError::conflict(format!(
                "embargo advisory '{advisory}' has already been published"
            )));
        }
        let is_admin_caller = principal.roles.iter().any(|r| r == "admin");
        let existing_cs = repo.store.list_changesets()?;
        for cs in &existing_cs {
            if let Some(EmbargoState::Active { advisory_id, .. }) = &cs.visibility.embargo
                && advisory_id == advisory
                && !is_admin_caller
                && !can_publish_embargo(&policy, &principal, cs)
            {
                return Err(ApiError::forbidden(format!(
                    "principal '{}' is not authorized to attach commits to existing embargo advisory '{advisory}'",
                    principal.id
                )));
            }
        }
    }

    // Resolve target bookmark and parent changeset under a per-target RwLock guard BEFORE
    // checking overwrites so commits cannot race with an in-flight `publish_embargo` / `post_land_cmd`.
    let target_name = req.target.clone().unwrap_or_else(|| "master".to_string());
    let should_update_target = req.update_target.unwrap_or(true);
    let _target_write_guard = if should_update_target {
        Some(repo.try_write_target(&target_name)?)
    } else {
        None
    };
    let _target_read_guard = if !should_update_target {
        Some(repo.try_read_target(&target_name)?)
    } else {
        None
    };
    let current_target_head = repo.store.get_bookmark(&target_name)?;
    let _master_fallback_read_guard =
        if req.parent.is_none() && current_target_head.is_none() && target_name != "master" {
            Some(repo.try_read_target("master")?)
        } else {
            None
        };
    if let Some(h) = current_target_head
        && repo.is_head_pending_verification(h)
    {
        return Err(ApiError::conflict(format!(
            "target '{target_name}' is currently undergoing post-land verification; retry shortly"
        )));
    }
    let parent_hash = if let Some(ref parent_str) = req.parent {
        Some(resolve_hash_or_bookmark_visible(
            &repo, &policy, &principal, parent_str,
        )?)
    } else if let Some(h) = current_target_head {
        Some(h)
    } else if target_name != "master" {
        repo.store.get_bookmark("master")?
    } else {
        None
    };

    if let Some(h) = parent_hash
        && repo.is_head_pending_verification(h)
    {
        return Err(ApiError::conflict(
            "parent revision is currently undergoing post-land verification; retry shortly",
        ));
    }

    let parent_cs = parent_hash
        .map(|h| repo.store.get_changeset(h))
        .transpose()?;

    if let Some(ref p_cs) = parent_cs
        && repo.is_unlive_published_changeset(p_cs)?
    {
        return Err(ApiError::conflict(
            "cannot base a commit on an unverified, unlanded, or reverted embargo publication",
        ));
    }

    if req.parent.is_some()
        && let Some(ref p_cs) = parent_cs
        && !repo.can_read_changeset_live(&policy, &principal, p_cs)
    {
        return Err(ApiError::forbidden(format!(
            "principal '{}' cannot base a commit on unreadable parent {}",
            principal.id, p_cs.id
        )));
    }

    // Start from parent's domain trees (preserving unaffected domains).
    let mut domain_trees: BTreeMap<DomainId, DomainTree> = BTreeMap::new();
    if let Some(ref p_cs) = parent_cs {
        for (dom, &tree_hash) in &p_cs.domain_trees {
            let tree = repo.store.get_tree(tree_hash)?;
            domain_trees.insert(dom.clone(), tree);
        }
    }

    let is_admin = principal.roles.iter().any(|r| r == "admin");

    // Classify every submitted file and enforce zero-trust secret scanning + write ACLs.
    let mut files_by_domain: BTreeMap<DomainId, Vec<(String, Vec<u8>)>> = BTreeMap::new();
    let mut touched_domains: BTreeSet<DomainId> = BTreeSet::new();

    for (path, bytes) in &decoded_files {
        let acl_routed = policy.domain_for_path(path);
        let target_domain = if let Some(ref emb_dom) = embargo_domain {
            emb_dom.clone()
        } else if let Some(ref vis_dom) = explicit_visibility_domain {
            if vis_dom.is_public() {
                // Never allow caller to downgrade a non-public ACL-protected path into `public`.
                if !acl_routed.is_public() {
                    return Err(ApiError::forbidden(format!(
                        "path '{path}' is routed to protected domain '{acl_routed}' and cannot be forced into 'public'"
                    )));
                }
                DomainId::public()
            } else if acl_routed.is_secret() && !vis_dom.is_secret() {
                acl_routed
            } else {
                vis_dom.clone()
            }
        } else {
            acl_routed
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

        // Unconfigured `secret:*` domains act as write-only dropboxes for new secrets;
        // overwriting or shadowing an existing secret in ANY secret tree requires explicit
        // write permission on that secret domain or the admin role.
        if embargo_domain.is_none() {
            for tree in domain_trees.values() {
                if tree.domain.is_secret()
                    && tree.entries.contains_key(path)
                    && !is_admin
                    && !policy.can_write_domain(&principal, &tree.domain)
                {
                    return Err(ApiError::forbidden(format!(
                        "principal '{}' is not authorized to overwrite or shadow existing secret '{}' in '{}'",
                        principal.id, path, tree.domain
                    )));
                }
            }
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
        if norm == ".gitxacl" && !can_administer_acl(&policy, &principal) {
            return Err(ApiError::forbidden(format!(
                "principal '{}' is not authorized to delete .gitxacl",
                principal.id
            )));
        }
        let acl_routed = policy.domain_for_path(&norm);
        let dom = if let Some(ref emb_dom) = embargo_domain {
            emb_dom.clone()
        } else if let Some(ref vis_dom) = explicit_visibility_domain {
            if vis_dom.is_public() && !acl_routed.is_public() {
                return Err(ApiError::forbidden(format!(
                    "path '{norm}' is routed to protected domain '{acl_routed}' and cannot be deleted via 'public'"
                )));
            }
            if acl_routed.is_secret() && !vis_dom.is_secret() {
                acl_routed
            } else {
                vis_dom.clone()
            }
        } else {
            acl_routed
        };
        if !can_write_domain_effective(&policy, &principal, &dom, &embargo_allowed_domains) {
            return Err(ApiError::forbidden(format!(
                "principal '{}' is not authorized to delete '{}' in domain '{}'",
                principal.id, norm, dom
            )));
        }
        if dom.is_secret() && !is_admin && !policy.can_write_domain(&principal, &dom) {
            return Err(ApiError::forbidden(format!(
                "principal '{}' is not authorized to delete secret '{}' in '{}'",
                principal.id, norm, dom
            )));
        }
        if embargo_domain.is_none() {
            for tree in domain_trees.values() {
                if tree.entries.contains_key(&norm)
                    && tree.domain.is_secret()
                    && !is_admin
                    && !policy.can_write_domain(&principal, &tree.domain)
                {
                    return Err(ApiError::forbidden(format!(
                        "principal '{}' is not authorized to delete existing secret '{}' in '{}'",
                        principal.id, norm, tree.domain
                    )));
                }
            }
        }
        touched_domains.insert(dom);
        delete_paths.push(norm);
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
                    && !(tree.domain.is_secret()
                        && !is_admin
                        && !policy.can_write_domain(&principal, &tree.domain))
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

    // Validate and store end-to-end encrypted secret envelopes (`secret:*` domains only).
    for (dom_raw, entries) in &req.secret_envelopes {
        let dom = DomainId::new(dom_raw)?;
        if !dom.is_secret() {
            return Err(ApiError::bad_request(format!(
                "secret_envelopes domain '{dom}' must start with 'secret:'"
            )));
        }
        if !can_write_domain_effective(&policy, &principal, &dom, &embargo_allowed_domains) {
            return Err(ApiError::forbidden(format!(
                "principal '{}' is not authorized to write encrypted secrets to domain '{}'",
                principal.id, dom
            )));
        }
        let mut validated_envelopes: Vec<(String, SecretEnvelope)> =
            Vec::with_capacity(entries.len());
        for (raw_path, env_json) in entries {
            let norm_path = normalize_repo_path(raw_path)?;
            for existing_tree in domain_trees.values() {
                if existing_tree.domain.is_secret()
                    && existing_tree.entries.contains_key(&norm_path)
                    && !is_admin
                    && !policy.can_write_domain(&principal, &existing_tree.domain)
                {
                    return Err(ApiError::forbidden(format!(
                        "principal '{}' is not authorized to overwrite or shadow existing secret '{}' in '{}'",
                        principal.id, norm_path, existing_tree.domain
                    )));
                }
            }
            let envelope: SecretEnvelope = serde_json::from_str(env_json).map_err(|e| {
                ApiError::bad_request(format!(
                    "invalid SecretEnvelope JSON for '{norm_path}' in '{dom}': {e}"
                ))
            })?;
            if envelope.domain != dom {
                return Err(ApiError::bad_request(format!(
                    "SecretEnvelope domain '{}' does not match target domain '{}'",
                    envelope.domain, dom
                )));
            }
            validated_envelopes.push((norm_path, envelope));
        }
        let tree = domain_trees
            .entry(dom.clone())
            .or_insert_with(|| DomainTree::new(dom.clone()));
        for (norm_path, envelope) in validated_envelopes {
            let env_bytes = serde_json::to_vec(&envelope)
                .map_err(|e| ApiError::internal(format!("failed to encode SecretEnvelope: {e}")))?;
            let env_hash = envelope.hash();
            repo.store.put_raw_object(env_hash, &env_bytes)?;
            tree.insert(
                norm_path,
                EntryKind::EncryptedSecret {
                    envelope_hash: env_hash,
                    key_epoch: envelope.key_epoch,
                    mode: FileMode::Regular,
                },
            );
        }
        touched_domains.insert(dom);
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

    let updated_target = if should_update_target {
        // Prevent non-fast-forward bookmark rewinds or silent concurrent overwrites:
        // if the target bookmark already exists, require that this commit's parent is the
        // current target head and update atomically via CAS.
        if let Some(existing_head) = current_target_head
            && parent_hash != Some(existing_head)
        {
            return Err(ApiError::conflict(format!(
                "cannot fast-forward target '{target_name}' from parent {parent_hash:?} while current head is {existing_head}; commit with update_target=false and land instead"
            )));
        }
        repo.store
            .cas_bookmark(&target_name, current_target_head, cs.id)?;
        if target_name == "master" {
            if let Some(ref acl_text) = new_acl_text {
                repo.update_acl_from_text(acl_text)?;
            } else if delete_paths.iter().any(|p| p == ".gitxacl") {
                repo.reload_acl_from_store()?;
            }
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

    if !repo.can_read_changeset_live(&policy, &principal, &incoming_cs) {
        return Err(ApiError::forbidden(format!(
            "principal '{}' cannot access changeset {}",
            principal.id, incoming_hash
        )));
    }
    if repo.is_head_pending_verification(incoming_hash)
        || repo.is_unlive_published_changeset(&incoming_cs)?
    {
        return Err(ApiError::conflict(
            "cannot land an unverified, unlanded, or reverted embargo publication",
        ));
    }

    let incoming_parent_cs = incoming_cs
        .parents
        .first()
        .copied()
        .map(|h| repo.store.get_changeset(h))
        .transpose()?;
    verify_changeset_write_permissions(
        repo.store.as_ref(),
        &policy,
        &principal,
        &incoming_cs,
        incoming_parent_cs.as_ref(),
    )?;

    let _target_write_guard = repo.try_write_target(&req.target)?;
    let current_head = repo.store.get_bookmark(&req.target)?;
    if let Some(h) = current_head
        && repo.is_head_pending_verification(h)
    {
        return Err(ApiError::conflict(format!(
            "target '{}' is currently undergoing post-land verification; retry shortly",
            req.target
        )));
    }
    let current_head_cs = current_head
        .map(|h| repo.store.get_changeset(h))
        .transpose()?;
    if let Some(ref cur_cs) = current_head_cs
        && repo.is_unlive_published_changeset(cur_cs)?
    {
        return Err(ApiError::conflict(format!(
            "target '{}' points to an unverified or reverted embargo publication",
            req.target
        )));
    }

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
            let base_cs = lca_hash.map(|h| repo.store.get_changeset(h)).transpose()?;

            let mut all_domains: BTreeSet<DomainId> = BTreeSet::new();
            if let Some(ref b) = base_cs {
                all_domains.extend(b.domain_trees.keys().cloned());
            }
            all_domains.extend(target_cs.domain_trees.keys().cloned());
            all_domains.extend(incoming_cs.domain_trees.keys().cloned());

            let mut merged_domain_trees: BTreeMap<DomainId, ObjectHash> = BTreeMap::new();
            let mut all_conflicts: Vec<String> = Vec::new();

            for dom in all_domains {
                let base_tree =
                    load_domain_tree_or_empty(repo.store.as_ref(), base_cs.as_ref(), &dom)?;
                let ours_tree =
                    load_domain_tree_or_empty(repo.store.as_ref(), Some(&target_cs), &dom)?;
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

    let final_cs = repo.store.get_changeset(final_head)?;
    // Verify write permissions for the net delta actually applied to the target bookmark
    // (closing stacked-parent bypasses where an unlanded/reverted ancestor modified restricted
    // domains or secrets relative to `current_head_cs`).
    verify_changeset_write_permissions(
        repo.store.as_ref(),
        &policy,
        &principal,
        &final_cs,
        current_head_cs.as_ref(),
    )?;
    let master_acl_changed = req.target == "master"
        && acl_file_changed(repo.store.as_ref(), current_head_cs.as_ref(), &final_cs)?;
    if master_acl_changed && !can_administer_acl(&policy, &principal) {
        return Err(ApiError::forbidden(format!(
            "principal '{}' is not authorized to modify .gitxacl on 'master'",
            principal.id
        )));
    }

    let pending_guard = repo.track_pending_verification(final_head);

    let record = repo.store.record_land(
        &req.target,
        current_head,
        final_head,
        vec![incoming_cs.change_id],
    )?;

    // Run optional post-land verification BEFORE reloading `.gitxacl` or recording `"land"` so an
    // unverified `.gitxacl` is never applied mid-hook and an API-configured `<root_dir>/.gitxacl`
    // is never wiped on auto-revert.
    if let Err(reason) = state
        .run_post_land_hook_async(
            format!("{owner}/{name}"),
            record.target.clone(),
            record.land_seq,
            record.new_head,
        )
        .await
    {
        match repo.store.revert_land(record.land_seq) {
            Ok(revert_rec) => {
                let rev_payload = json!({
                    "event": "auto_revert",
                    "repo": format!("{owner}/{name}"),
                    "target": record.target,
                    "reverted_land_seq": record.land_seq,
                    "revert_land_seq": revert_rec.land_seq,
                    "restored_head": revert_rec.new_head.to_hex(),
                    "reason": reason,
                });
                let ev = repo.outbox.record_event(
                    "auto_revert",
                    &record.target,
                    revert_rec.land_seq,
                    revert_rec.previous_head,
                    revert_rec.new_head,
                    &rev_payload,
                )?;
                drop(pending_guard);
                spawn_webhook_dispatch(
                    Arc::clone(&repo.outbox),
                    state.config.webhook_urls.clone(),
                    ev,
                );
                return Err(ApiError::conflict(format!(
                    "land_seq {} auto-reverted: {reason}",
                    record.land_seq
                )));
            }
            Err(revert_err) => {
                if master_acl_changed {
                    let _ = repo.reload_acl_from_store();
                }
                // Bookmark remains live at `record.new_head`; best-effort record the land event
                // (startup/list_outbox reconciliation also guarantees durability).
                let land_payload = json!({
                    "event": "land",
                    "repo": format!("{owner}/{name}"),
                    "target": record.target,
                    "land_seq": record.land_seq,
                    "previous_head": record.previous_head.map(|h| h.to_hex()),
                    "new_head": record.new_head.to_hex(),
                });
                let ev_opt = repo
                    .outbox
                    .record_event(
                        "land",
                        &record.target,
                        record.land_seq,
                        record.previous_head,
                        record.new_head,
                        &land_payload,
                    )
                    .ok();
                drop(pending_guard);
                if let Some(ev) = ev_opt {
                    spawn_webhook_dispatch(
                        Arc::clone(&repo.outbox),
                        state.config.webhook_urls.clone(),
                        ev,
                    );
                }
                return Err(ApiError::internal(format!(
                    "post-land verification failed for land_seq {} ({reason}), and auto-revert failed ({revert_err}); bookmark '{}' remains at {}",
                    record.land_seq, record.target, record.new_head
                )));
            }
        }
    }

    if master_acl_changed {
        repo.reload_acl_from_store()?;
    }

    let land_payload = json!({
        "event": "land",
        "repo": format!("{owner}/{name}"),
        "target": record.target,
        "land_seq": record.land_seq,
        "previous_head": record.previous_head.map(|h| h.to_hex()),
        "new_head": record.new_head.to_hex(),
    });
    let ev = repo.outbox.record_event(
        "land",
        &record.target,
        record.land_seq,
        record.previous_head,
        record.new_head,
        &land_payload,
    )?;
    drop(pending_guard);
    spawn_webhook_dispatch(
        Arc::clone(&repo.outbox),
        state.config.webhook_urls.clone(),
        ev,
    );

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
    let _target_write_guard = repo.try_write_target(&original.target)?;
    let policy = repo.acl_snapshot()?;
    // Re-read `original` under the exclusive target write lock so `reverted_by` cannot race.
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

    if repo.is_head_pending_verification(original.new_head)
        || repo.is_head_pending_verification(previous_head)
    {
        return Err(ApiError::conflict(format!(
            "land_seq {land_seq} is currently undergoing post-land verification; retry shortly"
        )));
    }

    let new_cs = repo.store.get_changeset(original.new_head)?;
    let prev_cs = repo.store.get_changeset(previous_head)?;
    // Block un-reverting an auto-reverted or unverified `EmbargoState::Published` changeset
    // (which would bypass `can_publish_embargo` and `post_land_cmd` and disclose the embargo).
    if repo.is_unlive_published_changeset(&prev_cs)?
        || repo.is_unlive_published_changeset(&new_cs)?
    {
        return Err(ApiError::conflict(format!(
            "land_seq {land_seq} references an unverified or reverted embargo publication and cannot be reverted"
        )));
    }
    if !repo.can_read_changeset_live(&policy, &principal, &new_cs)
        || !repo.can_read_changeset_live(&policy, &principal, &prev_cs)
    {
        return Err(ApiError::forbidden(format!(
            "principal '{}' cannot revert unreadable land_seq {land_seq}",
            principal.id
        )));
    }
    let new_embargo_allowed = match &new_cs.visibility.embargo {
        Some(EmbargoState::Active {
            allowed_domains, ..
        }) => allowed_domains.as_slice(),
        _ => &[],
    };
    if !can_write_domain_effective(
        &policy,
        &principal,
        &new_cs.visibility.primary_domain,
        new_embargo_allowed,
    ) {
        return Err(ApiError::forbidden(format!(
            "principal '{}' cannot revert land in domain '{}'",
            principal.id, new_cs.visibility.primary_domain
        )));
    }
    // Verify write permissions for transitioning `new_cs -> prev_cs` so reverting a secret
    // addition in an unconfigured `secret:*` dropbox requires explicit write/admin permission.
    verify_changeset_write_permissions(
        repo.store.as_ref(),
        &policy,
        &principal,
        &prev_cs,
        Some(&new_cs),
    )?;
    let master_acl_changed = original.target == "master"
        && acl_file_changed(repo.store.as_ref(), Some(&new_cs), &prev_cs)?;
    if master_acl_changed && !can_administer_acl(&policy, &principal) {
        return Err(ApiError::forbidden(format!(
            "principal '{}' is not authorized to revert .gitxacl on 'master'",
            principal.id
        )));
    }

    let revert_rec = repo.store.revert_land(land_seq)?;

    if master_acl_changed {
        repo.reload_acl_from_store()?;
    }

    let rev_payload = json!({
        "event": "revert",
        "repo": format!("{owner}/{name}"),
        "target": original.target,
        "reverted_land_seq": land_seq,
        "revert_land_seq": revert_rec.land_seq,
        "restored_head": previous_head.to_hex(),
    });
    let ev = repo.outbox.record_event(
        "revert",
        &original.target,
        revert_rec.land_seq,
        revert_rec.previous_head,
        revert_rec.new_head,
        &rev_payload,
    )?;
    spawn_webhook_dispatch(
        Arc::clone(&repo.outbox),
        state.config.webhook_urls.clone(),
        ev,
    );

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
pub struct TreeSecretEntry {
    pub path: String,
    pub domain: String,
    pub key_epoch: u64,
    pub envelope_hash: String,
    pub envelope_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeResponse {
    pub rev: Option<String>,
    pub domains: Vec<String>,
    pub files: Vec<TreeFileEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<TreeSecretEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutboxQuery {
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxResponse {
    pub events: Vec<OutboxEvent>,
}

/// `GET /v1/repos/{owner}/{name}/outbox`
pub async fn list_outbox(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<OutboxQuery>,
) -> ApiResult<Json<OutboxResponse>> {
    if principal.is_anonymous {
        return Err(ApiError::forbidden(
            "anonymous callers cannot inspect repository outbox events",
        ));
    }
    let repo = get_existing_repo(&state, &owner, &name)?;
    let _ = repo.reconcile_outbox();
    let policy = repo.acl_snapshot()?;
    let limit = query.limit.unwrap_or(50).min(500);
    let page_size = limit.clamp(64, 500);

    // Fail-closed ACL filter with full table pagination:
    // - Both `new_head` AND `previous_head` (when present) must be readable by `principal`.
    // - Keeps paging older events until `limit` visible events are found or the outbox is exhausted
    //   so a burst of unreadable private/embargoed lands never hides older readable events.
    let mut visible_events = Vec::with_capacity(limit);
    let mut cursor: Option<u64> = None;
    loop {
        let batch = repo.outbox.list_events_before(cursor, page_size)?;
        if batch.is_empty() {
            break;
        }
        let batch_len = batch.len();
        cursor = batch.last().map(|e| e.event_id);

        for ev in batch {
            let Ok(head_hash) = ObjectHash::from_str(&ev.new_head) else {
                continue;
            };
            let Ok(cs) = repo.store.get_changeset(head_hash) else {
                continue;
            };
            if !repo.can_read_changeset_live(&policy, &principal, &cs) {
                continue;
            }
            if let Some(ref prev_hex) = ev.previous_head {
                let Ok(prev_hash) = ObjectHash::from_str(prev_hex) else {
                    continue;
                };
                let Ok(prev_cs) = repo.store.get_changeset(prev_hash) else {
                    continue;
                };
                if !repo.can_read_changeset_live(&policy, &principal, &prev_cs) {
                    continue;
                }
            }
            visible_events.push(ev);
            if visible_events.len() >= limit {
                break;
            }
        }

        if visible_events.len() >= limit || batch_len < page_size {
            break;
        }
    }
    Ok(Json(OutboxResponse {
        events: visible_events,
    }))
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

    let Some(cs) = resolve_visible_changeset(&repo, &policy, &principal, query.rev.as_deref())?
    else {
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
            secrets: Vec::new(),
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
    let mut secrets: Vec<TreeSecretEntry> = Vec::new();

    for (dom, tree_hash) in ordered_domains {
        if domain_filter.as_ref().is_some_and(|f| f != dom) {
            continue;
        }
        active_domains.push(dom.to_string());
        let tree = repo.store.get_tree(tree_hash)?;
        for (path, entry) in &tree.entries {
            match entry {
                EntryKind::File {
                    blob_hash, size, ..
                } => {
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
                EntryKind::EncryptedSecret {
                    envelope_hash,
                    key_epoch,
                    ..
                } => {
                    if let Ok(raw) = repo.store.get_raw_object(*envelope_hash)
                        && let Ok(env_json) = String::from_utf8(raw)
                    {
                        secrets.push(TreeSecretEntry {
                            path: path.clone(),
                            domain: dom.to_string(),
                            key_epoch: *key_epoch,
                            envelope_hash: envelope_hash.to_hex(),
                            envelope_json: env_json,
                        });
                    }
                }
                EntryKind::Conflict { .. } => {}
            }
        }
    }

    Ok(Json(TreeResponse {
        rev: Some(cs.id.to_hex()),
        domains: active_domains,
        files: merged.into_values().collect(),
        secrets,
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

    let Some(to_cs) = resolve_visible_changeset(&repo, &policy, &principal, query.to.as_deref())?
    else {
        return Ok(Json(DiffResponse {
            from: None,
            to: None,
            files: Vec::new(),
            unified_diff: String::new(),
        }));
    };

    let from_cs = match query.from.as_deref().filter(|s| !s.is_empty()) {
        Some(from_rev) => resolve_visible_changeset(&repo, &policy, &principal, Some(from_rev))?,
        None => first_visible_parent(&repo, &policy, &principal, &to_cs)?,
    };

    let old_files = match &from_cs {
        Some(cs) => materialize_authorized_files(repo.store.as_ref(), &policy, &principal, cs)?,
        None => BTreeMap::new(),
    };
    let new_files = materialize_authorized_files(repo.store.as_ref(), &policy, &principal, &to_cs)?;

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
        to: Some(to_cs.id.to_hex()),
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

    let Some(cs) = resolve_visible_changeset(&repo, &policy, &principal, query.rev.as_deref())?
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
        resolve_visible_changeset(&repo, &policy, &principal, query.rev.as_deref())?
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
        if !repo.can_read_changeset_live(&policy, &principal, &cs) {
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
                DiffOp::Equal { old_index, len, .. } => {
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

    let Some(start_hash) =
        resolve_raw_rev_for_principal(&repo, &policy, &principal, query.rev.as_deref())?
    else {
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
        if repo.can_read_changeset_live(&policy, &principal, &cs) {
            visible.push(cs);
        }
    }

    // Order newest first.
    visible.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| b.id.cmp(&a.id))
    });
    visible.truncate(limit);

    let visible_head = visible.first().map(|c| c.id.to_hex());
    let commits: Vec<LogEntry> = visible
        .into_iter()
        .map(|cs| {
            let filtered = policy.filter_domain_trees(&principal, &cs);
            let domains: Vec<String> = filtered.keys().map(ToString::to_string).collect();
            let visible_parents = visible_parent_hashes(&repo, &policy, &principal, &cs);
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

    let Some(cs) = resolve_visible_changeset(&repo, &policy, &principal, query.rev.as_deref())?
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    let embargo_domain = DomainId::embargo(&advisory)?;

    // Serialize embargo publication per repository so two concurrent publish requests (even
    // targeting different bookmarks) cannot both pass the already-published check and double-publish.
    let _publish_guard = repo.publish_lock.lock().await;
    // Snapshot ACL after acquiring `publish_lock` so we see any `.gitxacl` reloaded by an
    // immediately preceding publish.
    let policy = repo.acl_snapshot()?;

    // Locate active embargo ChangeSets for this advisory and verify it has not already been published.
    let all_cs = repo.store.list_changesets()?;
    let active_candidates: Vec<ChangeSet> = all_cs
        .iter()
        .filter(|cs| {
            matches!(
                &cs.visibility.embargo,
                Some(EmbargoState::Active { advisory_id, .. }) if advisory_id == &advisory
            )
        })
        .cloned()
        .collect();

    if active_candidates.is_empty() {
        return Err(ApiError::not_found(format!(
            "no active embargo found for advisory '{advisory}'"
        )));
    }

    // Key already-published check strictly on `advisory_id` using live/unreverted land status so:
    // - an advisory can never be double-published (even onto a different bookmark),
    // - a transient CAS conflict or crash orphan never permanently bricks the advisory, and
    // - an auto-reverted publish (failing `post_land_cmd`) allows repair commits and retry.
    if repo.is_advisory_published(&advisory)? {
        return Err(ApiError::conflict(format!(
            "embargo '{advisory}' has already been published"
        )));
    }

    // Prefer the latest active embargo this principal is authorized to publish.
    let embargo_cs = active_candidates
        .into_iter()
        .rev()
        .find(|cs| can_publish_embargo(&policy, &principal, cs))
        .ok_or_else(|| {
            ApiError::forbidden(format!(
                "principal '{}' is not authorized to publish embargo '{advisory}'",
                principal.id
            ))
        })?;

    let embargo_tree = match embargo_cs.domain_trees.get(&embargo_domain) {
        Some(&tree_hash) => repo.store.get_tree(tree_hash)?,
        None => DomainTree::new(embargo_domain.clone()),
    };

    let target = req.target.unwrap_or_else(|| "master".to_string());
    let _target_write_guard = repo.try_write_target(&target)?;
    let current_head = repo.store.get_bookmark(&target)?;
    if let Some(h) = current_head
        && repo.is_head_pending_verification(h)
    {
        return Err(ApiError::conflict(format!(
            "target '{target}' is currently undergoing post-land verification; retry shortly"
        )));
    }

    let mut domain_trees: BTreeMap<DomainId, DomainTree> = BTreeMap::new();
    let current_head_cs = current_head
        .map(|h| repo.store.get_changeset(h))
        .transpose()?;
    if let Some(ref cur_cs) = current_head_cs
        && repo.is_unlive_published_changeset(cur_cs)?
    {
        return Err(ApiError::conflict(format!(
            "target '{target}' points to an unverified or reverted embargo publication"
        )));
    }
    let base_source_cs = current_head_cs.unwrap_or_else(|| embargo_cs.clone());

    for (dom, &tree_hash) in &base_source_cs.domain_trees {
        if dom == &embargo_domain {
            continue;
        }
        domain_trees.insert(dom.clone(), repo.store.get_tree(tree_hash)?);
    }

    let is_admin = principal.roles.iter().any(|r| r == "admin");
    let mut promoted_paths: Vec<String> = Vec::new();
    let mut promoted_acl = false;
    for (path, entry) in &embargo_tree.entries {
        let dest_domain = policy.domain_for_path(path);
        if !can_write_domain_effective(&policy, &principal, &dest_domain, &[]) {
            return Err(ApiError::forbidden(format!(
                "principal '{}' is not authorized to promote '{path}' into domain '{dest_domain}'",
                principal.id
            )));
        }
        for existing_tree in domain_trees.values() {
            if existing_tree.domain.is_secret()
                && existing_tree.entries.contains_key(path)
                && !is_admin
                && !policy.can_write_domain(&principal, &existing_tree.domain)
            {
                return Err(ApiError::forbidden(format!(
                    "principal '{}' is not authorized to overwrite or shadow existing secret '{path}' in domain '{}'",
                    principal.id, existing_tree.domain
                )));
            }
        }
        if path == ".gitxacl" {
            if !can_administer_acl(&policy, &principal) {
                return Err(ApiError::forbidden(format!(
                    "principal '{}' is not authorized to promote .gitxacl",
                    principal.id
                )));
            }
            if let EntryKind::File { blob_hash, .. } = entry {
                let bytes = repo.store.read_blob_bytes(*blob_hash)?;
                let text = std::str::from_utf8(&bytes).map_err(|e| {
                    ApiError::bad_request(format!(".gitxacl must be valid UTF-8: {e}"))
                })?;
                let _ = AclPolicy::parse(text)?;
                promoted_acl = true;
            }
        }
        if dest_domain.is_public()
            && let EntryKind::File { blob_hash, .. } = entry
        {
            let bytes = repo.store.read_blob_bytes(*blob_hash)?;
            let findings = scan_content(path, &bytes);
            if !findings.is_empty() {
                return Err(ApiError::secret_rejected(
                    format!("cannot publish embargo '{advisory}': secret detected in '{path}'"),
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

    let description = req
        .message
        .unwrap_or_else(|| format!("Publish advisory {}: {}", advisory, embargo_cs.description));

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

    // Track `published_cs.id` as pending verification BEFORE persisting it so unprivileged callers
    // cannot observe it while `post_land_cmd` runs AND concurrent `GET /outbox` reconciliation
    // never prematurely backfills a `"land"` row before verification succeeds.
    let pending_guard = repo.track_pending_verification(published_cs.id);
    repo.store.put_changeset(&published_cs)?;

    let land_rec = match repo.store.record_land(
        &target,
        current_head,
        published_cs.id,
        vec![published_cs.change_id],
    ) {
        Ok(rec) => rec,
        Err(err) => {
            // Roll back the unlanded `Published` changeset on CAS conflict so no orphan remains.
            let _ = repo.store.delete_changeset(published_cs.id);
            return Err(err.into());
        }
    };

    // Run optional post-land verification BEFORE reloading `.gitxacl`, recording `"land"`,
    // releasing public visibility, or promoting embargo context records so a failing `post_land_cmd`
    // atomically auto-reverts without disclosing the embargo or wiping `<root_dir>/.gitxacl`.
    if let Err(reason) = state
        .run_post_land_hook_async(
            format!("{owner}/{name}"),
            land_rec.target.clone(),
            land_rec.land_seq,
            land_rec.new_head,
        )
        .await
    {
        match repo.store.revert_land(land_rec.land_seq) {
            Ok(revert_rec) => {
                let rev_payload = json!({
                    "event": "auto_revert",
                    "repo": format!("{owner}/{name}"),
                    "target": land_rec.target,
                    "reverted_land_seq": land_rec.land_seq,
                    "revert_land_seq": revert_rec.land_seq,
                    "restored_head": revert_rec.new_head.to_hex(),
                    "advisory_id": advisory,
                    "reason": reason,
                });
                let ev = repo.outbox.record_event(
                    "auto_revert",
                    &land_rec.target,
                    revert_rec.land_seq,
                    revert_rec.previous_head,
                    revert_rec.new_head,
                    &rev_payload,
                )?;
                drop(pending_guard);
                spawn_webhook_dispatch(
                    Arc::clone(&repo.outbox),
                    state.config.webhook_urls.clone(),
                    ev,
                );
                return Err(ApiError::conflict(format!(
                    "land_seq {} auto-reverted: {reason}",
                    land_rec.land_seq
                )));
            }
            Err(revert_err) => {
                if target == "master" && promoted_acl {
                    let _ = repo.reload_acl_from_store();
                }
                let publish_payload = json!({
                    "event": "land",
                    "repo": format!("{owner}/{name}"),
                    "target": land_rec.target,
                    "land_seq": land_rec.land_seq,
                    "previous_head": land_rec.previous_head.map(|h| h.to_hex()),
                    "new_head": land_rec.new_head.to_hex(),
                    "advisory_id": advisory,
                });
                let ev_opt = repo
                    .outbox
                    .record_event(
                        "land",
                        &land_rec.target,
                        land_rec.land_seq,
                        land_rec.previous_head,
                        land_rec.new_head,
                        &publish_payload,
                    )
                    .ok();
                drop(pending_guard);
                if let Some(ev) = ev_opt {
                    spawn_webhook_dispatch(
                        Arc::clone(&repo.outbox),
                        state.config.webhook_urls.clone(),
                        ev,
                    );
                }
                return Err(ApiError::internal(format!(
                    "post-land verification failed for land_seq {} ({reason}), and auto-revert failed ({revert_err}); bookmark '{}' remains at {}",
                    land_rec.land_seq, land_rec.target, land_rec.new_head
                )));
            }
        }
    }

    if target == "master" && promoted_acl {
        repo.reload_acl_from_store()?;
    }

    let publish_payload = json!({
        "event": "land",
        "repo": format!("{owner}/{name}"),
        "target": land_rec.target,
        "land_seq": land_rec.land_seq,
        "previous_head": land_rec.previous_head.map(|h| h.to_hex()),
        "new_head": land_rec.new_head.to_hex(),
        "advisory_id": advisory,
    });
    let ev = repo.outbox.record_event(
        "land",
        &land_rec.target,
        land_rec.land_seq,
        land_rec.previous_head,
        land_rec.new_head,
        &publish_payload,
    )?;
    // Verification succeeded and outbox event recorded — release pending guard so `published_cs`
    // is now publicly visible.
    drop(pending_guard);
    spawn_webhook_dispatch(
        Arc::clone(&repo.outbox),
        state.config.webhook_urls.clone(),
        ev,
    );

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

    let Some(cs) = resolve_visible_changeset(&repo, &policy, principal, rev)? else {
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

// ---------------------------------------------------------------------------
// Zero-Clone Server-Side Rebase & Derived AST Symbol Query
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct RebaseRequest {
    pub changeset_id: String,
    pub onto: String,
    #[serde(default)]
    pub update_bookmark: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebaseResponse {
    pub changeset_id: String,
    pub change_id: String,
    pub onto: String,
    pub has_conflicts: bool,
    pub conflicts: Vec<String>,
    pub updated_bookmark: Option<String>,
}

/// `POST /v1/repos/{owner}/{name}/rebase`
///
/// Zero-clone server-side 3-way semantic rebase of `changeset_id` onto `onto`.
/// Records first-class algebraic conflicts inside the resulting `ChangeSet` without blocking.
pub async fn rebase_changeset(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<RebaseRequest>,
) -> ApiResult<Json<RebaseResponse>> {
    if principal.is_anonymous {
        return Err(ApiError::forbidden(
            "anonymous callers are not permitted to rebase changesets",
        ));
    }

    let repo = get_existing_repo(&state, &owner, &name)?;
    let policy = repo.acl_snapshot()?;

    let _bm_guard = match req
        .update_bookmark
        .as_deref()
        .filter(|b| !b.trim().is_empty())
    {
        Some(bm) => Some(repo.try_write_target(bm)?),
        None => None,
    };

    let src_hash = resolve_hash_or_bookmark_visible(&repo, &policy, &principal, &req.changeset_id)?;
    let onto_hash = resolve_hash_or_bookmark_visible(&repo, &policy, &principal, &req.onto)?;

    let src_cs = repo.store.get_changeset(src_hash)?;
    let onto_cs = repo.store.get_changeset(onto_hash)?;

    if !repo.can_read_changeset_live(&policy, &principal, &src_cs)
        || !repo.can_read_changeset_live(&policy, &principal, &onto_cs)
    {
        return Err(ApiError::forbidden(format!(
            "principal '{}' cannot read source or target changeset for rebase",
            principal.id
        )));
    }
    if repo.is_unlive_published_changeset(&src_cs)?
        || repo.is_unlive_published_changeset(&onto_cs)?
    {
        return Err(ApiError::conflict(
            "cannot rebase onto or from an unverified or reverted embargo publication",
        ));
    }

    let old_base_cs = src_cs
        .parents
        .first()
        .copied()
        .map(|h| repo.store.get_changeset(h))
        .transpose()?;

    verify_changeset_write_permissions(
        repo.store.as_ref(),
        &policy,
        &principal,
        &src_cs,
        old_base_cs.as_ref(),
    )?;

    let mut all_domains: BTreeSet<DomainId> = BTreeSet::new();
    if let Some(ref b) = old_base_cs {
        all_domains.extend(b.domain_trees.keys().cloned());
    }
    all_domains.extend(src_cs.domain_trees.keys().cloned());
    all_domains.extend(onto_cs.domain_trees.keys().cloned());

    let mut merged_domain_trees = BTreeMap::new();
    let mut conflict_paths = Vec::new();
    let store_ref = repo.store.as_ref();

    for dom in all_domains {
        let base_tree = load_domain_tree_or_empty(store_ref, old_base_cs.as_ref(), &dom)?;
        let ours_tree = load_domain_tree_or_empty(store_ref, Some(&onto_cs), &dom)?;
        let theirs_tree = load_domain_tree_or_empty(store_ref, Some(&src_cs), &dom)?;

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
        for cp in merge_res.conflict_paths {
            conflict_paths.push(format!("{dom}:{cp}"));
        }
        if dom.is_public() || !merge_res.tree.entries.is_empty() {
            let tree_hash = store_ref.put_tree(&merge_res.tree)?;
            merged_domain_trees.insert(dom, tree_hash);
        }
    }

    let has_conflicts = !conflict_paths.is_empty();
    let public_parents = compute_public_parents(store_ref, &[onto_cs.id]);
    let rebased = ChangeSetBuilder::new(src_cs.author.clone())
        .change_id(src_cs.change_id)
        .previous_revision(Some(src_cs.id))
        .parents(vec![onto_cs.id])
        .public_parents(public_parents)
        .domain_trees(merged_domain_trees)
        .committer(src_cs.committer.clone())
        .visibility(src_cs.visibility.clone())
        .has_conflicts(has_conflicts)
        .description(src_cs.description.clone())
        .build();

    store_ref.put_changeset(&rebased)?;

    let updated_bookmark = if let Some(ref bm) = req.update_bookmark
        && !bm.trim().is_empty()
    {
        if has_conflicts && bm == "master" {
            return Err(ApiError::conflict(format!(
                "rebased changeset {} has unresolved conflicts; refusing to advance 'master'",
                rebased.id
            )));
        }
        let current = store_ref.get_bookmark(bm)?;
        store_ref.cas_bookmark(bm, current, rebased.id)?;
        Some(bm.clone())
    } else {
        None
    };

    Ok(Json(RebaseResponse {
        changeset_id: rebased.id.to_hex(),
        change_id: rebased.change_id.to_string(),
        onto: onto_cs.id.to_hex(),
        has_conflicts,
        conflicts: conflict_paths,
        updated_bookmark,
    }))
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SymbolsQuery {
    #[serde(default)]
    pub rev: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolsResponse {
    pub rev: Option<String>,
    pub symbols: Vec<IndexedSymbol>,
}

/// `GET /v1/repos/{owner}/{name}/symbols?rev=...&path=...`
///
/// Zero-clone server-side Tree-sitter AST symbol listing backed by the domain-partitioned
/// [`crate::derived::SymbolIndex`] cache.
pub async fn get_symbols(
    State(state): State<Arc<AppState>>,
    AuthenticatedPrincipal(principal): AuthenticatedPrincipal,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<SymbolsQuery>,
) -> ApiResult<Json<SymbolsResponse>> {
    let repo = get_existing_repo(&state, &owner, &name)?;
    let policy = repo.acl_snapshot()?;

    let Some(cs) = resolve_visible_changeset(&repo, &policy, &principal, query.rev.as_deref())?
    else {
        return Ok(Json(SymbolsResponse {
            rev: None,
            symbols: Vec::new(),
        }));
    };

    let path_filter = query
        .path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(normalize_repo_path)
        .transpose()?;

    let filtered = policy.filter_domain_trees(&principal, &cs);
    let ordered = ordered_domain_entries(&filtered, &cs.visibility.primary_domain);
    let mut symbols = Vec::new();

    for (dom, tree_hash) in ordered {
        let cached = {
            let derived = repo
                .derived
                .read()
                .map_err(|_| ApiError::internal("derived index rwlock poisoned"))?;
            derived
                .symbols
                .try_query_cached(tree_hash, dom, path_filter.as_deref())
        };

        let entries = match cached {
            Some(hit) => hit,
            None => {
                let mut derived = repo
                    .derived
                    .write()
                    .map_err(|_| ApiError::internal("derived index rwlock poisoned"))?;
                derived.symbols.query_or_build(
                    repo.store.as_ref(),
                    tree_hash,
                    dom,
                    path_filter.as_deref(),
                )?
            }
        };
        symbols.extend(entries);
    }

    Ok(Json(SymbolsResponse {
        rev: Some(cs.id.to_hex()),
        symbols,
    }))
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
        || trimmed
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
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

fn resolve_hash_or_bookmark_visible(
    repo: &RepoHandle,
    policy: &AclPolicy,
    principal: &Principal,
    spec: &str,
) -> ApiResult<ObjectHash> {
    let store = repo.store.as_ref();
    if let Some(h) = store.get_bookmark(spec)? {
        return Ok(h);
    }
    if let Ok(h) = ObjectHash::from_str(spec) {
        let cs = store.get_changeset(h)?;
        if !repo.can_read_changeset_live(policy, principal, &cs) {
            return Err(ApiError::not_found(format!("revision '{spec}' not found")));
        }
        return Ok(h);
    }
    let all = store.list_changesets()?;
    let matches: Vec<ObjectHash> = all
        .iter()
        .filter(|cs| {
            repo.can_read_changeset_live(policy, principal, cs)
                && (cs.id.to_hex().starts_with(spec) || cs.change_id.to_string() == spec)
        })
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

/// Verify that `principal` is permitted to write `incoming_cs`'s primary domain and EVERY
/// domain tree modified relative to `baseline_cs` (plus `.gitxacl` admin check if changed).
pub(crate) fn verify_changeset_write_permissions(
    store: &dyn ObjectStore,
    policy: &AclPolicy,
    principal: &Principal,
    incoming_cs: &ChangeSet,
    baseline_cs: Option<&ChangeSet>,
) -> ApiResult<()> {
    let incoming_embargo_allowed = match &incoming_cs.visibility.embargo {
        Some(EmbargoState::Active {
            allowed_domains, ..
        }) => allowed_domains.as_slice(),
        _ => &[],
    };
    let baseline_embargo_allowed = match baseline_cs.and_then(|b| b.visibility.embargo.as_ref()) {
        Some(EmbargoState::Active {
            allowed_domains, ..
        }) => allowed_domains.as_slice(),
        _ => &[],
    };

    if !can_write_domain_effective(
        policy,
        principal,
        &incoming_cs.visibility.primary_domain,
        incoming_embargo_allowed,
    ) {
        return Err(ApiError::forbidden(format!(
            "principal '{}' cannot write to domain '{}'",
            principal.id, incoming_cs.visibility.primary_domain
        )));
    }

    let mut domains_to_check: BTreeSet<&DomainId> = BTreeSet::new();
    for (dom, &hash) in &incoming_cs.domain_trees {
        let base_hash = baseline_cs.and_then(|b| b.domain_trees.get(dom).copied());
        if base_hash != Some(hash) {
            domains_to_check.insert(dom);
        }
    }
    if let Some(base) = baseline_cs {
        for dom in base.domain_trees.keys() {
            if !incoming_cs.domain_trees.contains_key(dom) {
                domains_to_check.insert(dom);
            }
        }
    }

    for dom in domains_to_check {
        let dom_embargo_allowed = if *dom == incoming_cs.visibility.primary_domain {
            incoming_embargo_allowed
        } else if baseline_cs.is_some_and(|b| *dom == b.visibility.primary_domain) {
            baseline_embargo_allowed
        } else {
            &[]
        };
        if !can_write_domain_effective(policy, principal, dom, dom_embargo_allowed) {
            return Err(ApiError::forbidden(format!(
                "principal '{}' cannot write to modified domain '{}'",
                principal.id, dom
            )));
        }
        // For unconfigured `secret:*` dropbox domains, non-admin callers without explicit write
        // permission may only append new secrets; they may never overwrite or delete existing ones.
        if dom.is_secret()
            && !principal.roles.iter().any(|r| r == "admin")
            && !policy.can_write_domain(principal, dom)
        {
            let base_tree = load_domain_tree_or_empty(store, baseline_cs, dom)?;
            let incoming_tree = load_domain_tree_or_empty(store, Some(incoming_cs), dom)?;
            for (path, existing_entry) in &base_tree.entries {
                if incoming_tree.entries.get(path) != Some(existing_entry) {
                    return Err(ApiError::forbidden(format!(
                        "principal '{}' cannot overwrite or delete existing secret '{path}' in domain '{dom}'",
                        principal.id
                    )));
                }
            }
        }
    }

    if acl_file_changed(store, baseline_cs, incoming_cs)? && !can_administer_acl(policy, principal)
    {
        return Err(ApiError::forbidden(format!(
            "principal '{}' is not authorized to modify .gitxacl",
            principal.id
        )));
    }

    Ok(())
}

/// Returns `true` if `.gitxacl` in the `public` domain tree differs between `old_cs` and `new_cs`.
pub(crate) fn acl_file_changed(
    store: &dyn ObjectStore,
    old_cs: Option<&ChangeSet>,
    new_cs: &ChangeSet,
) -> ApiResult<bool> {
    let pub_dom = DomainId::public();
    let old_entry = match old_cs.and_then(|c| c.domain_trees.get(&pub_dom).copied()) {
        Some(h) => store.get_tree(h)?.entries.get(".gitxacl").cloned(),
        None => None,
    };
    let new_entry = match new_cs.domain_trees.get(&pub_dom).copied() {
        Some(h) => store.get_tree(h)?.entries.get(".gitxacl").cloned(),
        None => None,
    };
    Ok(old_entry != new_entry)
}

fn resolve_raw_rev_for_principal(
    repo: &RepoHandle,
    policy: &AclPolicy,
    principal: &Principal,
    rev: Option<&str>,
) -> ApiResult<Option<ObjectHash>> {
    let store = repo.store.as_ref();
    let spec = rev.map(str::trim).filter(|s| !s.is_empty());
    match spec {
        None => Ok(store.get_bookmark("master")?),
        Some(s) => {
            if let Some(h) = store.get_bookmark(s)? {
                return Ok(Some(h));
            }
            if let Ok(h) = ObjectHash::from_str(s) {
                match store.get_changeset(h) {
                    Ok(cs) if repo.can_read_changeset_live(policy, principal, &cs) => {
                        return Ok(Some(h));
                    }
                    _ => return Ok(None),
                }
            }
            let all = store.list_changesets()?;
            let mut found = None;
            for cs in all {
                if repo.can_read_changeset_live(policy, principal, &cs)
                    && (cs.id.to_hex().starts_with(s) || cs.change_id.to_string() == s)
                {
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
    repo: &RepoHandle,
    policy: &AclPolicy,
    principal: &Principal,
    rev: Option<&str>,
) -> ApiResult<Option<ChangeSet>> {
    let Some(start) = resolve_raw_rev_for_principal(repo, policy, principal, rev)? else {
        return Ok(None);
    };
    nearest_visible_changeset(repo, policy, principal, start)
}

fn nearest_visible_changeset(
    repo: &RepoHandle,
    policy: &AclPolicy,
    principal: &Principal,
    start: ObjectHash,
) -> ApiResult<Option<ChangeSet>> {
    let store = repo.store.as_ref();
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
        if repo.can_read_changeset_live(policy, principal, &cs) {
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
    repo: &RepoHandle,
    policy: &AclPolicy,
    principal: &Principal,
    cs: &ChangeSet,
) -> ApiResult<Option<ChangeSet>> {
    for &parent in &cs.parents {
        if let Some(vis) = nearest_visible_changeset(repo, policy, principal, parent)? {
            return Ok(Some(vis));
        }
    }
    Ok(None)
}

fn visible_parent_hashes(
    repo: &RepoHandle,
    policy: &AclPolicy,
    principal: &Principal,
    cs: &ChangeSet,
) -> Vec<ObjectHash> {
    let mut out = Vec::new();
    for &parent in &cs.parents {
        if let Ok(Some(vis)) = nearest_visible_changeset(repo, policy, principal, parent)
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
    let mut entries: Vec<(&DomainId, ObjectHash)> = filtered.iter().map(|(d, &h)| (d, h)).collect();
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
            if cs.visibility.is_publicly_visible() {
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
