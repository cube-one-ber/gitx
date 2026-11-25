use chrono::Utc;
use gitx_context::{
    Checkpoint, CodeAnchor, ContextId, ContextKind, ContextRecord, ContextStore, WhyMatch,
};
use gitx_core::{
    Actor, ChangeId, ChangeSet, ChangeSetBuilder, DomainId, DomainTree, EntryKind, FileMode,
    GitxError, Identity, ObjectHash, OpId, OpKind, OpLogEntry, Result, VisibilityPolicy,
    WorkspaceRef,
};
use gitx_crypto::{AclPolicy, Principal, SecretFinding, scan_content};
use gitx_merge::{
    DiffStatus, TreeDiffEntry, diff_trees, merge_domain_trees, revert_agent_tree_step, unified_diff,
};
#[cfg(feature = "local")]
use gitx_store::LocalStore;
use gitx_store::{LandRecord, MemoryStore, ObjectStore};
use gitx_vfs::{MemVfs, WorkspaceBackend, WorkspaceBackendKind, normalize_rel_path};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
#[cfg(feature = "local")]
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use ulid::Ulid;

const DEFAULT_BOOKMARK: &str = "master";
const DEFAULT_WORKSPACE: &str = "default";
const MAX_LAND_RETRIES: usize = 8;

/// AI agent identity recorded in `Actor::Agent` provenance on commits and checkpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub harness: String,
    pub model: String,
    pub session_id: String,
}

impl AgentIdentity {
    pub fn new(
        harness: impl Into<String>,
        model: impl Into<String>,
        session_id: impl Into<String>,
    ) -> Self {
        Self {
            harness: harness.into(),
            model: model.into(),
            session_id: session_id.into(),
        }
    }

    pub fn into_actor(self, initiated_by: Identity) -> Actor {
        Actor::Agent {
            harness: self.harness,
            model: self.model,
            session_id: self.session_id,
            initiated_by,
        }
    }
}

impl Default for AgentIdentity {
    fn default() -> Self {
        Self {
            harness: "gitx-sdk".to_string(),
            model: "unknown".to_string(),
            session_id: "default".to_string(),
        }
    }
}

/// Optional durable "Why" prompt context attached to a commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitContext {
    pub prompt: String,
    pub visibility: DomainId,
    /// Explicit code anchors. If empty, anchors are auto-derived from added/modified UTF-8 hunks.
    pub anchors: Vec<CodeAnchor>,
}

impl CommitContext {
    pub fn prompt(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            visibility: DomainId::public(),
            anchors: Vec::new(),
        }
    }

    pub fn with_visibility(mut self, visibility: DomainId) -> Self {
        self.visibility = visibility;
        self
    }

    pub fn with_anchors(mut self, anchors: Vec<CodeAnchor>) -> Self {
        self.anchors = anchors;
        self
    }
}

/// Single line match returned by [`AgentRepo::grep`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrepMatch {
    pub path: String,
    pub line_number: usize,
    pub line: String,
}

/// Outcome of [`AgentRepo::commit`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitOutcome {
    pub changeset: ChangeSet,
    pub context_record: Option<ContextRecord>,
    pub secret_warnings: Vec<SecretFinding>,
}

/// Outcome of transactional [`AgentRepo::land`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandOutcome {
    pub land_record: LandRecord,
    pub merged_changeset: ChangeSet,
    pub auto_merged: bool,
    pub conflict_paths: Vec<String>,
}

/// Outcome of surgical [`AgentRepo::undo_checkpoint`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndoCheckpointOutcome {
    pub reverted_checkpoint: Checkpoint,
    pub restored_to_checkpoint: Option<Ulid>,
    pub clean_paths: Vec<String>,
    pub conflict_paths: Vec<String>,
}

/// High-level Agent SDK repository managing named in-memory [`MemVfs`] workspaces,
/// content-addressed storage, durable "Why" context, ACL enforcement, and semantic landing.
pub struct AgentRepo {
    store: Arc<dyn ObjectStore>,
    context: ContextStore,
    acl: AclPolicy,
    author: Identity,
    principal: Principal,
    workspaces: BTreeMap<String, MemVfs>,
}

impl AgentRepo {
    /// Create a pure in-memory `AgentRepo` backed by [`MemoryStore`] and an in-memory
    /// [`ContextStore`] — performs zero disk I/O and zero OS filesystem syscalls.
    pub fn in_memory(author: Identity, principal: Principal) -> Result<Self> {
        let store: Arc<dyn ObjectStore> = Arc::new(MemoryStore::new());
        let context = ContextStore::in_memory()?;
        Self::from_parts(
            store,
            context,
            AclPolicy::default_secure(),
            author,
            principal,
        )
    }

    #[cfg(feature = "local")]
    /// Open (or initialize) a durable local repository at `root` (`.gitx/store` + `.gitx/context.db`),
    /// while executing agent workspace edits in isolated in-memory [`MemVfs`] instances.
    pub fn open_local(
        root: impl AsRef<Path>,
        author: Identity,
        principal: Principal,
    ) -> Result<Self> {
        let root = root.as_ref();
        let gitx_dir = root.join(".gitx");
        fs::create_dir_all(gitx_dir.join("store"))?;

        let acl_path = root.join(".gitxacl");
        let acl = if acl_path.is_file() {
            let text = fs::read_to_string(&acl_path)?;
            AclPolicy::parse(&text)?
        } else {
            AclPolicy::default_secure()
        };

        let store: Arc<dyn ObjectStore> = Arc::new(LocalStore::open(gitx_dir.join("store"))?);
        let context = ContextStore::open(gitx_dir.join("context.db"))?;
        Self::from_parts(store, context, acl, author, principal)
    }

    /// Assemble an `AgentRepo` from custom storage, context, and ACL components.
    pub fn from_parts(
        store: Arc<dyn ObjectStore>,
        context: ContextStore,
        acl: AclPolicy,
        author: Identity,
        principal: Principal,
    ) -> Result<Self> {
        let mut repo = Self {
            store,
            context,
            acl,
            author,
            principal,
            workspaces: BTreeMap::new(),
        };

        // Ensure a root `master` bookmark exists.
        let master_cs = match repo.store.get_bookmark(DEFAULT_BOOKMARK)? {
            Some(hash) => repo.store.get_changeset(hash)?,
            None => {
                let empty_tree = DomainTree::new(DomainId::public());
                let tree_hash = repo.store.put_tree(&empty_tree)?;
                let root_cs = ChangeSetBuilder::new(repo.author.clone())
                    .domain_tree(DomainId::public(), tree_hash)
                    .visibility(VisibilityPolicy::public())
                    .description("Initial commit")
                    .build();
                repo.store.put_changeset(&root_cs)?;
                repo.store.set_bookmark(DEFAULT_BOOKMARK, root_cs.id)?;
                repo.append_op(OpKind::Init, "Initialize AgentRepo")?;
                root_cs
            }
        };

        // Hydrate any pre-existing persisted workspaces into in-memory MemVfs views.
        let existing_ws = repo.store.list_workspaces()?;
        for (name, ws_ref) in existing_ws {
            if let Ok(cs) = repo.store.get_changeset(ws_ref.head_changeset) {
                let vfs = repo.materialize_authorized_vfs(&cs)?;
                repo.workspaces.insert(name, vfs);
            }
        }

        // Guarantee a `"default"` in-memory workspace exists.
        if !repo.workspaces.contains_key(DEFAULT_WORKSPACE) {
            let vfs = repo.materialize_authorized_vfs(&master_cs)?;
            let ws_ref = WorkspaceRef {
                name: DEFAULT_WORKSPACE.to_string(),
                root_path: None,
                backend: WorkspaceBackendKind::Memory,
                head_changeset: master_cs.id,
                head_change_id: master_cs.change_id,
            };
            repo.store.put_workspace(&ws_ref)?;
            repo.workspaces.insert(DEFAULT_WORKSPACE.to_string(), vfs);
        }

        Ok(repo)
    }

    pub fn store(&self) -> &Arc<dyn ObjectStore> {
        &self.store
    }

    pub fn context(&self) -> &ContextStore {
        &self.context
    }

    pub fn acl(&self) -> &AclPolicy {
        &self.acl
    }

    pub fn acl_mut(&mut self) -> &mut AclPolicy {
        &mut self.acl
    }

    pub fn set_acl(&mut self, acl: AclPolicy) {
        self.acl = acl;
    }

    pub fn author(&self) -> &Identity {
        &self.author
    }

    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    pub fn set_principal(&mut self, principal: Principal) {
        self.principal = principal;
    }

    pub fn bookmark(&self, name: &str) -> Result<Option<ObjectHash>> {
        self.store.get_bookmark(name)
    }

    pub fn get_changeset(&self, id: ObjectHash) -> Result<ChangeSet> {
        self.store.get_changeset(id)
    }

    /// Create a new named in-memory workspace forked off `base_ref` (a bookmark like `"master"`,
    /// an existing workspace name for O(1) copy-on-write cloning, a revision hash, or a `ChangeId`).
    pub fn create_workspace(&mut self, name: &str, base_ref: &str) -> Result<WorkspaceRef> {
        let name = name.trim();
        if name.is_empty() {
            return Err(GitxError::Workspace(
                "workspace name cannot be empty".to_string(),
            ));
        }
        if self.workspaces.contains_key(name) {
            return Err(GitxError::Workspace(format!(
                "workspace '{name}' already exists"
            )));
        }

        let (base_cs, vfs) = if let Some(existing_vfs) = self.workspaces.get(base_ref) {
            let ws_ref = self
                .store
                .get_workspace(base_ref)?
                .ok_or_else(|| GitxError::NotFound(format!("workspace ref '{base_ref}'")))?;
            let cs = self.store.get_changeset(ws_ref.head_changeset)?;
            if !self.acl.can_read_changeset(&self.principal, &cs) {
                return Err(GitxError::AccessDenied {
                    domain: cs.visibility.primary_domain.to_string(),
                    reason: format!(
                        "principal '{}' cannot read base workspace '{base_ref}'",
                        self.principal.id
                    ),
                });
            }
            let mut cloned = existing_vfs.clone_instant();
            for path in cloned.list_files()? {
                let dom = self.acl.domain_for_path(&path);
                if !self.acl.can_read_domain(&self.principal, &dom) {
                    let _ = cloned.remove_file(&path);
                }
            }
            (cs, cloned)
        } else {
            let cs = self.resolve_changeset(base_ref)?;
            let vfs = self.materialize_authorized_vfs(&cs)?;
            (cs, vfs)
        };

        let ws_ref = WorkspaceRef {
            name: name.to_string(),
            root_path: None,
            backend: WorkspaceBackendKind::Memory,
            head_changeset: base_cs.id,
            head_change_id: base_cs.change_id,
        };
        self.store.put_workspace(&ws_ref)?;
        self.workspaces.insert(name.to_string(), vfs);
        self.append_op(
            OpKind::WorkspaceCreate {
                name: name.to_string(),
            },
            format!(
                "Create in-memory workspace '{name}' at {}",
                base_cs.id.short()
            ),
        )?;

        Ok(ws_ref)
    }

    /// List all active in-memory workspaces.
    pub fn list_workspaces(&self) -> Result<Vec<WorkspaceRef>> {
        let mut out = Vec::with_capacity(self.workspaces.len());
        for name in self.workspaces.keys() {
            if let Some(ws) = self.store.get_workspace(name)? {
                out.push(ws);
            }
        }
        Ok(out)
    }

    /// Read a file's raw bytes from a named workspace, enforcing Visibility Domain ACLs.
    pub fn read_file(&self, workspace: &str, path: &str) -> Result<Vec<u8>> {
        let norm = normalize_rel_path(path)?;
        self.check_read_path(&norm)?;
        let vfs = self.workspace_vfs(workspace)?;
        vfs.read_file(&norm)
    }

    /// Read a file as UTF-8 text from a named workspace, enforcing Visibility Domain ACLs.
    pub fn read_file_string(&self, workspace: &str, path: &str) -> Result<String> {
        let bytes = self.read_file(workspace, path)?;
        String::from_utf8(bytes)
            .map_err(|e| GitxError::Workspace(format!("file '{path}' is not valid UTF-8: {e}")))
    }

    /// Read a file's raw bytes from a bookmark, changeset hash, or workspace name.
    pub fn read_file_at(&self, rev_or_workspace: &str, path: &str) -> Result<Vec<u8>> {
        let norm = normalize_rel_path(path)?;
        self.check_read_path(&norm)?;
        if let Some(vfs) = self.workspaces.get(rev_or_workspace) {
            return vfs.read_file(&norm);
        }
        let cs = self.resolve_changeset(rev_or_workspace)?;
        let tree = self.build_authorized_combined_tree(&cs)?;
        match tree.entries.get(&norm) {
            Some(EntryKind::File { blob_hash, .. }) => self.store.read_blob_bytes(*blob_hash),
            _ => Err(GitxError::NotFound(format!(
                "file '{norm}' in revision '{rev_or_workspace}'"
            ))),
        }
    }

    /// Write a file into a named in-memory workspace, enforcing ACLs and scanning for secrets.
    ///
    /// Returns any [`SecretFinding`] warnings detected by the zero-trust secret scanner.
    pub fn write_file(
        &mut self,
        workspace: &str,
        path: &str,
        content: &[u8],
    ) -> Result<Vec<SecretFinding>> {
        self.write_file_with_mode(workspace, path, content, FileMode::Regular)
    }

    /// Write a file with an explicit [`FileMode`], enforcing ACLs and returning secret warnings.
    pub fn write_file_with_mode(
        &mut self,
        workspace: &str,
        path: &str,
        content: &[u8],
        mode: FileMode,
    ) -> Result<Vec<SecretFinding>> {
        let norm = normalize_rel_path(path)?;
        self.check_write_path(&norm)?;
        let warnings = scan_content(&norm, content);
        let vfs = self.workspace_vfs_mut(workspace)?;
        vfs.write_file(&norm, content, mode)?;
        Ok(warnings)
    }

    /// Delete a file from a named in-memory workspace, enforcing ACLs.
    pub fn delete_file(&mut self, workspace: &str, path: &str) -> Result<()> {
        let norm = normalize_rel_path(path)?;
        self.check_write_path(&norm)?;
        let vfs = self.workspace_vfs_mut(workspace)?;
        vfs.remove_file(&norm)
    }

    /// List all readable files in a named in-memory workspace (sorted).
    pub fn list_files(&self, workspace: &str) -> Result<Vec<String>> {
        let vfs = self.workspace_vfs(workspace)?;
        let files = vfs.list_files()?;
        Ok(files
            .into_iter()
            .filter(|p| {
                let domain = self.acl.domain_for_path(p);
                self.acl.can_read_domain(&self.principal, &domain)
            })
            .collect())
    }

    /// List all readable files at a bookmark, changeset hash, or workspace name.
    pub fn list_files_at(&self, rev_or_workspace: &str) -> Result<Vec<String>> {
        if self.workspaces.contains_key(rev_or_workspace) {
            return self.list_files(rev_or_workspace);
        }
        let cs = self.resolve_changeset(rev_or_workspace)?;
        let tree = self.build_authorized_combined_tree(&cs)?;
        Ok(tree.entries.keys().cloned().collect())
    }

    /// Search all readable UTF-8 files in `workspace` for lines containing `query`.
    pub fn grep(&self, workspace: &str, query: &str) -> Result<Vec<GrepMatch>> {
        if query.is_empty() {
            return Ok(Vec::new());
        }
        let vfs = self.workspace_vfs(workspace)?;
        let files = self.list_files(workspace)?;
        let mut matches = Vec::new();
        for path in files {
            let Ok(bytes) = vfs.read_slice(&path) else {
                continue;
            };
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            for (idx, line) in text.lines().enumerate() {
                if line.contains(query) {
                    matches.push(GrepMatch {
                        path: path.clone(),
                        line_number: idx + 1,
                        line: line.to_string(),
                    });
                }
            }
        }
        Ok(matches)
    }

    /// Scan either a single file or all readable files in `workspace` for leaked secrets.
    pub fn scan_secrets(&self, workspace: &str, path: Option<&str>) -> Result<Vec<SecretFinding>> {
        if let Some(raw_path) = path {
            let norm = normalize_rel_path(raw_path)?;
            let bytes = self.read_file(workspace, &norm)?;
            return Ok(scan_content(&norm, &bytes));
        }

        let vfs = self.workspace_vfs(workspace)?;
        let files = self.list_files(workspace)?;
        let mut findings = Vec::new();
        for file in files {
            if let Ok(bytes) = vfs.read_slice(&file) {
                findings.extend(scan_content(&file, bytes));
            }
        }
        Ok(findings)
    }

    /// Compute the unified diff between `workspace`'s committed head ChangeSet and its current
    /// in-memory working copy.
    pub fn diff(&self, workspace: &str) -> Result<String> {
        let ws_ref = self.workspace_ref(workspace)?;
        let base_cs = self.store.get_changeset(ws_ref.head_changeset)?;
        self.diff_workspace_against_changeset(workspace, &base_cs)
    }

    /// Compute the unified diff between an arbitrary `base_ref` (e.g. `"master"`) and `workspace`'s
    /// current in-memory working copy.
    pub fn diff_against(&self, workspace: &str, base_ref: &str) -> Result<String> {
        let base_cs = self.resolve_changeset(base_ref)?;
        self.diff_workspace_against_changeset(workspace, &base_cs)
    }

    /// Return path-level [`TreeDiffEntry`] items comparing `workspace`'s head ChangeSet to its
    /// current working copy.
    pub fn diff_entries(&self, workspace: &str) -> Result<Vec<TreeDiffEntry>> {
        let ws_ref = self.workspace_ref(workspace)?;
        let base_cs = self.store.get_changeset(ws_ref.head_changeset)?;
        let old_tree = self.build_authorized_combined_tree(&base_cs)?;
        let new_tree = self.snapshot_authorized_combined_tree(workspace)?;
        Ok(diff_trees(&old_tree, &new_tree))
    }

    /// Return path-level [`TreeDiffEntry`] items comparing an arbitrary `base_ref` to
    /// `workspace`'s current working copy.
    pub fn diff_entries_against(
        &self,
        workspace: &str,
        base_ref: &str,
    ) -> Result<Vec<TreeDiffEntry>> {
        let base_cs = self.resolve_changeset(base_ref)?;
        let old_tree = self.build_authorized_combined_tree(&base_cs)?;
        let new_tree = self.snapshot_authorized_combined_tree(workspace)?;
        Ok(diff_trees(&old_tree, &new_tree))
    }

    /// Commit the current state of `workspace` as a new immutable [`ChangeSet`] with
    /// [`Actor::Agent`] provenance and an optional durable [`ContextRecord`] anchored to the
    /// modified lines.
    pub fn commit(
        &mut self,
        workspace: &str,
        message: impl Into<String>,
        agent: AgentIdentity,
        context: Option<CommitContext>,
    ) -> Result<CommitOutcome> {
        let ws_ref = self.workspace_ref(workspace)?;
        let parent_cs = self.store.get_changeset(ws_ref.head_changeset)?;
        let old_combined = self.build_authorized_combined_tree(&parent_cs)?;

        let vfs = self.workspace_vfs(workspace)?;
        let mut scanned =
            vfs.snapshot_by_domain(self.store.as_ref(), |p| self.acl.domain_for_path(p))?;

        let mut secret_warnings = Vec::new();
        let mut new_domain_trees = BTreeMap::new();

        // Check context visibility write authorization before mutating any state.
        if let Some(ref ctx) = context
            && !self.acl.can_write_domain(&self.principal, &ctx.visibility)
        {
            return Err(GitxError::AccessDenied {
                domain: ctx.visibility.to_string(),
                reason: format!(
                    "principal '{}' lacks write permission for context visibility domain '{}'",
                    self.principal.id, ctx.visibility
                ),
            });
        }

        // Preserve unreadable domains and secret domains untouched by this workspace,
        // and preserve readable-but-read-only domains as long as their materialized entries
        // were not modified.
        for (domain, &tree_hash) in &parent_cs.domain_trees {
            if !self.acl.can_read_domain(&self.principal, domain) {
                new_domain_trees.insert(domain.clone(), tree_hash);
                scanned.remove(domain);
                continue;
            }
            if domain.is_secret() && !scanned.contains_key(domain) {
                // `build_authorized_combined_tree` intentionally omits `secret:*` entries from
                // plaintext workspaces; preserve the parent's encrypted secret tree verbatim.
                new_domain_trees.insert(domain.clone(), tree_hash);
                continue;
            }
            if !self.acl.can_write_domain(&self.principal, domain) {
                let parent_tree = self.store.get_tree(tree_hash)?;
                let expected_plain: BTreeMap<&String, &EntryKind> = parent_tree
                    .entries
                    .iter()
                    .filter(|(_, k)| !matches!(k, EntryKind::EncryptedSecret { .. }))
                    .collect();
                let scanned_plain: BTreeMap<&String, &EntryKind> = scanned
                    .get(domain)
                    .map(|t| t.entries.iter().collect())
                    .unwrap_or_default();
                if expected_plain == scanned_plain {
                    new_domain_trees.insert(domain.clone(), tree_hash);
                    scanned.remove(domain);
                } else {
                    return Err(GitxError::AccessDenied {
                        domain: domain.to_string(),
                        reason: format!(
                            "principal '{}' lacks write permission for domain '{}'",
                            self.principal.id, domain
                        ),
                    });
                }
            }
        }

        // Persist modified writable domains from the workspace snapshot, preserving any
        // `EncryptedSecret` entries that existed in `parent_cs` for those domains.
        for (domain, mut tree) in scanned {
            if !self.acl.can_write_domain(&self.principal, &domain) {
                return Err(GitxError::AccessDenied {
                    domain: domain.to_string(),
                    reason: format!(
                        "principal '{}' lacks write permission for domain '{}'",
                        self.principal.id, domain
                    ),
                });
            }

            if let Some(&parent_tree_hash) = parent_cs.domain_trees.get(&domain) {
                let parent_tree = self.store.get_tree(parent_tree_hash)?;
                for (path, kind) in parent_tree.entries {
                    if matches!(kind, EntryKind::EncryptedSecret { .. })
                        && !tree.entries.contains_key(&path)
                    {
                        tree.insert(path, kind);
                    }
                }
            }

            if domain.is_public() {
                for (path, kind) in &tree.entries {
                    if let EntryKind::File { blob_hash, .. } = kind {
                        let bytes = self.store.read_blob_bytes(*blob_hash)?;
                        secret_warnings.extend(scan_content(path, &bytes));
                    }
                }
            }

            let tree_hash = self.store.put_tree(&tree)?;
            new_domain_trees.insert(domain, tree_hash);
        }

        // If a principal deleted all files from a previously non-empty writable public domain,
        // verify they actually have write permission on `public`.
        if let Some(&parent_pub_hash) = parent_cs.domain_trees.get(&DomainId::public())
            && !new_domain_trees.contains_key(&DomainId::public())
            && !self.store.get_tree(parent_pub_hash)?.entries.is_empty()
            && !self
                .acl
                .can_write_domain(&self.principal, &DomainId::public())
        {
            return Err(GitxError::AccessDenied {
                domain: DomainId::public().to_string(),
                reason: format!(
                    "principal '{}' lacks write permission for domain 'public'",
                    self.principal.id
                ),
            });
        }

        // Always include a public domain tree.
        if let std::collections::btree_map::Entry::Vacant(e) =
            new_domain_trees.entry(DomainId::public())
        {
            let empty_pub = DomainTree::new(DomainId::public());
            let hash = self.store.put_tree(&empty_pub)?;
            e.insert(hash);
        }

        let actor = agent.clone().into_actor(self.author.clone());
        let description = message.into();
        let cs = ChangeSetBuilder::new(self.author.clone())
            .parents(vec![parent_cs.id])
            .public_parents(vec![parent_cs.public_projection_hash])
            .domain_trees(new_domain_trees)
            .committer(actor.clone())
            .visibility(VisibilityPolicy::public())
            .description(description.clone())
            .build();

        self.store.put_changeset(&cs)?;

        let mut updated_ws = ws_ref;
        updated_ws.head_changeset = cs.id;
        updated_ws.head_change_id = cs.change_id;
        self.store.put_workspace(&updated_ws)?;

        self.append_op(
            OpKind::NewChange {
                change_id: cs.change_id,
            },
            format!(
                "Agent commit in '{workspace}' ({}): {description}",
                cs.id.short()
            ),
        )?;

        let context_record = if let Some(ctx) = context {
            let anchors = if !ctx.anchors.is_empty() {
                ctx.anchors
            } else {
                let new_combined = self.build_authorized_combined_tree(&cs)?;
                self.derive_code_anchors(&old_combined, &new_combined)?
            };

            let rec = ContextRecord {
                id: ContextId::new(),
                change_id: cs.change_id,
                revision: cs.id,
                visibility: ctx.visibility,
                author: actor,
                kind: ContextKind::Prompt {
                    prompt: ctx.prompt,
                    model: agent.model,
                    harness: agent.harness,
                    session_id: agent.session_id,
                },
                anchors,
                created_at: Utc::now(),
            };
            self.context.add_record(&rec)?;
            Some(rec)
        } else {
            None
        };

        Ok(CommitOutcome {
            changeset: cs,
            context_record,
            secret_warnings,
        })
    }

    /// Transactionally land `workspace`'s committed changes onto `target_bookmark` (e.g. `"master"`).
    ///
    /// - Performs fast-forward when `target_bookmark` is an ancestor of the workspace head.
    /// - Otherwise computes the common ancestor and performs a 3-way semantic
    ///   [`gitx_merge::merge_domain_trees`] auto-merge (including key-aware JSON/TOML merging).
    /// - Commits atomically via [`ObjectStore::record_land`] with strictly monotonic `land_seq`
    ///   and CAS retry on concurrent updates.
    /// - Rejects landings that produce unresolved merge conflicts (`GitxError::ConflictPresent`).
    pub fn land(&mut self, workspace: &str, target_bookmark: &str) -> Result<LandOutcome> {
        let ws_ref = self.workspace_ref(workspace)?;
        let ws_head = self.store.get_changeset(ws_ref.head_changeset)?;

        // Ensure no uncommitted working-copy edits are silently dropped during landing.
        let head_tree = self.build_authorized_combined_tree(&ws_head)?;
        let working_tree = self.snapshot_authorized_combined_tree(workspace)?;
        if !diff_trees(&head_tree, &working_tree).is_empty() {
            return Err(GitxError::Workspace(format!(
                "workspace '{workspace}' has uncommitted changes; commit before landing"
            )));
        }

        for _attempt in 0..MAX_LAND_RETRIES {
            let target_head_hash = self.store.get_bookmark(target_bookmark)?;

            let (landed_cs, auto_merged, landed_changes) = match target_head_hash {
                None => {
                    let changes = self.collect_changes_since(ws_head.id, None)?;
                    (ws_head.clone(), false, changes)
                }
                Some(target_hash) => {
                    if self.is_ancestor(ws_head.id, target_hash)? {
                        return Err(GitxError::Merge(format!(
                            "workspace '{workspace}' has no new commits to land onto '{target_bookmark}'"
                        )));
                    }

                    if self.is_ancestor(target_hash, ws_head.id)? {
                        let changes = self.collect_changes_since(ws_head.id, Some(target_hash))?;
                        (ws_head.clone(), false, changes)
                    } else {
                        let target_cs = self.store.get_changeset(target_hash)?;
                        let base_hash = self.find_common_ancestor(target_hash, ws_head.id)?;
                        let base_cs = match base_hash {
                            Some(h) => Some(self.store.get_changeset(h)?),
                            None => None,
                        };

                        let (merged_trees, conflict_paths) =
                            self.merge_changeset_trees(base_cs.as_ref(), &target_cs, &ws_head)?;

                        if !conflict_paths.is_empty() {
                            return Err(GitxError::ConflictPresent(format!(
                                "cannot land workspace '{workspace}' onto '{target_bookmark}': conflicts in {}",
                                conflict_paths.join(", ")
                            )));
                        }

                        let merged_cs = ChangeSetBuilder::new(ws_head.author.clone())
                            .parents(vec![target_cs.id, ws_head.id])
                            .public_parents(vec![
                                target_cs.public_projection_hash,
                                ws_head.public_projection_hash,
                            ])
                            .domain_trees(merged_trees)
                            .committer(ws_head.committer.clone())
                            .visibility(ws_head.visibility.clone())
                            .description(format!(
                                "Land '{workspace}' onto {target_bookmark}: {}",
                                ws_head.description
                            ))
                            .build();
                        self.store.put_changeset(&merged_cs)?;

                        let changes = self.collect_changes_since(ws_head.id, base_hash)?;
                        (merged_cs, true, changes)
                    }
                }
            };

            match self.store.record_land(
                target_bookmark,
                target_head_hash,
                landed_cs.id,
                landed_changes.clone(),
            ) {
                Ok(land_record) => {
                    // Sync the workspace's head & MemVfs with the landed changeset.
                    let synced_vfs = self.materialize_authorized_vfs(&landed_cs)?;
                    self.workspaces.insert(workspace.to_string(), synced_vfs);
                    let updated_ws = WorkspaceRef {
                        name: workspace.to_string(),
                        root_path: ws_ref.root_path.clone(),
                        backend: WorkspaceBackendKind::Memory,
                        head_changeset: landed_cs.id,
                        head_change_id: landed_cs.change_id,
                    };
                    self.store.put_workspace(&updated_ws)?;

                    self.append_op(
                        OpKind::Land {
                            target: target_bookmark.to_string(),
                            land_seq: land_record.land_seq,
                            changes: landed_changes,
                        },
                        format!(
                            "Land '{workspace}' onto '{target_bookmark}' (seq #{}, head {})",
                            land_record.land_seq,
                            landed_cs.id.short()
                        ),
                    )?;

                    return Ok(LandOutcome {
                        land_record,
                        merged_changeset: landed_cs,
                        auto_merged,
                        conflict_paths: Vec::new(),
                    });
                }
                Err(GitxError::Merge(msg)) if msg.contains("CAS conflict") => {
                    continue;
                }
                Err(err) => return Err(err),
            }
        }

        Err(GitxError::Merge(format!(
            "exceeded {MAX_LAND_RETRIES} CAS retries landing workspace '{workspace}' onto '{target_bookmark}'"
        )))
    }

    /// Save a sub-commit agent checkpoint of `workspace`'s current in-memory tree state.
    pub fn save_checkpoint(
        &mut self,
        workspace: &str,
        agent: AgentIdentity,
        prompt_summary: impl Into<String>,
    ) -> Result<Checkpoint> {
        let vfs = self.workspace_vfs(workspace)?;
        let tree = vfs.snapshot_tree(DomainId::public(), self.store.as_ref())?;
        let tree_hash = self.store.put_tree(&tree)?;

        let parent_checkpoint = self
            .context
            .list_checkpoints(workspace, 1)?
            .into_iter()
            .next()
            .map(|cp| cp.id);

        let summary = prompt_summary.into();
        let session_id = agent.session_id.clone();
        let actor = agent.into_actor(self.author.clone());
        let cp = Checkpoint::new(
            workspace,
            session_id.clone(),
            actor,
            summary.clone(),
            tree_hash,
            parent_checkpoint,
        );
        self.context.save_checkpoint(&cp)?;

        self.append_op(
            OpKind::AgentCheckpoint {
                session_id,
                prompt_hash: ObjectHash::of_bytes(summary.as_bytes()),
            },
            format!("Save checkpoint {} in '{workspace}': {summary}", cp.id),
        )?;

        Ok(cp)
    }

    /// List checkpoints saved for `workspace`, newest first.
    pub fn list_checkpoints(&self, workspace: &str, limit: usize) -> Result<Vec<Checkpoint>> {
        let _ = self.workspace_vfs(workspace)?;
        self.context.list_checkpoints(workspace, limit)
    }

    /// Surgically undo an agent checkpoint using [`gitx_merge::revert_agent_tree_step`],
    /// preserving any concurrent non-overlapping human edits made after the checkpoint!
    ///
    /// - If `checkpoint_id` is `None`, reverts the most recent checkpoint for `workspace`.
    /// - The `before_agent` baseline is taken from `checkpoint.parent_checkpoint` if present;
    ///   otherwise it falls back to `workspace`'s `head_changeset` tree (or its parent if the
    ///   checkpoint matches `head_changeset`).
    pub fn undo_checkpoint(
        &mut self,
        workspace: &str,
        checkpoint_id: Option<Ulid>,
    ) -> Result<UndoCheckpointOutcome> {
        let ws_ref = self.workspace_ref(workspace)?;
        let target_cp = match checkpoint_id {
            Some(id) => self
                .context
                .get_checkpoint(id)?
                .ok_or_else(|| GitxError::NotFound(format!("checkpoint {id}")))?,
            None => self
                .context
                .list_checkpoints(workspace, 1)?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    GitxError::NotFound(format!("no checkpoints found for workspace '{workspace}'"))
                })?,
        };

        if target_cp.workspace != workspace {
            return Err(GitxError::Workspace(format!(
                "checkpoint {} belongs to workspace '{}', not '{workspace}'",
                target_cp.id, target_cp.workspace
            )));
        }

        let after_agent = self.store.get_tree(target_cp.tree_hash)?;
        let before_agent = match target_cp.parent_checkpoint {
            Some(parent_id) => {
                let parent_cp = self
                    .context
                    .get_checkpoint(parent_id)?
                    .ok_or_else(|| GitxError::NotFound(format!("parent checkpoint {parent_id}")))?;
                self.store.get_tree(parent_cp.tree_hash)?
            }
            None => {
                let head_cs = self.store.get_changeset(ws_ref.head_changeset)?;
                let head_tree = self.build_authorized_combined_tree(&head_cs)?;
                if head_tree == after_agent {
                    if let Some(&parent_hash) = head_cs.parents.first() {
                        let parent_cs = self.store.get_changeset(parent_hash)?;
                        self.build_authorized_combined_tree(&parent_cs)?
                    } else {
                        DomainTree::new(DomainId::public())
                    }
                } else {
                    head_tree
                }
            }
        };

        let current_tree = {
            let vfs = self.workspace_vfs(workspace)?;
            vfs.snapshot_tree(DomainId::public(), self.store.as_ref())?
        };

        let merge_result = revert_agent_tree_step(
            &before_agent,
            &after_agent,
            &current_tree,
            |h| self.store.read_blob_bytes(h),
            |bytes| {
                let blob = self.store.put_blob_bytes(bytes)?;
                Ok((blob.manifest_hash(), blob.total_size))
            },
        )?;

        let store = Arc::clone(&self.store);
        let vfs = self.workspace_vfs_mut(workspace)?;
        vfs.materialize_tree(&merge_result.tree, store.as_ref())?;

        Ok(UndoCheckpointOutcome {
            restored_to_checkpoint: target_cp.parent_checkpoint,
            reverted_checkpoint: target_cp,
            clean_paths: merge_result.clean_paths,
            conflict_paths: merge_result.conflict_paths,
        })
    }

    /// Answer "why does this line exist?" by querying durable [`ContextRecord`]s anchored to
    /// `path`, relocating each anchor against the current file content in `rev_or_workspace`
    /// (a workspace name, bookmark like `"master"`, or changeset hash), filtered by the active
    /// [`Principal`]'s ACL permissions.
    pub fn why(
        &self,
        rev_or_workspace: &str,
        path: &str,
        line_1based: u32,
    ) -> Result<Vec<WhyMatch>> {
        let norm = normalize_rel_path(path)?;
        self.check_read_path(&norm)?;
        let bytes = self.read_file_at(rev_or_workspace, &norm)?;
        let content = String::from_utf8_lossy(&bytes);
        let allowed = self.allowed_domains();
        let matches = self.context.why(&norm, line_1based, &content, &allowed)?;
        if !matches.is_empty() || !is_json_path(&norm) {
            return Ok(matches);
        }

        // Semantic JSON merges frequently add or remove trailing commas on untouched keys when
        // sibling keys are inserted/deleted alphabetically; retry with comma-normalized lines.
        let without_commas = strip_trailing_json_commas(&content);
        let matches = self
            .context
            .why(&norm, line_1based, &without_commas, &allowed)?;
        if !matches.is_empty() {
            return Ok(matches);
        }

        let with_comma = add_trailing_json_comma_at_line(&content, line_1based);
        self.context.why(&norm, line_1based, &with_comma, &allowed)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn workspace_vfs(&self, workspace: &str) -> Result<&MemVfs> {
        self.workspaces
            .get(workspace)
            .ok_or_else(|| GitxError::NotFound(format!("workspace '{workspace}'")))
    }

    fn workspace_vfs_mut(&mut self, workspace: &str) -> Result<&mut MemVfs> {
        self.workspaces
            .get_mut(workspace)
            .ok_or_else(|| GitxError::NotFound(format!("workspace '{workspace}'")))
    }

    fn workspace_ref(&self, workspace: &str) -> Result<WorkspaceRef> {
        self.store
            .get_workspace(workspace)?
            .ok_or_else(|| GitxError::NotFound(format!("workspace '{workspace}'")))
    }

    fn check_read_path(&self, norm_path: &str) -> Result<()> {
        let domain = self.acl.domain_for_path(norm_path);
        if !self.acl.can_read_domain(&self.principal, &domain) {
            return Err(GitxError::AccessDenied {
                domain: domain.to_string(),
                reason: format!(
                    "principal '{}' cannot read '{norm_path}' in domain '{domain}'",
                    self.principal.id
                ),
            });
        }
        Ok(())
    }

    fn check_write_path(&self, norm_path: &str) -> Result<()> {
        let domain = self.acl.domain_for_path(norm_path);
        if !self.acl.can_write_domain(&self.principal, &domain) {
            return Err(GitxError::AccessDenied {
                domain: domain.to_string(),
                reason: format!(
                    "principal '{}' cannot write '{norm_path}' in domain '{domain}'",
                    self.principal.id
                ),
            });
        }
        Ok(())
    }

    fn allowed_domains(&self) -> Vec<DomainId> {
        let mut set = BTreeSet::new();
        let pub_dom = DomainId::public();
        if self.acl.can_read_domain(&self.principal, &pub_dom) {
            set.insert(pub_dom);
        }
        if !self.principal.is_anonymous {
            if let Ok(priv_dom) = DomainId::private_user(&self.principal.id)
                && self.acl.can_read_domain(&self.principal, &priv_dom)
            {
                set.insert(priv_dom);
            }
            for team in &self.principal.teams {
                if let Ok(team_dom) = DomainId::team(team)
                    && self.acl.can_read_domain(&self.principal, &team_dom)
                {
                    set.insert(team_dom);
                }
            }
        }
        for dom in self.acl.domain_permissions().keys() {
            if self.acl.can_read_domain(&self.principal, dom) {
                set.insert(dom.clone());
            }
        }
        for rule in self.acl.path_rules() {
            if self.acl.can_read_domain(&self.principal, &rule.domain) {
                set.insert(rule.domain.clone());
            }
        }
        set.into_iter().collect()
    }

    fn resolve_changeset(&self, spec: &str) -> Result<ChangeSet> {
        let spec = spec.trim();
        if let Some(hash) = self.store.get_bookmark(spec)? {
            return self.store.get_changeset(hash);
        }
        if let Some(ws) = self.store.get_workspace(spec)? {
            return self.store.get_changeset(ws.head_changeset);
        }
        if let Ok(full_hash) = ObjectHash::from_str(spec) {
            return self.store.get_changeset(full_hash);
        }

        let lower = spec.to_lowercase();
        let all = self.store.list_changesets()?;
        let mut matched: Option<ChangeSet> = None;
        for cs in all {
            let hex = cs.id.to_hex();
            let cid = cs.change_id.to_string();
            let cid_short = cs.change_id.short();
            if hex.starts_with(&lower) || cid.starts_with(&lower) || cid_short == lower {
                matched = Some(cs);
            }
        }
        matched.ok_or_else(|| GitxError::NotFound(format!("revision '{spec}'")))
    }

    fn build_authorized_combined_tree(&self, cs: &ChangeSet) -> Result<DomainTree> {
        let authorized = self.acl.filter_domain_trees(&self.principal, cs);
        let mut combined = DomainTree::new(DomainId::public());
        for (domain, tree_hash) in authorized {
            if domain.is_secret() {
                continue;
            }
            let tree = self.store.get_tree(tree_hash)?;
            for (path, kind) in tree.entries {
                if !matches!(kind, EntryKind::EncryptedSecret { .. }) {
                    combined.insert(path, kind);
                }
            }
        }
        Ok(combined)
    }

    fn snapshot_authorized_combined_tree(&self, workspace: &str) -> Result<DomainTree> {
        let vfs = self.workspace_vfs(workspace)?;
        let full = vfs.snapshot_tree(DomainId::public(), self.store.as_ref())?;
        let mut filtered = DomainTree::new(DomainId::public());
        for (path, kind) in full.entries {
            let domain = self.acl.domain_for_path(&path);
            if !domain.is_secret() && self.acl.can_read_domain(&self.principal, &domain) {
                filtered.insert(path, kind);
            }
        }
        Ok(filtered)
    }

    fn materialize_authorized_vfs(&self, cs: &ChangeSet) -> Result<MemVfs> {
        let combined = self.build_authorized_combined_tree(cs)?;
        MemVfs::from_tree(&combined, self.store.as_ref())
    }

    fn diff_workspace_against_changeset(
        &self,
        workspace: &str,
        base_cs: &ChangeSet,
    ) -> Result<String> {
        let vfs = self.workspace_vfs(workspace)?;
        let old_tree = self.build_authorized_combined_tree(base_cs)?;
        let new_files = self.list_files(workspace)?;

        let mut all_paths: BTreeSet<String> = old_tree.entries.keys().cloned().collect();
        all_paths.extend(new_files);

        let mut out = String::new();
        for path in all_paths {
            let old_bytes = match old_tree.entries.get(&path) {
                Some(EntryKind::File { blob_hash, .. }) => {
                    self.store.read_blob_bytes(*blob_hash)?
                }
                _ => Vec::new(),
            };
            let new_bytes = match vfs.read_slice(&path) {
                Ok(slice) => slice.to_vec(),
                Err(_) => Vec::new(),
            };
            out.push_str(&unified_diff(&path, &old_bytes, &new_bytes));
        }
        Ok(out)
    }

    fn derive_code_anchors(
        &self,
        old_tree: &DomainTree,
        new_tree: &DomainTree,
    ) -> Result<Vec<CodeAnchor>> {
        let entries = diff_trees(old_tree, new_tree);
        let mut anchors = Vec::new();

        for entry in entries {
            if !matches!(entry.status, DiffStatus::Added | DiffStatus::Modified) {
                continue;
            }
            let Some(EntryKind::File {
                blob_hash: new_hash,
                ..
            }) = new_tree.entries.get(&entry.path)
            else {
                continue;
            };
            let new_bytes = self.store.read_blob_bytes(*new_hash)?;
            let Ok(new_str) = std::str::from_utf8(&new_bytes) else {
                continue;
            };
            let new_lines: Vec<&str> = new_str.lines().collect();
            if new_lines.is_empty() {
                continue;
            }

            let old_bytes = match old_tree.entries.get(&entry.path) {
                Some(EntryKind::File { blob_hash, .. }) => {
                    self.store.read_blob_bytes(*blob_hash)?
                }
                _ => Vec::new(),
            };

            let (line_start, line_end) = match std::str::from_utf8(&old_bytes) {
                Ok(old_str) if !old_str.is_empty() => {
                    let old_lines: Vec<&str> = old_str.lines().collect();
                    let mut prefix = 0usize;
                    while prefix < old_lines.len()
                        && prefix < new_lines.len()
                        && lines_logically_equal(&entry.path, old_lines[prefix], new_lines[prefix])
                    {
                        prefix += 1;
                    }
                    let mut suffix = 0usize;
                    while suffix < (old_lines.len() - prefix)
                        && suffix < (new_lines.len() - prefix)
                        && lines_logically_equal(
                            &entry.path,
                            old_lines[old_lines.len() - 1 - suffix],
                            new_lines[new_lines.len() - 1 - suffix],
                        )
                    {
                        suffix += 1;
                    }
                    let start_0 = prefix;
                    let end_0 = new_lines.len().saturating_sub(suffix);
                    if start_0 < end_0 {
                        ((start_0 + 1) as u32, end_0 as u32)
                    } else {
                        let clamped = (start_0.min(new_lines.len() - 1) + 1) as u32;
                        (clamped, clamped)
                    }
                }
                _ => (1u32, new_lines.len() as u32),
            };

            anchors.push(CodeAnchor::from_file_lines(
                &entry.path,
                new_str,
                line_start,
                line_end,
            ));
        }

        Ok(anchors)
    }

    fn get_domain_tree_or_empty(
        &self,
        cs: Option<&ChangeSet>,
        domain: &DomainId,
    ) -> Result<DomainTree> {
        match cs.and_then(|c| c.domain_trees.get(domain)) {
            Some(&hash) => self.store.get_tree(hash),
            None => Ok(DomainTree::new(domain.clone())),
        }
    }

    fn merge_changeset_trees(
        &self,
        base: Option<&ChangeSet>,
        ours: &ChangeSet,
        theirs: &ChangeSet,
    ) -> Result<(BTreeMap<DomainId, ObjectHash>, Vec<String>)> {
        let mut domains = BTreeSet::new();
        if let Some(b) = base {
            domains.extend(b.domain_trees.keys().cloned());
        }
        domains.extend(ours.domain_trees.keys().cloned());
        domains.extend(theirs.domain_trees.keys().cloned());
        domains.insert(DomainId::public());

        let mut merged_trees = BTreeMap::new();
        let mut conflicts = Vec::new();

        for domain in domains {
            let base_tree = self.get_domain_tree_or_empty(base, &domain)?;
            let ours_tree = self.get_domain_tree_or_empty(Some(ours), &domain)?;
            let theirs_tree = self.get_domain_tree_or_empty(Some(theirs), &domain)?;

            let result = merge_domain_trees(
                &base_tree,
                &ours_tree,
                &theirs_tree,
                |h| self.store.read_blob_bytes(h),
                |bytes| {
                    let blob = self.store.put_blob_bytes(bytes)?;
                    Ok((blob.manifest_hash(), blob.total_size))
                },
            )?;

            conflicts.extend(result.conflict_paths);
            if domain.is_public() || !result.tree.entries.is_empty() {
                let hash = self.store.put_tree(&result.tree)?;
                merged_trees.insert(domain, hash);
            }
        }

        Ok((merged_trees, conflicts))
    }

    fn is_ancestor(&self, ancestor: ObjectHash, descendant: ObjectHash) -> Result<bool> {
        if ancestor == descendant {
            return Ok(true);
        }
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(descendant);
        visited.insert(descendant);

        while let Some(cur) = queue.pop_front() {
            let Ok(cs) = self.store.get_changeset(cur) else {
                continue;
            };
            for &p in &cs.parents {
                if p == ancestor {
                    return Ok(true);
                }
                if visited.insert(p) {
                    queue.push_back(p);
                }
            }
        }
        Ok(false)
    }

    fn find_common_ancestor(&self, a: ObjectHash, b: ObjectHash) -> Result<Option<ObjectHash>> {
        let mut ancestors_a = HashSet::new();
        let mut qa = VecDeque::new();
        qa.push_back(a);
        ancestors_a.insert(a);

        while let Some(cur) = qa.pop_front() {
            if let Ok(cs) = self.store.get_changeset(cur) {
                for &p in &cs.parents {
                    if ancestors_a.insert(p) {
                        qa.push_back(p);
                    }
                }
            }
        }

        let mut visited_b = HashSet::new();
        let mut qb = VecDeque::new();
        qb.push_back(b);
        visited_b.insert(b);

        while let Some(cur) = qb.pop_front() {
            if ancestors_a.contains(&cur) {
                return Ok(Some(cur));
            }
            if let Ok(cs) = self.store.get_changeset(cur) {
                for &p in &cs.parents {
                    if visited_b.insert(p) {
                        qb.push_back(p);
                    }
                }
            }
        }
        Ok(None)
    }

    fn collect_changes_since(
        &self,
        tip: ObjectHash,
        stop_at: Option<ObjectHash>,
    ) -> Result<Vec<ChangeId>> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut out = Vec::new();
        let mut seen_ids = HashSet::new();

        queue.push_back(tip);
        visited.insert(tip);

        while let Some(cur) = queue.pop_front() {
            if Some(cur) == stop_at {
                continue;
            }
            let cs = self.store.get_changeset(cur)?;
            if seen_ids.insert(cs.change_id) {
                out.push(cs.change_id);
            }
            for &p in &cs.parents {
                if Some(p) != stop_at && visited.insert(p) {
                    queue.push_back(p);
                }
            }
        }

        out.reverse();
        Ok(out)
    }

    fn append_op(&self, kind: OpKind, summary: impl Into<String>) -> Result<OpLogEntry> {
        let parent = self.store.latest_op()?.map(|o| o.id);
        let bookmarks = self.store.list_bookmarks()?;
        let workspaces = self.store.list_workspaces()?;
        let mut change_heads = BTreeMap::new();
        for cs in self.store.list_changesets()? {
            change_heads.insert(cs.change_id, cs.id);
        }

        let entry = OpLogEntry {
            id: OpId::new(),
            parent,
            timestamp: Utc::now(),
            kind,
            summary: summary.into(),
            bookmarks,
            workspaces,
            change_heads,
        };
        self.store.append_op(&entry)?;
        Ok(entry)
    }
}

fn is_json_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("json"))
}

fn lines_logically_equal(path: &str, a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    if is_json_path(path) {
        return a.trim().trim_end_matches(',') == b.trim().trim_end_matches(',');
    }
    false
}

fn strip_trailing_json_commas(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    for line in content.lines() {
        let trimmed = line.trim_end();
        if let Some(stripped) = trimmed.strip_suffix(',') {
            out.push_str(stripped);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

fn add_trailing_json_comma_at_line(content: &str, line_1based: u32) -> String {
    let mut out = String::with_capacity(content.len() + 1);
    for (idx, line) in content.lines().enumerate() {
        if (idx + 1) as u32 == line_1based && !line.trim_end().ends_with(',') {
            out.push_str(line.trim_end());
            out.push(',');
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}
