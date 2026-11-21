use crate::backend::WorkspaceBackend;
use crate::cow::CowWorkspace;
use crate::memory::MemVfs;
use gitx_core::oplog::WorkspaceBackendKind;
use gitx_core::{
    ChangeId, ChangeSet, DomainId, DomainTree, EntryKind, GitxError, ObjectHash, Result,
    WorkspaceRef,
};
use gitx_store::ObjectStore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Summary of path-level differences between a workspace tree and its base tree.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WorkspaceChanges {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub removed: Vec<String>,
}

impl WorkspaceChanges {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.removed.is_empty()
    }

    pub fn total_changes(&self) -> usize {
        self.added.len() + self.modified.len() + self.removed.len()
    }
}

/// Compute added, modified, and removed paths between `ws_tree` and `base_tree`.
pub fn detect_changes(ws_tree: &DomainTree, base_tree: &DomainTree) -> WorkspaceChanges {
    let mut changes = WorkspaceChanges::default();

    for (path, ws_entry) in &ws_tree.entries {
        match base_tree.entries.get(path) {
            None => changes.added.push(path.clone()),
            Some(base_entry) if base_entry != ws_entry => changes.modified.push(path.clone()),
            Some(_) => {}
        }
    }

    for path in base_tree.entries.keys() {
        if !ws_tree.entries.contains_key(path) {
            changes.removed.push(path.clone());
        }
    }

    changes
}

/// High-level lock-free workspace coordinator over an [`ObjectStore`].
///
/// Any number of `Memory` or `CopyOnWrite` workspaces can base off the exact same `master`
/// bookmark or `ChangeSet` simultaneously without locking branches or blocking sibling agents.
pub struct WorkspaceManager {
    store: Arc<dyn ObjectStore>,
    pool_dir: Option<PathBuf>,
}

impl WorkspaceManager {
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self {
            store,
            pool_dir: None,
        }
    }

    /// Create a manager configured with a shared read-only CAS materialization pool for
    /// Copy-on-Write disk workspaces.
    pub fn with_pool_dir(store: Arc<dyn ObjectStore>, pool_dir: impl Into<PathBuf>) -> Self {
        Self {
            store,
            pool_dir: Some(pool_dir.into()),
        }
    }

    pub fn store(&self) -> &Arc<dyn ObjectStore> {
        &self.store
    }

    pub fn pool_dir(&self) -> Option<&Path> {
        self.pool_dir.as_deref()
    }

    /// Create a new in-memory [`MemVfs`] workspace materialized from `base_changeset`.
    ///
    /// Multiple workspaces may target the same `base_changeset` simultaneously without locking.
    pub fn create_mem_workspace(
        &self,
        name: impl Into<String>,
        base_changeset: ObjectHash,
    ) -> Result<(WorkspaceRef, MemVfs)> {
        let name = validate_workspace_name(name.into())?;
        self.ensure_workspace_name_available(&name)?;

        let cs = self.store.get_changeset(base_changeset)?;
        let tree = collect_materializable_tree(self.store.as_ref(), &cs)?;
        let vfs = MemVfs::from_tree(&tree, self.store.as_ref())?;

        let ws_ref = WorkspaceRef {
            name,
            root_path: None,
            backend: WorkspaceBackendKind::Memory,
            head_changeset: cs.id,
            head_change_id: cs.change_id,
        };
        self.store.put_workspace(&ws_ref)?;

        Ok((ws_ref, vfs))
    }

    /// Create a new in-memory workspace based on a named bookmark (e.g. `"master"`).
    pub fn create_mem_workspace_from_bookmark(
        &self,
        name: impl Into<String>,
        bookmark: &str,
    ) -> Result<(WorkspaceRef, MemVfs)> {
        let base = self.resolve_bookmark(bookmark)?;
        self.create_mem_workspace(name, base)
    }

    /// Create a new Copy-on-Write disk workspace at `root`, materialized from `base_changeset`
    /// via the configured shared CAS pool (or `<root>/.gitx/pool` if no pool dir was set).
    pub fn create_cow_workspace(
        &self,
        name: impl Into<String>,
        root: impl AsRef<Path>,
        base_changeset: ObjectHash,
    ) -> Result<(WorkspaceRef, CowWorkspace)> {
        let pool_dir = self
            .pool_dir
            .clone()
            .unwrap_or_else(|| root.as_ref().join(".gitx").join("pool"));
        self.create_cow_workspace_with_pool(name, root, pool_dir, base_changeset)
    }

    /// Create a new Copy-on-Write disk workspace at `root` with an explicit `pool_dir`.
    pub fn create_cow_workspace_with_pool(
        &self,
        name: impl Into<String>,
        root: impl AsRef<Path>,
        pool_dir: impl AsRef<Path>,
        base_changeset: ObjectHash,
    ) -> Result<(WorkspaceRef, CowWorkspace)> {
        let name = validate_workspace_name(name.into())?;
        self.ensure_workspace_name_available(&name)?;

        let cs = self.store.get_changeset(base_changeset)?;
        let tree = collect_materializable_tree(self.store.as_ref(), &cs)?;
        let mut ws = CowWorkspace::open(root.as_ref(), pool_dir.as_ref())?;
        ws.materialize_tree(&tree, self.store.as_ref())?;

        let ws_ref = WorkspaceRef {
            name,
            root_path: Some(root.as_ref().to_string_lossy().into_owned()),
            backend: WorkspaceBackendKind::CopyOnWrite,
            head_changeset: cs.id,
            head_change_id: cs.change_id,
        };
        self.store.put_workspace(&ws_ref)?;

        Ok((ws_ref, ws))
    }

    /// Create a new Copy-on-Write disk workspace based on a named bookmark (e.g. `"master"`).
    pub fn create_cow_workspace_from_bookmark(
        &self,
        name: impl Into<String>,
        root: impl AsRef<Path>,
        bookmark: &str,
    ) -> Result<(WorkspaceRef, CowWorkspace)> {
        let base = self.resolve_bookmark(bookmark)?;
        self.create_cow_workspace(name, root, base)
    }

    pub fn get_workspace(&self, name: &str) -> Result<Option<WorkspaceRef>> {
        self.store.get_workspace(name)
    }

    pub fn list_workspaces(&self) -> Result<BTreeMap<String, WorkspaceRef>> {
        self.store.list_workspaces()
    }

    pub fn remove_workspace(&self, name: &str) -> Result<()> {
        if self.store.get_workspace(name)?.is_none() {
            return Err(GitxError::NotFound(format!("workspace '{name}'")));
        }
        self.store.remove_workspace(name)
    }

    /// Advance a registered workspace's head pointer to a new `ChangeSet` revision.
    pub fn update_workspace_head(
        &self,
        name: &str,
        head_changeset: ObjectHash,
        head_change_id: ChangeId,
    ) -> Result<WorkspaceRef> {
        let mut ws_ref = self
            .store
            .get_workspace(name)?
            .ok_or_else(|| GitxError::NotFound(format!("workspace '{name}'")))?;
        ws_ref.head_changeset = head_changeset;
        ws_ref.head_change_id = head_change_id;
        self.store.put_workspace(&ws_ref)?;
        Ok(ws_ref)
    }

    /// Compare a workspace's snapshotted `DomainTree` against its `base_tree`.
    pub fn detect_changes(ws_tree: &DomainTree, base_tree: &DomainTree) -> WorkspaceChanges {
        detect_changes(ws_tree, base_tree)
    }

    fn resolve_bookmark(&self, bookmark: &str) -> Result<ObjectHash> {
        self.store
            .get_bookmark(bookmark)?
            .ok_or_else(|| GitxError::NotFound(format!("bookmark '{bookmark}'")))
    }

    fn ensure_workspace_name_available(&self, name: &str) -> Result<()> {
        if self.store.get_workspace(name)?.is_some() {
            return Err(GitxError::Workspace(format!(
                "workspace '{name}' already exists"
            )));
        }
        Ok(())
    }
}

fn validate_workspace_name(name: String) -> Result<String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
    {
        return Err(GitxError::Workspace(format!(
            "invalid workspace name: '{name}'"
        )));
    }
    Ok(name)
}

fn collect_materializable_tree(store: &dyn ObjectStore, cs: &ChangeSet) -> Result<DomainTree> {
    let mut combined = DomainTree::new(DomainId::public());
    for tree_hash in cs.domain_trees.values() {
        let domain_tree = store.get_tree(*tree_hash)?;
        for (path, kind) in domain_tree.entries {
            if !matches!(kind, EntryKind::EncryptedSecret { .. }) {
                combined.insert(path, kind);
            }
        }
    }
    Ok(combined)
}
