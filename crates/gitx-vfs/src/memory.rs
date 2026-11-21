use crate::backend::{
    WorkspaceBackend, normalize_rel_path, render_conflict_bytes, store_blob_if_changed,
};
use gitx_core::oplog::WorkspaceBackendKind;
use gitx_core::{DomainId, DomainTree, EntryKind, FileMode, GitxError, Result};
use gitx_store::ObjectStore;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
struct MemEntry {
    data: Arc<[u8]>,
    mode: FileMode,
}

/// Pure Rust in-memory virtual filesystem workspace.
///
/// Performs zero disk writes and zero OS syscalls — built for `just-bash`-style in-memory AI
/// agents, speculative tool sandboxes, and ultra-fast CI steps.
///
/// Backed by copy-on-write `Arc<BTreeMap<...>>` and shared `Arc<[u8]>` file buffers so
/// [`MemVfs::clone_instant`] is strictly O(1) and mutating a single file in a forked workspace
/// never copies unaffected file payloads.
#[derive(Debug, Default)]
pub struct MemVfs {
    files: Arc<BTreeMap<String, MemEntry>>,
}

impl Clone for MemVfs {
    fn clone(&self) -> Self {
        self.clone_instant()
    }
}

impl MemVfs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Materialize a `DomainTree` directly into a new in-memory workspace.
    pub fn from_tree(tree: &DomainTree, store: &dyn ObjectStore) -> Result<Self> {
        let mut vfs = Self::new();
        vfs.materialize_tree(tree, store)?;
        Ok(vfs)
    }

    /// O(1) copy-on-write fork of this in-memory workspace for parallel agents.
    pub fn clone_instant(&self) -> Self {
        Self {
            files: Arc::clone(&self.files),
        }
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn contains(&self, path: &str) -> bool {
        normalize_rel_path(path)
            .map(|p| self.files.contains_key(&p))
            .unwrap_or(false)
    }

    pub fn file_mode(&self, path: &str) -> Result<FileMode> {
        let norm = normalize_rel_path(path)?;
        self.files
            .get(&norm)
            .map(|e| e.mode)
            .ok_or_else(|| GitxError::NotFound(format!("mem workspace file '{norm}'")))
    }

    /// Read a borrowed slice to the file bytes without copying.
    pub fn read_slice(&self, path: &str) -> Result<&[u8]> {
        let norm = normalize_rel_path(path)?;
        self.files
            .get(&norm)
            .map(|e| e.data.as_ref())
            .ok_or_else(|| GitxError::NotFound(format!("mem workspace file '{norm}'")))
    }

    /// Export a plain owned map of `(path -> (bytes, mode))`.
    pub fn to_owned_map(&self) -> BTreeMap<String, (Vec<u8>, FileMode)> {
        self.files
            .iter()
            .map(|(k, v)| (k.clone(), (v.data.to_vec(), v.mode)))
            .collect()
    }

    /// Partition all in-memory workspace files across Visibility Domains using `classify`.
    pub fn snapshot_by_domain<F>(
        &self,
        store: &dyn ObjectStore,
        classify: F,
    ) -> Result<BTreeMap<DomainId, DomainTree>>
    where
        F: Fn(&str) -> DomainId,
    {
        let mut trees: BTreeMap<DomainId, DomainTree> = BTreeMap::new();
        for (path, entry) in self.files.iter() {
            let domain = classify(path);
            let blob = store_blob_if_changed(store, &entry.data)?;
            let tree = trees
                .entry(domain.clone())
                .or_insert_with(|| DomainTree::new(domain));
            tree.insert(
                path.clone(),
                EntryKind::File {
                    blob_hash: blob.manifest_hash(),
                    mode: entry.mode,
                    size: blob.total_size,
                },
            );
        }
        Ok(trees)
    }
}

impl WorkspaceBackend for MemVfs {
    fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let norm = normalize_rel_path(path)?;
        self.files
            .get(&norm)
            .map(|e| e.data.to_vec())
            .ok_or_else(|| GitxError::NotFound(format!("mem workspace file '{norm}'")))
    }

    fn write_file(&mut self, path: &str, data: &[u8], mode: FileMode) -> Result<()> {
        let norm = normalize_rel_path(path)?;
        let map = Arc::make_mut(&mut self.files);
        map.insert(
            norm,
            MemEntry {
                data: Arc::from(data),
                mode,
            },
        );
        Ok(())
    }

    fn remove_file(&mut self, path: &str) -> Result<()> {
        let norm = normalize_rel_path(path)?;
        let map = Arc::make_mut(&mut self.files);
        map.remove(&norm)
            .map(|_| ())
            .ok_or_else(|| GitxError::NotFound(format!("mem workspace file '{norm}'")))
    }

    fn list_files(&self) -> Result<Vec<String>> {
        Ok(self.files.keys().cloned().collect())
    }

    fn materialize_tree(&mut self, tree: &DomainTree, store: &dyn ObjectStore) -> Result<()> {
        let mut next = BTreeMap::new();
        for (raw_path, kind) in &tree.entries {
            let norm = normalize_rel_path(raw_path)?;
            match kind {
                EntryKind::File {
                    blob_hash, mode, ..
                } => {
                    let bytes = store.read_blob_bytes(*blob_hash)?;
                    next.insert(
                        norm,
                        MemEntry {
                            data: Arc::from(bytes),
                            mode: *mode,
                        },
                    );
                }
                EntryKind::Conflict { term, mode } => {
                    let bytes = render_conflict_bytes(term, store)?;
                    next.insert(
                        norm,
                        MemEntry {
                            data: Arc::from(bytes),
                            mode: *mode,
                        },
                    );
                }
                EntryKind::EncryptedSecret { key_epoch, .. } => {
                    return Err(GitxError::AccessDenied {
                        domain: tree.domain.to_string(),
                        reason: format!(
                            "encrypted secret '{norm}' (key_epoch {key_epoch}) cannot be materialized without decryption"
                        ),
                    });
                }
            }
        }
        self.files = Arc::new(next);
        Ok(())
    }

    fn snapshot_tree(&self, domain: DomainId, store: &dyn ObjectStore) -> Result<DomainTree> {
        let mut tree = DomainTree::new(domain);
        for (path, entry) in self.files.iter() {
            let blob = store_blob_if_changed(store, &entry.data)?;
            tree.insert(
                path.clone(),
                EntryKind::File {
                    blob_hash: blob.manifest_hash(),
                    mode: entry.mode,
                    size: blob.total_size,
                },
            );
        }
        Ok(tree)
    }

    fn backend_kind(&self) -> WorkspaceBackendKind {
        WorkspaceBackendKind::Memory
    }
}
