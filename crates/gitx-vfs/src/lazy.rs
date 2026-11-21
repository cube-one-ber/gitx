use crate::backend::{
    WorkspaceBackend, normalize_rel_path, render_conflict_bytes, store_blob_if_changed,
};
use crate::cow::{apply_workspace_permissions, remove_if_exists, write_symlink};
use gitx_core::oplog::WorkspaceBackendKind;
use gitx_core::{DomainId, DomainTree, EntryKind, FileMode, GitxError, Result};
use gitx_store::ObjectStore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// Runtime telemetry for a demand-paged [`LazyWorkspace`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LazyStats {
    pub total_virtual_files: usize,
    pub hydrated_reads: usize,
    pub overlay_dirty_files: usize,
    pub tombstones: usize,
    pub cache_hits: usize,
}

/// Demand-paged virtualized sparse workspace (`WorkspaceBackendKind::LazyMount`).
///
/// Mounts arbitrarily large `DomainTree`s in O(1) time with **zero** base files written to
/// disk. Unmodified files live purely in the virtual directory index and are hydrated lazily
/// from the [`ObjectStore`] into an in-memory read cache on first read. Mutations
/// (`write_file`, `remove_file`) use Copy-on-Write semantics against a sparse local
/// `overlay_root` directory plus an in-memory tombstone set, so only dirty files ever touch
/// disk and [`WorkspaceBackend::snapshot_tree`] hashes/uploads strictly `O(dirty_files)`.
pub struct LazyWorkspace {
    overlay_root: PathBuf,
    store: Arc<dyn ObjectStore>,
    base_tree: DomainTree,
    dirty_files: BTreeMap<String, FileMode>,
    tombstones: BTreeSet<String>,
    read_cache: RwLock<BTreeMap<String, Arc<[u8]>>>,
    hydrated_reads: AtomicUsize,
    cache_hits: AtomicUsize,
}

impl fmt::Debug for LazyWorkspace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazyWorkspace")
            .field("overlay_root", &self.overlay_root)
            .field("base_entries", &self.base_tree.entries.len())
            .field("dirty_files", &self.dirty_files.len())
            .field("tombstones", &self.tombstones.len())
            .field("stats", &self.stats())
            .finish()
    }
}

impl LazyWorkspace {
    /// Mount `base_tree` instantaneously in O(1) without writing any base files to disk.
    ///
    /// Ensures `overlay_root` exists as an empty directory ready to store Copy-on-Write dirty
    /// overlay files when written.
    pub fn mount(
        overlay_root: impl AsRef<Path>,
        store: Arc<dyn ObjectStore>,
        base_tree: DomainTree,
    ) -> Result<Self> {
        let overlay_root = overlay_root.as_ref().to_path_buf();
        fs::create_dir_all(&overlay_root)?;
        Ok(Self {
            overlay_root,
            store,
            base_tree,
            dirty_files: BTreeMap::new(),
            tombstones: BTreeSet::new(),
            read_cache: RwLock::new(BTreeMap::new()),
            hydrated_reads: AtomicUsize::new(0),
            cache_hits: AtomicUsize::new(0),
        })
    }

    pub fn overlay_root(&self) -> &Path {
        &self.overlay_root
    }

    pub fn base_tree(&self) -> &DomainTree {
        &self.base_tree
    }

    pub fn dirty_files(&self) -> &BTreeMap<String, FileMode> {
        &self.dirty_files
    }

    pub fn tombstones(&self) -> &BTreeSet<String> {
        &self.tombstones
    }

    /// Returns `true` if `path` currently exists in the virtual workspace view.
    pub fn contains(&self, path: &str) -> bool {
        let Ok(norm) = normalize_rel_path(path) else {
            return false;
        };
        if self.tombstones.contains(&norm) {
            return false;
        }
        self.dirty_files.contains_key(&norm) || self.base_tree.entries.contains_key(&norm)
    }

    /// Snapshot current demand-paging and sparse-overlay statistics in `O(dirty_files)`.
    pub fn stats(&self) -> LazyStats {
        let added_dirty = self
            .dirty_files
            .keys()
            .filter(|p| !self.base_tree.entries.contains_key(*p))
            .count();
        let total_virtual_files = self
            .base_tree
            .entries
            .len()
            .saturating_sub(self.tombstones.len())
            + added_dirty;

        LazyStats {
            total_virtual_files,
            hydrated_reads: self.hydrated_reads.load(Ordering::Relaxed),
            overlay_dirty_files: self.dirty_files.len(),
            tombstones: self.tombstones.len(),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
        }
    }

    /// Evict all cached hydrated base-file payloads from memory.
    pub fn clear_cache(&self) {
        self.read_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// List all virtual files under `dir_prefix` using the in-memory sorted directory index
    /// without touching disk or hydrating blobs.
    pub fn list_dir(&self, dir_prefix: &str) -> Result<Vec<String>> {
        let trimmed = dir_prefix.trim().trim_matches('/');
        if trimmed.is_empty() || trimmed == "." {
            return self.list_files();
        }
        let norm = normalize_rel_path(trimmed)?;
        let prefix = format!("{norm}/");

        let mut results = BTreeSet::new();
        for key in self.base_tree.entries.range(prefix.clone()..).map(|(k, _)| k) {
            if !key.starts_with(&prefix) {
                break;
            }
            if !self.tombstones.contains(key) {
                results.insert(key.clone());
            }
        }
        for key in self.dirty_files.range(prefix.clone()..).map(|(k, _)| k) {
            if !key.starts_with(&prefix) {
                break;
            }
            results.insert(key.clone());
        }
        Ok(results.into_iter().collect())
    }

    /// Partition the virtual workspace across Visibility Domains using `classify`, cloning
    /// unmodified base entries directly in memory and ONLY hashing/uploading dirty overlay
    /// files (`O(dirty_files)` I/O and hashing).
    pub fn snapshot_by_domain<F>(
        &self,
        store: &dyn ObjectStore,
        classify: F,
    ) -> Result<BTreeMap<DomainId, DomainTree>>
    where
        F: Fn(&str) -> DomainId,
    {
        let mut dirty_entries = Vec::with_capacity(self.dirty_files.len());
        for (rel_path, &mode) in &self.dirty_files {
            let data = self.read_overlay_file(rel_path)?;
            let blob = store_blob_if_changed(store, &data)?;
            dirty_entries.push((
                rel_path.clone(),
                EntryKind::File {
                    blob_hash: blob.manifest_hash(),
                    mode,
                    size: blob.total_size,
                },
            ));
        }

        let mut trees: BTreeMap<DomainId, DomainTree> = BTreeMap::new();

        for (path, entry) in &self.base_tree.entries {
            if self.tombstones.contains(path) || self.dirty_files.contains_key(path) {
                continue;
            }
            let domain = classify(path);
            let tree = trees
                .entry(domain.clone())
                .or_insert_with(|| DomainTree::new(domain));
            tree.insert(path.clone(), entry.clone());
        }

        for (rel_path, entry) in dirty_entries {
            let domain = classify(&rel_path);
            let tree = trees
                .entry(domain.clone())
                .or_insert_with(|| DomainTree::new(domain));
            tree.insert(rel_path, entry);
        }

        Ok(trees)
    }

    fn read_overlay_file(&self, norm: &str) -> Result<Vec<u8>> {
        let full = self.overlay_root.join(norm);
        match fs::symlink_metadata(&full) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let target = fs::read_link(&full)?;
                Ok(target.to_string_lossy().into_owned().into_bytes())
            }
            Ok(_) => Ok(fs::read(&full)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(GitxError::NotFound(format!("lazy workspace file '{norm}'")))
            }
            Err(e) => Err(GitxError::Io(e)),
        }
    }

    fn remove_empty_parent_dirs(&self, path: &Path) {
        let mut cur = path.parent();
        while let Some(dir) = cur {
            if dir == self.overlay_root || !dir.starts_with(&self.overlay_root) {
                break;
            }
            match fs::remove_dir(dir) {
                Ok(()) => cur = dir.parent(),
                Err(_) => break,
            }
        }
    }
}

impl WorkspaceBackend for LazyWorkspace {
    fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let norm = normalize_rel_path(path)?;

        // 1. Tombstones always shadow the base tree.
        if self.tombstones.contains(&norm) {
            return Err(GitxError::NotFound(format!("lazy workspace file '{norm}'")));
        }

        // 2. Sparse local Copy-on-Write overlay takes precedence over the virtual base.
        if self.dirty_files.contains_key(&norm) {
            return self.read_overlay_file(&norm);
        }

        // 3. Check the in-memory hydration cache before touching the ObjectStore.
        {
            let cache = self.read_cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some(cached) = cache.get(&norm) {
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(cached.to_vec());
            }
        }

        // 4. Demand-page from the backing ObjectStore and cache in memory (zero disk writes).
        let entry = self
            .base_tree
            .entries
            .get(&norm)
            .ok_or_else(|| GitxError::NotFound(format!("lazy workspace file '{norm}'")))?;

        let bytes = match entry {
            EntryKind::File { blob_hash, .. } => self.store.read_blob_bytes(*blob_hash)?,
            EntryKind::Conflict { term, .. } => render_conflict_bytes(term, self.store.as_ref())?,
            EntryKind::EncryptedSecret { key_epoch, .. } => {
                return Err(GitxError::AccessDenied {
                    domain: self.base_tree.domain.to_string(),
                    reason: format!(
                        "encrypted secret '{norm}' (key_epoch {key_epoch}) cannot be read without decryption"
                    ),
                });
            }
        };

        self.hydrated_reads.fetch_add(1, Ordering::Relaxed);
        {
            let mut cache = self.read_cache.write().unwrap_or_else(|e| e.into_inner());
            cache.insert(norm, Arc::from(bytes.as_slice()));
        }

        Ok(bytes)
    }

    fn write_file(&mut self, path: &str, data: &[u8], mode: FileMode) -> Result<()> {
        let norm = normalize_rel_path(path)?;
        let full = self.overlay_root.join(&norm);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        remove_if_exists(&full)?;

        if mode == FileMode::Symlink {
            write_symlink(&full, data)?;
        } else {
            fs::write(&full, data)?;
            apply_workspace_permissions(&full, mode)?;
        }

        self.tombstones.remove(&norm);
        self.dirty_files.insert(norm.clone(), mode);
        self.read_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&norm);

        Ok(())
    }

    fn remove_file(&mut self, path: &str) -> Result<()> {
        let norm = normalize_rel_path(path)?;
        if self.tombstones.contains(&norm) {
            return Err(GitxError::NotFound(format!("lazy workspace file '{norm}'")));
        }

        let was_dirty = self.dirty_files.remove(&norm).is_some();
        let in_base = self.base_tree.entries.contains_key(&norm);
        if !was_dirty && !in_base {
            return Err(GitxError::NotFound(format!("lazy workspace file '{norm}'")));
        }

        if was_dirty {
            let full = self.overlay_root.join(&norm);
            remove_if_exists(&full)?;
            self.remove_empty_parent_dirs(&full);
        }

        if in_base {
            self.tombstones.insert(norm.clone());
        }

        self.read_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&norm);

        Ok(())
    }

    fn list_files(&self) -> Result<Vec<String>> {
        let mut files = BTreeSet::new();
        for path in self.base_tree.entries.keys() {
            if !self.tombstones.contains(path) {
                files.insert(path.clone());
            }
        }
        for path in self.dirty_files.keys() {
            files.insert(path.clone());
        }
        Ok(files.into_iter().collect())
    }

    fn materialize_tree(&mut self, tree: &DomainTree, _store: &dyn ObjectStore) -> Result<()> {
        // Clear any existing sparse overlay files on disk without writing base files.
        let existing_dirty: Vec<String> = self.dirty_files.keys().cloned().collect();
        for rel_path in existing_dirty {
            let full = self.overlay_root.join(&rel_path);
            remove_if_exists(&full)?;
            self.remove_empty_parent_dirs(&full);
        }

        self.dirty_files.clear();
        self.tombstones.clear();
        self.clear_cache();
        self.base_tree = tree.clone();
        Ok(())
    }

    fn snapshot_tree(&self, domain: DomainId, store: &dyn ObjectStore) -> Result<DomainTree> {
        let mut tree = DomainTree {
            domain,
            entries: self.base_tree.entries.clone(),
        };

        for tomb in &self.tombstones {
            tree.remove(tomb);
        }

        for (rel_path, &mode) in &self.dirty_files {
            let data = self.read_overlay_file(rel_path)?;
            let blob = store_blob_if_changed(store, &data)?;
            tree.insert(
                rel_path.clone(),
                EntryKind::File {
                    blob_hash: blob.manifest_hash(),
                    mode,
                    size: blob.total_size,
                },
            );
        }

        Ok(tree)
    }

    fn backend_kind(&self) -> WorkspaceBackendKind {
        WorkspaceBackendKind::LazyMount
    }
}
