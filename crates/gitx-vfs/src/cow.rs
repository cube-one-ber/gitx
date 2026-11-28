use crate::backend::{
    WorkspaceBackend, normalize_rel_path, render_conflict_bytes, store_blob_if_changed,
};
use gitx_core::oplog::WorkspaceBackendKind;
use gitx_core::{
    DomainId, DomainTree, EntryKind, FileMode, GitxError, ObjectHash, Result, chunk_bytes,
};
use gitx_store::ObjectStore;
use globset::{GlobBuilder, GlobMatcher};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use walkdir::WalkDir;

/// Default ignore patterns always skipped during workspace snapshots.
pub const DEFAULT_IGNORES: &[&str] = &[".git/", ".gitx/", "target/", "node_modules/"];

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
struct IgnoreRule {
    matcher: GlobMatcher,
    basename_matcher: Option<GlobMatcher>,
    dir_only: bool,
    negated: bool,
}

#[derive(Debug, Clone)]
struct IgnoreMatcher {
    rules: Vec<IgnoreRule>,
}

impl IgnoreMatcher {
    fn load(root: &Path, extra_patterns: &[String]) -> Result<Self> {
        let mut raw_patterns: Vec<String> =
            DEFAULT_IGNORES.iter().map(|s| (*s).to_string()).collect();

        // Honor `.gitignore` before `.gitxignore` so colocated Git repositories never
        // snapshot gitignored build artifacts while `.gitxignore` still takes precedence.
        let gitignore_file = root.join(".gitignore");
        let mut gitignore_patterns = Vec::new();
        if gitignore_file.is_file()
            && let Ok(contents) = fs::read_to_string(&gitignore_file)
        {
            for line in contents.lines() {
                gitignore_patterns.push(line.to_string());
            }
        }

        let ignore_file = root.join(".gitxignore");
        if ignore_file.is_file() {
            let contents = fs::read_to_string(&ignore_file)?;
            for line in contents.lines() {
                raw_patterns.push(line.to_string());
            }
        }

        raw_patterns.extend(extra_patterns.iter().cloned());

        let mut rules = Vec::new();
        for raw in gitignore_patterns {
            if let Ok(Some(rule)) = Self::parse_rule(&raw) {
                rules.push(rule);
            }
        }
        for raw in raw_patterns {
            if let Some(rule) = Self::parse_rule(&raw)? {
                rules.push(rule);
            }
        }

        Ok(Self { rules })
    }

    fn parse_rule(raw: &str) -> Result<Option<IgnoreRule>> {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            return Ok(None);
        }

        let (negated, rest) = if let Some(stripped) = line.strip_prefix('!') {
            (true, stripped)
        } else {
            (false, line)
        };

        let (dir_only, rest) = if let Some(stripped) = rest.strip_suffix('/') {
            (true, stripped)
        } else {
            (false, rest)
        };

        let (anchored, pat) = if let Some(stripped) = rest.strip_prefix('/') {
            (true, stripped)
        } else {
            (false, rest)
        };

        if pat.is_empty() {
            return Ok(None);
        }

        let has_slash = pat.contains('/');
        let full_pattern = if anchored || has_slash {
            pat.to_string()
        } else {
            format!("**/{pat}")
        };

        let matcher = GlobBuilder::new(&full_pattern)
            .literal_separator(true)
            .build()
            .map_err(|e| GitxError::Workspace(format!("invalid ignore pattern '{raw}': {e}")))?
            .compile_matcher();

        let basename_matcher = if !anchored && !has_slash {
            Some(
                GlobBuilder::new(pat)
                    .literal_separator(true)
                    .build()
                    .map_err(|e| {
                        GitxError::Workspace(format!("invalid ignore pattern '{raw}': {e}"))
                    })?
                    .compile_matcher(),
            )
        } else {
            None
        };

        Ok(Some(IgnoreRule {
            matcher,
            basename_matcher,
            dir_only,
            negated,
        }))
    }

    fn is_ignored(&self, rel_path: &str, is_dir: bool) -> bool {
        let basename = rel_path.rsplit('/').next().unwrap_or(rel_path);
        let mut ignored = false;

        for rule in &self.rules {
            if rule.dir_only && !is_dir {
                continue;
            }
            let matched = rule.matcher.is_match(rel_path)
                || rule
                    .basename_matcher
                    .as_ref()
                    .is_some_and(|bm| bm.is_match(basename));
            if matched {
                ignored = !rule.negated;
            }
        }

        ignored
    }
}

/// Copy-on-Write / Reflink local disk workspace backed by a shared read-only CAS
/// materialization pool (`<pool_dir>/<blob_hash>`).
///
/// Uses `reflink_copy::reflink_or_copy` (`FICLONE` on XFS/Btrfs, `clonefile` on APFS, with
/// automatic copy fallback) so parallel workspaces materialize cleanly without duplicating
/// disk blocks or locking branches.
#[derive(Debug)]
pub struct CowWorkspace {
    root: PathBuf,
    pool_dir: PathBuf,
    tracked_files: BTreeSet<String>,
    extra_ignores: Vec<String>,
}

impl CowWorkspace {
    /// Open or create a Copy-on-Write workspace at `root` using `pool_dir` as the shared
    /// read-only CAS materialization pool.
    pub fn open(root: impl AsRef<Path>, pool_dir: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let pool_dir = pool_dir.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        fs::create_dir_all(&pool_dir)?;
        Ok(Self {
            root,
            pool_dir,
            tracked_files: BTreeSet::new(),
            extra_ignores: Vec::new(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn pool_dir(&self) -> &Path {
        &self.pool_dir
    }

    pub fn tracked_files(&self) -> &BTreeSet<String> {
        &self.tracked_files
    }

    /// Return the path inside the shared CAS pool for `blob_hash`.
    pub fn pool_path_for(&self, blob_hash: ObjectHash) -> PathBuf {
        self.pool_dir.join(blob_hash.to_hex())
    }

    /// Add extra ignore patterns programmatically (in addition to [`DEFAULT_IGNORES`] and
    /// `<root>/.gitxignore`).
    pub fn add_ignore_pattern(&mut self, pattern: impl Into<String>) {
        self.extra_ignores.push(pattern.into());
    }

    /// Scan all non-ignored working files from disk without writing blobs to an `ObjectStore`.
    pub fn scan_files(&self) -> Result<Vec<(String, Vec<u8>, FileMode)>> {
        self.scan_working_files_with(|_| false)
    }

    /// Scan working files from disk, allowing files matching `force_include` (such as `.env`
    /// files routed to `secret:*` domains in `.gitxacl`) even if listed in `.gitignore`.
    pub fn scan_files_allowing<F>(
        &self,
        force_include: F,
    ) -> Result<Vec<(String, Vec<u8>, FileMode)>>
    where
        F: Fn(&str) -> bool,
    {
        self.scan_working_files_with(force_include)
    }

    /// Partition all non-ignored working files cleanly across Visibility Domains using
    /// `classify`.
    pub fn snapshot_by_domain<F>(
        &self,
        store: &dyn ObjectStore,
        classify: F,
    ) -> Result<BTreeMap<DomainId, DomainTree>>
    where
        F: Fn(&str) -> DomainId,
    {
        let files = self.scan_working_files()?;
        let mut trees: BTreeMap<DomainId, DomainTree> = BTreeMap::new();
        for (rel_path, data, mode) in files {
            let domain = classify(&rel_path);
            let blob = store_blob_if_changed(store, &data)?;
            let tree = trees
                .entry(domain.clone())
                .or_insert_with(|| DomainTree::new(domain));
            tree.insert(
                rel_path,
                EntryKind::File {
                    blob_hash: blob.manifest_hash(),
                    mode,
                    size: blob.total_size,
                },
            );
        }
        Ok(trees)
    }

    fn ensure_pool_blob(&self, blob_hash: ObjectHash, store: &dyn ObjectStore) -> Result<PathBuf> {
        let pool_path = self.pool_path_for(blob_hash);
        if pool_path.is_file() {
            return Ok(pool_path);
        }

        let bytes = store.read_blob_bytes(blob_hash)?;
        fs::create_dir_all(&self.pool_dir)?;

        let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = self.pool_dir.join(format!(
            ".tmp-{}-{}-{}",
            blob_hash.short(),
            std::process::id(),
            seq
        ));

        write_private_temp_file(&tmp_path, &bytes)?;
        set_readonly_pool_permissions(&tmp_path)?;

        match fs::rename(&tmp_path, &pool_path) {
            Ok(()) => Ok(pool_path),
            Err(err) => {
                let _ = fs::remove_file(&tmp_path);
                if pool_path.is_file() {
                    Ok(pool_path)
                } else {
                    Err(GitxError::Io(err))
                }
            }
        }
    }

    fn scan_working_files(&self) -> Result<Vec<(String, Vec<u8>, FileMode)>> {
        self.scan_working_files_with(|_| false)
    }

    fn scan_working_files_with<F>(
        &self,
        force_include: F,
    ) -> Result<Vec<(String, Vec<u8>, FileMode)>>
    where
        F: Fn(&str) -> bool,
    {
        let matcher = IgnoreMatcher::load(&self.root, &self.extra_ignores)?;
        let mut results = Vec::new();

        let walker = WalkDir::new(&self.root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                if entry.depth() == 0 {
                    return true;
                }
                let Ok(rel) = entry.path().strip_prefix(&self.root) else {
                    return false;
                };
                let rel_str = path_to_slash_string(rel);
                if rel_str == ".git" || rel_str == ".gitx" {
                    return false;
                }
                let is_dir = entry.file_type().is_dir();
                if !is_dir && force_include(&rel_str) {
                    return true;
                }
                !matcher.is_ignored(&rel_str, is_dir)
            });

        for entry_res in walker {
            let entry = entry_res
                .map_err(|e| GitxError::Workspace(format!("walkdir error in workspace: {e}")))?;
            if entry.depth() == 0 {
                continue;
            }
            let ft = entry.file_type();
            if ft.is_dir() {
                continue;
            }

            let rel = entry.path().strip_prefix(&self.root).map_err(|e| {
                GitxError::Workspace(format!("failed to strip workspace root prefix: {e}"))
            })?;
            let rel_str = normalize_rel_path(&path_to_slash_string(rel))?;

            if ft.is_symlink() {
                let target = fs::read_link(entry.path())?;
                let target_bytes = target.to_string_lossy().into_owned().into_bytes();
                results.push((rel_str, target_bytes, FileMode::Symlink));
            } else if ft.is_file() {
                let data = fs::read(entry.path())?;
                let mode = detect_file_mode(entry.path())?;
                results.push((rel_str, data, mode));
            }
        }

        results.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(results)
    }

    fn remove_empty_parent_dirs(&self, path: &Path) {
        let mut cur = path.parent();
        while let Some(dir) = cur {
            if dir == self.root || !dir.starts_with(&self.root) {
                break;
            }
            match fs::remove_dir(dir) {
                Ok(()) => cur = dir.parent(),
                Err(_) => break,
            }
        }
    }
}

impl WorkspaceBackend for CowWorkspace {
    fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let norm = normalize_rel_path(path)?;
        ensure_no_symlink_ancestors(&self.root, &norm)?;
        let full = self.root.join(&norm);
        match fs::symlink_metadata(&full) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let target = fs::read_link(&full)?;
                Ok(target.to_string_lossy().into_owned().into_bytes())
            }
            Ok(_) => Ok(fs::read(&full)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(GitxError::NotFound(format!("workspace file '{norm}'")))
            }
            Err(e) => Err(GitxError::Io(e)),
        }
    }

    fn write_file(&mut self, path: &str, data: &[u8], mode: FileMode) -> Result<()> {
        let norm = normalize_rel_path(path)?;
        ensure_no_symlink_ancestors(&self.root, &norm)?;
        let full = self.root.join(&norm);
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

        self.tracked_files.insert(norm);
        Ok(())
    }

    fn remove_file(&mut self, path: &str) -> Result<()> {
        let norm = normalize_rel_path(path)?;
        ensure_no_symlink_ancestors(&self.root, &norm)?;
        let full = self.root.join(&norm);
        match fs::symlink_metadata(&full) {
            Ok(_) => {
                make_writable_if_needed(&full);
                fs::remove_file(&full)?;
                self.remove_empty_parent_dirs(&full);
                self.tracked_files.remove(&norm);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(GitxError::NotFound(format!("workspace file '{norm}'")))
            }
            Err(e) => Err(GitxError::Io(e)),
        }
    }

    fn list_files(&self) -> Result<Vec<String>> {
        let matcher = IgnoreMatcher::load(&self.root, &self.extra_ignores)?;
        let mut paths = Vec::new();

        let walker = WalkDir::new(&self.root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                if entry.depth() == 0 {
                    return true;
                }
                let Ok(rel) = entry.path().strip_prefix(&self.root) else {
                    return false;
                };
                let rel_str = path_to_slash_string(rel);
                !matcher.is_ignored(&rel_str, entry.file_type().is_dir())
            });

        for entry_res in walker {
            let entry = entry_res
                .map_err(|e| GitxError::Workspace(format!("walkdir error in workspace: {e}")))?;
            if entry.depth() == 0 || entry.file_type().is_dir() {
                continue;
            }
            let rel = entry.path().strip_prefix(&self.root).map_err(|e| {
                GitxError::Workspace(format!("failed to strip workspace root prefix: {e}"))
            })?;
            paths.push(normalize_rel_path(&path_to_slash_string(rel))?);
        }

        paths.sort();
        Ok(paths)
    }

    fn materialize_tree(&mut self, tree: &DomainTree, store: &dyn ObjectStore) -> Result<()> {
        let mut new_tracked = BTreeSet::new();

        // Pre-validate that no tree entry writes beneath a symlink entry in the same tree.
        let mut symlink_paths: BTreeSet<String> = BTreeSet::new();
        let mut normalized_entries: Vec<(String, &EntryKind)> =
            Vec::with_capacity(tree.entries.len());
        for (raw_path, kind) in &tree.entries {
            let norm = normalize_rel_path(raw_path)?;
            if matches!(
                kind,
                EntryKind::File {
                    mode: FileMode::Symlink,
                    ..
                }
            ) {
                symlink_paths.insert(norm.clone());
            }
            normalized_entries.push((norm, kind));
        }
        for (norm, kind) in &normalized_entries {
            if let EntryKind::EncryptedSecret { key_epoch, .. } = kind {
                return Err(GitxError::AccessDenied {
                    domain: tree.domain.to_string(),
                    reason: format!(
                        "encrypted secret '{norm}' (key_epoch {key_epoch}) cannot be materialized without decryption"
                    ),
                });
            }
            for prefix in ancestor_rel_paths(norm) {
                if symlink_paths.contains(&prefix) {
                    return Err(GitxError::Workspace(format!(
                        "refusing to materialize '{norm}' beneath symlink ancestor '{prefix}'"
                    )));
                }
            }
        }

        let incoming_paths: BTreeSet<String> = normalized_entries
            .iter()
            .map(|(norm, _)| norm.clone())
            .collect();

        // Remove stale tracked files BEFORE materializing new entries (and never traverse a
        // symlink ancestor) so replacing a directory with a symlink cannot delete files outside
        // the workspace root.
        for stale in self.tracked_files.difference(&incoming_paths) {
            if ensure_no_symlink_ancestors(&self.root, stale).is_err() {
                // Preserve tracking for any stale path that could not be safely inspected/removed.
                new_tracked.insert(stale.clone());
                continue;
            }
            let full = self.root.join(stale);
            if fs::symlink_metadata(&full).is_ok() {
                make_writable_if_needed(&full);
                remove_if_exists(&full)?;
                self.remove_empty_parent_dirs(&full);
            }
        }

        for (norm, kind) in normalized_entries {
            ensure_no_symlink_ancestors(&self.root, &norm)?;
            let dest = self.root.join(&norm);

            match kind {
                EntryKind::File {
                    blob_hash,
                    mode,
                    size,
                } => {
                    if *mode == FileMode::Symlink {
                        let target_bytes = store.read_blob_bytes(*blob_hash)?;
                        let unchanged = fs::symlink_metadata(&dest)
                            .ok()
                            .filter(|m| m.file_type().is_symlink())
                            .and_then(|_| fs::read_link(&dest).ok())
                            .is_some_and(|existing| {
                                existing.to_string_lossy().as_bytes() == target_bytes.as_slice()
                            });
                        if !unchanged {
                            if let Some(parent) = dest.parent() {
                                fs::create_dir_all(parent)?;
                            }
                            remove_if_exists(&dest)?;
                            write_symlink(&dest, &target_bytes)?;
                        }
                    } else {
                        let unchanged = is_unchanged_regular_file(&dest, *blob_hash, *size)?;
                        if unchanged {
                            apply_workspace_permissions(&dest, *mode)?;
                        } else {
                            let pool_path = self.ensure_pool_blob(*blob_hash, store)?;
                            if let Some(parent) = dest.parent() {
                                fs::create_dir_all(parent)?;
                            }
                            remove_if_exists(&dest)?;
                            reflink_copy::reflink_or_copy(&pool_path, &dest)?;
                            apply_workspace_permissions(&dest, *mode)?;
                        }
                    }
                }
                EntryKind::Conflict { term, mode } => {
                    let bytes = render_conflict_bytes(term, store)?;
                    if let Some(parent) = dest.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    remove_if_exists(&dest)?;
                    fs::write(&dest, &bytes)?;
                    apply_workspace_permissions(&dest, *mode)?;
                }
                EntryKind::EncryptedSecret { .. } => unreachable!("validated above"),
            }

            new_tracked.insert(norm);
        }

        self.tracked_files = new_tracked;
        Ok(())
    }

    fn snapshot_tree(&self, domain: DomainId, store: &dyn ObjectStore) -> Result<DomainTree> {
        let mut tree = DomainTree::new(domain);
        for (rel_path, data, mode) in self.scan_working_files()? {
            let blob = store_blob_if_changed(store, &data)?;
            tree.insert(
                rel_path,
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
        WorkspaceBackendKind::CopyOnWrite
    }
}

fn path_to_slash_string(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn is_unchanged_regular_file(
    dest: &Path,
    expected_blob: ObjectHash,
    expected_size: u64,
) -> Result<bool> {
    let meta = match fs::symlink_metadata(dest) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(GitxError::Io(e)),
    };

    if !meta.file_type().is_file() || meta.len() != expected_size {
        return Ok(false);
    }

    let bytes = fs::read(dest)?;
    let (blob, _) = chunk_bytes(&bytes);
    Ok(blob.manifest_hash() == expected_blob)
}

pub(crate) fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
                // Only remove empty directories so replacing a directory path with a file never
                // silently wipes untracked user files inside that directory.
                fs::remove_dir(path)?;
            } else {
                make_writable_if_needed(path);
                fs::remove_file(path)?;
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(GitxError::Io(e)),
    }
}

pub(crate) fn make_writable_if_needed(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::symlink_metadata(path)
            && !meta.file_type().is_symlink()
        {
            let mode = meta.permissions().mode();
            if mode & 0o200 == 0 {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o600));
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Ok(meta) = fs::symlink_metadata(path)
            && !meta.file_type().is_symlink()
        {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = fs::set_permissions(path, perms);
            }
        }
    }
}

fn set_readonly_pool_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
    }
    #[cfg(not(unix))]
    {
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_readonly(true);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

pub(crate) fn apply_workspace_permissions(path: &Path, mode: FileMode) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let unix_mode = match mode {
            FileMode::Executable => 0o755,
            FileMode::Regular | FileMode::Symlink => 0o644,
        };
        fs::set_permissions(path, fs::Permissions::from_mode(unix_mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        let mut perms = fs::metadata(path)?.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            fs::set_permissions(path, perms)?;
        }
    }
    Ok(())
}

pub(crate) fn detect_file_mode(path: &Path) -> Result<FileMode> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Ok(FileMode::Symlink);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 != 0 {
            return Ok(FileMode::Executable);
        }
    }
    Ok(FileMode::Regular)
}

pub(crate) fn ancestor_rel_paths(rel_path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut parts = rel_path.split('/').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            break;
        }
        if !cur.is_empty() {
            cur.push('/');
        }
        cur.push_str(part);
        out.push(cur.clone());
    }
    out
}

pub(crate) fn ensure_no_symlink_ancestors(root: &Path, rel_path: &str) -> Result<()> {
    let mut cur = root.to_path_buf();
    let mut parts = rel_path.split('/').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            break;
        }
        cur.push(part);
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(GitxError::Workspace(format!(
                    "refusing to traverse symlink ancestor '{}' while accessing '{rel_path}'",
                    cur.display()
                )));
            }
            Ok(meta) if !meta.file_type().is_dir() => {
                return Err(GitxError::Workspace(format!(
                    "non-directory ancestor '{}' while accessing '{rel_path}'",
                    cur.display()
                )));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(GitxError::Io(e)),
        }
    }
    Ok(())
}

fn write_private_temp_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

pub(crate) fn write_symlink(dest: &Path, target_bytes: &[u8]) -> Result<()> {
    let target = std::str::from_utf8(target_bytes)
        .map_err(|e| GitxError::Workspace(format!("invalid UTF-8 symlink target: {e}")))?;
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, dest)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(dest, target.as_bytes())?;
        Ok(())
    }
}
