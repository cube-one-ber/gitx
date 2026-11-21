use gitx_core::oplog::WorkspaceBackendKind;
use gitx_core::{ConflictTerm, DomainId, DomainTree, FileMode, GitxError, Result, chunk_bytes};
use gitx_store::ObjectStore;

/// Lock-free workspace abstraction allowing any number of workspaces (in-memory or
/// copy-on-write on disk) to materialize, edit, and snapshot trees off the same base
/// ChangeSet or bookmark without ever locking a branch.
pub trait WorkspaceBackend: Send + Sync {
    fn read_file(&self, path: &str) -> Result<Vec<u8>>;

    fn write_file(&mut self, path: &str, data: &[u8], mode: FileMode) -> Result<()>;

    fn remove_file(&mut self, path: &str) -> Result<()>;

    fn list_files(&self) -> Result<Vec<String>>;

    fn materialize_tree(&mut self, tree: &DomainTree, store: &dyn ObjectStore) -> Result<()>;

    fn snapshot_tree(&self, domain: DomainId, store: &dyn ObjectStore) -> Result<DomainTree>;

    fn backend_kind(&self) -> WorkspaceBackendKind;
}

/// Normalize and validate a workspace-relative path.
///
/// Converts backslashes to forward slashes, strips leading `./` segments, and rejects
/// empty paths, absolute paths, NUL bytes, Windows drive prefixes, and `.`/`..` traversal
/// components.
pub fn normalize_rel_path(raw: &str) -> Result<String> {
    if raw.is_empty() || raw.contains('\0') {
        return Err(GitxError::Workspace(format!(
            "invalid workspace path: '{raw}'"
        )));
    }

    let replaced = raw.replace('\\', "/");
    if replaced.starts_with('/') {
        return Err(GitxError::Workspace(format!(
            "workspace path must be relative: '{raw}'"
        )));
    }

    let mut trimmed = replaced.as_str();
    while let Some(rest) = trimmed.strip_prefix("./") {
        trimmed = rest;
    }

    if trimmed.is_empty() {
        return Err(GitxError::Workspace(format!(
            "invalid empty workspace path: '{raw}'"
        )));
    }

    let mut parts = Vec::new();
    for (idx, part) in trimmed.split('/').enumerate() {
        if part.is_empty() || part == "." || part == ".." {
            return Err(GitxError::Workspace(format!(
                "invalid path component in '{raw}'"
            )));
        }
        if idx == 0 && part.contains(':') && part.len() == 2 && part.as_bytes()[1] == b':' {
            return Err(GitxError::Workspace(format!(
                "drive-prefixed path is not allowed: '{raw}'"
            )));
        }
        parts.push(part);
    }

    Ok(parts.join("/"))
}

/// Store a blob in `store` only if its manifest is not already persisted.
pub(crate) fn store_blob_if_changed(
    store: &dyn ObjectStore,
    data: &[u8],
) -> Result<gitx_core::ChunkedBlob> {
    let (blob, _) = chunk_bytes(data);
    let manifest_hash = blob.manifest_hash();
    if store.get_blob_manifest(manifest_hash).is_ok() {
        return Ok(blob);
    }
    store.put_blob_bytes(data)
}

/// Render a first-class algebraic `ConflictTerm` into deterministic Jujutsu-style conflict
/// markers so unresolved conflicts never block workspace materialization.
pub(crate) fn render_conflict_bytes(
    term: &ConflictTerm,
    store: &dyn ObjectStore,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(b"<<<<<<< conflict\n");
    for (idx, add) in term.adds.iter().enumerate() {
        out.extend_from_slice(format!("+++++++ side {}\n", idx + 1).as_bytes());
        if let Some(hash) = add {
            let bytes = store.read_blob_bytes(*hash)?;
            out.extend_from_slice(&bytes);
            if !bytes.ends_with(b"\n") {
                out.push(b'\n');
            }
        }
    }
    for (idx, rem) in term.removes.iter().enumerate() {
        out.extend_from_slice(format!("------- base {}\n", idx + 1).as_bytes());
        if let Some(hash) = rem {
            let bytes = store.read_blob_bytes(*hash)?;
            out.extend_from_slice(&bytes);
            if !bytes.ends_with(b"\n") {
                out.push(b'\n');
            }
        }
    }
    out.extend_from_slice(b">>>>>>> conflict end\n");
    Ok(out)
}
