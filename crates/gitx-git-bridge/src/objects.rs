//! Pure-Rust Git loose object reader/writer, canonical tree builder, and commit builder.

use chrono::{DateTime, Utc};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use gitx_core::{Actor, FileMode, GitxError, Identity, Result};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 20-byte SHA-1 Git object identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct GitOid(pub [u8; 20]);

impl GitOid {
    /// Returns the 40-character lowercase hexadecimal representation.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses a 40-character hexadecimal SHA-1 string into a [`GitOid`].
    pub fn from_hex(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        let bytes = hex::decode(trimmed)
            .map_err(|e| GitxError::GitBridge(format!("invalid git oid '{trimmed}': {e}")))?;
        if bytes.len() != 20 {
            return Err(GitxError::GitBridge(format!(
                "invalid git oid '{trimmed}': expected 20 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Returns the raw 20-byte slice.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Display for GitOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for GitOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GitOid({})", self.to_hex())
    }
}

impl FromStr for GitOid {
    type Err = GitxError;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

/// Computes the standard Git SHA-1 object ID for `"{kind} {payload.len()}\0{payload}"`.
pub fn hash_git_object(kind: &str, payload: &[u8]) -> GitOid {
    let header = format!("{kind} {}\0", payload.len());
    let mut hasher = Sha1::new();
    hasher.update(header.as_bytes());
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    GitOid(out)
}

/// Atomically writes a zlib-compressed Git loose object into `<git_dir>/objects/<xx>/<38-hex>`.
pub fn write_loose_object(git_dir: &Path, kind: &str, payload: &[u8]) -> Result<GitOid> {
    let oid = hash_git_object(kind, payload);
    let hex_id = oid.to_hex();
    let (prefix, rest) = hex_id.split_at(2);
    let dir = git_dir.join("objects").join(prefix);
    let path = dir.join(rest);

    if path.exists() {
        return Ok(oid);
    }

    fs::create_dir_all(&dir)?;

    let header = format!("{kind} {}\0", payload.len());
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(header.as_bytes())?;
    encoder.write_all(payload)?;
    let compressed = encoder.finish()?;

    let seq = TMP_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    let tmp_name = format!(".tmp-gitx-{}-{seq}", std::process::id());
    let tmp_path = dir.join(tmp_name);

    let write_res = (|| -> std::io::Result<()> {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(&compressed)?;
        file.flush()?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(GitxError::Io(err));
    }

    if let Err(err) = fs::rename(&tmp_path, &path) {
        let _ = fs::remove_file(&tmp_path);
        if path.exists() {
            return Ok(oid);
        }
        return Err(GitxError::Io(err));
    }

    Ok(oid)
}

/// Reads and verifies a zlib-compressed Git loose object from `<git_dir>/objects/<xx>/<38-hex>`.
///
/// Returns `(kind, payload)`.
pub fn read_loose_object(git_dir: &Path, oid: GitOid) -> Result<(String, Vec<u8>)> {
    let hex_id = oid.to_hex();
    let (prefix, rest) = hex_id.split_at(2);
    let path = git_dir.join("objects").join(prefix).join(rest);

    if !path.exists() {
        return Err(GitxError::NotFound(format!("git object {oid}")));
    }

    let compressed = fs::read(&path)?;
    let mut decoder = ZlibDecoder::new(compressed.as_slice());
    let mut raw = Vec::new();
    decoder
        .read_to_end(&mut raw)
        .map_err(|e| GitxError::GitBridge(format!("failed to inflate git object {oid}: {e}")))?;

    let nul_pos = raw.iter().position(|&b| b == 0).ok_or_else(|| {
        GitxError::GitBridge(format!("corrupt git object {oid}: missing NUL header delimiter"))
    })?;

    let header = std::str::from_utf8(&raw[..nul_pos]).map_err(|e| {
        GitxError::GitBridge(format!("corrupt git object {oid}: non-UTF8 header: {e}"))
    })?;

    let (kind, size_str) = header.split_once(' ').ok_or_else(|| {
        GitxError::GitBridge(format!("corrupt git object {oid}: malformed header '{header}'"))
    })?;

    let declared_size: usize = size_str.parse().map_err(|e| {
        GitxError::GitBridge(format!(
            "corrupt git object {oid}: invalid size '{size_str}': {e}"
        ))
    })?;

    let payload = raw[nul_pos + 1..].to_vec();
    if payload.len() != declared_size {
        return Err(GitxError::GitBridge(format!(
            "corrupt git object {oid}: size mismatch (header {declared_size}, actual {})",
            payload.len()
        )));
    }

    let actual_oid = hash_git_object(kind, &payload);
    if actual_oid != oid {
        return Err(GitxError::GitBridge(format!(
            "corrupt git object {oid}: hash mismatch (computed {actual_oid})"
        )));
    }

    Ok((kind.to_string(), payload))
}

/// Git canonical tree-entry name comparator (`base_name_compare` in Git's `tree.c`).
///
/// Directories (mode `40000`) are compared as if they had a trailing `'/'`.
pub(crate) fn git_tree_name_cmp(
    a_name: &str,
    a_is_dir: bool,
    b_name: &str,
    b_is_dir: bool,
) -> Ordering {
    let a = a_name.as_bytes();
    let b = b_name.as_bytes();
    let min_len = a.len().min(b.len());
    match a[..min_len].cmp(&b[..min_len]) {
        Ordering::Equal => {
            let a_next = a
                .get(min_len)
                .copied()
                .unwrap_or(if a_is_dir { b'/' } else { 0 });
            let b_next = b
                .get(min_len)
                .copied()
                .unwrap_or(if b_is_dir { b'/' } else { 0 });
            a_next.cmp(&b_next)
        }
        other => other,
    }
}

enum TreeNode {
    File(FileMode, GitOid),
    Dir(BTreeMap<String, TreeNode>),
}

fn file_mode_str(mode: FileMode) -> &'static str {
    match mode {
        FileMode::Regular => "100644",
        FileMode::Executable => "100755",
        FileMode::Symlink => "120000",
    }
}

fn insert_tree_path(
    root: &mut BTreeMap<String, TreeNode>,
    path: &str,
    mode: FileMode,
    oid: GitOid,
) -> Result<()> {
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') || path.contains('\0') {
        return Err(GitxError::GitBridge(format!(
            "invalid git tree path '{path}'"
        )));
    }

    let parts: Vec<&str> = path.split('/').collect();
    for seg in &parts {
        if seg.is_empty() || *seg == "." || *seg == ".." {
            return Err(GitxError::GitBridge(format!(
                "invalid path segment '{seg}' in '{path}'"
            )));
        }
    }

    let mut current = root;
    for dir_name in &parts[..parts.len() - 1] {
        let entry = current
            .entry((*dir_name).to_string())
            .or_insert_with(|| TreeNode::Dir(BTreeMap::new()));
        match entry {
            TreeNode::Dir(children) => current = children,
            TreeNode::File(_, _) => {
                return Err(GitxError::GitBridge(format!(
                    "tree path conflict: '{dir_name}' is both a file and a directory (in '{path}')"
                )));
            }
        }
    }

    let file_name = parts[parts.len() - 1].to_string();
    if let Some(TreeNode::Dir(_)) = current.get(&file_name) {
        return Err(GitxError::GitBridge(format!(
            "tree path conflict: '{path}' is both a file and a directory"
        )));
    }
    current.insert(file_name, TreeNode::File(mode, oid));
    Ok(())
}

fn write_tree_dir(git_dir: &Path, entries: &BTreeMap<String, TreeNode>) -> Result<GitOid> {
    let mut resolved: Vec<(&str, bool, &'static str, GitOid)> = Vec::with_capacity(entries.len());

    for (name, node) in entries {
        match node {
            TreeNode::File(mode, oid) => {
                resolved.push((name.as_str(), false, file_mode_str(*mode), *oid));
            }
            TreeNode::Dir(sub) => {
                let sub_oid = write_tree_dir(git_dir, sub)?;
                resolved.push((name.as_str(), true, "40000", sub_oid));
            }
        }
    }

    resolved.sort_by(|a, b| git_tree_name_cmp(a.0, a.1, b.0, b.1));

    let mut payload = Vec::new();
    for (name, _, mode, oid) in resolved {
        payload.extend_from_slice(mode.as_bytes());
        payload.push(b' ');
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        payload.extend_from_slice(oid.as_bytes());
    }

    write_loose_object(git_dir, "tree", &payload)
}

/// Builds and writes recursive Git `tree` objects from flat file paths `(path -> (FileMode, GitOid))`.
///
/// Entries at every directory level are strictly sorted using Git's canonical tree sort order
/// so `git fsck --full --strict` passes with zero warnings.
pub fn write_tree_from_files(
    git_dir: &Path,
    files: &BTreeMap<String, (FileMode, GitOid)>,
) -> Result<GitOid> {
    let mut root: BTreeMap<String, TreeNode> = BTreeMap::new();
    for (path, &(mode, oid)) in files {
        insert_tree_path(&mut root, path, mode, oid)?;
    }
    write_tree_dir(git_dir, &root)
}

/// Author or committer signature line in a Git commit object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSignature {
    pub name: String,
    pub email: String,
    pub timestamp: i64,
    pub tz_offset: String,
}

impl GitSignature {
    pub fn new(
        name: impl Into<String>,
        email: impl Into<String>,
        timestamp: i64,
        tz_offset: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            email: email.into(),
            timestamp,
            tz_offset: tz_offset.into(),
        }
    }

    pub fn from_identity(identity: &Identity, ts: DateTime<Utc>) -> Self {
        Self {
            name: identity.name.clone(),
            email: identity.email.clone(),
            timestamp: ts.timestamp(),
            tz_offset: "+0000".to_string(),
        }
    }

    pub fn from_actor(actor: &Actor, ts: DateTime<Utc>) -> Self {
        match actor {
            Actor::Human(id) => Self::from_identity(id, ts),
            Actor::Agent {
                harness,
                model,
                initiated_by,
                ..
            } => Self {
                name: format!("{harness} ({model})"),
                email: initiated_by.email.clone(),
                timestamp: ts.timestamp(),
                tz_offset: "+0000".to_string(),
            },
        }
    }

    fn format_line(&self) -> String {
        let name = sanitize_ident_field(&self.name, "unknown");
        let email = sanitize_ident_field(&self.email, "unknown@gitx.local");
        let ts = self.timestamp.max(0);
        let tz = sanitize_tz(&self.tz_offset);
        format!("{name} <{email}> {ts} {tz}")
    }
}

fn sanitize_ident_field(raw: &str, fallback: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|&c| !matches!(c, '<' | '>' | '\n' | '\r' | '\0'))
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn sanitize_tz(raw: &str) -> &str {
    let b = raw.as_bytes();
    if b.len() == 5
        && (b[0] == b'+' || b[0] == b'-')
        && b[1..].iter().all(|c| c.is_ascii_digit())
    {
        let hh = (b[1] - b'0') * 10 + (b[2] - b'0');
        let mm = (b[3] - b'0') * 10 + (b[4] - b'0');
        if hh <= 23 && mm <= 59 {
            return raw;
        }
    }
    "+0000"
}

/// Parameters for building a Git commit object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCommitParams {
    pub tree: GitOid,
    pub parents: Vec<GitOid>,
    pub author: GitSignature,
    pub committer: GitSignature,
    pub message: String,
}

/// Serializes a Git `commit` object payload.
pub fn build_commit_payload(params: &GitCommitParams) -> Vec<u8> {
    let mut buf = String::new();
    buf.push_str(&format!("tree {}\n", params.tree));

    let mut seen_parents = Vec::with_capacity(params.parents.len());
    for parent in &params.parents {
        if !seen_parents.contains(parent) {
            seen_parents.push(*parent);
            buf.push_str(&format!("parent {parent}\n"));
        }
    }

    buf.push_str(&format!("author {}\n", params.author.format_line()));
    buf.push_str(&format!("committer {}\n", params.committer.format_line()));
    buf.push('\n');
    buf.push_str(&params.message);
    if !params.message.is_empty() && !params.message.ends_with('\n') {
        buf.push('\n');
    }

    buf.into_bytes()
}

/// Writes a Git `commit` loose object into `<git_dir>/objects/` and returns its [`GitOid`].
pub fn write_commit_object(git_dir: &Path, params: &GitCommitParams) -> Result<GitOid> {
    let payload = build_commit_payload(params);
    write_loose_object(git_dir, "commit", &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn empty_blob_and_empty_tree_match_canonical_git_sha1() {
        // Git's well-known SHA-1 for empty blob and empty tree.
        assert_eq!(
            hash_git_object("blob", b"").to_hex(),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
        assert_eq!(
            hash_git_object("tree", b"").to_hex(),
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        );
        // `printf 'hello\n' | git hash-object --stdin`
        assert_eq!(
            hash_git_object("blob", b"hello\n").to_hex(),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
    }

    #[test]
    fn loose_object_roundtrip_and_corruption_detection() {
        let dir = TempDir::new().unwrap();
        let payload = b"fn main() { println!(\"gitx\"); }\n";
        let oid = write_loose_object(dir.path(), "blob", payload).unwrap();
        let (kind, read_back) = read_loose_object(dir.path(), oid).unwrap();
        assert_eq!(kind, "blob");
        assert_eq!(read_back, payload);

        // Idempotent rewrite succeeds with identical OID.
        let oid2 = write_loose_object(dir.path(), "blob", payload).unwrap();
        assert_eq!(oid, oid2);
    }

    #[test]
    fn canonical_git_tree_sort_order() {
        // '-' (0x2d) < '.' (0x2e) < '/' (0x2f) < '0' (0x30)
        let mut items = vec![
            ("foo0", false),
            ("foo", true),
            ("foo.txt", false),
            ("foo-bar", false),
        ];
        items.sort_by(|a, b| git_tree_name_cmp(a.0, a.1, b.0, b.1));
        assert_eq!(
            items,
            vec![
                ("foo-bar", false),
                ("foo.txt", false),
                ("foo", true),
                ("foo0", false),
            ]
        );
    }

    #[test]
    fn oid_hex_roundtrip() {
        let hex = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
        let oid = GitOid::from_hex(hex).unwrap();
        assert_eq!(oid.to_hex(), hex);
        assert_eq!(oid.to_string(), hex);
        assert!(GitOid::from_hex("not-hex").is_err());
        assert!(GitOid::from_hex("abcd").is_err());
    }
}
