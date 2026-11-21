use crate::merge::{MergeOutcome, merge_bytes};
use crate::tree_merge::materialize_conflict;
use gitx_core::{DomainTree, EntryKind, ObjectHash, Result};
use serde::{Deserialize, Serialize};
use similar::TextDiff;
use std::collections::BTreeSet;

/// Status of a path between two `DomainTree`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffStatus {
    Added,
    Modified,
    Deleted,
    Conflicted,
}

/// Diff entry summarizing a single changed path between two `DomainTree`s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeDiffEntry {
    pub path: String,
    pub status: DiffStatus,
    pub old_hash: Option<ObjectHash>,
    pub new_hash: Option<ObjectHash>,
}

/// Render a standard unified diff between two byte buffers for `path`.
///
/// Returns an empty string when `old == new`. For non-UTF-8 content, returns a binary diff notice.
pub fn unified_diff(path: &str, old: &[u8], new: &[u8]) -> String {
    if old == new {
        return String::new();
    }

    let (Ok(old_str), Ok(new_str)) = (std::str::from_utf8(old), std::str::from_utf8(new)) else {
        return format!("Binary files a/{path} and b/{path} differ\n");
    };

    TextDiff::from_lines(old_str, new_str)
        .unified_diff()
        .context_radius(3)
        .header(&format!("a/{path}"), &format!("b/{path}"))
        .to_string()
}

/// Compute the sorted list of path-level differences between `old` and `new` trees.
pub fn diff_trees(old: &DomainTree, new: &DomainTree) -> Vec<TreeDiffEntry> {
    let mut paths: BTreeSet<&str> = BTreeSet::new();
    paths.extend(old.entries.keys().map(String::as_str));
    paths.extend(new.entries.keys().map(String::as_str));

    let mut entries = Vec::new();
    for path in paths {
        let old_entry = old.entries.get(path);
        let new_entry = new.entries.get(path);

        if old_entry == new_entry {
            continue;
        }

        let (status, old_hash, new_hash) = match (old_entry, new_entry) {
            (None, Some(new_e)) => {
                let status = if matches!(new_e, EntryKind::Conflict { .. }) {
                    DiffStatus::Conflicted
                } else {
                    DiffStatus::Added
                };
                (status, None, entry_primary_hash(new_e))
            }
            (Some(old_e), None) => (DiffStatus::Deleted, entry_primary_hash(old_e), None),
            (Some(old_e), Some(new_e)) => {
                let status = if matches!(new_e, EntryKind::Conflict { .. }) {
                    DiffStatus::Conflicted
                } else {
                    DiffStatus::Modified
                };
                (status, entry_primary_hash(old_e), entry_primary_hash(new_e))
            }
            (None, None) => unreachable!(),
        };

        entries.push(TreeDiffEntry {
            path: path.to_string(),
            status,
            old_hash,
            new_hash,
        });
    }

    entries
}

/// Compute a Graphite-style interdiff between revision v1 (`v1_base -> v1_head`) and
/// revision v2 (`v2_base -> v2_head`) of the same logical `ChangeId`.
///
/// Works seamlessly even when `v2` was rebased onto a newer upstream base (`v2_base != v1_base`):
/// - Upstream-only changes to unrelated files produce zero noise.
/// - For files modified by both upstream and the change, `v1` is virtually rebased onto `v2_base`
///   using 3-way merge so only the author's actual v1->v2 delta is rendered.
/// - When upstream changes overlapped directly with `v1` (conflict during rebase), falls back to
///   a diff-of-diffs comparing the v1 patch against the v2 patch.
pub fn render_interdiff<F>(
    v1_base: &DomainTree,
    v1_head: &DomainTree,
    v2_base: &DomainTree,
    v2_head: &DomainTree,
    read_blob: F,
) -> Result<String>
where
    F: Fn(ObjectHash) -> Result<Vec<u8>>,
{
    let v1_diff = diff_trees(v1_base, v1_head);
    let v2_diff = diff_trees(v2_base, v2_head);

    let mut touched_paths: BTreeSet<&str> = BTreeSet::new();
    for e in &v1_diff {
        touched_paths.insert(e.path.as_str());
    }
    for e in &v2_diff {
        touched_paths.insert(e.path.as_str());
    }

    let mut out = String::new();
    for path in touched_paths {
        let b1 = read_tree_entry(v1_base, path, &read_blob)?;
        let h1 = read_tree_entry(v1_head, path, &read_blob)?;
        let b2 = read_tree_entry(v2_base, path, &read_blob)?;
        let h2 = read_tree_entry(v2_head, path, &read_blob)?;

        let patch = if b1 == b2 {
            // Same base for this file: direct diff from v1_head to v2_head
            unified_diff(path, &h1, &h2)
        } else {
            // Rebased base for this file: virtually rebase v1's edit onto v2_base
            match merge_bytes(path, &b1, &h1, &b2) {
                MergeOutcome::Clean(v1_rebased) => unified_diff(path, &v1_rebased, &h2),
                MergeOutcome::Conflict { .. } => {
                    // Upstream overlapped directly with v1's edit: fall back to diff-of-diffs
                    let p1 = unified_diff(path, &b1, &h1);
                    let p2 = unified_diff(path, &b2, &h2);
                    if p1 == p2 {
                        String::new()
                    } else {
                        TextDiff::from_lines(&p1, &p2)
                            .unified_diff()
                            .context_radius(3)
                            .header(&format!("v1/{path}"), &format!("v2/{path}"))
                            .to_string()
                    }
                }
            }
        };

        out.push_str(&patch);
    }

    Ok(out)
}

fn entry_primary_hash(entry: &EntryKind) -> Option<ObjectHash> {
    match entry {
        EntryKind::File { blob_hash, .. } => Some(*blob_hash),
        EntryKind::EncryptedSecret { envelope_hash, .. } => Some(*envelope_hash),
        EntryKind::Conflict { .. } => None,
    }
}

fn read_tree_entry<F>(tree: &DomainTree, path: &str, read_blob: &F) -> Result<Vec<u8>>
where
    F: Fn(ObjectHash) -> Result<Vec<u8>>,
{
    match tree.entries.get(path) {
        None => Ok(Vec::new()),
        Some(EntryKind::File { blob_hash, .. }) => read_blob(*blob_hash),
        Some(EntryKind::EncryptedSecret { envelope_hash, .. }) => read_blob(*envelope_hash),
        Some(EntryKind::Conflict { term, .. }) => materialize_conflict(term, path, read_blob),
    }
}
