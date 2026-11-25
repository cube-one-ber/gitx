use crate::merge::{MergeOutcome, merge_bytes};
use gitx_core::{ConflictTerm, DomainTree, EntryKind, FileMode, GitxError, ObjectHash, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Result of an algebraic 3-way merge of two `DomainTree`s against a common base.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeMergeResult {
    /// Resulting tree. Conflicting paths are recorded directly as `EntryKind::Conflict`.
    pub tree: DomainTree,
    /// Sorted list of paths that resolved cleanly without conflict.
    pub clean_paths: Vec<String>,
    /// Sorted list of paths stored as `EntryKind::Conflict` in `tree`.
    pub conflict_paths: Vec<String>,
}

/// Perform a first-class Jujutsu-style algebraic 3-way merge of `ours` and `theirs` against `base`.
///
/// Conflicts never fail the merge: conflicting files are recorded directly as
/// `EntryKind::Conflict { term, mode }` inside the returned `DomainTree`, allowing
/// snapshots, checkouts, agent handoffs, and incremental per-file resolution.
pub fn merge_domain_trees<F, W>(
    base: &DomainTree,
    ours: &DomainTree,
    theirs: &DomainTree,
    read_blob: F,
    mut write_blob: W,
) -> Result<TreeMergeResult>
where
    F: Fn(ObjectHash) -> Result<Vec<u8>>,
    W: FnMut(&[u8]) -> Result<(ObjectHash, u64)>,
{
    if base.domain != ours.domain || base.domain != theirs.domain {
        return Err(GitxError::Merge(format!(
            "cannot merge trees from different domains: base={}, ours={}, theirs={}",
            base.domain, ours.domain, theirs.domain
        )));
    }

    let mut all_paths: BTreeSet<&str> = BTreeSet::new();
    all_paths.extend(base.entries.keys().map(String::as_str));
    all_paths.extend(ours.entries.keys().map(String::as_str));
    all_paths.extend(theirs.entries.keys().map(String::as_str));

    let mut tree = DomainTree::new(ours.domain.clone());
    let mut clean_paths = Vec::new();
    let mut conflict_paths = Vec::new();

    for path in all_paths {
        let b = base.entries.get(path);
        let o = ours.entries.get(path);
        let t = theirs.entries.get(path);

        // Fast paths when at least two sides agree on the exact entry
        if o == t {
            record_resolved_entry(&mut tree, &mut clean_paths, &mut conflict_paths, path, o);
            continue;
        }
        if o == b {
            record_resolved_entry(&mut tree, &mut clean_paths, &mut conflict_paths, path, t);
            continue;
        }
        if t == b {
            record_resolved_entry(&mut tree, &mut clean_paths, &mut conflict_paths, path, o);
            continue;
        }

        // Both sides diverged from base and from each other.
        match (b, o, t) {
            // Standard 3-way file merge (modify/modify or add/add)
            (
                b_entry @ (None | Some(EntryKind::File { .. })),
                Some(EntryKind::File {
                    blob_hash: o_hash,
                    mode: o_mode,
                    ..
                }),
                Some(EntryKind::File {
                    blob_hash: t_hash,
                    mode: t_mode,
                    ..
                }),
            ) => {
                let (b_hash, b_mode) = match b_entry {
                    Some(EntryKind::File {
                        blob_hash, mode, ..
                    }) => (Some(*blob_hash), Some(*mode)),
                    _ => (None, None),
                };

                let merged_mode = merge_file_mode(b_mode, *o_mode, *t_mode);

                let base_bytes = match b_hash {
                    Some(h) => read_blob(h)?,
                    None => Vec::new(),
                };
                let ours_bytes = read_blob(*o_hash)?;
                let theirs_bytes = read_blob(*t_hash)?;

                match (
                    merge_bytes(path, &base_bytes, &ours_bytes, &theirs_bytes),
                    merged_mode,
                ) {
                    (MergeOutcome::Clean(merged), Some(mode)) => {
                        let (blob_hash, size) = write_blob(&merged)?;
                        tree.insert(
                            path,
                            EntryKind::File {
                                blob_hash,
                                mode,
                                size,
                            },
                        );
                        clean_paths.push(path.to_string());
                    }
                    _ => {
                        let term = ConflictTerm {
                            adds: vec![Some(*o_hash), Some(*t_hash)],
                            removes: vec![b_hash],
                        };
                        tree.insert(
                            path,
                            EntryKind::Conflict {
                                term,
                                mode: merged_mode.unwrap_or(*o_mode),
                            },
                        );
                        conflict_paths.push(path.to_string());
                    }
                }
            }
            // Modify/delete, delete/modify, encrypted secret divergence, or algebraic conflict propagation
            _ => {
                let term = combine_terms(entry_to_term(b), entry_to_term(o), entry_to_term(t));
                let mode = preferred_mode(b, o, t);

                if term.is_resolved() {
                    match term.adds.first().copied().flatten() {
                        Some(resolved_hash) => {
                            if let Some(secret_entry) = [o, t, b].into_iter().flatten().find(|e| {
                                matches!(
                                    e,
                                    EntryKind::EncryptedSecret { envelope_hash, .. }
                                        if *envelope_hash == resolved_hash
                                )
                            }) {
                                tree.insert(path, secret_entry.clone());
                            } else {
                                let bytes = read_blob(resolved_hash)?;
                                tree.insert(
                                    path,
                                    EntryKind::File {
                                        blob_hash: resolved_hash,
                                        mode,
                                        size: bytes.len() as u64,
                                    },
                                );
                            }
                        }
                        None => {
                            // Resolved to deletion
                        }
                    }
                    clean_paths.push(path.to_string());
                } else {
                    tree.insert(path, EntryKind::Conflict { term, mode });
                    conflict_paths.push(path.to_string());
                }
            }
        }
    }

    Ok(TreeMergeResult {
        tree,
        clean_paths,
        conflict_paths,
    })
}

/// Render human-readable conflict markers on demand from an algebraic `ConflictTerm`.
pub fn materialize_conflict<F>(term: &ConflictTerm, path: &str, read_blob: F) -> Result<Vec<u8>>
where
    F: Fn(ObjectHash) -> Result<Vec<u8>>,
{
    if term.is_resolved() {
        return match term.adds.first().copied().flatten() {
            Some(h) => read_blob(h),
            None => Ok(Vec::new()),
        };
    }

    // Standard 2-sided conflict (adds: [ours, theirs], removes: [base])
    if term.adds.len() == 2 && term.removes.len() <= 1 {
        let ours_opt = term.adds[0];
        let theirs_opt = term.adds[1];
        let base_opt = term.removes.first().copied().flatten();

        return match (ours_opt, theirs_opt) {
            (Some(o_hash), Some(t_hash)) => {
                let base_bytes = match base_opt {
                    Some(b_hash) => read_blob(b_hash)?,
                    None => Vec::new(),
                };
                let ours_bytes = read_blob(o_hash)?;
                let theirs_bytes = read_blob(t_hash)?;
                match merge_bytes(path, &base_bytes, &ours_bytes, &theirs_bytes) {
                    MergeOutcome::Conflict { materialized, .. } => Ok(materialized),
                    MergeOutcome::Clean(bytes) => Ok(bytes),
                }
            }
            (Some(o_hash), None) => {
                let ours_bytes = read_blob(o_hash)?;
                let base_bytes = match base_opt {
                    Some(b_hash) => read_blob(b_hash)?,
                    None => Vec::new(),
                };
                Ok(render_modify_delete_conflict(
                    &base_bytes,
                    Some(&ours_bytes),
                    None,
                ))
            }
            (None, Some(t_hash)) => {
                let theirs_bytes = read_blob(t_hash)?;
                let base_bytes = match base_opt {
                    Some(b_hash) => read_blob(b_hash)?,
                    None => Vec::new(),
                };
                Ok(render_modify_delete_conflict(
                    &base_bytes,
                    None,
                    Some(&theirs_bytes),
                ))
            }
            (None, None) => Ok(Vec::new()),
        };
    }

    // General N-way algebraic conflict rendering
    let mut out = String::new();
    out.push_str(&format!("<<<<<<< Conflict ({path})\n"));
    for (idx, side) in term.adds.iter().enumerate() {
        out.push_str(&format!("+++++++ Side {}\n", idx + 1));
        match side {
            Some(h) => {
                let bytes = read_blob(*h)?;
                append_bytes_as_text(&mut out, &bytes, *h);
            }
            None => out.push_str("(deleted)\n"),
        }
    }
    for (idx, rem) in term.removes.iter().enumerate() {
        out.push_str(&format!("------- Base {}\n", idx + 1));
        match rem {
            Some(h) => {
                let bytes = read_blob(*h)?;
                append_bytes_as_text(&mut out, &bytes, *h);
            }
            None => out.push_str("(absent)\n"),
        }
    }
    out.push_str(&format!(">>>>>>> Conflict ({path}) ends\n"));
    Ok(out.into_bytes())
}

/// Resolve a single conflicted entry in `tree` by replacing it with a concrete `EntryKind::File`.
///
/// Other conflicted entries in `tree` remain untouched. Returns `true` if `path` was a conflict
/// and was resolved, or `false` if `path` was absent or not in a conflicted state.
pub fn resolve_conflict_in_tree(
    tree: &mut DomainTree,
    path: &str,
    resolved_blob: ObjectHash,
    mode: FileMode,
    size: u64,
) -> bool {
    if matches!(tree.entries.get(path), Some(EntryKind::Conflict { .. })) {
        tree.entries.insert(
            path.to_string(),
            EntryKind::File {
                blob_hash: resolved_blob,
                mode,
                size,
            },
        );
        true
    } else {
        false
    }
}

/// Resolve a single conflicted entry in `tree` by deleting the path (e.g., accepting deletion in a
/// modify/delete conflict). Returns `true` if `path` was a conflict and was removed.
pub fn resolve_conflict_by_deletion(tree: &mut DomainTree, path: &str) -> bool {
    if matches!(tree.entries.get(path), Some(EntryKind::Conflict { .. })) {
        tree.entries.remove(path);
        true
    } else {
        false
    }
}

fn record_resolved_entry(
    tree: &mut DomainTree,
    clean_paths: &mut Vec<String>,
    conflict_paths: &mut Vec<String>,
    path: &str,
    entry: Option<&EntryKind>,
) {
    match entry {
        Some(e @ EntryKind::Conflict { .. }) => {
            tree.insert(path, e.clone());
            conflict_paths.push(path.to_string());
        }
        Some(e) => {
            tree.insert(path, e.clone());
            clean_paths.push(path.to_string());
        }
        None => {
            clean_paths.push(path.to_string());
        }
    }
}

fn merge_file_mode(base: Option<FileMode>, ours: FileMode, theirs: FileMode) -> Option<FileMode> {
    if ours == theirs {
        Some(ours)
    } else if Some(ours) == base {
        Some(theirs)
    } else if Some(theirs) == base {
        Some(ours)
    } else {
        None
    }
}

fn entry_mode(entry: Option<&EntryKind>) -> Option<FileMode> {
    match entry? {
        EntryKind::File { mode, .. }
        | EntryKind::EncryptedSecret { mode, .. }
        | EntryKind::Conflict { mode, .. } => Some(*mode),
    }
}

fn preferred_mode(
    base: Option<&EntryKind>,
    ours: Option<&EntryKind>,
    theirs: Option<&EntryKind>,
) -> FileMode {
    entry_mode(ours)
        .or_else(|| entry_mode(theirs))
        .or_else(|| entry_mode(base))
        .unwrap_or(FileMode::Regular)
}

fn entry_to_term(entry: Option<&EntryKind>) -> ConflictTerm {
    match entry {
        None => ConflictTerm {
            adds: vec![None],
            removes: Vec::new(),
        },
        Some(EntryKind::File { blob_hash, .. }) => ConflictTerm {
            adds: vec![Some(*blob_hash)],
            removes: Vec::new(),
        },
        Some(EntryKind::EncryptedSecret { envelope_hash, .. }) => ConflictTerm {
            adds: vec![Some(*envelope_hash)],
            removes: Vec::new(),
        },
        Some(EntryKind::Conflict { term, .. }) => term.clone(),
    }
}

/// Algebraic combination `ours - base + theirs` with cancellation of matching positive/negative terms.
fn combine_terms(base: ConflictTerm, ours: ConflictTerm, theirs: ConflictTerm) -> ConflictTerm {
    let mut adds = Vec::with_capacity(ours.adds.len() + theirs.adds.len() + base.removes.len());
    adds.extend(ours.adds);
    adds.extend(theirs.adds);
    adds.extend(base.removes);

    let mut removes =
        Vec::with_capacity(ours.removes.len() + theirs.removes.len() + base.adds.len());
    removes.extend(ours.removes);
    removes.extend(theirs.removes);
    removes.extend(base.adds);

    // Cancel identical terms appearing in both `adds` and `removes`
    let mut remaining_removes = Vec::with_capacity(removes.len());
    for rem in removes {
        if let Some(pos) = adds.iter().position(|a| *a == rem) {
            adds.remove(pos);
        } else {
            remaining_removes.push(rem);
        }
    }

    ConflictTerm {
        adds,
        removes: remaining_removes,
    }
}

fn render_modify_delete_conflict(
    base: &[u8],
    ours: Option<&[u8]>,
    theirs: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = String::new();
    match ours {
        Some(bytes) => {
            out.push_str("<<<<<<< OURS\n");
            append_bytes_as_text(&mut out, bytes, ObjectHash::of_bytes(bytes));
        }
        None => {
            out.push_str("<<<<<<< OURS (deleted)\n");
        }
    }
    out.push_str("||||||| BASE\n");
    if !base.is_empty() {
        append_bytes_as_text(&mut out, base, ObjectHash::of_bytes(base));
    }
    out.push_str("=======\n");
    match theirs {
        Some(bytes) => {
            append_bytes_as_text(&mut out, bytes, ObjectHash::of_bytes(bytes));
            out.push_str(">>>>>>> THEIRS\n");
        }
        None => {
            out.push_str(">>>>>>> THEIRS (deleted)\n");
        }
    }
    out.into_bytes()
}

fn append_bytes_as_text(out: &mut String, bytes: &[u8], hash: ObjectHash) {
    match std::str::from_utf8(bytes) {
        Ok(s) => {
            out.push_str(s);
            if !s.is_empty() && !s.ends_with('\n') {
                out.push('\n');
            }
        }
        Err(_) => {
            out.push_str(&format!(
                "[binary content: {} bytes, blake3:{}]\n",
                bytes.len(),
                hash.short()
            ));
        }
    }
}
