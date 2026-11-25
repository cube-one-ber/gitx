//! Pure-Rust colocated Git repository importer powered by `gitoxide` (`gix`).
//!
//! Reads loose objects, packfiles, delta chains, refs, commits, trees, and blobs directly
//! from `.git` without spawning any `git` CLI subprocesses.

use chrono::{DateTime, Utc};
use gitx_core::{
    Actor, ChangeSetBuilder, DomainId, DomainTree, EntryKind, FileMode, GitxError, Identity,
    ObjectHash, Result, VisibilityPolicy,
};
use gitx_store::ObjectStore;
use gix::bstr::ByteSlice;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::Path;

/// Summary of an import from an existing Git repository into `gitx-store`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReport {
    pub imported_commits: usize,
    pub head_changeset: Option<ObjectHash>,
    pub branch: String,
}

struct ParsedCommitMeta {
    oid: gix::ObjectId,
    tree_oid: gix::ObjectId,
    parents: Vec<gix::ObjectId>,
    author: Identity,
    committer: Identity,
    created_at: DateTime<Utc>,
    description: String,
}

struct ParsedTreeEntry {
    mode: FileMode,
    blob_oid: gix::ObjectId,
    path: String,
}

fn parse_commit_with_gix(repo: &gix::Repository, oid: gix::ObjectId) -> Result<ParsedCommitMeta> {
    let obj = repo
        .find_object(oid)
        .map_err(|e| GitxError::GitBridge(format!("gitoxide failed to find commit {oid}: {e}")))?;
    let commit = obj
        .try_into_commit()
        .map_err(|e| GitxError::GitBridge(format!("gitoxide object {oid} is not a commit: {e}")))?;
    let decoded = commit.decode().map_err(|e| {
        GitxError::GitBridge(format!("gitoxide failed to decode commit {oid}: {e}"))
    })?;

    let tree_oid = decoded.tree();
    let parents: Vec<gix::ObjectId> = decoded.parents().collect();

    let author_sig = decoded.author().map_err(|e| {
        GitxError::GitBridge(format!("gitoxide invalid author in commit {oid}: {e}"))
    })?;
    let committer_sig = decoded.committer().map_err(|e| {
        GitxError::GitBridge(format!("gitoxide invalid committer in commit {oid}: {e}"))
    })?;

    let author_ts = author_sig.time().map(|t| t.seconds).unwrap_or(0);
    let created_at = DateTime::from_timestamp(author_ts, 0).unwrap_or_else(Utc::now);

    let raw_msg = decoded.message.to_str_lossy();
    let description = raw_msg.strip_suffix('\n').unwrap_or(&raw_msg).to_string();

    Ok(ParsedCommitMeta {
        oid,
        tree_oid,
        parents,
        author: Identity {
            name: author_sig.name.to_str_lossy().into_owned(),
            email: author_sig.email.to_str_lossy().into_owned(),
            key_fingerprint: None,
        },
        committer: Identity {
            name: committer_sig.name.to_str_lossy().into_owned(),
            email: committer_sig.email.to_str_lossy().into_owned(),
            key_fingerprint: None,
        },
        created_at,
        description,
    })
}

fn collect_tree_entries_gix(
    repo: &gix::Repository,
    tree_oid: gix::ObjectId,
    prefix: &str,
    out: &mut Vec<ParsedTreeEntry>,
) -> Result<()> {
    let tree = repo.find_tree(tree_oid).map_err(|e| {
        GitxError::GitBridge(format!("gitoxide failed to find tree {tree_oid}: {e}"))
    })?;
    for entry_res in tree.iter() {
        let entry = entry_res
            .map_err(|e| GitxError::GitBridge(format!("gitoxide tree entry decode error: {e}")))?;
        let name = entry.filename().to_str().map_err(|e| {
            GitxError::GitBridge(format!("non-UTF8 filename in git tree {tree_oid}: {e}"))
        })?;
        let rel_path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };

        use gix::objs::tree::EntryKind as GitEntryKind;
        match entry.mode().kind() {
            GitEntryKind::Tree => {
                collect_tree_entries_gix(repo, entry.oid().to_owned(), &rel_path, out)?;
            }
            GitEntryKind::Blob => {
                out.push(ParsedTreeEntry {
                    mode: FileMode::Regular,
                    blob_oid: entry.oid().to_owned(),
                    path: rel_path,
                });
            }
            GitEntryKind::BlobExecutable => {
                out.push(ParsedTreeEntry {
                    mode: FileMode::Executable,
                    blob_oid: entry.oid().to_owned(),
                    path: rel_path,
                });
            }
            GitEntryKind::Link => {
                out.push(ParsedTreeEntry {
                    mode: FileMode::Symlink,
                    blob_oid: entry.oid().to_owned(),
                    path: rel_path,
                });
            }
            GitEntryKind::Commit => {
                // Skip submodule gitlinks cleanly.
            }
        }
    }
    Ok(())
}

/// Topologically sort all commits reachable from `head_oid` (parents strictly before children).
fn load_commits_topo_order(
    repo: &gix::Repository,
    head_oid: gix::ObjectId,
) -> Result<Vec<ParsedCommitMeta>> {
    let mut loaded: HashMap<gix::ObjectId, ParsedCommitMeta> = HashMap::new();
    let mut queue: VecDeque<gix::ObjectId> = VecDeque::new();
    queue.push_back(head_oid);

    while let Some(oid) = queue.pop_front() {
        if loaded.contains_key(&oid) {
            continue;
        }
        let meta = parse_commit_with_gix(repo, oid)?;
        for &p in &meta.parents {
            if !loaded.contains_key(&p) {
                queue.push_back(p);
            }
        }
        loaded.insert(oid, meta);
    }

    let mut children: HashMap<gix::ObjectId, Vec<gix::ObjectId>> =
        HashMap::with_capacity(loaded.len());
    let mut in_degree: HashMap<gix::ObjectId, usize> = HashMap::with_capacity(loaded.len());

    for (&oid, meta) in &loaded {
        let mut uniq_parents = HashSet::new();
        let mut deg = 0usize;
        for &p in &meta.parents {
            if loaded.contains_key(&p) && uniq_parents.insert(p) {
                children.entry(p).or_default().push(oid);
                deg += 1;
            }
        }
        in_degree.insert(oid, deg);
    }

    let mut ready: BTreeSet<(DateTime<Utc>, gix::ObjectId)> = BTreeSet::new();
    for (&oid, &deg) in &in_degree {
        if deg == 0 {
            ready.insert((loaded[&oid].created_at, oid));
        }
    }

    let mut ordered = Vec::with_capacity(loaded.len());
    while let Some((_, oid)) = ready.pop_first() {
        if let Some(child_ids) = children.get(&oid) {
            for &child in child_ids {
                if let Some(deg) = in_degree.get_mut(&child) {
                    *deg -= 1;
                    if *deg == 0 {
                        ready.insert((loaded[&child].created_at, child));
                    }
                }
            }
        }
        if let Some(meta) = loaded.remove(&oid) {
            ordered.push(meta);
        }
    }

    if !loaded.is_empty() {
        return Err(GitxError::GitBridge(
            "cycle detected in imported Git commit graph".into(),
        ));
    }
    Ok(ordered)
}

/// Imports an existing Git repository (working tree or bare repo) losslessly into `store`
/// under `target_domain` using pure-Rust **`gitoxide` (`gix`)**—no `git` CLI subprocesses.
pub fn import_from_git_repo(
    git_worktree: &Path,
    store: &dyn ObjectStore,
    target_domain: DomainId,
) -> Result<ImportReport> {
    let repo = gix::open(git_worktree).map_err(|e| {
        GitxError::GitBridge(format!(
            "gitoxide failed to open repository '{}': {e}",
            git_worktree.display()
        ))
    })?;

    let mut head = repo
        .head()
        .map_err(|e| GitxError::GitBridge(format!("gitoxide failed to read HEAD: {e}")))?;

    let branch = head
        .referent_name()
        .map(|n| n.shorten().to_str_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "HEAD".to_string());

    if head.is_unborn() {
        return Ok(ImportReport {
            imported_commits: 0,
            head_changeset: None,
            branch,
        });
    }

    let head_commit = match head.peel_to_commit() {
        Ok(c) => c,
        Err(_) => {
            return Ok(ImportReport {
                imported_commits: 0,
                head_changeset: None,
                branch,
            });
        }
    };
    let head_oid = head_commit.id().detach();

    let commits = load_commits_topo_order(&repo, head_oid)?;

    let mut git_to_gitx: HashMap<gix::ObjectId, ObjectHash> = HashMap::with_capacity(commits.len());
    let mut git_to_pub_proj: HashMap<gix::ObjectId, ObjectHash> =
        HashMap::with_capacity(commits.len());
    let mut blob_cache: HashMap<gix::ObjectId, (ObjectHash, u64)> = HashMap::new();
    let mut head_changeset: Option<ObjectHash> = None;

    let visibility = if target_domain.is_public() {
        VisibilityPolicy::public()
    } else {
        VisibilityPolicy::private(target_domain.clone(), false)
    };

    for meta in &commits {
        let mut tree_entries = Vec::new();
        collect_tree_entries_gix(&repo, meta.tree_oid, "", &mut tree_entries)?;

        let mut domain_tree = DomainTree::new(target_domain.clone());
        for entry in tree_entries {
            let (manifest_hash, size) = if let Some(&cached) = blob_cache.get(&entry.blob_oid) {
                cached
            } else {
                let blob_obj = repo.find_blob(entry.blob_oid).map_err(|e| {
                    GitxError::GitBridge(format!(
                        "gitoxide failed to read blob {}: {e}",
                        entry.blob_oid
                    ))
                })?;
                let stored = store.put_blob_bytes(&blob_obj.data)?;
                let pair = (stored.manifest_hash(), stored.total_size);
                blob_cache.insert(entry.blob_oid, pair);
                pair
            };

            domain_tree.insert(
                entry.path,
                EntryKind::File {
                    blob_hash: manifest_hash,
                    mode: entry.mode,
                    size,
                },
            );
        }

        let tree_hash = store.put_tree(&domain_tree)?;

        let parents: Vec<ObjectHash> = meta
            .parents
            .iter()
            .filter_map(|p| git_to_gitx.get(p).copied())
            .collect();

        let public_parents: Vec<ObjectHash> = if target_domain.is_public() {
            meta.parents
                .iter()
                .filter_map(|p| git_to_pub_proj.get(p).copied())
                .collect()
        } else {
            Vec::new()
        };

        let cs = ChangeSetBuilder::new(meta.author.clone())
            .committer(Actor::Human(meta.committer.clone()))
            .parents(parents)
            .public_parents(public_parents)
            .domain_tree(target_domain.clone(), tree_hash)
            .visibility(visibility.clone())
            .created_at(meta.created_at)
            .description(meta.description.clone())
            .build();

        let cs_id = store.put_changeset(&cs)?;
        git_to_gitx.insert(meta.oid, cs_id);
        git_to_pub_proj.insert(meta.oid, cs.public_projection_hash);
        head_changeset = Some(cs_id);
    }

    if let Some(head_id) = head_changeset {
        store.set_bookmark(&branch, head_id)?;
    }

    Ok(ImportReport {
        imported_commits: commits.len(),
        head_changeset,
        branch,
    })
}
