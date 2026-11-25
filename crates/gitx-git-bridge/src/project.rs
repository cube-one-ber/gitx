//! ACL-filtered projection engine from a `gitx-store` repository into a valid Git repository.

use crate::objects::{
    GitCommitParams, GitOid, GitSignature, write_commit_object, write_loose_object,
    write_tree_from_files,
};
use chrono::{DateTime, Utc};
use gitx_core::{
    ChangeSet, DomainId, EmbargoState, EntryKind, FileMode, GitxError, ObjectHash, Result,
};
use gitx_store::ObjectStore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::path::Path;

/// Summary of an ACL-filtered export into a Git repository.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProjectionReport {
    pub exported_commits: usize,
    pub skipped_private_commits: usize,
    pub omitted_private_files: usize,
    pub ref_map: BTreeMap<String, GitOid>,
}

/// Initializes a minimal valid Git directory layout if not already present.
fn ensure_git_dir_initialized(target_git_dir: &Path) -> Result<()> {
    fs::create_dir_all(target_git_dir.join("objects").join("info"))?;
    fs::create_dir_all(target_git_dir.join("objects").join("pack"))?;
    fs::create_dir_all(target_git_dir.join("refs").join("heads"))?;
    fs::create_dir_all(target_git_dir.join("refs").join("tags"))?;

    let config_path = target_git_dir.join("config");
    if !config_path.exists() {
        let is_bare = target_git_dir.file_name().and_then(|n| n.to_str()) != Some(".git");
        let bare_val = if is_bare { "true" } else { "false" };
        let config = format!(
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = {bare_val}\n"
        );
        fs::write(&config_path, config)?;
    }

    let head_path = target_git_dir.join("HEAD");
    if !head_path.exists() {
        fs::write(&head_path, "ref: refs/heads/master\n")?;
    }

    Ok(())
}

/// Returns true iff `cs` may be projected under `allowed_domains`.
///
/// Active embargoes are NEVER authorized solely by placing `embargo:<advisory>` in the flat
/// `allowed` set; each active embargo changeset must intersect `allowed` on a non-public
/// domain listed in that changeset's own `allowed_domains`.
fn is_changeset_visible(cs: &ChangeSet, allowed: &HashSet<&DomainId>) -> bool {
    match &cs.visibility.embargo {
        Some(EmbargoState::Active {
            allowed_domains, ..
        }) => allowed_domains
            .iter()
            .any(|d| !d.is_public() && allowed.contains(d)),
        Some(EmbargoState::Published { .. }) => {
            allowed.contains(&DomainId::public()) || allowed.contains(&cs.visibility.primary_domain)
        }
        None => allowed.contains(&cs.visibility.primary_domain),
    }
}

/// Loads all ChangeSets reachable from `bookmarks` and returns them in topological order
/// (parents strictly before children).
fn load_reachable_topo_order(
    store: &dyn ObjectStore,
    bookmarks: &BTreeMap<String, ObjectHash>,
) -> Result<Vec<ChangeSet>> {
    let mut loaded: HashMap<ObjectHash, ChangeSet> = HashMap::new();
    let mut queue: VecDeque<ObjectHash> = bookmarks.values().copied().collect();

    while let Some(hash) = queue.pop_front() {
        if loaded.contains_key(&hash) {
            continue;
        }
        let cs = store.get_changeset(hash)?;
        for &parent in &cs.parents {
            if !loaded.contains_key(&parent) {
                queue.push_back(parent);
            }
        }
        loaded.insert(hash, cs);
    }

    if loaded.is_empty() {
        return Ok(Vec::new());
    }

    // Kahn's topological sort: edge parent -> child.
    let mut children: HashMap<ObjectHash, Vec<ObjectHash>> = HashMap::with_capacity(loaded.len());
    let mut in_degree: HashMap<ObjectHash, usize> = HashMap::with_capacity(loaded.len());

    for (&id, cs) in &loaded {
        let mut unique_parents = HashSet::new();
        let mut deg = 0usize;
        for &parent in &cs.parents {
            if loaded.contains_key(&parent) && unique_parents.insert(parent) {
                children.entry(parent).or_default().push(id);
                deg += 1;
            }
        }
        in_degree.insert(id, deg);
    }

    let mut ready: BTreeSet<(DateTime<Utc>, ObjectHash)> = BTreeSet::new();
    for (&id, &deg) in &in_degree {
        if deg == 0 {
            ready.insert((loaded[&id].created_at, id));
        }
    }

    let mut ordered = Vec::with_capacity(loaded.len());
    while let Some((_, id)) = ready.pop_first() {
        if let Some(child_ids) = children.get(&id) {
            for &child in child_ids {
                if let Some(deg) = in_degree.get_mut(&child) {
                    *deg -= 1;
                    if *deg == 0 {
                        ready.insert((loaded[&child].created_at, child));
                    }
                }
            }
        }
        if let Some(cs) = loaded.remove(&id) {
            ordered.push(cs);
        }
    }

    if !loaded.is_empty() {
        return Err(GitxError::GitBridge(
            "cycle detected in changeset parent DAG".to_string(),
        ));
    }

    Ok(ordered)
}

fn validate_bookmark_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.starts_with('/')
        || name.ends_with('/')
        || name.contains("..")
        || name.contains('\0')
        || name.contains('\\')
    {
        return Err(GitxError::GitBridge(format!(
            "invalid git branch name '{name}'"
        )));
    }
    Ok(())
}

/// Projects ONLY authorized visibility domains from `store` into `target_git_dir`.
///
/// - Initializes a valid bare (or non-bare when ending in `.git`) Git directory structure if needed.
/// - Walks reachable ChangeSets from `bookmarks` in topological order (parents before children).
/// - Skips unauthorized or actively embargoed ChangeSets, remapping descendants' parent pointers
///   to the nearest visible ancestor(s).
/// - Merges only `DomainTree`s whose `DomainId` is in `allowed_domains`, omitting encrypted
///   secrets and unresolved conflicts.
/// - Updates `refs/heads/<bookmark>` and `HEAD` (`refs/heads/master` if exported, else the first
///   exported bookmark).
pub fn export_to_git_repo(
    store: &dyn ObjectStore,
    target_git_dir: &Path,
    allowed_domains: &[DomainId],
    bookmarks: &BTreeMap<String, ObjectHash>,
) -> Result<ProjectionReport> {
    let allowed_set: HashSet<&DomainId> = allowed_domains.iter().collect();
    export_to_git_repo_filtered(store, target_git_dir, allowed_domains, bookmarks, |cs| {
        is_changeset_visible(cs, &allowed_set)
    })
}

/// Projects authorized visibility domains from `store` into `target_git_dir`, using an explicit
/// per-changeset visibility predicate `can_read_cs` (e.g. `AclPolicy::can_read_changeset`) so
/// active embargoes are always authorized per-changeset rather than via a flat domain allowlist.
pub fn export_to_git_repo_filtered<F>(
    store: &dyn ObjectStore,
    target_git_dir: &Path,
    allowed_domains: &[DomainId],
    bookmarks: &BTreeMap<String, ObjectHash>,
    mut can_read_cs: F,
) -> Result<ProjectionReport>
where
    F: FnMut(&ChangeSet) -> bool,
{
    ensure_git_dir_initialized(target_git_dir)?;

    let allowed_set: HashSet<&DomainId> = allowed_domains.iter().collect();
    let ordered = load_reachable_topo_order(store, bookmarks)?;

    let mut report = ProjectionReport::default();

    // Maps each visited ChangeSet ObjectHash to the visible Git commit OID(s) it represents:
    // - If exported: vec![own_git_oid]
    // - If skipped: deduplicated union of parents' effective visible Git commit OIDs
    let mut effective_ancestors: HashMap<ObjectHash, Vec<GitOid>> =
        HashMap::with_capacity(ordered.len());
    let mut skipped_commit_ids: HashSet<ObjectHash> = HashSet::new();
    // Cache GitX blob manifest ObjectHash -> Git blob GitOid across commits.
    let mut blob_cache: HashMap<ObjectHash, GitOid> = HashMap::new();

    for cs in &ordered {
        // Compute remapped visible parent OIDs in deterministic order without duplicates.
        let mut visible_parents: Vec<GitOid> = Vec::new();
        for parent_hash in &cs.parents {
            if let Some(mapped) = effective_ancestors.get(parent_hash) {
                for &oid in mapped {
                    if !visible_parents.contains(&oid) {
                        visible_parents.push(oid);
                    }
                }
            }
        }

        if !can_read_cs(cs) {
            report.skipped_private_commits += 1;
            skipped_commit_ids.insert(cs.id);
            effective_ancestors.insert(cs.id, visible_parents);
            continue;
        }

        // Merge allowed DomainTrees in canonical precedence matching `gitx-server`:
        // public (0) < team/private/secret (1) < active primary embargo (2).
        let mut merged_files: BTreeMap<String, (FileMode, GitOid)> = BTreeMap::new();

        let mut domain_entries: Vec<(&DomainId, &ObjectHash)> = cs.domain_trees.iter().collect();
        domain_entries.sort_by(|(a, _), (b, _)| {
            let rank = |d: &DomainId| -> u8 {
                if d.is_public() {
                    0
                } else if *d == cs.visibility.primary_domain && d.is_embargo() {
                    2
                } else {
                    1
                }
            };
            rank(a).cmp(&rank(b)).then_with(|| a.cmp(b))
        });

        for (domain_id, &tree_hash) in domain_entries {
            // An `embargo:*` tree is projected ONLY when it is the primary domain of THIS
            // changeset that already passed `can_read_cs(cs)` — never via a flat allowlist entry.
            let tree_allowed = if domain_id.is_embargo() {
                *domain_id == cs.visibility.primary_domain
                    && matches!(
                        &cs.visibility.embargo,
                        Some(EmbargoState::Active { .. }) | Some(EmbargoState::Published { .. })
                    )
            } else {
                allowed_set.contains(domain_id)
            };

            if !tree_allowed {
                match store.get_tree(tree_hash) {
                    Ok(tree) => {
                        report.omitted_private_files += tree.entries.len();
                    }
                    Err(GitxError::NotFound(_)) => {
                        // In a stripped/partial store, unauthorized trees may not exist locally.
                    }
                    Err(e) => return Err(e),
                }
                continue;
            }

            let tree = store.get_tree(tree_hash)?;
            for (path, kind) in &tree.entries {
                match kind {
                    EntryKind::File {
                        blob_hash, mode, ..
                    } => {
                        let blob_oid = if let Some(&cached) = blob_cache.get(blob_hash) {
                            cached
                        } else {
                            let bytes = store.read_blob_bytes(*blob_hash)?;
                            let oid = write_loose_object(target_git_dir, "blob", &bytes)?;
                            blob_cache.insert(*blob_hash, oid);
                            oid
                        };
                        merged_files.insert(path.clone(), (*mode, blob_oid));
                    }
                    EntryKind::EncryptedSecret { .. } | EntryKind::Conflict { .. } => {
                        report.omitted_private_files += 1;
                    }
                }
            }
        }

        let tree_oid = write_tree_from_files(target_git_dir, &merged_files)?;
        let commit_oid = write_commit_object(
            target_git_dir,
            &GitCommitParams {
                tree: tree_oid,
                parents: visible_parents,
                author: GitSignature::from_identity(&cs.author, cs.created_at),
                committer: GitSignature::from_actor(&cs.committer, cs.created_at),
                message: cs.description.clone(),
            },
        )?;

        report.exported_commits += 1;
        effective_ancestors.insert(cs.id, vec![commit_oid]);
    }

    // Update refs/heads/<bookmark> for every bookmark that resolves to a visible commit.
    // Never advertise a non-default bookmark whose tip is an unauthorized/skipped commit
    // (avoiding leaking embargo or private branch names to unauthorized callers).
    for (bookmark, target_hash) in bookmarks {
        validate_bookmark_name(bookmark)?;
        if bookmark != "master" && skipped_commit_ids.contains(target_hash) {
            continue;
        }
        if let Some(oids) = effective_ancestors.get(target_hash)
            && let Some(&tip_oid) = oids.first()
        {
            let ref_path = target_git_dir.join("refs").join("heads").join(bookmark);
            if let Some(parent) = ref_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&ref_path, format!("{tip_oid}\n"))?;
            report.ref_map.insert(bookmark.clone(), tip_oid);
        }
    }

    // Update HEAD to refs/heads/master if present, else the first exported bookmark.
    let head_branch = if report.ref_map.contains_key("master") {
        "master"
    } else if let Some(first) = report.ref_map.keys().next() {
        first.as_str()
    } else {
        "master"
    };
    fs::write(
        target_git_dir.join("HEAD"),
        format!("ref: refs/heads/{head_branch}\n"),
    )?;

    Ok(report)
}
